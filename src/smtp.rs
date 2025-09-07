use std::{net::SocketAddr, str::FromStr};

use email_address::EmailAddress;
use mail_auth::{
    common::headers::HeaderWriter, dmarc::verify::DmarcParameters, spf::verify::SpfParameters,
    AuthenticatedMessage, AuthenticationResults, DmarcResult,
};
use mail_parser::{Message, MessageParser};
use reqwest::StatusCode;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader, BufWriter},
    net::{TcpListener, TcpStream},
};
use tokio_rustls::{server::TlsStream, TlsAcceptor};

use crate::ctx;

pub async fn listen() -> tokio::io::Result<()> {
    let smtp_port = std::env::var("SMTP_PORT")
        .unwrap_or_else(|_| "25".to_string())
        .parse::<u16>()
        .expect("Invalid SMTP_PORT");
    let addr = std::net::SocketAddr::V6(std::net::SocketAddrV6::new(
        std::net::Ipv6Addr::UNSPECIFIED,
        smtp_port,
        0,
        0,
    ));
    let listener = TcpListener::bind(addr).await?;
    tracing::info!("SMTP server listening on port {}", smtp_port);

    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                tracing::info!("New connection from {}", addr);
                tokio::spawn(async move {
                    if let Err(e) = handle_client(stream, addr).await {
                        tracing::error!("Error handling client {}: {}", addr, e);
                    }
                });
            },
            Err(e) => {
                tracing::error!("Failed to accept connection: {}", e);
            },
        }
    }
}

#[tracing::instrument(skip(stream))]
async fn handle_client(mut stream: TcpStream, addr: SocketAddr) -> anyhow::Result<()> {
    let (reader, writer) = stream.split();
    let mut reader = BufReader::new(reader);
    let mut writer = BufWriter::new(writer);

    if handle_unsecure_client(&mut reader, &mut writer, addr).await? {
        let acceptor = TlsAcceptor::from(ctx().rustls_config.clone());
        let mut stream = acceptor.accept(stream).await?;
        println!("TLS established with {}", addr);
        let (reader, writer) = tokio::io::split(&mut stream);
        let mut reader = BufReader::new(reader);
        let mut writer = BufWriter::new(writer);
        handle_secure_client(&mut reader, &mut writer, addr).await?;
        stream.shutdown().await?;
    }
    Ok(())
}

async fn handle_unsecure_client(
    reader: &mut BufReader<tokio::net::tcp::ReadHalf<'_>>,
    writer: &mut BufWriter<tokio::net::tcp::WriteHalf<'_>>,
    addr: SocketAddr,
) -> anyhow::Result<bool> {
    writer
        .write_all(format!("220 {}\r\n", ctx().hostname).as_bytes())
        .await?;
    writer.flush().await?;

    let mut buffer = String::new();
    loop {
        buffer.clear();
        // TODO: should read until \r\n, not just \n
        match reader.read_line(&mut buffer).await {
            Ok(0) => {
                tracing::info!("Client {} disconnected", addr);
                return Ok(false);
            },
            Ok(_) => {
                let (cmd, _) = if let Some(space_pos) = buffer.find(' ') {
                    (&buffer[..space_pos], buffer[space_pos + 1..].trim_end())
                } else {
                    (buffer.trim_end(), "")
                };
                tracing::info!("Received from {}: {}", addr, cmd);
                match cmd.to_uppercase().as_str() {
                    "EHLO" | "HELO" => {
                        writer
                            .write_all(
                                format!(
                                    "250-{}\r\n250-STARTTLS\r\n250-SIZE 26214400\r\n250 \
                                     ENHANCEDSTATUSCODES\r\n",
                                    ctx().hostname
                                )
                                .as_bytes(),
                            )
                            .await?;
                        writer.flush().await?;
                    },
                    "STARTTLS" => {
                        writer
                            .write_all(b"220 2.0.0 Ready to start TLS\r\n")
                            .await?;
                        writer.flush().await?;
                        return Ok(true);
                    },

                    "NOOP" => {
                        writer.write_all(b"250 2.0.0 OK\r\n").await?;
                        writer.flush().await?;
                    },
                    "QUIT" => {
                        writer.write_all(b"221 2.0.0 Bye\r\n").await?;
                        writer.flush().await?;
                        return Ok(false);
                    },
                    _ => {
                        writer
                            .write_all(b"530 5.7.0 Must issue a STARTTLS command first\r\n")
                            .await?;
                        writer.flush().await?;
                    },
                }
            },
            Err(e) => {
                tracing::error!("Error reading from {}: {}", addr, e);
                return Err(e.into());
            },
        }
    }
}

async fn handle_secure_client(
    reader: &mut BufReader<tokio::io::ReadHalf<&mut TlsStream<TcpStream>>>,
    writer: &mut BufWriter<tokio::io::WriteHalf<&mut TlsStream<TcpStream>>>,
    addr: SocketAddr,
) -> anyhow::Result<()> {
    let ctx = ctx();
    // writer
    //     .write_all(format!("220 {}\r\n", ctx.hostname).as_bytes())
    //     .await?;
    // writer.flush().await?;
    let mut buffer = String::new();
    let mut message = String::new();
    let mut state = SmtpState::Command;
    let mut helo_domain = None;
    let mut mail_from = None;
    let mut bounce = false;
    let mut rcpt_to = Vec::new();
    loop {
        buffer.clear();
        match reader.read_line(&mut buffer).await {
            Ok(0) => {
                tracing::info!("Client {} disconnected", addr);
                break;
            },
            Ok(_) => {
                match state {
                    SmtpState::Command => {
                        let (cmd, rest) = if let Some(space_pos) = buffer.find(' ') {
                            (&buffer[..space_pos], buffer[space_pos + 1..].trim_end())
                        } else {
                            (buffer.trim_end(), "")
                        };
                        tracing::info!("Received from {}: {}", addr, cmd);

                        let response = match cmd.to_uppercase().as_str() {
                            "HELO" | "EHLO" => {
                                // SPF and IPREV are typically in relaxed mode, so for now we don't
                                // actually care about them
                                helo_domain = Some(rest.to_string());
                                format!(
                                    "250-{}\r\n250-SIZE 26214400\r\n250-PIPELINING\r\n250-8BITMIME\r\n250 ENHANCEDSTATUSCODES\r\n",
                                    ctx.hostname
                                )
                            },
                            "MAIL" => {
                                if helo_domain.is_none() {
                                    "503 5.5.1 Bad sequence of commands\r\n".to_string()
                                } else {
                                    // need to get the sender address,
                                    let rest = rest.trim().to_lowercase();
                                    if let Some(rest) = rest.strip_prefix("from:") {
                                        // ignore any parameters after the address
                                        let addr_str = rest
                                            .split_whitespace()
                                            .next()
                                            .unwrap_or("")
                                            .trim_matches(|c| c == '<' || c == '>')
                                            .to_lowercase();
                                        if addr_str.is_empty() {
                                            // empty sender address means a bounce
                                            bounce = true;
                                            "250 2.1.0 OK\r\n".to_string()
                                        } else if let Ok(address) =
                                            EmailAddress::from_str(addr_str.as_str())
                                        {
                                            mail_from = Some(address);
                                            "250 2.1.0 OK\r\n".to_string()
                                        } else {
                                            "550 5.1.7 Bad sender address syntax\r\n".to_string()
                                        }
                                    } else {
                                        "550 5.1.7 Bad sender address syntax\r\n".to_string()
                                    }
                                }
                            },
                            "RCPT" => {
                                let rest = rest.trim().to_lowercase();
                                if mail_from.is_none() && !bounce {
                                    "503 5.5.1 Bad sequence of commands\r\n".to_string()
                                } else if let Some(rest) = rest.strip_prefix("to:") {
                                    // ignore any parameters after the address
                                    let addr_str = rest
                                        .split_whitespace()
                                        .next()
                                        .unwrap_or("")
                                        .trim_matches(|c| c == '<' || c == '>')
                                        .to_lowercase();
                                    if let Ok(address) = EmailAddress::from_str(addr_str.as_str()) {
                                        if address.domain() == ctx.hostname
                                            && address.local_part().starts_with("bounce-")
                                        {
                                            bounce = true;
                                        }
                                        if bounce {
                                            // if this is a bounce, we only allow one recipient
                                            if !rcpt_to.is_empty() {
                                                "452 4.5.3 Too many recipients\r\n".to_string()
                                            } else if address.domain() == ctx.hostname {
                                                rcpt_to.push(address);
                                                "250 2.1.5 OK\r\n".to_string()
                                            } else {
                                                "550 5.7.1 Cannot send to non-local address\r\n"
                                                    .to_string()
                                            }
                                        } else if rcpt_to.len() >= 100 {
                                            "452 4.5.3 Too many recipients\r\n".to_string()
                                        } else if !rcpt_to.contains(&address) {
                                            rcpt_to.push(address);
                                            "250 2.1.5 OK\r\n".to_string()
                                        } else {
                                            "250 2.1.5 OK\r\n".to_string()
                                        }
                                    } else {
                                        "550 5.1.3 Bad recipient address syntax\r\n".to_string()
                                    }
                                } else {
                                    "550 5.1.3 Bad recipient address syntax\r\n".to_string()
                                }
                            },
                            "DATA" => {
                                if rcpt_to.is_empty() {
                                    "503 5.5.1 Bad sequence of commands\r\n".to_string()
                                } else {
                                    state = SmtpState::Data;
                                    "354 Start mail input; end with <CRLF>.<CRLF>\r\n".to_string()
                                }
                            },
                            "RSET" => {
                                mail_from = None;
                                rcpt_to.clear();
                                state = SmtpState::Command;
                                "250 2.0.0 OK\r\n".to_string()
                            },
                            "NOOP" => "250 2.0.0 OK\r\n".to_string(),
                            "QUIT" => {
                                writer.write_all(b"221 2.0.0 Bye\r\n").await?;
                                writer.flush().await?;
                                break;
                            },
                            _ => "500 5.5.1 Command unrecognized\r\n".to_string(),
                        };
                        println!("Response: {}", response.trim_end());

                        writer.write_all(response.as_bytes()).await?;
                        writer.flush().await?;
                    },
                    SmtpState::Data => {
                        if buffer.trim_end() == "." {
                            // End of data
                            state = SmtpState::Command;
                            println!("{}", message);
                            let Some(msg) = MessageParser::new()
                                .parse(message.as_bytes())
                                .filter(|x| x.headers().iter().any(|x| !x.name.is_other()))
                            else {
                                tracing::error!(
                                    "Failed to parse message from {}: {}",
                                    addr,
                                    message
                                );
                                writer
                                    .write_all(b"550 5.6.0 Message parsing failed\r\n")
                                    .await?;
                                writer.flush().await?;
                                // Reset state
                                mail_from = None;
                                rcpt_to.clear();
                                message.clear();
                                bounce = false;
                                continue;
                            };
                            println!("HEADERS: {:#?}", msg.headers());
                            // Process the message
                            let msg = AuthenticatedMessage::from_parsed(&msg, false);
                            // if this is a bounce, then we send a webhook
                            if bounce {
                                let local_part = rcpt_to[0].local_part();
                                if !local_part.starts_with("bounce-") {
                                    writer.write_all(b"550 5.7.1 Message rejected\r\n").await?;
                                    writer.flush().await?;
                                    // Reset state
                                    mail_from = None;
                                    rcpt_to.clear();
                                    message.clear();
                                    bounce = false;
                                    continue;
                                }
                                let id = &local_part[7..];
                                if ctx.has_webhook() {
                                    let body = serde_json::json!({
                                        "id": id,
                                    });
                                    let status = match ctx
                                        .send_webhook(crate::WebhookEventType::Bounced, body)
                                        .await
                                    {
                                        Ok(status) => status,
                                        Err(e) => {
                                            tracing::error!(
                                                "Failed to send webhook for bounce id {}: {}",
                                                id,
                                                e
                                            );
                                            StatusCode::INTERNAL_SERVER_ERROR
                                        },
                                    };
                                    if status.is_client_error() {
                                        writer.write_all(b"550 5.7.1 Message rejected\r\n").await?;
                                        writer.flush().await?;
                                        // Reset state
                                        mail_from = None;
                                        rcpt_to.clear();
                                        message.clear();
                                        bounce = false;
                                        continue;
                                    } else if status.is_server_error() {
                                        writer
                                            .write_all(b"451 4.3.1 Temporary server failure\r\n")
                                            .await?;
                                        writer.flush().await?;
                                        // Reset state
                                        mail_from = None;
                                        rcpt_to.clear();
                                        message.clear();
                                        bounce = false;
                                        continue;
                                    }
                                }
                            } else {
                                println!(
                                    "Received message from {:?}",
                                    msg.headers
                                        .iter()
                                        .map(|(k, v)| (
                                            String::from_utf8_lossy(k),
                                            String::from_utf8_lossy(v)
                                        ))
                                        .collect::<Vec<_>>()
                                );
                                let dkim_result = ctx.authenticator.verify_dkim(&msg).await;
                                println!(
                                    "DKIM results for message from {}: {:#?}",
                                    mail_from
                                        .as_ref()
                                        .map(|e| e.email())
                                        .unwrap_or("unknown".to_string()),
                                    dkim_result
                                );
                                let mail_from_addr = mail_from
                                    .as_ref()
                                    .map(|e| e.email())
                                    .expect("MAIL FROM missing");
                                let mail_from_domain = mail_from
                                    .as_ref()
                                    .map(|e| e.domain())
                                    .expect("MAIL FROM missing");
                                let spf_mailfrom_result = ctx
                                    .authenticator
                                    .verify_spf(SpfParameters::verify_mail_from(
                                        addr.ip(),
                                        helo_domain.as_ref().expect("HELO/EHLO missing"),
                                        ctx.hostname.as_str(),
                                        mail_from_addr.as_str(),
                                    ))
                                    .await;
                                let dmarc_result = ctx
                                    .authenticator
                                    .verify_dmarc(
                                        DmarcParameters::new(
                                            &msg,
                                            &dkim_result,
                                            mail_from_domain,
                                            &spf_mailfrom_result,
                                        )
                                        .with_domain_suffix_fn(|domain| {
                                            psl::domain_str(domain).unwrap_or(domain)
                                        }),
                                    )
                                    .await;
                                // if DMARC did not pass, we reject
                                match (dmarc_result.dkim_result(), dmarc_result.spf_result()) {
                                    (DmarcResult::Pass, _) | (_, DmarcResult::Pass) => {
                                        // OK
                                    },
                                    (DmarcResult::TempError(e), _)
                                    | (_, DmarcResult::TempError(e)) => {
                                        tracing::error!(
                                            "Temporary DMARC error for message from {}: {}",
                                            mail_from_addr,
                                            e
                                        );
                                        writer
                                            .write_all(
                                                b"451 4.7.0 Message rejected due to DMARC\r\n",
                                            )
                                            .await?;
                                        writer.flush().await?;
                                        // Reset state
                                        mail_from = None;
                                        rcpt_to.clear();
                                        message.clear();
                                        bounce = false;
                                        continue;
                                    },
                                    _ => {
                                        println!(
                                            "DMARC failed for message from {}: {:#?}",
                                            mail_from_addr, dmarc_result
                                        );
                                        writer
                                            .write_all(
                                                b"550 5.7.1 Message rejected due to DMARC\r\n",
                                            )
                                            .await?;
                                        writer.flush().await?;
                                        // Reset state
                                        mail_from = None;
                                        rcpt_to.clear();
                                        message.clear();
                                        bounce = false;
                                        continue;
                                    },
                                }

                                let arc_result = ctx.authenticator.verify_arc(&msg).await;
                                let iprev_result = ctx.authenticator.verify_iprev(addr.ip()).await;
                                let mut results = AuthenticationResults::new(&ctx.hostname)
                                    .with_spf_mailfrom_result(
                                        &spf_mailfrom_result,
                                        addr.ip(),
                                        &mail_from_addr,
                                        helo_domain.as_ref().expect("HELO/EHLO missing"),
                                    )
                                    .with_dmarc_result(&dmarc_result)
                                    .with_arc_result(&arc_result, addr.ip())
                                    .with_iprev_result(&iprev_result, addr.ip());
                                for dkim in &dkim_result {
                                    results = results.with_dkim_result(dkim, msg.from());
                                }
                                let auth_results = results.to_header();
                                let received = format!(
                                    "Received: from {} ({})\r\n\tby {} with SMTP; {}\r\n",
                                    helo_domain.as_deref().unwrap_or("unknown"),
                                    addr,
                                    ctx.hostname,
                                    chrono::Utc::now().format("%a, %d %b %Y %H:%M:%S +0000")
                                );
                                println!(
                                    "Authentication results for message from {}: {:#?}",
                                    mail_from_addr, results
                                );
                                let final_message =
                                    format!("{}{}{}", auth_results, received, message);
                                if ctx.has_webhook() {
                                    let body = serde_json::json!({
                                        "from": mail_from_addr,
                                        "to": rcpt_to.iter().map(|e| e.email()).collect::<Vec<_>>(),
                                        "message": final_message,
                                    });
                                    let status = match ctx
                                        .send_webhook(crate::WebhookEventType::Received, body)
                                        .await
                                    {
                                        Ok(status) => status,
                                        Err(e) => {
                                            tracing::error!(
                                                "Failed to send webhook for message from {}: {}",
                                                mail_from_addr,
                                                e
                                            );
                                            StatusCode::INTERNAL_SERVER_ERROR
                                        },
                                    };
                                    if status.is_client_error() {
                                        writer.write_all(b"550 5.7.1 Message rejected\r\n").await?;
                                        writer.flush().await?;
                                        // Reset state
                                        mail_from = None;
                                        rcpt_to.clear();
                                        message.clear();
                                        bounce = false;
                                        continue;
                                    } else if status.is_server_error() {
                                        writer
                                            .write_all(b"451 4.3.1 Temporary server failure\r\n")
                                            .await?;
                                        writer.flush().await?;
                                        // Reset state
                                        mail_from = None;
                                        rcpt_to.clear();
                                        message.clear();
                                        bounce = false;
                                        continue;
                                    }
                                }
                                // println!("Final message:\n{}", final_message);
                            }
                            writer
                                .write_all(b"250 2.0.0 Message accepted for delivery\r\n")
                                .await?;
                            writer.flush().await?;
                            // Reset state
                            mail_from = None;
                            rcpt_to.clear();
                            message.clear();
                            bounce = false;
                        } else {
                            message.push_str(&buffer);
                            message.push('\n');
                        }
                    },
                }
            },
            Err(e) => {
                tracing::error!("Error reading from {}: {}", addr, e);
                return Err(e.into());
            },
        }
    }

    tracing::info!("Connection with {} closed", addr);
    Ok(())
}

enum SmtpState {
    Command,
    Data,
}
