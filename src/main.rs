mod http;
mod smtp;

use std::sync::Arc;

use axum::{extract::Request, ServiceExt};
use axum_server::tls_rustls::RustlsConfig;
use base64ct::Encoding;
use hickory_resolver::{
    config::ResolverConfig, name_server::TokioConnectionProvider, TokioResolver,
};
use hmac::Mac;
use mail_auth::MessageAuthenticator;
use reqwest::StatusCode;
use tokio_rustls::rustls::{
    pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer},
    ServerConfig,
};
use tower::Layer;
use tower_http::normalize_path::NormalizePathLayer;
use url::Url;

pub struct Ctx {
    pub hostname: String,
    pub auth_token: String,
    pub webhook_secret: Option<String>,
    pub webhook_url: Option<Url>,
    pub client: reqwest::Client,
    pub authenticator: MessageAuthenticator,
    pub resolver: TokioResolver,
    pub rustls_config: Arc<ServerConfig>,
}

pub enum WebhookEventType {
    Received,
    Bounced,
}

impl Ctx {
    pub fn has_webhook(&self) -> bool {
        self.webhook_url.is_some()
    }

    pub async fn send_webhook(
        &self,
        event_type: WebhookEventType,
        payload: serde_json::Value,
    ) -> Result<StatusCode, reqwest::Error> {
        if let Some(webhook_url) = self.webhook_url.clone() {
            let mut req = self.client.post(webhook_url);
            let body = serde_json::json!({
                "event": match event_type {
                    WebhookEventType::Received => "received",
                    WebhookEventType::Bounced => "bounced",
                },
                "data": payload,
            })
            .to_string();
            req = req.header("Content-Type", "application/json");
            if let Some(secret) = self.webhook_secret.as_ref() {
                let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(secret.as_bytes())
                    .expect("HMAC can take key of any size");
                mac.update(body.as_bytes());

                let signature = base64ct::Base64::encode_string(&mac.finalize().into_bytes());
                req = req.header("X-Signature", signature);
            }
            let res = req.send().await?;
            Ok(res.status())
        } else {
            panic!("Webhook URL is not set");
        }
    }
}

static mut CTX: Option<Ctx> = None;

pub fn ctx() -> &'static Ctx {
    #[allow(static_mut_refs)]
    unsafe {
        CTX.as_ref().expect("CTX not initialized")
    }
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let _ = dotenvy::dotenv();
    let _ = dotenvy::from_path("/opt/parcel/parcel.conf");
    rustls::crypto::CryptoProvider::install_default(rustls::crypto::ring::default_provider())
        .expect("Failed to install default crypto provider");

    let hostname = std::env::var("HOSTNAME").expect("HOSTNAME not set");
    let auth_token = std::env::var("AUTH_TOKEN").expect("AUTH_TOKEN not set");
    let webhook_secret = std::env::var("WEBHOOK_SECRET").ok();
    let webhook_url = std::env::var("WEBHOOK_URL").ok().and_then(|url| {
        Url::parse(&url)
            .inspect_err(|e| {
                eprintln!("Invalid WEBHOOK_URL: {}", e);
            })
            .ok()
    });
    let cert_path = std::env::var("TLS_CERT")
        .unwrap_or_else(|_| "/opt/parcel/cert.pem".to_string())
        .parse::<std::path::PathBuf>()
        .expect("TLS_CERT must be a valid path");
    let key_path = std::env::var("TLS_KEY")
        .unwrap_or_else(|_| "/opt/parcel/key.pem".to_string())
        .parse::<std::path::PathBuf>()
        .expect("TLS_KEY must be a valid path");
    let certs = CertificateDer::pem_file_iter(cert_path)
        .expect("Failed to read TLS_CERT")
        .collect::<Result<Vec<_>, _>>()
        .expect("Failed to parse TLS_CERT");
    let key = PrivateKeyDer::from_pem_file(key_path).expect("Failed to read TLS_KEY");
    unsafe {
        CTX = Some(Ctx {
            hostname,
            auth_token,
            webhook_secret,
            webhook_url,
            client: reqwest::Client::new(),
            // authenticator: MessageAuthenticator::new_cloudflare_tls()
            authenticator: MessageAuthenticator::new_cloudflare()
                .expect("Failed to create MessageAuthenticator"),
            resolver: TokioResolver::builder_with_config(
                // ResolverConfig::cloudflare_tls(),
                ResolverConfig::cloudflare(),
                TokioConnectionProvider::default(),
            )
            .build(),
            rustls_config: Arc::new(
                ServerConfig::builder()
                    .with_no_client_auth()
                    .with_single_cert(certs, key)
                    .expect("Failed to create Rustls ServerConfig"),
            ),
        });
    }

    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let config = RustlsConfig::from_config(ctx().rustls_config.clone());
    let port = std::env::var("PORT")
        .unwrap_or_else(|_| "443".to_string())
        .parse::<u16>()
        .expect("PORT must be a valid u16 number");
    let addr = std::net::SocketAddr::V6(std::net::SocketAddrV6::new(
        std::net::Ipv6Addr::UNSPECIFIED,
        port,
        0,
        0,
    ));
    tokio::spawn(smtp::listen());
    axum_server::bind_rustls(addr, config)
        .serve(ServiceExt::<Request>::into_make_service(
            NormalizePathLayer::trim_trailing_slash().layer(http::router()),
        ))
        .await
}
