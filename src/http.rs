use axum::{http::StatusCode, response::IntoResponse, Json};
use axum_extra::{
    headers::{authorization::Bearer, Authorization},
    TypedHeader,
};
use email_address::EmailAddress;
use mail_parser::MessageParser;
use mail_send::{smtp::message::Message, SmtpClientBuilder};
use serde_json::json;

use crate::ctx;

pub fn router() -> axum::Router {
    axum::Router::new()
        .route("/v1/health", axum::routing::get(health))
        .route("/v1/send", axum::routing::post(send_email))
}

async fn health() -> &'static str {
    "OK"
}

#[derive(serde::Deserialize)]
struct SendEmail {
    id: String,
    to: EmailAddress,
    from: EmailAddress,
    body: String,
}

#[tracing::instrument(skip(header, body))]
async fn send_email(
    header: TypedHeader<Authorization<Bearer>>,
    Json(body): Json<SendEmail>,
) -> impl IntoResponse {
    if header.token() != ctx().auth_token {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "unauthorized"})),
        );
    }
    // let mail_from = format!("bounce-{}@{}", body.id, ctx().hostname);
    let mail_from = format!("bounce-{}@{}", body.id, body.from.domain());
    println!("mail_from: {}", mail_from);
    let message = Message::new(mail_from.as_str(), [body.to.as_str()], body.body.as_bytes());
    let Ok(mx_records) = ctx().resolver.mx_lookup(body.to.domain()).await else {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "no_mx"})));
    };
    if mx_records.iter().count() == 0 {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "no_mx"})));
    }
    let mx_record = mx_records
        .iter()
        .min_by_key(|record| record.preference())
        .unwrap();
    let mx_host = mx_record.exchange().to_string();
    let mut smtp_client = match SmtpClientBuilder::new(&mx_host, 25)
        .implicit_tls(false)
        .connect()
        .await
    {
        Ok(client) => client,
        Err(e) => {
            tracing::error!("Failed to connect to SMTP server {}: {}", mx_host, e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "failed_to_connect"})),
            );
        },
    };
    if let Err(e) = smtp_client.send(message).await {
        tracing::error!("Failed to send email to {}: {}", body.to, e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "failed_to_send"})),
        );
    }
    (StatusCode::OK, Json(json!({})))
}
