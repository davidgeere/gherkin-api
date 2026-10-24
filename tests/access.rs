use std::time::Duration;

use gherkin::{router, AppState};
use hmac::{Hmac, Mac};
use serde_json::{json, Value};
use sha2::Sha256;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

type HmacSha256 = Hmac<Sha256>;

struct Running {
    base: String,
    setup: String,
}

async fn boot() -> Running {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://gherkin@127.0.0.1:54329/gherkin_test".to_string());
    let setup = "test-setup-token".to_string();
    let state = AppState::connect(&database_url, &setup)
        .await
        .expect("connect");
    sqlx_truncate(&database_url).await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, router(state)).await.unwrap();
    });
    Running {
        base: format!("http://{address}"),
        setup,
    }
}

async fn sqlx_truncate(database_url: &str) {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .connect(database_url)
        .await
        .unwrap();
    sqlx::query("TRUNCATE commands, events, webhooks, devices, tokens, users CASCADE")
        .execute(&pool)
        .await
        .unwrap();
}

async fn request(
    method: &str,
    url: &str,
    token: Option<&str>,
    body: Option<Value>,
) -> (u16, Value) {
    let client = reqwest::Client::new();
    let mut call = client.request(method.parse().unwrap(), url);
    if let Some(token) = token {
        call = call.bearer_auth(token);
    }
    if let Some(body) = body {
        call = call.json(&body);
    }
    let response = call.send().await.unwrap();
    let status = response.status().as_u16();
    let text = response.text().await.unwrap();
    let json = if text.is_empty() {
        Value::Null
    } else {
        serde_json::from_str(&text).unwrap_or(Value::String(text))
    };
    (status, json)
}

#[tokio::test]
async fn users_are_isolated_and_the_api_is_closed() {
    let api = boot().await;

    let (status, _) = request("GET", &format!("{}/v1/events", api.base), None, None).await;
    assert_eq!(status, 401);

    let (status, _) = request(
        "POST",
        &format!("{}/v1/users", api.base),
        None,
        Some(json!({
            "email": "ada@example.com",
            "display_name": "Ada",
            "password": "correct horse"
        })),
    )
    .await;
    assert_eq!(status, 401);

    let (status, ada_user) = request(
        "POST",
        &format!("{}/v1/users", api.base),
        Some(&api.setup),
        Some(json!({
            "email": "ada@example.com",
            "display_name": "Ada",
            "password": "correct horse"
        })),
    )
    .await;
    assert_eq!(status, 201, "{ada_user}");
    let (status, bea_user) = request(
        "POST",
        &format!("{}/v1/users", api.base),
        Some(&api.setup),
        Some(json!({
            "email": "bea@example.com",
            "display_name": "Bea",
            "password": "battery staple"
        })),
    )
    .await;
    assert_eq!(status, 201, "{bea_user}");

    let (status, ada_login) = request(
        "POST",
        &format!("{}/v1/login", api.base),
        None,
        Some(json!({"email": "ada@example.com", "password": "correct horse"})),
    )
    .await;
    assert_eq!(status, 201, "{ada_login}");
    let ada = ada_login["token"].as_str().unwrap();
    let (status, bea_login) = request(
        "POST",
        &format!("{}/v1/login", api.base),
        None,
        Some(json!({"email": "bea@example.com", "password": "battery staple"})),
    )
    .await;
    assert_eq!(status, 201, "{bea_login}");
    let bea = bea_login["token"].as_str().unwrap();

    let (status, ada_me) = request("GET", &format!("{}/v1/me", api.base), Some(ada), None).await;
    assert_eq!(status, 200);
    assert_eq!(ada_me["email"], "ada@example.com");
    let (status, bea_sees_ada) =
        request("GET", &format!("{}/v1/me", api.base), Some(bea), None).await;
    assert_eq!(bea_sees_ada["email"], "bea@example.com");
    let _ = status;

    let (status, device) = request(
        "POST",
        &format!("{}/v1/devices", api.base),
        Some(ada),
        Some(json!({"name": "Ada phone", "platform": "ios"})),
    )
    .await;
    assert_eq!(status, 201, "{device}");
    let device_id = device["id"].as_str().unwrap();

    let hook_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let hook_addr = hook_listener.local_addr().unwrap();
    let (status, hook) = request(
        "POST",
        &format!("{}/v1/webhooks", api.base),
        Some(ada),
        Some(json!({"url": format!("http://{hook_addr}/hook")})),
    )
    .await;
    assert_eq!(status, 201, "{hook}");
    let secret = hook["secret"].as_str().unwrap().to_string();

    let (status, _) = request(
        "POST",
        &format!("{}/v1/webhooks", api.base),
        Some(bea),
        Some(json!({"url": format!("http://{hook_addr}/bea")})),
    )
    .await;
    assert_eq!(status, 201);

    let (status, event) = request(
        "POST",
        &format!("{}/v1/events", api.base),
        Some(ada),
        Some(json!({
            "kind": "location.update",
            "device_id": device_id,
            "payload": {"latitude": 49.28, "longitude": -123.12}
        })),
    )
    .await;
    assert_eq!(status, 201, "{event}");

    let (status, ada_events) =
        request("GET", &format!("{}/v1/events", api.base), Some(ada), None).await;
    assert_eq!(status, 200);
    assert_eq!(ada_events.as_array().unwrap().len(), 1);
    let (status, bea_events) =
        request("GET", &format!("{}/v1/events", api.base), Some(bea), None).await;
    assert_eq!(status, 200);
    assert_eq!(bea_events.as_array().unwrap().len(), 0);

    let (status, stolen) = request(
        "POST",
        &format!("{}/v1/events", api.base),
        Some(bea),
        Some(json!({"kind": "location.update", "device_id": device_id, "payload": {}})),
    )
    .await;
    assert_eq!(status, 404, "{stolen}");

    let delivery = tokio::time::timeout(Duration::from_secs(3), read_http(&hook_listener))
        .await
        .expect("webhook did not arrive")
        .expect("webhook read");
    assert!(delivery.starts_with("POST /hook "));
    let signature = header(&delivery, "x-gherkin-signature");
    let raw_body = delivery.split("\r\n\r\n").nth(1).unwrap();
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(raw_body.as_bytes());
    let expected = format!(
        "sha256={}",
        hex::encode(mac.finalize().into_bytes())
    );
    assert_eq!(signature, expected);
    assert!(raw_body.contains("location.update"));

    let (status, command) = request(
        "POST",
        &format!("{}/v1/commands", api.base),
        Some(ada),
        Some(json!({
            "device_id": device_id,
            "kind": "location.now",
            "payload": {}
        })),
    )
    .await;
    assert_eq!(status, 201, "{command}");

    let (status, bea_device) = request(
        "POST",
        &format!("{}/v1/devices", api.base),
        Some(bea),
        Some(json!({"name": "Bea phone", "platform": "ios"})),
    )
    .await;
    assert_eq!(status, 201, "{bea_device}");
    let bea_device_id = bea_device["id"].as_str().unwrap();
    let (status, bea_pending) = request(
        "GET",
        &format!(
            "{}/v1/commands/pending?device_id={bea_device_id}&wait=0",
            api.base
        ),
        Some(bea),
        None,
    )
    .await;
    assert_eq!(status, 200, "{bea_pending}");
    assert_eq!(bea_pending.as_array().unwrap().len(), 0);

    let (status, ada_pending) = request(
        "GET",
        &format!(
            "{}/v1/commands/pending?device_id={device_id}&wait=0",
            api.base
        ),
        Some(ada),
        None,
    )
    .await;
    assert_eq!(status, 200, "{ada_pending}");
    assert_eq!(ada_pending.as_array().unwrap().len(), 1);
    assert_eq!(ada_pending[0]["kind"], "location.now");
    let command_id = ada_pending[0]["id"].as_str().unwrap();

    let (status, _) = request(
        "POST",
        &format!("{}/v1/commands/{command_id}/result", api.base),
        Some(bea),
        Some(json!({"status": "done", "result": {"stolen": true}})),
    )
    .await;
    assert_eq!(status, 404);

    let (status, _) = request(
        "POST",
        &format!("{}/v1/commands/{command_id}/result", api.base),
        Some(ada),
        Some(json!({"status": "done", "result": {"latitude": 49.28}})),
    )
    .await;
    assert_eq!(status, 204);
}

fn header(message: &str, name: &str) -> String {
    message
        .lines()
        .find(|line| line.to_ascii_lowercase().starts_with(&format!("{name}:")))
        .unwrap_or_default()
        .split_once(':')
        .map(|(_, value)| value.trim().to_string())
        .unwrap_or_default()
}

async fn read_http(listener: &TcpListener) -> std::io::Result<String> {
    let (mut socket, _) = listener.accept().await?;
    let mut buf = vec![0u8; 8192];
    let n = socket.read(&mut buf).await?;
    let message = String::from_utf8_lossy(&buf[..n]).to_string();
    let response = "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    socket.write_all(response.as_bytes()).await?;
    Ok(message)
}
