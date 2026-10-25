use std::time::Duration;

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use axum::{
    extract::{FromRequestParts, Path, Query, State},
    http::{header::AUTHORIZATION, request::Parts, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::{postgres::PgPoolOptions, FromRow, PgPool};
use subtle::ConstantTimeEq;
use tokio::sync::Notify;
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS tokens (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id),
    name TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    kind TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS devices (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id),
    name TEXT NOT NULL,
    platform TEXT NOT NULL,
    last_seen_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS events (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id),
    device_id UUID REFERENCES devices(id),
    kind TEXT NOT NULL,
    payload JSONB NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS events_user_recorded ON events (user_id, recorded_at DESC);

CREATE TABLE IF NOT EXISTS webhooks (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id),
    url TEXT NOT NULL,
    secret TEXT NOT NULL,
    kinds TEXT[],
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS commands (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id),
    device_id UUID REFERENCES devices(id),
    kind TEXT NOT NULL,
    payload JSONB NOT NULL,
    status TEXT NOT NULL,
    result JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS commands_user_status ON commands (user_id, status, created_at);

CREATE TABLE IF NOT EXISTS capabilities (
    user_id UUID PRIMARY KEY REFERENCES users(id),
    state JSONB NOT NULL DEFAULT '{}'::jsonb,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE devices ADD COLUMN IF NOT EXISTS model TEXT NOT NULL DEFAULT '';
ALTER TABLE devices ADD COLUMN IF NOT EXISTS system_name TEXT NOT NULL DEFAULT '';
ALTER TABLE devices ADD COLUMN IF NOT EXISTS system_version TEXT NOT NULL DEFAULT '';
ALTER TABLE devices ADD COLUMN IF NOT EXISTS vendor_id TEXT NOT NULL DEFAULT '';
CREATE UNIQUE INDEX IF NOT EXISTS devices_user_unique ON devices (user_id);

ALTER TABLE users ADD COLUMN IF NOT EXISTS role TEXT NOT NULL DEFAULT 'parent';

CREATE TABLE IF NOT EXISTS family_rules (
    child_user_id UUID PRIMARY KEY REFERENCES users(id),
    blocked_domains TEXT[] NOT NULL DEFAULT '{}',
    allowed_domains TEXT[] NOT NULL DEFAULT '{}',
    downtime_start SMALLINT,
    downtime_end SMALLINT,
    web_locked BOOLEAN NOT NULL DEFAULT false,
    updated_by UUID REFERENCES users(id),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS family_activity (
    id UUID PRIMARY KEY,
    child_user_id UUID NOT NULL REFERENCES users(id),
    kind TEXT NOT NULL,
    detail TEXT NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS family_activity_child ON family_activity (child_user_id, recorded_at DESC);

CREATE TABLE IF NOT EXISTS collection (
    user_id UUID PRIMARY KEY REFERENCES users(id),
    location BOOLEAN NOT NULL DEFAULT true,
    motion BOOLEAN NOT NULL DEFAULT false,
    health BOOLEAN NOT NULL DEFAULT false,
    wifi BOOLEAN NOT NULL DEFAULT false,
    bluetooth BOOLEAN NOT NULL DEFAULT false,
    battery BOOLEAN NOT NULL DEFAULT false,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE family_rules ADD COLUMN IF NOT EXISTS web_locked BOOLEAN NOT NULL DEFAULT false;

CREATE TABLE IF NOT EXISTS admins (
    id UUID PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS admin_sessions (
    id UUID PRIMARY KEY,
    admin_id UUID NOT NULL REFERENCES admins(id),
    token_hash TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at TIMESTAMPTZ
);
"#;

#[derive(Clone)]
pub struct AppState {
    pool: PgPool,
    setup_token: String,
    notify: std::sync::Arc<Notify>,
    http: reqwest::Client,
    dummy_password_hash: String,
}

impl AppState {
    pub async fn connect(database_url: &str, setup_token: &str) -> Result<Self, sqlx::Error> {
        let pool = PgPoolOptions::new()
            .max_connections(8)
            .connect(database_url)
            .await?;
        sqlx::raw_sql(SCHEMA).execute(&pool).await?;
        seed_people(&pool).await?;
        if let Ok(password) = std::env::var("GHERKIN_ADMIN_PASSWORD") {
            if !password.is_empty() {
                let _ = seed_admin(&pool, &password).await;
            }
        }
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("http client");
        Ok(Self {
            pool,
            setup_token: setup_token.to_string(),
            notify: std::sync::Arc::new(Notify::new()),
            http,
            dummy_password_hash: hash_password("gherkin-timing-pad").unwrap_or_default(),
        })
    }
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/v1/users", post(create_user))
        .route("/v1/people", get(list_people))
        .route("/v1/claim", post(claim_person))
        .route("/v1/login", post(login))
        .route("/v1/me", get(me))
        .route("/v1/tokens", post(create_token))
        .route("/v1/tokens/{id}", axum::routing::delete(revoke_token))
        .route("/v1/devices", post(create_device).get(list_devices))
        .route("/v1/admin/login", post(admin_login))
        .route("/v1/admin/people", get(admin_people))
        .route("/v1/admin/tokens", get(admin_list_tokens).post(admin_create_token))
        .route("/v1/admin/tokens/{id}", axum::routing::delete(admin_revoke_token))
        .route("/v1/events", post(create_event).get(list_events))
        .route("/v1/webhooks", post(create_webhook).get(list_webhooks))
        .route("/v1/webhooks/{id}", axum::routing::delete(delete_webhook))
        .route("/v1/commands", post(create_command).get(list_commands))
        .route("/v1/commands/pending", get(pending_commands))
        .route("/v1/commands/{id}/result", post(finish_command))
        .route("/v1/capabilities", get(get_capabilities).put(put_capabilities))
        .route("/v1/family/people", get(list_family))
        .route("/v1/family/rules", get(get_rules).put(put_rules))
        .route("/v1/family/activity", get(list_activity).post(post_activity))
        .route("/v1/collection", get(get_collection).put(put_collection))
        .layer(axum::extract::DefaultBodyLimit::max(8 * 1024 * 1024))
        .with_state(state)
}

async fn health() -> Json<Value> {
    Json(json!({ "ok": true }))
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }
    fn bad(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, message)
    }
    fn unauthorized() -> Self {
        Self::new(StatusCode::UNAUTHORIZED, "unauthorized")
    }
    fn not_found(message: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, message)
    }
    fn conflict(message: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, message)
    }
    fn db(err: sqlx::Error) -> Self {
        eprintln!("database: {err}");
        if is_unique(&err) {
            return Self::conflict("already exists");
        }
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "database error")
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, Json(json!({ "error": self.message }))).into_response()
    }
}

fn is_unique(err: &sqlx::Error) -> bool {
    err.as_database_error()
        .and_then(|e| e.code())
        .is_some_and(|code| code == "23505")
}

struct AuthUser {
    user_id: Uuid,
    token_id: Uuid,
}

#[derive(FromRow)]
struct TokenRow {
    id: Uuid,
    user_id: Uuid,
    kind: String,
}

impl FromRequestParts<AppState> for AuthUser {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let token = bearer(&parts.headers).ok_or_else(ApiError::unauthorized)?;
        let hash = hash_token(&token);
        let row = sqlx::query_as::<_, TokenRow>(
            "SELECT id, user_id, kind FROM tokens WHERE token_hash = $1 AND revoked_at IS NULL",
        )
        .bind(&hash)
        .fetch_optional(&state.pool)
        .await
        .map_err(ApiError::db)?;
        let Some(row) = row else {
            return Err(ApiError::unauthorized());
        };
        let _ = row.kind;
        Ok(AuthUser {
            user_id: row.user_id,
            token_id: row.id,
        })
    }
}

fn bearer(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(AUTHORIZATION)?.to_str().ok()?;
    let token = value.strip_prefix("Bearer ")?.trim();
    if token.is_empty() {
        None
    } else {
        Some(token.to_string())
    }
}

fn tokens_equal(a: &str, b: &str) -> bool {
    if a.is_empty() || a.len() != b.len() {
        return false;
    }
    a.as_bytes().ct_eq(b.as_bytes()).into()
}

fn hash_password(password: &str) -> Result<String, ApiError> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "password hash failed"))
}

fn verify_password(password: &str, encoded: &str) -> bool {
    PasswordHash::new(encoded)
        .ok()
        .and_then(|parsed| {
            Argon2::default()
                .verify_password(password.as_bytes(), &parsed)
                .ok()
        })
        .is_some()
}

fn hash_token(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

fn new_secret(prefix: &str) -> (String, String) {
    let mut bytes = [0u8; 32];
    argon2::password_hash::rand_core::RngCore::fill_bytes(&mut OsRng, &mut bytes);
    let token = format!("{prefix}_{}", URL_SAFE_NO_PAD.encode(bytes));
    (token.clone(), hash_token(&token))
}

fn valid_kind(kind: &str) -> bool {
    !kind.is_empty()
        && kind.len() <= 64
        && kind
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-')
}

fn normalize_email(email: &str) -> String {
    email.trim().to_ascii_lowercase()
}

#[derive(Serialize)]
struct UserOut {
    id: Uuid,
    email: String,
    display_name: String,
    role: String,
}

#[derive(FromRow)]
struct UserRow {
    id: Uuid,
    email: String,
    display_name: String,
    password_hash: String,
    role: String,
}

#[derive(Deserialize)]
struct NewUser {
    email: String,
    display_name: String,
    password: String,
}

async fn seed_people(pool: &PgPool) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"INSERT INTO users (id, email, display_name, password_hash, role) VALUES
           ('11111111-1111-4111-8111-111111111111', 'david.geere@gherkin.local', 'David Geere', '!', 'parent'),
           ('22222222-2222-4222-8222-222222222222', 'stephanie.geere@gherkin.local', 'Stephanie Geere', '!', 'parent'),
           ('33333333-3333-4333-8333-333333333333', 'maya.geere@gherkin.local', 'Maya Geere', '!', 'child'),
           ('44444444-4444-4444-8444-444444444444', 'test@gherkin.local', 'Test', '!', 'parent')
           ON CONFLICT (id) DO UPDATE SET role = EXCLUDED.role, display_name = EXCLUDED.display_name, email = EXCLUDED.email"#,
    )
    .execute(pool)
    .await?;
    Ok(())
}

#[derive(Serialize, FromRow)]
struct PersonOut {
    id: Uuid,
    display_name: String,
}

async fn list_people(State(state): State<AppState>) -> Result<Json<Vec<PersonOut>>, ApiError> {
    let rows = sqlx::query_as::<_, PersonOut>(
        r#"SELECT id, display_name FROM users u
           WHERE NOT EXISTS (SELECT 1 FROM devices d WHERE d.user_id = u.id)
           ORDER BY display_name"#,
    )
    .fetch_all(&state.pool)
    .await
    .map_err(ApiError::db)?;
    Ok(Json(rows))
}

#[derive(Deserialize)]
struct ClaimDevice {
    name: String,
    model: String,
    system_name: String,
    system_version: String,
    vendor_id: String,
}

#[derive(Deserialize)]
struct ClaimBody {
    user_id: Uuid,
    device: ClaimDevice,
}

#[derive(Serialize)]
struct ClaimOut {
    token: String,
    user: UserOut,
    device_id: Uuid,
}

async fn claim_person(
    State(state): State<AppState>,
    Json(body): Json<ClaimBody>,
) -> Result<(StatusCode, Json<ClaimOut>), ApiError> {
    let user = sqlx::query_as::<_, UserRow>(
        "SELECT id, email, display_name, password_hash, role FROM users WHERE id = $1",
    )
    .bind(body.user_id)
    .fetch_optional(&state.pool)
    .await
    .map_err(ApiError::db)?;
    let Some(user) = user else {
        return Err(ApiError::not_found("person not found"));
    };
    let taken = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM devices WHERE user_id = $1")
        .bind(user.id)
        .fetch_one(&state.pool)
        .await
        .map_err(ApiError::db)?;
    if taken > 0 {
        return Err(ApiError::conflict("that person is already on a device"));
    }
    let device_id = Uuid::new_v4();
    let name = if body.device.name.trim().is_empty() {
        "iPhone"
    } else {
        body.device.name.trim()
    };
    sqlx::query(
        r#"INSERT INTO devices (id, user_id, name, platform, model, system_name, system_version, vendor_id, last_seen_at)
           VALUES ($1, $2, $3, 'ios', $4, $5, $6, $7, now())"#,
    )
    .bind(device_id)
    .bind(user.id)
    .bind(name)
    .bind(body.device.model.trim())
    .bind(body.device.system_name.trim())
    .bind(body.device.system_version.trim())
    .bind(body.device.vendor_id.trim())
    .execute(&state.pool)
    .await
    .map_err(ApiError::db)?;
    let (token, hash) = new_secret("ghk");
    sqlx::query(
        "INSERT INTO tokens (id, user_id, name, token_hash, kind) VALUES ($1, $2, 'passkey', $3, 'session')",
    )
    .bind(Uuid::new_v4())
    .bind(user.id)
    .bind(&hash)
    .execute(&state.pool)
    .await
    .map_err(ApiError::db)?;
    Ok((
        StatusCode::CREATED,
        Json(ClaimOut {
            token,
            user: UserOut {
                id: user.id,
                email: user.email,
                display_name: user.display_name,
                role: user.role,
            },
            device_id,
        }),
    ))
}

async fn create_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<NewUser>,
) -> Result<(StatusCode, Json<UserOut>), ApiError> {
    let presented = bearer(&headers).unwrap_or_default();
    if !tokens_equal(&state.setup_token, &presented) {
        return Err(ApiError::unauthorized());
    }
    let email = normalize_email(&body.email);
    if !email.contains('@') || body.password.len() < 8 || body.display_name.trim().is_empty() {
        return Err(ApiError::bad(
            "email, display_name, and a password of at least 8 characters are required",
        ));
    }
    let id = Uuid::new_v4();
    let hash = hash_password(&body.password)?;
    sqlx::query(
        "INSERT INTO users (id, email, display_name, password_hash) VALUES ($1, $2, $3, $4)",
    )
    .bind(id)
    .bind(&email)
    .bind(body.display_name.trim())
    .bind(&hash)
    .execute(&state.pool)
    .await
    .map_err(ApiError::db)?;
    Ok((
        StatusCode::CREATED,
        Json(UserOut {
            id,
            email,
            display_name: body.display_name.trim().to_string(),
            role: "parent".to_string(),
        }),
    ))
}

#[derive(Deserialize)]
struct Login {
    email: String,
    password: String,
}

#[derive(Serialize)]
struct LoginOut {
    token: String,
    user: UserOut,
}

async fn login(
    State(state): State<AppState>,
    Json(body): Json<Login>,
) -> Result<(StatusCode, Json<LoginOut>), ApiError> {
    let email = normalize_email(&body.email);
    let row = sqlx::query_as::<_, UserRow>(
        "SELECT id, email, display_name, password_hash, role FROM users WHERE email = $1",
    )
    .bind(&email)
    .fetch_optional(&state.pool)
    .await
    .map_err(ApiError::db)?;
    let (ok, user) = match &row {
        Some(user) => (verify_password(&body.password, &user.password_hash), user),
        None => {
            let _ = verify_password(&body.password, &state.dummy_password_hash);
            return Err(ApiError::unauthorized_login());
        }
    };
    if !ok {
        return Err(ApiError::unauthorized_login());
    }
    let (token, hash) = new_secret("ghk");
    let token_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO tokens (id, user_id, name, token_hash, kind) VALUES ($1, $2, $3, $4, 'session')",
    )
    .bind(token_id)
    .bind(user.id)
    .bind("app")
    .bind(&hash)
    .execute(&state.pool)
    .await
    .map_err(ApiError::db)?;
    Ok((
        StatusCode::CREATED,
        Json(LoginOut {
            token,
            user: UserOut {
                id: user.id,
                email: user.email.clone(),
                display_name: user.display_name.clone(),
                role: user.role.clone(),
            },
        }),
    ))
}

impl ApiError {
    fn unauthorized_login() -> Self {
        Self::new(StatusCode::UNAUTHORIZED, "invalid email or password")
    }
}

async fn me(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<UserOut>, ApiError> {
    let row = sqlx::query_as::<_, UserRow>(
        "SELECT id, email, display_name, password_hash, role FROM users WHERE id = $1",
    )
    .bind(auth.user_id)
    .fetch_one(&state.pool)
    .await
    .map_err(ApiError::db)?;
    Ok(Json(UserOut {
        id: row.id,
        email: row.email,
        display_name: row.display_name,
        role: row.role,
    }))
}

fn forbidden() -> ApiError {
    ApiError::new(StatusCode::FORBIDDEN, "not allowed")
}

async fn role_of(pool: &PgPool, user_id: Uuid) -> Result<String, ApiError> {
    sqlx::query_scalar::<_, String>("SELECT role FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_optional(pool)
        .await
        .map_err(ApiError::db)?
        .ok_or_else(|| ApiError::not_found("person not found"))
}

async fn list_family(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<Vec<PersonOut>>, ApiError> {
    if role_of(&state.pool, auth.user_id).await? != "parent" {
        return Err(forbidden());
    }
    let rows = sqlx::query_as::<_, PersonOut>(
        "SELECT id, display_name FROM users ORDER BY display_name",
    )
    .fetch_all(&state.pool)
    .await
    .map_err(ApiError::db)?;
    Ok(Json(rows))
}

#[derive(Serialize, FromRow)]
struct FamilyRules {
    user_id: Uuid,
    blocked_domains: Vec<String>,
    allowed_domains: Vec<String>,
    downtime_start: Option<String>,
    downtime_end: Option<String>,
    web_locked: bool,
}

fn format_hhmm(minutes: Option<i16>) -> Option<String> {
    minutes.map(|mins| format!("{:02}:{:02}", mins / 60, mins % 60))
}

fn parse_hhmm(value: &str) -> Result<Option<i16>, ApiError> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    let Some((hour, minute)) = value.split_once(':') else {
        return Err(ApiError::bad("time is HH:MM"));
    };
    let hour: i16 = hour.parse().map_err(|_| ApiError::bad("time is HH:MM"))?;
    let minute: i16 = minute.parse().map_err(|_| ApiError::bad("time is HH:MM"))?;
    if !(0..24).contains(&hour) || !(0..60).contains(&minute) {
        return Err(ApiError::bad("time is HH:MM"));
    }
    Ok(Some(hour * 60 + minute))
}

fn normalize_domain(raw: &str) -> Option<String> {
    let mut host = raw.trim().to_ascii_lowercase();
    if let Some(rest) = host.strip_prefix("https://") {
        host = rest.to_string();
    }
    if let Some(rest) = host.strip_prefix("http://") {
        host = rest.to_string();
    }
    host = host.split(['/', '?', '#']).next().unwrap_or("").to_string();
    host = host.trim_end_matches('.').to_string();
    if host.is_empty() || host.len() > 253 || !host.contains('.') {
        return None;
    }
    if host
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
    {
        Some(host)
    } else {
        None
    }
}

async fn subject_for(
    pool: &PgPool,
    auth: &AuthUser,
    requested: Option<Uuid>,
) -> Result<Uuid, ApiError> {
    let role = role_of(pool, auth.user_id).await?;
    if role != "parent" {
        if requested.is_some_and(|id| id != auth.user_id) {
            return Err(forbidden());
        }
        return Ok(auth.user_id);
    }
    let Some(user_id) = requested else {
        return Ok(auth.user_id);
    };
    let _ = role_of(pool, user_id).await?;
    Ok(user_id)
}

#[derive(Deserialize)]
struct RulesQuery {
    user_id: Option<Uuid>,
}

async fn get_rules(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(query): Query<RulesQuery>,
) -> Result<Json<FamilyRules>, ApiError> {
    let user_id = subject_for(&state.pool, &auth, query.user_id).await?;
    let row = sqlx::query_as::<_, (Vec<String>, Vec<String>, Option<i16>, Option<i16>, bool)>(
        "SELECT blocked_domains, allowed_domains, downtime_start, downtime_end, web_locked FROM family_rules WHERE child_user_id = $1",
    )
    .bind(user_id)
    .fetch_optional(&state.pool)
    .await
    .map_err(ApiError::db)?;
    let (blocked, allowed, start, end, locked) = row.unwrap_or_default();
    Ok(Json(FamilyRules {
        user_id,
        blocked_domains: blocked,
        allowed_domains: allowed,
        downtime_start: format_hhmm(start),
        downtime_end: format_hhmm(end),
        web_locked: locked,
    }))
}

#[derive(Deserialize)]
struct RulesBody {
    user_id: Uuid,
    blocked_domains: Vec<String>,
    allowed_domains: Vec<String>,
    downtime_start: Option<String>,
    downtime_end: Option<String>,
    web_locked: Option<bool>,
}

async fn put_rules(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<RulesBody>,
) -> Result<Json<FamilyRules>, ApiError> {
    let user_id = subject_for(&state.pool, &auth, Some(body.user_id)).await?;
    let blocked: Vec<String> = body.blocked_domains.iter().filter_map(|d| normalize_domain(d)).collect();
    let allowed: Vec<String> = body.allowed_domains.iter().filter_map(|d| normalize_domain(d)).collect();
    let start = parse_hhmm(body.downtime_start.as_deref().unwrap_or(""))?;
    let end = parse_hhmm(body.downtime_end.as_deref().unwrap_or(""))?;
    if start.is_some() != end.is_some() {
        return Err(ApiError::bad("downtime needs a start and an end"));
    }
    let locked = body.web_locked.unwrap_or(false);
    sqlx::query(
        r#"INSERT INTO family_rules (child_user_id, blocked_domains, allowed_domains, downtime_start, downtime_end, web_locked, updated_by, updated_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7, now())
           ON CONFLICT (child_user_id) DO UPDATE SET
             blocked_domains = EXCLUDED.blocked_domains,
             allowed_domains = EXCLUDED.allowed_domains,
             downtime_start = EXCLUDED.downtime_start,
             downtime_end = EXCLUDED.downtime_end,
             web_locked = EXCLUDED.web_locked,
             updated_by = EXCLUDED.updated_by,
             updated_at = now()"#,
    )
    .bind(user_id)
    .bind(&blocked)
    .bind(&allowed)
    .bind(start)
    .bind(end)
    .bind(locked)
    .bind(auth.user_id)
    .execute(&state.pool)
    .await
    .map_err(ApiError::db)?;
    Ok(Json(FamilyRules {
        user_id,
        blocked_domains: blocked,
        allowed_domains: allowed,
        downtime_start: format_hhmm(start),
        downtime_end: format_hhmm(end),
        web_locked: locked,
    }))
}

#[derive(Serialize, FromRow)]
struct ActivityOut {
    id: Uuid,
    kind: String,
    detail: String,
    recorded_at: DateTime<Utc>,
}

async fn list_activity(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(query): Query<RulesQuery>,
) -> Result<Json<Vec<ActivityOut>>, ApiError> {
    let user_id = subject_for(&state.pool, &auth, query.user_id).await?;
    let rows = sqlx::query_as::<_, ActivityOut>(
        "SELECT id, kind, detail, recorded_at FROM family_activity WHERE child_user_id = $1 ORDER BY recorded_at DESC LIMIT 50",
    )
    .bind(user_id)
    .fetch_all(&state.pool)
    .await
    .map_err(ApiError::db)?;
    Ok(Json(rows))
}

#[derive(Deserialize)]
struct ActivityBody {
    kind: String,
    detail: String,
}

async fn post_activity(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<ActivityBody>,
) -> Result<StatusCode, ApiError> {
    if !valid_kind(&body.kind) || body.detail.trim().is_empty() || body.detail.len() > 500 {
        return Err(ApiError::bad("kind and detail are required"));
    }
    sqlx::query(
        "INSERT INTO family_activity (id, child_user_id, kind, detail) VALUES ($1, $2, $3, $4)",
    )
    .bind(Uuid::new_v4())
    .bind(auth.user_id)
    .bind(&body.kind)
    .bind(body.detail.trim())
    .execute(&state.pool)
    .await
    .map_err(ApiError::db)?;
    Ok(StatusCode::CREATED)
}

#[derive(Deserialize)]
struct NewToken {
    name: String,
}

#[derive(Serialize)]
struct TokenOut {
    id: Uuid,
    token: String,
    kind: &'static str,
}

const ADMIN_EMAIL: &str = "david@geere.org";

async fn seed_admin(pool: &PgPool, password: &str) -> Result<(), ApiError> {
    let hash = hash_password(password)?;
    sqlx::query(
        r#"INSERT INTO admins (id, email, password_hash) VALUES ($1, $2, $3)
           ON CONFLICT (email) DO UPDATE SET password_hash = EXCLUDED.password_hash"#,
    )
    .bind(Uuid::new_v4())
    .bind(ADMIN_EMAIL)
    .bind(&hash)
    .execute(pool)
    .await
    .map_err(ApiError::db)?;
    Ok(())
}

struct AdminAuth {
    #[allow(dead_code)]
    admin_id: Uuid,
}

impl FromRequestParts<AppState> for AdminAuth {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let token = bearer(&parts.headers).ok_or_else(ApiError::unauthorized)?;
        let hash = hash_token(&token);
        let admin_id = sqlx::query_scalar::<_, Uuid>(
            "SELECT admin_id FROM admin_sessions WHERE token_hash = $1 AND revoked_at IS NULL",
        )
        .bind(&hash)
        .fetch_optional(&state.pool)
        .await
        .map_err(ApiError::db)?;
        let Some(admin_id) = admin_id else {
            return Err(ApiError::unauthorized());
        };
        Ok(AdminAuth { admin_id })
    }
}

#[derive(Deserialize)]
struct AdminLogin {
    email: String,
    password: String,
}

#[derive(Serialize)]
struct AdminLoginOut {
    token: String,
}

async fn admin_login(
    State(state): State<AppState>,
    Json(body): Json<AdminLogin>,
) -> Result<(StatusCode, Json<AdminLoginOut>), ApiError> {
    if normalize_email(&body.email) != ADMIN_EMAIL {
        let _ = verify_password(&body.password, &state.dummy_password_hash);
        return Err(ApiError::unauthorized());
    }
    let row = sqlx::query_as::<_, (Uuid, String)>(
        "SELECT id, password_hash FROM admins WHERE email = $1",
    )
    .bind(ADMIN_EMAIL)
    .fetch_optional(&state.pool)
    .await
    .map_err(ApiError::db)?;
    let Some((admin_id, hash)) = row else {
        let _ = verify_password(&body.password, &state.dummy_password_hash);
        return Err(ApiError::unauthorized());
    };
    if !verify_password(&body.password, &hash) {
        return Err(ApiError::unauthorized());
    }
    let (token, token_hash) = new_secret("gha");
    sqlx::query(
        "INSERT INTO admin_sessions (id, admin_id, token_hash) VALUES ($1, $2, $3)",
    )
    .bind(Uuid::new_v4())
    .bind(admin_id)
    .bind(&token_hash)
    .execute(&state.pool)
    .await
    .map_err(ApiError::db)?;
    Ok((StatusCode::CREATED, Json(AdminLoginOut { token })))
}

#[derive(Serialize, FromRow)]
struct AdminPerson {
    id: Uuid,
    display_name: String,
    role: String,
}

async fn admin_people(
    State(state): State<AppState>,
    _: AdminAuth,
) -> Result<Json<Vec<AdminPerson>>, ApiError> {
    let rows = sqlx::query_as::<_, AdminPerson>(
        "SELECT id, display_name, role FROM users ORDER BY display_name",
    )
    .fetch_all(&state.pool)
    .await
    .map_err(ApiError::db)?;
    Ok(Json(rows))
}

#[derive(Deserialize)]
struct AdminTokenQuery {
    user_id: Uuid,
}

#[derive(Serialize, FromRow)]
struct AgentKey {
    id: Uuid,
    name: String,
    kind: String,
    created_at: DateTime<Utc>,
    revoked: bool,
}

async fn admin_list_tokens(
    State(state): State<AppState>,
    _: AdminAuth,
    Query(query): Query<AdminTokenQuery>,
) -> Result<Json<Vec<AgentKey>>, ApiError> {
    let _ = role_of(&state.pool, query.user_id).await?;
    let rows = sqlx::query_as::<_, AgentKey>(
        r#"SELECT id, name, kind, created_at, revoked_at IS NOT NULL AS revoked
           FROM tokens WHERE user_id = $1 ORDER BY created_at DESC"#,
    )
    .bind(query.user_id)
    .fetch_all(&state.pool)
    .await
    .map_err(ApiError::db)?;
    Ok(Json(rows))
}

#[derive(Deserialize)]
struct AdminNewToken {
    user_id: Uuid,
    name: String,
}

async fn admin_create_token(
    State(state): State<AppState>,
    _: AdminAuth,
    Json(body): Json<AdminNewToken>,
) -> Result<(StatusCode, Json<TokenOut>), ApiError> {
    let _ = role_of(&state.pool, body.user_id).await?;
    let name = body.name.trim();
    if name.is_empty() || name.len() > 80 {
        return Err(ApiError::bad("name is required"));
    }
    let (token, hash) = new_secret("ghk");
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO tokens (id, user_id, name, token_hash, kind) VALUES ($1, $2, $3, $4, 'agent')",
    )
    .bind(id)
    .bind(body.user_id)
    .bind(name)
    .bind(&hash)
    .execute(&state.pool)
    .await
    .map_err(ApiError::db)?;
    Ok((
        StatusCode::CREATED,
        Json(TokenOut {
            id,
            token,
            kind: "agent",
        }),
    ))
}

async fn admin_revoke_token(
    State(state): State<AppState>,
    _: AdminAuth,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    let result = sqlx::query(
        "UPDATE tokens SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL",
    )
    .bind(id)
    .execute(&state.pool)
    .await
    .map_err(ApiError::db)?;
    if result.rows_affected() == 0 {
        return Err(ApiError::not_found("token not found"));
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn create_token(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<NewToken>,
) -> Result<(StatusCode, Json<TokenOut>), ApiError> {
    let name = body.name.trim();
    if name.is_empty() || name.len() > 80 {
        return Err(ApiError::bad("name is required"));
    }
    let (token, hash) = new_secret("ghk");
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO tokens (id, user_id, name, token_hash, kind) VALUES ($1, $2, $3, $4, 'agent')",
    )
    .bind(id)
    .bind(auth.user_id)
    .bind(name)
    .bind(&hash)
    .execute(&state.pool)
    .await
    .map_err(ApiError::db)?;
    Ok((
        StatusCode::CREATED,
        Json(TokenOut {
            id,
            token,
            kind: "agent",
        }),
    ))
}

async fn revoke_token(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    let result = sqlx::query(
        "UPDATE tokens SET revoked_at = now() WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL",
    )
    .bind(id)
    .bind(auth.user_id)
    .execute(&state.pool)
    .await
    .map_err(ApiError::db)?;
    if result.rows_affected() == 0 {
        return Err(ApiError::not_found("token not found"));
    }
    let _ = auth.token_id;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct NewDevice {
    name: String,
    platform: String,
}

#[derive(Serialize, FromRow)]
struct DeviceOut {
    id: Uuid,
    name: String,
    platform: String,
}

async fn list_devices(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<Vec<DeviceOut>>, ApiError> {
    let rows = sqlx::query_as::<_, DeviceOut>(
        "SELECT id, name, platform FROM devices WHERE user_id = $1 ORDER BY created_at",
    )
    .bind(auth.user_id)
    .fetch_all(&state.pool)
    .await
    .map_err(ApiError::db)?;
    Ok(Json(rows))
}

async fn create_device(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<NewDevice>,
) -> Result<(StatusCode, Json<DeviceOut>), ApiError> {
    let name = body.name.trim();
    let platform = body.platform.trim();
    if name.is_empty() || platform.is_empty() {
        return Err(ApiError::bad("name and platform are required"));
    }
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO devices (id, user_id, name, platform) VALUES ($1, $2, $3, $4)")
        .bind(id)
        .bind(auth.user_id)
        .bind(name)
        .bind(platform)
        .execute(&state.pool)
        .await
        .map_err(ApiError::db)?;
    Ok((
        StatusCode::CREATED,
        Json(DeviceOut {
            id,
            name: name.to_string(),
            platform: platform.to_string(),
        }),
    ))
}

async fn device_owned(state: &AppState, user_id: Uuid, device_id: Uuid) -> Result<(), ApiError> {
    let found = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM devices WHERE id = $1 AND user_id = $2",
    )
    .bind(device_id)
    .bind(user_id)
    .fetch_one(&state.pool)
    .await
    .map_err(ApiError::db)?;
    if found == 0 {
        Err(ApiError::not_found("device not found"))
    } else {
        Ok(())
    }
}

#[derive(Deserialize)]
struct NewEvent {
    kind: String,
    device_id: Option<Uuid>,
    recorded_at: Option<DateTime<Utc>>,
    #[serde(default)]
    payload: Value,
}

#[derive(Serialize, FromRow)]
struct EventOut {
    id: Uuid,
    device_id: Option<Uuid>,
    kind: String,
    payload: Value,
    recorded_at: DateTime<Utc>,
}

async fn create_event(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<NewEvent>,
) -> Result<(StatusCode, Json<EventOut>), ApiError> {
    if !valid_kind(&body.kind) {
        return Err(ApiError::bad("invalid kind"));
    }
    if let Some(device_id) = body.device_id {
        device_owned(&state, auth.user_id, device_id).await?;
    }
    let id = Uuid::new_v4();
    let recorded_at = body.recorded_at.unwrap_or_else(Utc::now);
    let payload = if body.payload.is_null() {
        json!({})
    } else {
        body.payload
    };
    sqlx::query(
        "INSERT INTO events (id, user_id, device_id, kind, payload, recorded_at) VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(id)
    .bind(auth.user_id)
    .bind(body.device_id)
    .bind(&body.kind)
    .bind(&payload)
    .bind(recorded_at)
    .execute(&state.pool)
    .await
    .map_err(ApiError::db)?;
    if let Some(device_id) = body.device_id {
        let _ = sqlx::query("UPDATE devices SET last_seen_at = now() WHERE id = $1")
            .bind(device_id)
            .execute(&state.pool)
            .await;
    }
    let event = EventOut {
        id,
        device_id: body.device_id,
        kind: body.kind.clone(),
        payload: payload.clone(),
        recorded_at,
    };
    dispatch_webhooks(&state, auth.user_id, &event).await;
    Ok((StatusCode::CREATED, Json(event)))
}

#[derive(Deserialize)]
struct EventQuery {
    kind: Option<String>,
    since: Option<DateTime<Utc>>,
    until: Option<DateTime<Utc>>,
    limit: Option<i64>,
}

async fn list_events(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(query): Query<EventQuery>,
) -> Result<Json<Vec<EventOut>>, ApiError> {
    let limit = query.limit.unwrap_or(50).clamp(1, 200);
    let rows = sqlx::query_as::<_, EventOut>(
        r#"SELECT id, device_id, kind, payload, recorded_at
           FROM events
           WHERE user_id = $1
             AND ($2::text IS NULL OR kind = $2)
             AND ($3::timestamptz IS NULL OR recorded_at >= $3)
             AND ($4::timestamptz IS NULL OR recorded_at <= $4)
           ORDER BY recorded_at DESC
           LIMIT $5"#,
    )
    .bind(auth.user_id)
    .bind(&query.kind)
    .bind(query.since)
    .bind(query.until)
    .bind(limit)
    .fetch_all(&state.pool)
    .await
    .map_err(ApiError::db)?;
    Ok(Json(rows))
}

#[derive(FromRow)]
struct HookRow {
    url: String,
    secret: String,
}

async fn dispatch_webhooks(state: &AppState, user_id: Uuid, event: &EventOut) {
    let hooks = match sqlx::query_as::<_, HookRow>(
        "SELECT url, secret FROM webhooks WHERE user_id = $1 AND (kinds IS NULL OR $2 = ANY(kinds))",
    )
    .bind(user_id)
    .bind(&event.kind)
    .fetch_all(&state.pool)
    .await
    {
        Ok(hooks) => hooks,
        Err(err) => {
            eprintln!("webhook lookup: {err}");
            return;
        }
    };
    let body = match serde_json::to_vec(&json!({
        "id": event.id,
        "user_id": user_id,
        "device_id": event.device_id,
        "kind": event.kind,
        "recorded_at": event.recorded_at,
        "payload": event.payload,
    })) {
        Ok(body) => body,
        Err(err) => {
            eprintln!("webhook encode: {err}");
            return;
        }
    };
    for hook in hooks {
        let client = state.http.clone();
        let body = body.clone();
        let kind = event.kind.clone();
        tokio::spawn(async move {
            deliver_webhook(client, hook, body, kind).await;
        });
    }
}

async fn deliver_webhook(client: reqwest::Client, hook: HookRow, body: Vec<u8>, kind: String) {
    let signature = match HmacSha256::new_from_slice(hook.secret.as_bytes()) {
        Ok(mut mac) => {
            mac.update(&body);
            format!("sha256={}", hex::encode(mac.finalize().into_bytes()))
        }
        Err(err) => {
            eprintln!("webhook signature: {err}");
            return;
        }
    };
    for attempt in 0..3 {
        let result = client
            .post(&hook.url)
            .header("Content-Type", "application/json")
            .header("X-Gherkin-Event", &kind)
            .header("X-Gherkin-Signature", &signature)
            .body(body.clone())
            .send()
            .await;
        match result {
            Ok(response) if response.status().is_success() => return,
            Ok(response) => eprintln!("webhook {} status {}", hook.url, response.status()),
            Err(err) => eprintln!("webhook {}: {err}", hook.url),
        }
        tokio::time::sleep(Duration::from_millis(150 * (attempt + 1))).await;
    }
}

#[derive(Deserialize)]
struct NewHook {
    url: String,
    kinds: Option<Vec<String>>,
}

#[derive(Serialize)]
struct HookCreated {
    id: Uuid,
    url: String,
    secret: String,
    kinds: Option<Vec<String>>,
}

async fn create_webhook(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<NewHook>,
) -> Result<(StatusCode, Json<HookCreated>), ApiError> {
    let url = body.url.trim();
    if !(url.starts_with("https://") || url.starts_with("http://")) {
        return Err(ApiError::bad("url must be http or https"));
    }
    let kinds = body.kinds.filter(|kinds| !kinds.is_empty());
    if let Some(kinds) = &kinds {
        if kinds.iter().any(|kind| !valid_kind(kind)) {
            return Err(ApiError::bad("invalid kind"));
        }
    }
    let (secret, _) = new_secret("ghs");
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO webhooks (id, user_id, url, secret, kinds) VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(id)
    .bind(auth.user_id)
    .bind(url)
    .bind(&secret)
    .bind(&kinds)
    .execute(&state.pool)
    .await
    .map_err(ApiError::db)?;
    Ok((
        StatusCode::CREATED,
        Json(HookCreated {
            id,
            url: url.to_string(),
            secret,
            kinds,
        }),
    ))
}

#[derive(Serialize, FromRow)]
struct HookListItem {
    id: Uuid,
    url: String,
    kinds: Option<Vec<String>>,
}

async fn list_webhooks(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<Vec<HookListItem>>, ApiError> {
    let rows = sqlx::query_as::<_, HookListItem>(
        "SELECT id, url, kinds FROM webhooks WHERE user_id = $1 ORDER BY created_at",
    )
    .bind(auth.user_id)
    .fetch_all(&state.pool)
    .await
    .map_err(ApiError::db)?;
    Ok(Json(rows))
}

async fn delete_webhook(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    let result = sqlx::query("DELETE FROM webhooks WHERE id = $1 AND user_id = $2")
        .bind(id)
        .bind(auth.user_id)
        .execute(&state.pool)
        .await
        .map_err(ApiError::db)?;
    if result.rows_affected() == 0 {
        return Err(ApiError::not_found("webhook not found"));
    }
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Serialize)]
struct CollectionOut {
    location: bool,
    motion: bool,
    health: bool,
    wifi: bool,
    bluetooth: bool,
    battery: bool,
}

async fn get_collection(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<CollectionOut>, ApiError> {
    let row = sqlx::query_as::<_, (bool, bool, bool, bool, bool, bool)>(
        "SELECT location, motion, health, wifi, bluetooth, battery FROM collection WHERE user_id = $1",
    )
    .bind(auth.user_id)
    .fetch_optional(&state.pool)
    .await
    .map_err(ApiError::db)?;
    let (location, motion, health, wifi, bluetooth, battery) =
        row.unwrap_or((true, false, true, false, false, false));
    Ok(Json(CollectionOut {
        location,
        motion,
        health,
        wifi,
        bluetooth,
        battery,
    }))
}

#[derive(Deserialize)]
struct CollectionBody {
    location: bool,
    motion: bool,
    health: bool,
    wifi: bool,
    bluetooth: bool,
    battery: bool,
}

async fn put_collection(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<CollectionBody>,
) -> Result<Json<CollectionOut>, ApiError> {
    sqlx::query(
        r#"INSERT INTO collection (user_id, location, motion, health, wifi, bluetooth, battery, updated_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7, now())
           ON CONFLICT (user_id) DO UPDATE SET
             location = EXCLUDED.location,
             motion = EXCLUDED.motion,
             health = EXCLUDED.health,
             wifi = EXCLUDED.wifi,
             bluetooth = EXCLUDED.bluetooth,
             battery = EXCLUDED.battery,
             updated_at = now()"#,
    )
    .bind(auth.user_id)
    .bind(body.location)
    .bind(body.motion)
    .bind(body.health)
    .bind(body.wifi)
    .bind(body.bluetooth)
    .bind(body.battery)
    .execute(&state.pool)
    .await
    .map_err(ApiError::db)?;
    Ok(Json(CollectionOut {
        location: body.location,
        motion: body.motion,
        health: body.health,
        wifi: body.wifi,
        bluetooth: body.bluetooth,
        battery: body.battery,
    }))
}

#[derive(Deserialize)]
struct NewCommand {
    device_id: Option<Uuid>,
    kind: String,
    #[serde(default)]
    payload: Value,
}

#[derive(Serialize, FromRow)]
struct CommandOut {
    id: Uuid,
    device_id: Option<Uuid>,
    kind: String,
    payload: Value,
    status: String,
}

const CAPABILITY_KEYS: &[&str] = &[
    "location",
    "microphone",
    "camera",
    "screen",
    "motion",
    "health",
    "notifications",
    "bluetooth",
    "screen_time",
];

fn capability_label(key: &str) -> &str {
    match key {
        "location" => "Location",
        "microphone" => "Microphone",
        "camera" => "Camera",
        "screen" => "Screen recording",
        "motion" => "Motion",
        "health" => "Health",
        "notifications" => "Notifications",
        "bluetooth" => "Bluetooth",
        "screen_time" => "Screen Time",
        _ => key,
    }
}

fn capability_key(kind: &str) -> Option<&'static str> {
    match kind {
        "location.now" => Some("location"),
        "microphone.listen" => Some("microphone"),
        "camera.capture" => Some("camera"),
        "screen.capture" => Some("screen"),
        "motion.snapshot" => Some("motion"),
        "health.snapshot" => Some("health"),
        "notify" => Some("notifications"),
        "bluetooth.state" => Some("bluetooth"),
        "screen.sites" | "screen.apps" => Some("screen_time"),
        _ => None,
    }
}

fn normalize_capabilities(state: &Value) -> Value {
    let mut out = serde_json::Map::new();
    for key in CAPABILITY_KEYS {
        let entry = state.get(*key);
        let raw = entry
            .and_then(|value| value.get("status"))
            .and_then(|value| value.as_str())
            .unwrap_or("not_asked");
        let status = if matches!(raw, "granted" | "denied" | "not_asked") {
            raw
        } else {
            "not_asked"
        };
        let enabled = status == "granted"
            && entry
                .and_then(|value| value.get("enabled"))
                .and_then(|value| value.as_bool())
                .unwrap_or(false);
        out.insert((*key).to_string(), json!({ "status": status, "enabled": enabled }));
    }
    Value::Object(out)
}

fn capability_block(state: &Value, kind: &str) -> Option<String> {
    let key = capability_key(kind)?;
    let label = capability_label(key);
    let entry = state.get(key)?;
    match entry.get("status").and_then(|value| value.as_str()).unwrap_or("not_asked") {
        "granted" => {
            if entry.get("enabled").and_then(|value| value.as_bool()).unwrap_or(false) {
                None
            } else {
                Some(format!("{label} is turned off on the phone"))
            }
        }
        "denied" => Some(format!("{label} was denied on the phone")),
        _ => Some(format!("{label} has not been requested on the phone")),
    }
}

async fn load_capabilities(pool: &PgPool, user_id: Uuid) -> Result<Value, ApiError> {
    let stored: Option<Value> = sqlx::query_scalar("SELECT state FROM capabilities WHERE user_id = $1")
        .bind(user_id)
        .fetch_optional(pool)
        .await
        .map_err(ApiError::db)?;
    Ok(normalize_capabilities(&stored.unwrap_or_else(|| json!({}))))
}

async fn get_capabilities(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<Value>, ApiError> {
    Ok(Json(load_capabilities(&state.pool, auth.user_id).await?))
}

async fn put_capabilities(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<Value>,
) -> Result<Json<Value>, ApiError> {
    let state_json = normalize_capabilities(&body);
    sqlx::query(
        r#"INSERT INTO capabilities (user_id, state)
           VALUES ($1, $2)
           ON CONFLICT (user_id) DO UPDATE SET state = EXCLUDED.state, updated_at = now()"#,
    )
    .bind(auth.user_id)
    .bind(&state_json)
    .execute(&state.pool)
    .await
    .map_err(ApiError::db)?;
    Ok(Json(state_json))
}

#[derive(Serialize, FromRow)]
struct CommandListItem {
    id: Uuid,
    kind: String,
    status: String,
    result: Value,
    created_at: DateTime<Utc>,
}

async fn list_commands(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<Vec<CommandListItem>>, ApiError> {
    let rows = sqlx::query_as::<_, CommandListItem>(
        r#"SELECT id, kind, status,
                  COALESCE(result, '{}'::jsonb) - 'imageBase64' - 'audioBase64' AS result,
                  created_at
           FROM commands
           WHERE user_id = $1
           ORDER BY created_at DESC
           LIMIT 40"#,
    )
    .bind(auth.user_id)
    .fetch_all(&state.pool)
    .await
    .map_err(ApiError::db)?;
    Ok(Json(rows))
}

async fn create_command(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<NewCommand>,
) -> Result<(StatusCode, Json<CommandOut>), ApiError> {
    if !valid_kind(&body.kind) {
        return Err(ApiError::bad("invalid kind"));
    }
    let capabilities = load_capabilities(&state.pool, auth.user_id).await?;
    if let Some(message) = capability_block(&capabilities, &body.kind) {
        return Err(ApiError::conflict(message));
    }
    if let Some(device_id) = body.device_id {
        device_owned(&state, auth.user_id, device_id).await?;
    }
    let id = Uuid::new_v4();
    let payload = if body.payload.is_null() {
        json!({})
    } else {
        body.payload
    };
    sqlx::query(
        "INSERT INTO commands (id, user_id, device_id, kind, payload, status) VALUES ($1, $2, $3, $4, $5, 'pending')",
    )
    .bind(id)
    .bind(auth.user_id)
    .bind(body.device_id)
    .bind(&body.kind)
    .bind(&payload)
    .execute(&state.pool)
    .await
    .map_err(ApiError::db)?;
    state.notify.notify_waiters();
    Ok((
        StatusCode::CREATED,
        Json(CommandOut {
            id,
            device_id: body.device_id,
            kind: body.kind,
            payload,
            status: "pending".to_string(),
        }),
    ))
}

#[derive(Deserialize)]
struct PendingQuery {
    device_id: Uuid,
    wait: Option<u64>,
}

#[derive(Serialize, FromRow)]
struct PendingCommand {
    id: Uuid,
    device_id: Option<Uuid>,
    kind: String,
    payload: Value,
}

async fn pending_commands(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(query): Query<PendingQuery>,
) -> Result<Json<Vec<PendingCommand>>, ApiError> {
    device_owned(&state, auth.user_id, query.device_id).await?;
    let wait = query.wait.unwrap_or(25).min(25);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(wait);
    loop {
        let notified = state.notify.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        sqlx::query(
            r#"UPDATE commands
               SET status = 'pending', updated_at = now()
               WHERE user_id = $1
                 AND status = 'delivered'
                 AND updated_at < now() - interval '2 minutes'
                 AND (device_id IS NULL OR device_id = $2)"#,
        )
        .bind(auth.user_id)
        .bind(query.device_id)
        .execute(&state.pool)
        .await
        .map_err(ApiError::db)?;
        let rows = sqlx::query_as::<_, PendingCommand>(
            r#"WITH picked AS (
                   SELECT id FROM commands
                   WHERE user_id = $1
                     AND status = 'pending'
                     AND (device_id IS NULL OR device_id = $2)
                   ORDER BY created_at
                   FOR UPDATE SKIP LOCKED
                   LIMIT 20
               )
               UPDATE commands AS c
               SET status = 'delivered', updated_at = now()
               FROM picked
               WHERE c.id = picked.id
               RETURNING c.id, c.device_id, c.kind, c.payload"#,
        )
        .bind(auth.user_id)
        .bind(query.device_id)
        .fetch_all(&state.pool)
        .await
        .map_err(ApiError::db)?;
        if !rows.is_empty() || tokio::time::Instant::now() >= deadline {
            return Ok(Json(rows));
        }
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        tokio::select! {
            _ = notified => {}
            _ = tokio::time::sleep(remaining) => {}
        }
    }
}

#[derive(Deserialize)]
struct CommandResult {
    status: String,
    #[serde(default)]
    result: Value,
}

async fn finish_command(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<Uuid>,
    Json(body): Json<CommandResult>,
) -> Result<StatusCode, ApiError> {
    if !matches!(body.status.as_str(), "running" | "done" | "failed" | "timed_out") {
        return Err(ApiError::bad("status must be running, done, failed, or timed_out"));
    }
    let from = if body.status == "running" {
        "'delivered'"
    } else {
        "'delivered', 'running'"
    };
    let result = sqlx::query(&format!(
        r#"UPDATE commands
           SET status = $3, result = $4, updated_at = now()
           WHERE id = $1 AND user_id = $2 AND status IN ({from})"#
    ))
    .bind(id)
    .bind(auth.user_id)
    .bind(&body.status)
    .bind(&body.result)
    .execute(&state.pool)
    .await
    .map_err(ApiError::db)?;
    if result.rows_affected() == 0 {
        return Err(ApiError::not_found("command not found"));
    }
    Ok(StatusCode::NO_CONTENT)
}

impl AppState {
    pub async fn create_user_account(
        &self,
        email: &str,
        display_name: &str,
        password: &str,
    ) -> Result<Uuid, String> {
        let id = Uuid::new_v4();
        let hash = hash_password(password).map_err(|err| err.message)?;
        sqlx::query(
            "INSERT INTO users (id, email, display_name, password_hash) VALUES ($1, $2, $3, $4)",
        )
        .bind(id)
        .bind(normalize_email(email))
        .bind(display_name)
        .bind(&hash)
        .execute(&self.pool)
        .await
        .map_err(|err| err.to_string())?;
        Ok(id)
    }

    pub async fn create_agent_token(&self, email: &str, name: &str) -> Result<String, String> {
        let user_id = sqlx::query_scalar::<_, Uuid>("SELECT id FROM users WHERE email = $1")
            .bind(normalize_email(email))
            .fetch_optional(&self.pool)
            .await
            .map_err(|err| err.to_string())?
            .ok_or_else(|| format!("no user for {email}"))?;
        let (token, hash) = new_secret("ghk");
        sqlx::query(
            "INSERT INTO tokens (id, user_id, name, token_hash, kind) VALUES ($1, $2, $3, $4, 'agent')",
        )
        .bind(Uuid::new_v4())
        .bind(user_id)
        .bind(name)
        .bind(&hash)
        .execute(&self.pool)
        .await
        .map_err(|err| err.to_string())?;
        Ok(token)
    }
}
