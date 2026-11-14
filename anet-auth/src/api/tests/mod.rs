use chrono::{Duration as ChronoDuration, NaiveDateTime, Utc};
use jsonwebtoken::{encode, EncodingKey, Header};
use poem::{http::{Method, StatusCode}, Endpoint, IntoResponse, Request, Route};
use poem_openapi::OpenApiService;
use sea_orm::sea_query::Value;
use sea_orm::{DatabaseBackend, DatabaseConnection, MockDatabase};
use std::collections::BTreeMap;
use std::sync::Once;
use uuid::Uuid;

use crate::api::dto::Claims;
use crate::api::user_cabinet::issue_user_jwt;
use crate::crypto::DbEncryptor;
use crate::entities::{
    active_sessions,
    billing_enums::{Currency, OrderStatus, PaymentSystem, ProductType, VoucherStatus},
    groups, node_commands, orders, products, rates, servers, sessions, traffic_hourly,
    traffic_totals, transactions, users, verification_tokens, vouchers, ProtocolType,
};

pub mod admin_billing_tests;
pub mod freekassa_tests;
pub mod user_auth_tests;
pub mod user_cabinet_tests;
pub mod users_groups_auth_tests;

pub fn init_test_env() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        #[allow(unused_unsafe)]
        unsafe {
            std::env::set_var("APP_ENV", "production");
            std::env::set_var("JWT_SECRET", "test_jwt_secret_for_mock_suite_12345");
            std::env::set_var("PUBLIC_DOMAIN", "https://cabinet.test.local");
            std::env::set_var("ANET_PUBLIC_URL", "https://cabinet.test.local");
            std::env::set_var("EMAIL_WEBHOOK_URL", "");
            std::env::set_var("TELEGRAM_BOT_TOKEN", "123456:TEST_BOT_TOKEN_SECRET");
            std::env::set_var("FK_SHOP_ID", "777001");
            std::env::set_var("FK_SECRET1", "fk_sec_1");
            std::env::set_var("FK_SECRET2", "fk_sec_2");
            std::env::set_var("FK_API_KEY", "fk_api_secret_key");
            std::env::set_var("DB_ENCRYPTION_KEY", "test_db_master_key_32_bytes_min");
        }
        crate::config::init_config();
    });
}

pub fn build_test_app(
    db: DatabaseConnection,
    client_template_path: String,
) -> impl Endpoint {
    let api_service = OpenApiService::new(
        crate::api::get_api(db.clone(), client_template_path),
        "ANet Auth API",
        "1.0",
    )
    .server("/api/v1");

    Route::new()
        .nest("/api/v1", api_service)
        .at(
            "/billing/freekassa/notify",
            poem::post(crate::api::freekassa::freekassa_notify_handler).data(db),
        )
}

pub async fn send_request(
    app: &impl Endpoint,
    method: Method,
    uri: &str,
    bearer: Option<&str>,
    extra_headers: &[(&str, &str)],
    content_type: Option<&str>,
    body: Vec<u8>,
) -> (StatusCode, String) {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri.parse().expect("valid test URI"));

    if let Some(tok) = bearer {
        builder = builder.header("Authorization", format!("Bearer {}", tok));
    }
    for &(k, v) in extra_headers {
        builder = builder.header(k, v);
    }
    if let Some(ct) = content_type {
        builder = builder.header("Content-Type", ct);
    }

    let req = builder.body(body);
    let resp = match app.call(req).await {
        Ok(r) => r,
        Err(e) => e.into_response(),
    };
    let status = resp.status();
    let bytes = resp.into_body().into_bytes().await.unwrap_or_default();
    (status, String::from_utf8_lossy(&bytes).to_string())
}

pub async fn send_json(
    app: &impl Endpoint,
    method: Method,
    uri: &str,
    bearer: Option<&str>,
    payload: Option<serde_json::Value>,
) -> (StatusCode, String) {
    let (ct, body) = match payload {
        Some(v) => (Some("application/json"), serde_json::to_vec(&v).unwrap()),
        None => (None, Vec::new()),
    };
    send_request(app, method, uri, bearer, &[], ct, body).await
}

pub fn make_admin_auth() -> (Uuid, Uuid, String, sessions::Model) {
    init_test_env();
    let jti = Uuid::new_v4();
    let admin_id = Uuid::new_v4();
    let now = Utc::now();
    let exp = now + ChronoDuration::hours(4);
    let claims = Claims {
        jti: jti.to_string(),
        sub: admin_id.to_string(),
        exp: exp.timestamp() as usize,
    };
    let secret = crate::config::jwt_secret();
    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .unwrap();
    let sess = sessions::Model {
        id: jti,
        admin_id,
        expires_at: exp.naive_utc(),
        created_at: now.naive_utc(),
    };
    (jti, admin_id, token, sess)
}

pub fn make_user_jwt(user_id: Uuid, fp: &str) -> String {
    init_test_env();
    let (tok, _) = issue_user_jwt(user_id, fp).unwrap();
    tok
}

pub fn count_row(col: &str, count: i64) -> Vec<BTreeMap<String, Value>> {
    vec![BTreeMap::from([(col.to_string(), Value::from(count))])]
}

pub fn new_pg_mock() -> MockDatabase {
    MockDatabase::new(DatabaseBackend::Postgres)
}

pub fn sample_group(id: Uuid, name: &str, is_default: bool, duration_days: i32, sessions_limit: i32) -> groups::Model {
    let now = Utc::now().naive_utc();
    groups::Model {
        id,
        name: name.to_string(),
        is_default,
        traffic_limit: 10 * 1024 * 1024 * 1024,
        speed_limit: 100_000,
        sessions_limit,
        duration_days,
        created_at: now,
        updated_at: now,
    }
}

pub fn sample_user(id: Uuid, email: Option<&str>, group_id: Option<Uuid>) -> users::Model {
    init_test_env();
    let now = Utc::now().naive_utc();
    let encryptor = DbEncryptor::new();
    let enc_priv = encryptor.encrypt("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=").unwrap();
    let enc_pub = encryptor.encrypt("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=").unwrap();
    users::Model {
        id,
        fingerprint: format!("fp_{}", id.simple()),
        uid: Some(format!("user_{}", &id.to_string()[..8])),
        is_active: true,
        created_at: now,
        updated_at: now,
        static_ip: None,
        private_key: Some(enc_priv),
        public_key: Some(enc_pub),
        route_map_id: None,
        group_id,
        email: email.map(|s| s.to_string()),
        password_hash: None,
        telegram_id: None,
        balance: 0.0,
        activated_at: None,
        expires_at: None,
    }
}

pub fn sample_rate(id: Uuid, user_id: Uuid, sessions: i32, date_end: NaiveDateTime) -> rates::Model {
    let now = Utc::now().naive_utc();
    rates::Model {
        id,
        user_id,
        sessions,
        date_end,
        created_at: now,
        updated_at: now,
        traffic_limit: 50_000_000,
        speed_limit: 25_000,
    }
}

pub fn sample_product(id: Uuid, target_id: Option<Uuid>, price: f64) -> products::Model {
    let now = Utc::now();
    products::Model {
        id,
        name: "Pro 30d".to_string(),
        description: "Unlimited high-speed VPN".to_string(),
        price,
        currency: Currency::Rub,
        product_type: ProductType::GroupSubscription,
        target_id,
        sort_order: 1,
        badge: Some("HIT".to_string()),
        metadata: Some(serde_json::json!({ "days": 30 })),
        is_active: true,
        created_at: now,
        updated_at: now,
    }
}

pub fn sample_order(
    id: Uuid,
    user_id: Uuid,
    product_id: Uuid,
    amount: f64,
    status: OrderStatus,
    is_gift: bool,
) -> orders::Model {
    let now = Utc::now();
    orders::Model {
        id,
        user_id,
        product_id,
        amount,
        currency: Currency::Rub,
        status,
        is_gift,
        metadata: None,
        created_at: now,
        updated_at: now,
    }
}

pub fn sample_tx(order_id: Option<Uuid>, ext_id: &str, amount: f64) -> transactions::Model {
    transactions::Model {
        id: Uuid::new_v4(),
        order_id,
        payment_system: PaymentSystem::FreeKassa,
        external_tx_id: ext_id.to_string(),
        amount_received: amount,
        raw_request: serde_json::json!({ "intid": ext_id }),
        created_at: Utc::now(),
    }
}

pub fn sample_voucher(product_id: Uuid, buyer_id: Uuid) -> vouchers::Model {
    vouchers::Model {
        id: Uuid::new_v4(),
        code: "ANET-GIFT-TEST1234".to_string(),
        product_id,
        buyer_user_id: Some(buyer_id),
        claimed_by_user_id: None,
        status: VoucherStatus::Created,
        metadata: None,
        claimed_at: None,
        created_at: Utc::now(),
    }
}

pub fn sample_verification_token(
    user_id: Option<Uuid>,
    email: &str,
    token_hash: &str,
    expired: bool,
    used: bool,
) -> verification_tokens::Model {
    let now = Utc::now();
    verification_tokens::Model {
        id: Uuid::new_v4(),
        user_id,
        email: email.to_string(),
        token_hash: token_hash.to_string(),
        expires_at: if expired {
            now - ChronoDuration::minutes(5)
        } else {
            now + ChronoDuration::minutes(15)
        },
        used_at: if used { Some(now - ChronoDuration::minutes(1)) } else { None },
        created_at: now,
    }
}

pub fn sample_server(id: Uuid, name: &str) -> servers::Model {
    let now = Utc::now().naive_utc();
    servers::Model {
        id,
        name: name.to_string(),
        address: "198.51.100.10".to_string(),
        public_key: "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=".to_string(),
        quic_port: Some(443),
        ssh_port: Some(22),
        vnc_port: None,
        websocket_url: None,
        ahttp_url: None,
        wrtc_url: None,
        wrtc_mode: None,
        ssh_user: None,
        created_at: now,
        updated_at: now,
        is_active: true,
        control_token_hash: None,
    }
}

pub fn sample_active_session(user_id: Uuid, sessions_count: i32) -> active_sessions::Model {
    let now = Utc::now().naive_utc();
    active_sessions::Model {
        id: Uuid::new_v4(),
        user_id,
        sessions: sessions_count,
        created_at: now,
        updated_at: now,
    }
}

pub fn sample_traffic_total(server_id: Uuid, fp: &str, rx: i64, tx: i64) -> traffic_totals::Model {
    traffic_totals::Model {
        id: Uuid::new_v4(),
        server_id,
        boot_id: "boot-1".to_string(),
        user_id: None,
        fingerprint: fp.to_string(),
        rx_bytes: rx,
        tx_bytes: tx,
        updated_at: Utc::now().naive_utc(),
        protocol: ProtocolType::Quic,
    }
}

pub fn sample_traffic_hourly(
    bucket_start: NaiveDateTime,
    server_id: Uuid,
    user_id: Uuid,
    fp: &str,
    rx: i64,
    tx: i64,
) -> traffic_hourly::Model {
    traffic_hourly::Model {
        id: Uuid::new_v4(),
        bucket_start,
        server_id,
        user_id: Some(user_id),
        fingerprint: fp.to_string(),
        rx_bytes: rx,
        tx_bytes: tx,
        updated_at: Utc::now().naive_utc(),
        protocol: ProtocolType::Quic,
    }
}

pub fn sample_node_command(server_id: Uuid, fp: &str) -> node_commands::Model {
    node_commands::Model {
        id: Uuid::new_v4(),
        server_id,
        command_type: "disconnect_user".to_string(),
        accepting_connections: None,
        target_fingerprint: Some(fp.to_string()),
        status: "pending".to_string(),
        created_at: Utc::now().naive_utc(),
        started_at: None,
        completed_at: None,
        error: None,
    }
}
