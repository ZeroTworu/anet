use bcrypt::hash;
use chrono::Utc;
use poem::http::{Method, StatusCode};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::api::freekassa::{hex_encode, hmac_sha256_bytes, hmac_sha256_hex};
use crate::api::tests::{
    build_test_app, init_test_env, make_user_jwt, new_pg_mock, sample_group, sample_user,
    sample_verification_token, send_json,
};
use crate::entities::users;

#[tokio::test]
async fn test_request_link_invalid_email_returns_400() {
    init_test_env();
    let db = new_pg_mock().into_connection();
    let app = build_test_app(db, String::new());

    let (status, _) = send_json(
        &app,
        Method::POST,
        "/api/v1/user/auth/request-link",
        None,
        Some(serde_json::json!({ "email": "not-an-email" })),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_request_link_new_email_inserts_token_and_returns_sent() {
    init_test_env();
    let email = "newuser@example.com";
    let tok = sample_verification_token(None, email, "hash", false, false);

    let mock_db = new_pg_mock()
        .append_query_results([vec![] as Vec<users::Model>])
        .append_query_results([vec![tok]]);
    let db = mock_db.into_connection();
    let app = build_test_app(db.clone(), String::new());

    let (status, body) = send_json(
        &app,
        Method::POST,
        "/api/v1/user/auth/request-link",
        None,
        Some(serde_json::json!({ "email": "  NewUser@Example.com " })),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "body={}", body);
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(json["sent"], true);
    assert_eq!(json["expires_in_mins"], 15);
    assert!(json["dev_verify_url"].is_null());

    let sql_log = format!("{:?}", db.into_transaction_log());
    assert!(sql_log.contains("verification_tokens"));
    assert!(sql_log.contains("newuser@example.com"));
}

#[tokio::test]
async fn test_request_link_blocked_user_returns_403() {
    init_test_env();
    let uid = Uuid::new_v4();
    let mut blocked = sample_user(uid, Some("blocked@example.com"), None);
    blocked.is_active = false;

    let db = new_pg_mock()
        .append_query_results([vec![blocked]])
        .into_connection();
    let app = build_test_app(db, String::new());

    let (status, _) = send_json(
        &app,
        Method::POST,
        "/api/v1/user/auth/request-link",
        None,
        Some(serde_json::json!({ "email": "blocked@example.com" })),
    )
    .await;

    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_verify_creates_user_with_default_group_and_issues_jwt() {
    init_test_env();
    let raw_token = "raw_one_time_verify_token_123";
    let token_hash = hex_encode(&Sha256::digest(raw_token.as_bytes()));
    let email = "fresh@example.com";
    let default_group_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();

    let tok_unused = sample_verification_token(None, email, &token_hash, false, false);
    let mut tok_used = tok_unused.clone();
    tok_used.used_at = Some(Utc::now());

    let default_group = sample_group(default_group_id, "Free Default", true, 0, 1);
    let created_user = sample_user(user_id, Some(email), Some(default_group_id));

    let db = new_pg_mock()
        .append_query_results([vec![tok_unused]])
        .append_query_results([vec![tok_used]])
        .append_query_results([vec![] as Vec<users::Model>])
        .append_query_results([vec![default_group]])
        .append_query_results([vec![created_user.clone()]])
        .into_connection();
    let app = build_test_app(db, String::new());

    let (status, body) = send_json(
        &app,
        Method::POST,
        "/api/v1/user/auth/verify",
        None,
        Some(serde_json::json!({
            "token": raw_token,
            "password": "StrongPassword123"
        })),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "body={}", body);
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(json["token_type"], "Bearer");
    assert_eq!(json["email"], email);
    assert_eq!(json["user_id"], user_id.to_string());
    assert!(!json["token"].as_str().unwrap().is_empty());
}

#[tokio::test]
async fn test_verify_rejects_expired_and_used_tokens() {
    init_test_env();
    let raw_token = "expired_tok";
    let token_hash = hex_encode(&Sha256::digest(raw_token.as_bytes()));
    let expired = sample_verification_token(None, "exp@example.com", &token_hash, true, false);

    let db1 = new_pg_mock()
        .append_query_results([vec![expired]])
        .into_connection();
    let app1 = build_test_app(db1, String::new());
    let (status1, _) = send_json(
        &app1,
        Method::POST,
        "/api/v1/user/auth/verify",
        None,
        Some(serde_json::json!({ "token": raw_token, "password": "ValidPassword1" })),
    )
    .await;
    assert_eq!(status1, StatusCode::BAD_REQUEST);

    let used = sample_verification_token(None, "used@example.com", &token_hash, false, true);
    let db2 = new_pg_mock()
        .append_query_results([vec![used]])
        .into_connection();
    let app2 = build_test_app(db2, String::new());
    let (status2, _) = send_json(
        &app2,
        Method::POST,
        "/api/v1/user/auth/verify",
        None,
        Some(serde_json::json!({ "token": raw_token, "password": "ValidPassword1" })),
    )
    .await;
    assert_eq!(status2, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_link_email_success_and_conflict() {
    init_test_env();
    let tg_user_id = Uuid::new_v4();
    let other_user_id = Uuid::new_v4();
    let tg_user = sample_user(tg_user_id, None, None);
    let jwt = make_user_jwt(tg_user_id, &tg_user.fingerprint);

    let tok_row = sample_verification_token(Some(tg_user_id), "bind@example.com", "h", false, false);
    let db_ok = new_pg_mock()
        .append_query_results([vec![tg_user.clone()]])
        .append_query_results([vec![] as Vec<users::Model>])
        .append_query_results([vec![tok_row]])
        .into_connection();
    let app_ok = build_test_app(db_ok, String::new());

    let (st_ok, body_ok) = send_json(
        &app_ok,
        Method::POST,
        "/api/v1/user/auth/link-email",
        Some(&jwt),
        Some(serde_json::json!({ "email": "bind@example.com" })),
    )
    .await;
    assert_eq!(st_ok, StatusCode::OK, "body={}", body_ok);

    let other_user = sample_user(other_user_id, Some("taken@example.com"), None);
    let db_conflict = new_pg_mock()
        .append_query_results([vec![tg_user]])
        .append_query_results([vec![other_user]])
        .into_connection();
    let app_conflict = build_test_app(db_conflict, String::new());

    let (st_conflict, _) = send_json(
        &app_conflict,
        Method::POST,
        "/api/v1/user/auth/link-email",
        Some(&jwt),
        Some(serde_json::json!({ "email": "taken@example.com" })),
    )
    .await;
    assert_eq!(st_conflict, StatusCode::CONFLICT);
}

#[tokio::test]
async fn test_login_success_and_wrong_password() {
    init_test_env();
    let uid = Uuid::new_v4();
    let mut user = sample_user(uid, Some("client@example.com"), None);
    user.password_hash = Some(hash("SecretPass99", 4).unwrap());

    let db = new_pg_mock()
        .append_query_results([vec![user.clone()]])
        .append_query_results([vec![user]])
        .into_connection();
    let app = build_test_app(db, String::new());

    let (st_ok, body_ok) = send_json(
        &app,
        Method::POST,
        "/api/v1/user/auth/login",
        None,
        Some(serde_json::json!({ "email": "client@example.com", "password": "SecretPass99" })),
    )
    .await;
    assert_eq!(st_ok, StatusCode::OK, "body={}", body_ok);
    let json: serde_json::Value = serde_json::from_str(&body_ok).unwrap();
    assert_eq!(json["user_id"], uid.to_string());

    let (st_bad, _) = send_json(
        &app,
        Method::POST,
        "/api/v1/user/auth/login",
        None,
        Some(serde_json::json!({ "email": "client@example.com", "password": "WrongPassword" })),
    )
    .await;
    assert_eq!(st_bad, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_telegram_auth_hmac_verification_and_autocreation() {
    init_test_env();
    let bot_token = crate::config::get().cabinet.telegram.bot_token.clone();
    let auth_date = Utc::now().timestamp();
    let user_json = r#"{"id":99887766,"username":"anet_tester"}"#;
    // Ключи в data_check_string отсортированы по алфавиту (BTreeMap): auth_date, query_id, user
    let data_check = format!(
        "auth_date={}\nquery_id=AAHdF6IQAAAAAN0XohDhrOrc\nuser={}",
        auth_date, user_json
    );
    let secret_key = hmac_sha256_bytes(b"WebAppData", bot_token.as_bytes());
    let valid_hash = hmac_sha256_hex(&secret_key, data_check.as_bytes());

    let init_data = format!(
        "query_id=AAHdF6IQAAAAAN0XohDhrOrc&user=%7B%22id%22%3A99887766%2C%22username%22%3A%22anet_tester%22%7D&auth_date={}&hash={}",
        auth_date, valid_hash
    );

    let default_gid = Uuid::new_v4();
    let new_uid = Uuid::new_v4();
    let default_group = sample_group(default_gid, "Start", true, 0, 1);
    let mut created_user = sample_user(new_uid, None, Some(default_gid));
    created_user.telegram_id = Some(99887766);

    let db = new_pg_mock()
        .append_query_results([vec![] as Vec<users::Model>])
        .append_query_results([vec![default_group]])
        .append_query_results([vec![created_user]])
        .into_connection();
    let app = build_test_app(db, String::new());

    let (st_bad, _) = send_json(
        &app,
        Method::POST,
        "/api/v1/user/auth/telegram",
        None,
        Some(serde_json::json!({
            "init_data": format!("auth_date={}&user=%7B%22id%22%3A1%7D&hash=deadbeef", auth_date)
        })),
    )
    .await;
    assert_eq!(st_bad, StatusCode::UNAUTHORIZED);

    let (st_ok, body_ok) = send_json(
        &app,
        Method::POST,
        "/api/v1/user/auth/telegram",
        None,
        Some(serde_json::json!({ "init_data": init_data })),
    )
    .await;
    assert_eq!(st_ok, StatusCode::OK, "body={}", body_ok);
    let json: serde_json::Value = serde_json::from_str(&body_ok).unwrap();
    assert_eq!(json["user_id"], new_uid.to_string());
}
