use chrono::{Duration as ChronoDuration, Utc};
use poem::http::{Method, StatusCode};
use sea_orm::MockExecResult;
use uuid::Uuid;

use crate::api::tests::{
    build_test_app, count_row, init_test_env, make_admin_auth, new_pg_mock,
    sample_active_session, sample_group, sample_rate, sample_user, send_json,
};
use crate::entities::{active_sessions, group_node_pools, rates, users};

#[tokio::test]
async fn test_admin_users_list_add_and_patch_email_password_clear() {
    init_test_env();
    let (_jti, _aid, admin_jwt, admin_sess) = make_admin_auth();
    let uid = Uuid::new_v4();
    let gid = Uuid::new_v4();
    let rid = Uuid::new_v4();

    let mut base_user = sample_user(uid, Some("alice@example.com"), Some(gid));
    base_user.password_hash = Some("$2b$04$hashed".to_string());
    let rate = sample_rate(rid, uid, 5, Utc::now().naive_utc() + ChronoDuration::days(30));

    let mut updated_user = base_user.clone();
    updated_user.email = Some("alice.new@example.com".to_string());

    let mut cleared_user = updated_user.clone();
    cleared_user.email = None;
    cleared_user.password_hash = None;
    cleared_user.group_id = None;

    let db = new_pg_mock()
        // 1. GET /users
        .append_query_results([vec![admin_sess.clone()]])
        .append_query_results([count_row("num_items", 1)])
        .append_query_results([vec![(base_user.clone(), Some(rate.clone()))]])
        // 2. POST /add
        .append_query_results([vec![admin_sess.clone()]])
        .append_query_results([vec![] as Vec<users::Model>])
        .append_query_results([vec![base_user.clone()]])
        .append_query_results([vec![rate.clone()]])
        // 3. PATCH /user/:id (смена email и пароля)
        .append_query_results([vec![admin_sess.clone()]])
        .append_query_results([vec![(base_user, Some(rate.clone()))]])
        .append_query_results([vec![] as Vec<users::Model>])
        .append_query_results([vec![updated_user.clone()]])
        // 4. PATCH /user/:id (очистка email, пароля и группы)
        .append_query_results([vec![admin_sess]])
        .append_query_results([vec![(updated_user, Some(rate))]])
        .append_query_results([vec![cleared_user]])
        .into_connection();
    let app = build_test_app(db, String::new());

    let (st_list, b_list) = send_json(&app, Method::GET, "/api/v1/users", Some(&admin_jwt), None).await;
    assert_eq!(st_list, StatusCode::OK, "body={}", b_list);
    let list_json: serde_json::Value = serde_json::from_str(&b_list).unwrap();
    assert_eq!(list_json["total"], 1);
    assert_eq!(list_json["items"][0]["email"], "alice@example.com");
    assert_eq!(list_json["items"][0]["has_password"], true);
    assert_eq!(list_json["items"][0]["rate"]["traffic_limit"], 50_000_000);
    assert_eq!(list_json["items"][0]["rate"]["speed_limit"], 25_000);

    let (st_add, b_add) = send_json(
        &app,
        Method::POST,
        "/api/v1/add",
        Some(&admin_jwt),
        Some(serde_json::json!({
            "uid": "alice",
            "email": "alice@example.com",
            "password": "Password123",
            "group_id": gid,
            "rate": {
                "sessions": 5,
                "date_end": "2027-01-01-12:00",
                "traffic_limit": 50000000,
                "speed_limit": 25000
            }
        })),
    )
    .await;
    assert_eq!(st_add, StatusCode::OK, "body={}", b_add);
    let add_json: serde_json::Value = serde_json::from_str(&b_add).unwrap();
    assert_eq!(add_json["rate"]["sessions"], 5);
    assert_eq!(add_json["rate"]["traffic_limit"], 50_000_000);
    assert_eq!(add_json["rate"]["speed_limit"], 25_000);

    let (st_patch1, b_patch1) = send_json(
        &app,
        Method::PATCH,
        &format!("/api/v1/user/{}", uid),
        Some(&admin_jwt),
        Some(serde_json::json!({
            "email": "alice.new@example.com",
            "password": "NewPassword456"
        })),
    )
    .await;
    assert_eq!(st_patch1, StatusCode::OK, "body={}", b_patch1);
    let p1_json: serde_json::Value = serde_json::from_str(&b_patch1).unwrap();
    assert_eq!(p1_json["email"], "alice.new@example.com");
    assert_eq!(p1_json["has_password"], true);

    let (st_patch2, b_patch2) = send_json(
        &app,
        Method::PATCH,
        &format!("/api/v1/user/{}", uid),
        Some(&admin_jwt),
        Some(serde_json::json!({
            "clear_email": true,
            "clear_password": true,
            "clear_group": true
        })),
    )
    .await;
    assert_eq!(st_patch2, StatusCode::OK, "body={}", b_patch2);
    let p2_json: serde_json::Value = serde_json::from_str(&b_patch2).unwrap();
    assert!(p2_json["email"].is_null());
    assert_eq!(p2_json["has_password"], false);
    assert!(p2_json["group_id"].is_null());
}

#[tokio::test]
async fn test_admin_rate_add_patch_and_delete() {
    init_test_env();
    let (_jti, _aid, admin_jwt, admin_sess) = make_admin_auth();
    let uid = Uuid::new_v4();
    let rid = Uuid::new_v4();
    let user = sample_user(uid, None, None);
    let rate = sample_rate(rid, uid, 3, Utc::now().naive_utc() + ChronoDuration::days(15));
    let mut updated_rate = rate.clone();
    updated_rate.sessions = 10;
    updated_rate.traffic_limit = 99_000_000;
    updated_rate.speed_limit = 75_000;

    let db = new_pg_mock()
        // POST /addrate
        .append_query_results([vec![admin_sess.clone()]])
        .append_query_results([vec![user]])
        .append_query_results([vec![] as Vec<rates::Model>])
        .append_query_results([vec![rate.clone()]])
        // PATCH /rate/:id
        .append_query_results([vec![admin_sess.clone()]])
        .append_query_results([vec![rate]])
        .append_query_results([vec![updated_rate]])
        // DELETE /rate/:id (успех и 404)
        .append_query_results([vec![admin_sess.clone()]])
        .append_exec_results([MockExecResult {
            last_insert_id: 0,
            rows_affected: 1,
        }])
        .append_query_results([vec![admin_sess]])
        .append_exec_results([MockExecResult {
            last_insert_id: 0,
            rows_affected: 0,
        }])
        .into_connection();
    let app = build_test_app(db, String::new());

    let (st_add, b_add) = send_json(
        &app,
        Method::POST,
        &format!("/api/v1/addrate?user_id={}", uid),
        Some(&admin_jwt),
        Some(serde_json::json!({
            "sessions": 3,
            "date_end": "2027-02-01-10:00",
            "traffic_limit": 50000000,
            "speed_limit": 25000
        })),
    )
    .await;
    assert_eq!(st_add, StatusCode::OK, "body={}", b_add);

    let (st_patch, b_patch) = send_json(
        &app,
        Method::PATCH,
        &format!("/api/v1/rate/{}", rid),
        Some(&admin_jwt),
        Some(serde_json::json!({
            "sessions": 10,
            "traffic_limit": 99000000,
            "speed_limit": 75000
        })),
    )
    .await;
    assert_eq!(st_patch, StatusCode::OK, "body={}", b_patch);
    let p_json: serde_json::Value = serde_json::from_str(&b_patch).unwrap();
    assert_eq!(p_json["sessions"], 10);
    assert_eq!(p_json["traffic_limit"], 99_000_000);
    assert_eq!(p_json["speed_limit"], 75_000);

    let (st_del_ok, b_del_ok) = send_json(
        &app,
        Method::DELETE,
        &format!("/api/v1/rate/{}", rid),
        Some(&admin_jwt),
        None,
    )
    .await;
    assert_eq!(st_del_ok, StatusCode::OK, "body={}", b_del_ok);
    assert_eq!(b_del_ok.trim(), "true");

    let (st_del_404, _) = send_json(
        &app,
        Method::DELETE,
        &format!("/api/v1/rate/{}", Uuid::new_v4()),
        Some(&admin_jwt),
        None,
    )
    .await;
    assert_eq!(st_del_404, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_groups_create_and_update_is_default_flag() {
    init_test_env();
    let (_jti, _aid, admin_jwt, admin_sess) = make_admin_auth();
    let gid = Uuid::new_v4();
    let existing = sample_group(gid, "Standard", false, 30, 2);
    let created = sample_group(gid, "Free Default", true, 0, 1);

    let db = new_pg_mock()
        // POST /groups (is_default: true -> UPDATE groups SET is_default = false -> INSERT)
        .append_query_results([vec![admin_sess.clone()]])
        .append_exec_results([MockExecResult {
            last_insert_id: 0,
            rows_affected: 1,
        }])
        .append_query_results([vec![created.clone()]])
        // PATCH /groups/:id (is_default: true -> find_by_id -> UPDATE others -> COUNT -> UPDATE -> find pools)
        .append_query_results([vec![admin_sess]])
        .append_query_results([vec![existing]])
        .append_exec_results([MockExecResult {
            last_insert_id: 0,
            rows_affected: 1,
        }])
        .append_query_results([count_row("num_items", 4)])
        .append_query_results([vec![created]])
        .append_query_results([vec![] as Vec<group_node_pools::Model>])
        .into_connection();
    let app = build_test_app(db, String::new());

    let (st_c, b_c) = send_json(
        &app,
        Method::POST,
        "/api/v1/groups",
        Some(&admin_jwt),
        Some(serde_json::json!({
            "name": "Free Default",
            "is_default": true,
            "traffic_limit": 0,
            "speed_limit": 0,
            "sessions_limit": 1,
            "duration_days": 0
        })),
    )
    .await;
    assert_eq!(st_c, StatusCode::OK, "body={}", b_c);
    let c_json: serde_json::Value = serde_json::from_str(&b_c).unwrap();
    assert_eq!(c_json["is_default"], true);

    let (st_u, b_u) = send_json(
        &app,
        Method::PATCH,
        &format!("/api/v1/groups/{}", gid),
        Some(&admin_jwt),
        Some(serde_json::json!({
            "name": "Free Default",
            "is_default": true,
            "traffic_limit": 0,
            "speed_limit": 0,
            "sessions_limit": 1,
            "duration_days": 0
        })),
    )
    .await;
    assert_eq!(st_u, StatusCode::OK, "body={}", b_u);
    let u_json: serde_json::Value = serde_json::from_str(&b_u).unwrap();
    assert_eq!(u_json["is_default"], true);
    assert_eq!(u_json["user_count"], 4);
}

#[tokio::test]
async fn test_check_access_smart_activation_and_expired_default_fallback() {
    init_test_env();
    // 1. Smart Activation: activated_at == None + group.duration_days == 30
    let uid1 = Uuid::new_v4();
    let gid1 = Uuid::new_v4();
    let pending_user = sample_user(uid1, Some("smart@example.com"), Some(gid1));
    let mut activated_user = pending_user.clone();
    let now_utc = Utc::now();
    activated_user.activated_at = Some(now_utc);
    activated_user.expires_at = Some(now_utc + ChronoDuration::days(30));

    let paid_group = sample_group(gid1, "Pro 30d", false, 30, 3);
    let new_sess = sample_active_session(uid1, 1);

    let db1 = new_pg_mock()
        .append_query_results([vec![pending_user.clone()]])
        .append_query_results([vec![paid_group.clone()]])
        .append_query_results([vec![activated_user]])
        .append_query_results([vec![] as Vec<rates::Model>])
        .append_query_results([vec![] as Vec<active_sessions::Model>])
        .append_query_results([count_row("total", 100)])
        .append_query_results([vec![] as Vec<active_sessions::Model>])
        .append_query_results([vec![new_sess]])
        .into_connection();
    let app1 = build_test_app(db1, String::new());

    let (st1, b1) = send_json(
        &app1,
        Method::POST,
        "/api/v1/check_access",
        None,
        Some(serde_json::json!({ "fingerprint": pending_user.fingerprint })),
    )
    .await;
    assert_eq!(st1, StatusCode::OK, "body={}", b1);
    let j1: serde_json::Value = serde_json::from_str(&b1).unwrap();
    assert_eq!(j1["allowed"], true);
    assert_eq!(j1["active_sessions"], 1);
    assert_eq!(j1["allowed_sessions"], 3);
    assert!(j1["expires_at"].is_string());

    // 2. Истекшая подписка -> переключение на is_default группу (sessions_limit: 0) -> отказ
    let uid2 = Uuid::new_v4();
    let default_gid = Uuid::new_v4();
    let mut expired_user = sample_user(uid2, Some("exp@example.com"), Some(gid1));
    expired_user.activated_at = Some(now_utc - ChronoDuration::days(31));
    expired_user.expires_at = Some(now_utc - ChronoDuration::hours(1));

    let default_group = sample_group(default_gid, "Expired / Free", true, 0, 0);
    let mut downgraded_user = expired_user.clone();
    downgraded_user.group_id = Some(default_gid);
    downgraded_user.expires_at = None;

    let db2 = new_pg_mock()
        .append_query_results([vec![expired_user.clone()]])
        .append_query_results([vec![paid_group]])
        .append_query_results([vec![default_group]])
        .append_query_results([vec![downgraded_user]])
        .into_connection();
    let app2 = build_test_app(db2, String::new());

    let (st2, b2) = send_json(
        &app2,
        Method::POST,
        "/api/v1/check_access",
        None,
        Some(serde_json::json!({ "fingerprint": expired_user.fingerprint })),
    )
    .await;
    assert_eq!(st2, StatusCode::OK, "body={}", b2);
    let j2: serde_json::Value = serde_json::from_str(&b2).unwrap();
    assert_eq!(j2["allowed"], false);
    assert_eq!(j2["group_name"], "Expired / Free");
    assert_eq!(j2["allowed_sessions"], 0);
}

#[tokio::test]
async fn test_add_user_duplicate_email_returns_400() {
    init_test_env();
    let (_jti, _aid, admin_jwt, admin_sess) = make_admin_auth();
    let existing = sample_user(Uuid::new_v4(), Some("dup@example.com"), None);

    let db = new_pg_mock()
        .append_query_results([vec![admin_sess]])
        .append_query_results([vec![existing]])
        .into_connection();
    let app = build_test_app(db, String::new());

    let (status, body) = send_json(
        &app,
        Method::POST,
        "/api/v1/add",
        Some(&admin_jwt),
        Some(serde_json::json!({
            "uid": "dup_user",
            "email": "dup@example.com",
            "password": "Password123"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "body={}", body);
}
