use chrono::{Duration as ChronoDuration, Utc};
use poem::http::{Method, StatusCode};
use uuid::Uuid;

use crate::api::api::set_live_node_session_for_fingerprint;
use crate::api::tests::{
    build_test_app, count_row, init_test_env, make_user_jwt, new_pg_mock, sample_active_session,
    sample_group, sample_node_command, sample_order, sample_product, sample_rate, sample_server,
    sample_traffic_hourly, sample_traffic_total, sample_user, send_json,
};
use crate::entities::{billing_enums::OrderStatus, rates, user_node_pools};

#[tokio::test]
async fn test_user_me_rates_override_and_group_smart_activation_pending() {
    init_test_env();
    let uid1 = Uuid::new_v4();
    let gid1 = Uuid::new_v4();
    let user1 = sample_user(uid1, Some("vip@example.com"), Some(gid1));
    let jwt1 = make_user_jwt(uid1, &user1.fingerprint);
    let rate1 = sample_rate(Uuid::new_v4(), uid1, 7, Utc::now().naive_utc() + ChronoDuration::days(20));
    let group1 = sample_group(gid1, "Base Group", false, 30, 2);
    let sess1 = sample_active_session(uid1, 2);
    set_live_node_session_for_fingerprint(Uuid::new_v4(), &user1.fingerprint, 2);

    let db1 = new_pg_mock()
        .append_query_results([vec![user1.clone()]])
        .append_query_results([vec![user1]])
        .append_query_results([vec![rate1]])
        .append_query_results([vec![group1.clone()]])
        .append_query_results([vec![sess1]])
        .append_query_results([count_row("total", 8192)])
        .into_connection();
    let app1 = build_test_app(db1, String::new());

    let (st1, body1) = send_json(&app1, Method::GET, "/api/v1/user/me", Some(&jwt1), None).await;
    assert_eq!(st1, StatusCode::OK, "body={}", body1);
    let j1: serde_json::Value = serde_json::from_str(&body1).unwrap();
    assert_eq!(j1["effective_limits"]["source"], "rates");
    assert_eq!(j1["effective_limits"]["sessions_limit"], 7);
    assert_eq!(j1["effective_limits"]["speed_limit_kbps"], 25_000);
    assert_eq!(j1["effective_limits"]["traffic_limit_bytes"], 50_000_000);
    assert_eq!(j1["active_sessions_count"], 2);
    assert_eq!(j1["traffic_used_bytes"], 8192);

    // Проверка ветки группы + is_smart_activation_pending = true
    let uid2 = Uuid::new_v4();
    let user2 = sample_user(uid2, Some("pending@example.com"), Some(gid1));
    let jwt2 = make_user_jwt(uid2, &user2.fingerprint);

    let db2 = new_pg_mock()
        .append_query_results([vec![user2.clone()]])
        .append_query_results([vec![user2]])
        .append_query_results([vec![] as Vec<rates::Model>])
        .append_query_results([vec![group1]])
        .append_query_results([vec![] as Vec<crate::entities::active_sessions::Model>])
        .append_query_results([count_row("total", 512)])
        .into_connection();
    let app2 = build_test_app(db2, String::new());

    let (st2, body2) = send_json(&app2, Method::GET, "/api/v1/user/me", Some(&jwt2), None).await;
    assert_eq!(st2, StatusCode::OK, "body={}", body2);
    let j2: serde_json::Value = serde_json::from_str(&body2).unwrap();
    assert_eq!(j2["effective_limits"]["source"], "groups");
    assert_eq!(j2["is_smart_activation_pending"], true);
    assert_eq!(j2["group_name"], "Base Group");
    assert_eq!(j2["effective_limits"]["sessions_limit"], 2);
}

#[tokio::test]
async fn test_user_products_create_order_sci_and_list_orders() {
    init_test_env();
    let uid = Uuid::new_v4();
    let pid = Uuid::new_v4();
    let oid = Uuid::new_v4();
    let user = sample_user(uid, Some("buyer@example.com"), None);
    let jwt = make_user_jwt(uid, &user.fingerprint);
    let prod = sample_product(pid, None, 299.0);
    let order = sample_order(oid, uid, pid, 299.0, OrderStatus::Pending, false);

    let db = new_pg_mock()
        // GET /user/products
        .append_query_results([vec![user.clone()]])
        .append_query_results([vec![prod.clone()]])
        // POST /user/orders
        .append_query_results([vec![user.clone()]])
        .append_query_results([vec![user.clone()]])
        .append_query_results([vec![prod]])
        .append_query_results([vec![order.clone()]])
        // GET /user/orders
        .append_query_results([vec![user]])
        .append_query_results([vec![order]])
        .into_connection();
    let app = build_test_app(db, String::new());

    let (st_list, b_list) = send_json(&app, Method::GET, "/api/v1/user/products", Some(&jwt), None).await;
    assert_eq!(st_list, StatusCode::OK, "body={}", b_list);
    let prods: Vec<serde_json::Value> = serde_json::from_str(&b_list).unwrap();
    assert_eq!(prods.len(), 1);
    assert_eq!(prods[0]["name"], "Pro 30d");

    let (st_create, b_create) = send_json(
        &app,
        Method::POST,
        "/api/v1/user/orders",
        Some(&jwt),
        Some(serde_json::json!({ "product_id": pid, "is_gift": false })),
    )
    .await;
    assert_eq!(st_create, StatusCode::OK, "body={}", b_create);
    let created: serde_json::Value = serde_json::from_str(&b_create).unwrap();
    assert_eq!(created["amount"], 299.0);
    let pay_url = created["payment_url"].as_str().unwrap();
    assert!(pay_url.starts_with("https://pay.freekassa.ru/?"));
    assert!(pay_url.contains("m=777001"));
    assert!(pay_url.contains("oa=299.00"));
    assert!(pay_url.contains("&s="));

    let (st_orders, b_orders) = send_json(&app, Method::GET, "/api/v1/user/orders", Some(&jwt), None).await;
    assert_eq!(st_orders, StatusCode::OK, "body={}", b_orders);
    let orders_json: Vec<serde_json::Value> = serde_json::from_str(&b_orders).unwrap();
    assert_eq!(orders_json.len(), 1);
    assert_eq!(orders_json[0]["status"], "Pending");
}

#[tokio::test]
async fn test_user_sessions_and_disconnect_node_command() {
    init_test_env();
    let uid = Uuid::new_v4();
    let server_id = Uuid::new_v4();
    let user = sample_user(uid, Some("sess@example.com"), None);
    let jwt = make_user_jwt(uid, &user.fingerprint);

    set_live_node_session_for_fingerprint(server_id, &user.fingerprint, 2);

    let srv = sample_server(server_id, "DE-Frankfurt");
    let total = sample_traffic_total(server_id, &user.fingerprint, 1024, 2048);
    let cmd = sample_node_command(server_id, &user.fingerprint);

    let db = new_pg_mock()
        // GET /user/sessions
        .append_query_results([vec![user.clone()]])
        .append_query_results([vec![user.clone()]])
        .append_query_results([vec![srv.clone()]])
        .append_query_results([vec![total]])
        // POST /user/sessions/disconnect
        .append_query_results([vec![user.clone()]])
        .append_query_results([vec![srv]])
        .append_query_results([vec![cmd]])
        .into_connection();
    let app = build_test_app(db.clone(), String::new());

    let (st_s, b_s) = send_json(&app, Method::GET, "/api/v1/user/sessions", Some(&jwt), None).await;
    assert_eq!(st_s, StatusCode::OK, "body={}", b_s);
    let sessions: Vec<serde_json::Value> = serde_json::from_str(&b_s).unwrap();
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0]["server_name"], "DE-Frankfurt");
    assert_eq!(sessions[0]["rx_bytes"], 1024);
    assert_eq!(sessions[0]["tx_bytes"], 2048);
    assert_eq!(sessions[0]["connection_count"], 2);

    let (st_disc, b_disc) = send_json(
        &app,
        Method::POST,
        "/api/v1/user/sessions/disconnect",
        Some(&jwt),
        Some(serde_json::json!({
            "server_id": server_id,
            "session_id": format!("{}:quic", server_id)
        })),
    )
    .await;
    assert_eq!(st_disc, StatusCode::OK, "body={}", b_disc);
    assert_eq!(b_disc.trim(), "true");

    let sql_log = format!("{:?}", db.into_transaction_log());
    assert!(sql_log.contains("node_commands"));

    // Очистка live snapshot после теста
    set_live_node_session_for_fingerprint(server_id, &user.fingerprint, 0);
}

#[tokio::test]
async fn test_user_traffic_history_aggregates_hourly_buckets() {
    init_test_env();
    let uid = Uuid::new_v4();
    let server_id = Uuid::new_v4();
    let user = sample_user(uid, Some("traffic@example.com"), None);
    let jwt = make_user_jwt(uid, &user.fingerprint);

    let now_hour = Utc::now()
        .naive_utc()
        .date()
        .and_hms_opt(chrono::Timelike::hour(&Utc::now().naive_utc()), 0, 0)
        .unwrap();
    let row = sample_traffic_hourly(now_hour, server_id, uid, &user.fingerprint, 500, 1500);

    let db = new_pg_mock()
        .append_query_results([vec![user]])
        .append_query_results([vec![row]])
        .into_connection();
    let app = build_test_app(db, String::new());

    let (status, body) = send_json(
        &app,
        Method::GET,
        "/api/v1/user/traffic-history?hours=24&bucket_hours=1",
        Some(&jwt),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body={}", body);
    let pts: Vec<serde_json::Value> = serde_json::from_str(&body).unwrap();
    assert_eq!(pts.len(), 24);
    let total_rx: i64 = pts.iter().map(|p| p["rx_bytes"].as_i64().unwrap()).sum();
    let total_tx: i64 = pts.iter().map(|p| p["tx_bytes"].as_i64().unwrap()).sum();
    assert_eq!(total_rx, 500);
    assert_eq!(total_tx, 1500);
}

#[tokio::test]
async fn test_user_config_returns_decrypted_toml_and_qr_url() {
    init_test_env();
    let uid = Uuid::new_v4();
    let srv_id = Uuid::new_v4();
    let user = sample_user(uid, Some("cfg@example.com"), None);
    let srv = sample_server(srv_id, "NL-Amsterdam");
    let jwt = make_user_jwt(uid, &user.fingerprint);

    let tpl_path = std::env::temp_dir().join(format!("anet_test_tpl_{}.toml", Uuid::new_v4()));
    std::fs::write(
        &tpl_path,
        "[keys]\nprivate_key = \"{{PRIVATE_KEY}}\"\nserver_pub_key = \"{{SERVER_PUB_KEY}}\"\n",
    )
    .unwrap();

    let db = new_pg_mock()
        // ensure_user
        .append_query_results([vec![user.clone()]])
        // build_client_toml_for_user: find_with_related(servers::Entity)
        .append_query_results([vec![(user.clone(), Some(srv))]])
        // compiled_routes_for_user: users::Entity::find_by_id
        .append_query_results([vec![user]])
        // resolve_client_servers: user_node_pools::Entity::find
        .append_query_results([vec![] as Vec<user_node_pools::Model>])
        .into_connection();
    let app = build_test_app(db, tpl_path.to_string_lossy().to_string());

    let (status, body) = send_json(&app, Method::GET, "/api/v1/user/config", Some(&jwt), None).await;
    let _ = std::fs::remove_file(&tpl_path);

    assert_eq!(status, StatusCode::OK, "body={}", body);
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    let toml = json["client_toml"].as_str().unwrap();
    assert!(toml.contains("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="));
    assert!(toml.contains("quic://198.51.100.10:443"));
    assert_eq!(
        json["qr_code_url"],
        format!("https://cabinet.test.local/api/v1/config/qr/{}", uid)
    );
}

#[tokio::test]
async fn test_user_cabinet_unauthorized_and_missing_product() {
    init_test_env();
    let uid = Uuid::new_v4();
    let user = sample_user(uid, Some("err@example.com"), None);
    let jwt = make_user_jwt(uid, &user.fingerprint);

    let db = new_pg_mock()
        // POST /user/orders -> ensure_user -> user -> empty products (404)
        .append_query_results([vec![user.clone()]])
        .append_query_results([vec![user]])
        .append_query_results([vec![] as Vec<crate::entities::products::Model>])
        .into_connection();
    let app = build_test_app(db, String::new());

    let (st_no_auth, _) = send_json(&app, Method::GET, "/api/v1/user/me", None, None).await;
    assert_eq!(st_no_auth, StatusCode::UNAUTHORIZED);

    let (st_bad_tok, _) = send_json(&app, Method::GET, "/api/v1/user/me", Some("invalid.jwt"), None).await;
    assert_eq!(st_bad_tok, StatusCode::UNAUTHORIZED);

    let (st_not_found, _) = send_json(
        &app,
        Method::POST,
        "/api/v1/user/orders",
        Some(&jwt),
        Some(serde_json::json!({ "product_id": Uuid::new_v4(), "is_gift": false })),
    )
    .await;
    assert_eq!(st_not_found, StatusCode::NOT_FOUND);
}
