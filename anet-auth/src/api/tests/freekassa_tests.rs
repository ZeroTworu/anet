use poem::http::{Method, StatusCode};
use uuid::Uuid;

use crate::api::freekassa::{fulfill_order, hmac_sha256_hex, md5_hex};
use crate::api::tests::{
    build_test_app, init_test_env, new_pg_mock, sample_order, sample_product, sample_tx,
    sample_user, sample_voucher, send_request,
};
use crate::entities::billing_enums::OrderStatus;

#[test]
fn test_rfc_md5_and_hmac_sha256_vectors() {
    assert_eq!(md5_hex(b""), "d41d8cd98f00b204e9800998ecf8427e");
    assert_eq!(md5_hex(b"abc"), "900150983cd24fb0d6963f7d28e17f72");
    assert_eq!(
        hmac_sha256_hex(b"key", b"The quick brown fox jumps over the lazy dog"),
        "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"
    );
}

#[tokio::test]
async fn test_freekassa_notify_rejects_untrusted_ip_and_bad_signature() {
    init_test_env();
    let db = new_pg_mock().into_connection();
    let app = build_test_app(db, String::new());
    let oid = Uuid::new_v4();

    let sign = md5_hex(format!("777001:299.00:fk_sec_2:{}", oid).as_bytes());
    let body = format!(
        "MERCHANT_ID=777001&AMOUNT=299.00&MERCHANT_ORDER_ID={}&SIGN={}&intid=101",
        oid, sign
    );

    // 1. Недоверенный IP -> 403 Forbidden
    let (st_ip, _) = send_request(
        &app,
        Method::POST,
        "/billing/freekassa/notify",
        None,
        &[("X-Real-IP", "1.2.3.4")],
        Some("application/x-www-form-urlencoded"),
        body.as_bytes().to_vec(),
    )
    .await;
    assert_eq!(st_ip, StatusCode::FORBIDDEN);

    // 2. Доверенный IP, но битая подпись SIGN (хэш от "299.0" вместо сырого "299.00") -> 400
    let wrong_sign = md5_hex(format!("777001:299.0:fk_sec_2:{}", oid).as_bytes());
    let bad_body = format!(
        "MERCHANT_ID=777001&AMOUNT=299.00&MERCHANT_ORDER_ID={}&SIGN={}&intid=102",
        oid, wrong_sign
    );
    let (st_sig, _) = send_request(
        &app,
        Method::POST,
        "/billing/freekassa/notify",
        None,
        &[("X-Real-IP", "168.119.157.136")],
        Some("application/x-www-form-urlencoded"),
        bad_body.as_bytes().to_vec(),
    )
    .await;
    assert_eq!(st_sig, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_freekassa_notify_fulfills_group_subscription_and_resets_activation() {
    init_test_env();
    let oid = Uuid::new_v4();
    let uid = Uuid::new_v4();
    let pid = Uuid::new_v4();
    let target_gid = Uuid::new_v4();

    let pending_order = sample_order(oid, uid, pid, 299.0, OrderStatus::Pending, false);
    let mut paid_order = pending_order.clone();
    paid_order.status = OrderStatus::Paid;

    let tx = sample_tx(Some(oid), "fk_intid_555", 299.0);
    let product = sample_product(pid, Some(target_gid), 299.0);
    let user = sample_user(uid, Some("payer@example.com"), None);
    let mut updated_user = user.clone();
    updated_user.group_id = Some(target_gid);
    updated_user.activated_at = None;
    updated_user.expires_at = None;

    let db = new_pg_mock()
        .append_query_results([vec![pending_order]])
        .append_query_results([vec![tx]])
        .append_query_results([vec![paid_order]])
        .append_query_results([vec![product]])
        .append_query_results([vec![user]])
        .append_query_results([vec![updated_user]])
        .into_connection();
    let app = build_test_app(db.clone(), String::new());

    let sign = md5_hex(format!("777001:299.00:fk_sec_2:{}", oid).as_bytes());
    let form_body = format!(
        "MERCHANT_ID=777001&AMOUNT=299.00&MERCHANT_ORDER_ID={}&SIGN={}&intid=fk_intid_555",
        oid, sign
    );

    let (status, resp_body) = send_request(
        &app,
        Method::POST,
        "/billing/freekassa/notify",
        None,
        &[("X-Real-IP", "168.119.157.136")],
        Some("application/x-www-form-urlencoded"),
        form_body.as_bytes().to_vec(),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "body={}", resp_body);
    assert_eq!(resp_body, "YES");

    let sql_log = format!("{:?}", db.into_transaction_log());
    assert!(sql_log.contains("transactions"));
    assert!(sql_log.contains("orders"));
    assert!(sql_log.contains("users"));
}

#[tokio::test]
async fn test_freekassa_notify_gift_order_creates_voucher() {
    init_test_env();
    let oid = Uuid::new_v4();
    let uid = Uuid::new_v4();
    let pid = Uuid::new_v4();

    let gift_order = sample_order(oid, uid, pid, 499.0, OrderStatus::Pending, true);
    let mut paid_gift = gift_order.clone();
    paid_gift.status = OrderStatus::Paid;

    let tx = sample_tx(Some(oid), "fk_gift_1", 499.0);
    let prod = sample_product(pid, None, 499.0);
    let voucher = sample_voucher(pid, uid);

    let db = new_pg_mock()
        .append_query_results([vec![gift_order]])
        .append_query_results([vec![tx]])
        .append_query_results([vec![paid_gift]])
        .append_query_results([vec![prod]])
        .append_query_results([vec![voucher]])
        .into_connection();
    let app = build_test_app(db.clone(), String::new());

    let sign = md5_hex(format!("777001:499.00:fk_sec_2:{}", oid).as_bytes());
    let form_body = format!(
        "MERCHANT_ID=777001&AMOUNT=499.00&MERCHANT_ORDER_ID={}&SIGN={}&intid=fk_gift_1",
        oid, sign
    );

    let (status, resp_body) = send_request(
        &app,
        Method::POST,
        "/billing/freekassa/notify",
        None,
        &[("X-Real-IP", "168.119.60.227")],
        Some("application/x-www-form-urlencoded"),
        form_body.as_bytes().to_vec(),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "body={}", resp_body);
    assert_eq!(resp_body, "YES");
    let sql_log = format!("{:?}", db.into_transaction_log());
    assert!(sql_log.contains("vouchers"));
}

#[tokio::test]
async fn test_fulfill_order_idempotency_and_amount_mismatch() {
    init_test_env();
    let oid = Uuid::new_v4();
    let uid = Uuid::new_v4();
    let pid = Uuid::new_v4();

    // 1. Уже оплаченный заказ -> идемпотентный Ok(()) без INSERT в transactions
    let paid_order = sample_order(oid, uid, pid, 299.0, OrderStatus::Paid, false);
    let db_idem = new_pg_mock()
        .append_query_results([vec![paid_order]])
        .into_connection();

    let res_idem = fulfill_order(
        &db_idem,
        oid,
        "dup_tx".to_string(),
        Some(299.0),
        serde_json::json!({}),
    )
    .await;
    assert!(res_idem.is_ok());
    let log_idem = format!("{:?}", db_idem.into_transaction_log());
    assert!(!log_idem.contains("transactions"));

    // 2. Подмена суммы -> 400 Bad Request ("Amount mismatch")
    let pending = sample_order(oid, uid, pid, 299.0, OrderStatus::Pending, false);
    let db_mismatch = new_pg_mock()
        .append_query_results([vec![pending]])
        .into_connection();

    let res_mismatch = fulfill_order(
        &db_mismatch,
        oid,
        "bad_amt".to_string(),
        Some(10.0),
        serde_json::json!({}),
    )
    .await;
    assert!(res_mismatch.is_err());
    let (code, msg) = res_mismatch.unwrap_err();
    assert_eq!(code, StatusCode::BAD_REQUEST);
    assert!(msg.contains("Amount mismatch"));
}
