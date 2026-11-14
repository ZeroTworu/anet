use poem::http::{Method, StatusCode};
use sea_orm::MockExecResult;
use uuid::Uuid;

use crate::api::tests::{
    build_test_app, count_row, init_test_env, make_admin_auth, make_user_jwt, new_pg_mock,
    sample_order, sample_product, sample_tx, send_json,
};
use crate::entities::{billing_enums::OrderStatus, products};

#[tokio::test]
async fn test_admin_billing_rejects_non_admin_jwt_with_401() {
    init_test_env();
    let db = new_pg_mock().into_connection();
    let app = build_test_app(db, String::new());
    let user_jwt = make_user_jwt(Uuid::new_v4(), "fp_user");

    let (st_no_auth, _) = send_json(&app, Method::GET, "/api/v1/admin/products", None, None).await;
    assert_eq!(st_no_auth, StatusCode::UNAUTHORIZED);

    let (st_wrong_tok, _) = send_json(
        &app,
        Method::GET,
        "/api/v1/admin/products",
        Some(&user_jwt),
        None,
    )
    .await;
    assert_eq!(st_wrong_tok, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_admin_products_full_crud_with_mock_db() {
    init_test_env();
    let (_jti, _aid, admin_jwt, admin_sess) = make_admin_auth();
    let prod_id = Uuid::new_v4();
    let prod = sample_product(prod_id, None, 499.0);
    let mut updated_prod = prod.clone();
    updated_prod.price = 399.0;
    updated_prod.badge = Some("-20%".to_string());

    let db = new_pg_mock()
        // GET /admin/products
        .append_query_results([vec![admin_sess.clone()]])
        .append_query_results([vec![prod.clone()]])
        // POST /admin/products
        .append_query_results([vec![admin_sess.clone()]])
        .append_query_results([vec![prod.clone()]])
        // PATCH /admin/products/:id
        .append_query_results([vec![admin_sess.clone()]])
        .append_query_results([vec![prod]])
        .append_query_results([vec![updated_prod]])
        // DELETE /admin/products/:id
        .append_query_results([vec![admin_sess]])
        .append_exec_results([MockExecResult {
            last_insert_id: 0,
            rows_affected: 1,
        }])
        .into_connection();
    let app = build_test_app(db, String::new());

    let (st_get, b_get) = send_json(&app, Method::GET, "/api/v1/admin/products", Some(&admin_jwt), None).await;
    assert_eq!(st_get, StatusCode::OK, "body={}", b_get);
    let list: Vec<serde_json::Value> = serde_json::from_str(&b_get).unwrap();
    assert_eq!(list.len(), 1);

    let (st_post, b_post) = send_json(
        &app,
        Method::POST,
        "/api/v1/admin/products",
        Some(&admin_jwt),
        Some(serde_json::json!({
            "name": "Pro 30d",
            "description": "Unlimited high-speed VPN",
            "price": 499.0,
            "currency": "Rub",
            "product_type": "GroupSubscription",
            "is_active": true
        })),
    )
    .await;
    assert_eq!(st_post, StatusCode::OK, "body={}", b_post);

    let (st_patch, b_patch) = send_json(
        &app,
        Method::PATCH,
        &format!("/api/v1/admin/products/{}", prod_id),
        Some(&admin_jwt),
        Some(serde_json::json!({ "price": 399.0, "badge": "-20%" })),
    )
    .await;
    assert_eq!(st_patch, StatusCode::OK, "body={}", b_patch);
    let patched: serde_json::Value = serde_json::from_str(&b_patch).unwrap();
    assert_eq!(patched["price"], 399.0);
    assert_eq!(patched["badge"], "-20%");

    let (st_del, b_del) = send_json(
        &app,
        Method::DELETE,
        &format!("/api/v1/admin/products/{}", prod_id),
        Some(&admin_jwt),
        None,
    )
    .await;
    assert_eq!(st_del, StatusCode::OK, "body={}", b_del);
    assert_eq!(b_del.trim(), "true");
}

#[tokio::test]
async fn test_admin_products_patch_missing_returns_404() {
    init_test_env();
    let (_jti, _aid, admin_jwt, admin_sess) = make_admin_auth();
    let db = new_pg_mock()
        .append_query_results([vec![admin_sess]])
        .append_query_results([vec![] as Vec<products::Model>])
        .into_connection();
    let app = build_test_app(db, String::new());

    let (st, _) = send_json(
        &app,
        Method::PATCH,
        &format!("/api/v1/admin/products/{}", Uuid::new_v4()),
        Some(&admin_jwt),
        Some(serde_json::json!({ "price": 100.0 })),
    )
    .await;
    assert_eq!(st, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_admin_orders_and_transactions_pagination() {
    init_test_env();
    let (_jti, _aid, admin_jwt, admin_sess) = make_admin_auth();
    let oid = Uuid::new_v4();
    let uid = Uuid::new_v4();
    let pid = Uuid::new_v4();

    let order = sample_order(oid, uid, pid, 299.0, OrderStatus::Paid, false);
    let tx = sample_tx(Some(oid), "fk_998877", 299.0);

    let db = new_pg_mock()
        // GET /admin/orders
        .append_query_results([vec![admin_sess.clone()]])
        .append_query_results([count_row("num_items", 1)])
        .append_query_results([vec![order]])
        // GET /admin/transactions
        .append_query_results([vec![admin_sess]])
        .append_query_results([count_row("num_items", 1)])
        .append_query_results([vec![tx]])
        .into_connection();
    let app = build_test_app(db, String::new());

    let (st_ord, b_ord) = send_json(
        &app,
        Method::GET,
        "/api/v1/admin/orders?page=1&page_size=20&status=Paid",
        Some(&admin_jwt),
        None,
    )
    .await;
    assert_eq!(st_ord, StatusCode::OK, "body={}", b_ord);
    let ord_json: serde_json::Value = serde_json::from_str(&b_ord).unwrap();
    assert_eq!(ord_json["total"], 1);
    assert_eq!(ord_json["items"][0]["id"], oid.to_string());

    let (st_tx, b_tx) = send_json(
        &app,
        Method::GET,
        "/api/v1/admin/transactions?page=1&page_size=20",
        Some(&admin_jwt),
        None,
    )
    .await;
    assert_eq!(st_tx, StatusCode::OK, "body={}", b_tx);
    let tx_json: serde_json::Value = serde_json::from_str(&b_tx).unwrap();
    assert_eq!(tx_json["total"], 1);
    assert_eq!(tx_json["items"][0]["external_tx_id"], "fk_998877");
}
