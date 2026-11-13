use chrono::{Duration as ChronoDuration, Utc};
use poem::{
    handler,
    http::{HeaderMap, StatusCode},
    web::{Data, Form, RemoteAddr},
    Response,
};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, Set,
    TransactionTrait,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::time::Duration;
use tokio::time::sleep;
use uuid::Uuid;

use crate::entities::{
    billing_enums::{Currency, OrderStatus, PaymentSystem, ProductType, VoucherStatus},
    orders, products, transactions, users, vouchers,
};

pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        let _ = write!(&mut out, "{:02x}", b);
    }
    out
}

/// Чистая реализация RFC 2104 HMAC-SHA256 (сырые 32 байта) поверх уже подключённого крейта `sha2`
pub(crate) fn hmac_sha256_bytes(key: &[u8], data: &[u8]) -> [u8; 32] {
    const BLOCK_LEN: usize = 64;
    let mut k0 = [0u8; BLOCK_LEN];
    if key.len() > BLOCK_LEN {
        let hashed = Sha256::digest(key);
        k0[..32].copy_from_slice(&hashed);
    } else {
        k0[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0x36u8; BLOCK_LEN];
    let mut opad = [0x5cu8; BLOCK_LEN];
    for i in 0..BLOCK_LEN {
        ipad[i] ^= k0[i];
        opad[i] ^= k0[i];
    }

    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(data);
    let inner_hash = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner_hash);
    let digest = outer.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// HMAC-SHA256 в hex нижнего регистра
pub(crate) fn hmac_sha256_hex(key: &[u8], data: &[u8]) -> String {
    hex_encode(&hmac_sha256_bytes(key, data))
}

/// Чистая реализация RFC 1321 MD5 (для SCI и входящего вебхука FreeKassa)
fn md5_hex(data: &[u8]) -> String {
    const S: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
        5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
        4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
        6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];
    const K: [u32; 64] = [
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
        0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
        0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
        0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
        0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
        0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
        0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
        0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
        0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
        0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
        0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
        0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
        0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
        0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
        0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
    ];

    let orig_bit_len = (data.len() as u64).wrapping_mul(8);
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&orig_bit_len.to_le_bytes());

    let mut a0: u32 = 0x67452301;
    let mut b0: u32 = 0xefcdab89;
    let mut c0: u32 = 0x98badcfe;
    let mut d0: u32 = 0x10325476;

    for chunk in msg.chunks_exact(64) {
        let mut m = [0u32; 16];
        for (i, w) in m.iter_mut().enumerate() {
            let off = i * 4;
            *w = u32::from_le_bytes([chunk[off], chunk[off + 1], chunk[off + 2], chunk[off + 3]]);
        }

        let (mut a, mut b, mut c, mut d) = (a0, b0, c0, d0);
        for i in 0..64 {
            let (f, g) = match i {
                0..=15 => ((b & c) | ((!b) & d), i),
                16..=31 => ((d & b) | ((!d) & c), (5 * i + 1) % 16),
                32..=47 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | (!d)), (7 * i) % 16),
            };
            let temp = f
                .wrapping_add(a)
                .wrapping_add(K[i])
                .wrapping_add(m[g]);
            a = d;
            d = c;
            c = b;
            b = b.wrapping_add(temp.rotate_left(S[i]));
        }

        a0 = a0.wrapping_add(a);
        b0 = b0.wrapping_add(b);
        c0 = c0.wrapping_add(c);
        d0 = d0.wrapping_add(d);
    }

    let mut digest = [0u8; 16];
    digest[0..4].copy_from_slice(&a0.to_le_bytes());
    digest[4..8].copy_from_slice(&b0.to_le_bytes());
    digest[8..12].copy_from_slice(&c0.to_le_bytes());
    digest[12..16].copy_from_slice(&d0.to_le_bytes());
    hex_encode(&digest)
}

/// Форма входящего POST-уведомления от FreeKassa
#[derive(Deserialize, Debug)]
pub struct FkNotifyForm {
    #[serde(rename = "MERCHANT_ID")]
    pub merchant_id: String,
    #[serde(rename = "AMOUNT")]
    pub amount: String,
    #[serde(rename = "MERCHANT_ORDER_ID")]
    pub merchant_order_id: String,
    #[serde(rename = "SIGN")]
    pub sign: String,
    #[serde(default)]
    pub intid: Option<String>,
}

/// Белый список доверенных IP-адресов шлюза FreeKassa
const FK_TRUSTED_IPS: &[&str] = &[
    "168.119.157.136",
    "168.119.60.227",
    "138.201.88.124",
    "178.154.197.79",
];

fn is_trusted_proxy_peer(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => v4.is_loopback() || v4.is_private() || v4.is_link_local(),
        std::net::IpAddr::V6(v6) => v6.is_loopback() || ((v6.segments()[0] & 0xfe00) == 0xfc00),
    }
}

fn extract_client_ip(remote_addr: &RemoteAddr, headers: &HeaderMap) -> String {
    let peer_ip_opt = remote_addr.as_socket_addr().map(|s| s.ip());
    let raw_peer = peer_ip_opt.map(|ip| ip.to_string()).unwrap_or_default();

    // Если сервис запущен за локальным Nginx или внутри Docker-моста (172.16.0.0/12, 10.0.0.0/8, 127.0.0.1),
    // извлекаем реальный IP FreeKassa из заголовков, переданных прокси.
    let from_proxy = peer_ip_opt.map(is_trusted_proxy_peer).unwrap_or(true);
    if from_proxy {
        if let Some(real_ip) = headers.get("X-Real-IP").and_then(|v| v.to_str().ok()) {
            let trimmed = real_ip.trim();
            if !trimmed.is_empty() {
                return trimmed.to_string();
            }
        }
        if let Some(xff) = headers.get("X-Forwarded-For").and_then(|v| v.to_str().ok()) {
            if let Some(first) = xff.split(',').next() {
                let trimmed = first.trim();
                if !trimmed.is_empty() {
                    return trimmed.to_string();
                }
            }
        }
    }

    raw_peer
}

/// Генерация ссылки на оплату через SCI (https://pay.freekassa.ru/)
/// Строка подписи: merchant_id:amount:secret1:currency:order_id
pub fn build_sci_payment_url(
    order_id: Uuid,
    amount: f64,
    currency: Currency,
) -> Result<String, String> {
    let fk = &crate::config::get().billing.freekassa;
    if fk.shop_id.trim().is_empty() || fk.secret1.trim().is_empty() {
        return Err("FreeKassa FK_SHOP_ID / FK_SECRET1 are not configured in .env / EnvironmentFile".to_string());
    }

    let amount_str = format!("{:.2}", amount);
    let cur_str = currency.as_str();
    let sign_input = format!(
        "{}:{}:{}:{}:{}",
        fk.shop_id, amount_str, fk.secret1, cur_str, order_id
    );
    let sign = md5_hex(sign_input.as_bytes());

    let base_url = fk.pay_url.trim_end_matches('/');
    Ok(format!(
        "{}/?m={}&oa={}&currency={}&o={}&s={}",
        base_url, fk.shop_id, amount_str, cur_str, order_id, sign
    ))
}

#[derive(Deserialize, Debug)]
struct FkCreateOrderResponse {
    pub r#type: String,
    #[serde(default)]
    pub location: Option<String>,
    #[serde(default)]
    pub message: Option<String>,
}

/// Создание заказа через FreeKassa API v1 (POST /v1/orders/create) с подписью HMAC-SHA256
pub async fn create_fk_api_order(
    order_id: Uuid,
    amount: f64,
    currency: Currency,
    payment_system_id: i32,
    email: &str,
    client_ip: &str,
) -> Result<String, String> {
    let fk = &crate::config::get().billing.freekassa;
    if fk.shop_id.trim().is_empty() || fk.api_key.trim().is_empty() {
        return Err("FreeKassa FK_SHOP_ID / FK_API_KEY are not configured in .env / EnvironmentFile".to_string());
    }

    let shop_id_num = fk
        .shop_id
        .trim()
        .parse::<i64>()
        .map_err(|_| "Invalid FK_SHOP_ID (expected integer)".to_string())?;
    let nonce = Utc::now().timestamp_millis();
    let amount_str = format!("{:.2}", amount);
    let cur_str = currency.as_str();
    let order_id_str = order_id.to_string();

    // Сортировка ключей по алфавиту: amount, currency, email, i, ip, nonce, paymentId, shopId
    let mut sorted = BTreeMap::new();
    sorted.insert("amount", amount_str.clone());
    sorted.insert("currency", cur_str.to_string());
    sorted.insert("email", email.to_string());
    sorted.insert("i", payment_system_id.to_string());
    sorted.insert("ip", client_ip.to_string());
    sorted.insert("nonce", nonce.to_string());
    sorted.insert("paymentId", order_id_str.clone());
    sorted.insert("shopId", shop_id_num.to_string());

    let sign_data = sorted
        .values()
        .cloned()
        .collect::<Vec<String>>()
        .join("|");

    let signature = hmac_sha256_hex(fk.api_key.as_bytes(), sign_data.as_bytes());

    let payload = serde_json::json!({
        "shopId": shop_id_num,
        "nonce": nonce,
        "paymentId": order_id_str,
        "i": payment_system_id,
        "email": email,
        "ip": client_ip,
        "amount": amount_str,
        "currency": cur_str,
        "signature": signature
    });

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| e.to_string())?;
    let endpoint = format!("{}/orders/create", fk.api_url.trim_end_matches('/'));

    let resp = client
        .post(endpoint)
        .json(&payload)
        .send()
        .await
        .map_err(|e| format!("FreeKassa HTTP error: {}", e))?;
    let body = resp.text().await.unwrap_or_default();
    let parsed: FkCreateOrderResponse = serde_json::from_str(&body)
        .map_err(|e| format!("FreeKassa invalid JSON ({}): {}", body, e))?;

    if parsed.r#type == "success" {
        parsed
            .location
            .ok_or_else(|| "FreeKassa returned success without payment location URL".to_string())
    } else {
        Err(parsed
            .message
            .unwrap_or_else(|| format!("FreeKassa error: {}", body)))
    }
}

/// Атомарное начисление оплаченного заказа (используется и вебхуком, и фоновым крон-воркером)
pub async fn fulfill_order(
    db: &DatabaseConnection,
    order_id: Uuid,
    external_tx_id: String,
    received_amount_opt: Option<f64>,
    raw_request: serde_json::Value,
) -> Result<(), (StatusCode, String)> {
    let txn = db
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let order = orders::Entity::find_by_id(order_id)
        .one(&txn)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "Order not found".to_string()))?;

    if order.status == OrderStatus::Paid {
        log::info!(
            "[FreeKassa] Заказ {} уже был оплачен ранее. Идемпотентный пропуск",
            order.id
        );
        txn.commit()
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        return Ok(());
    }

    let received_amount = received_amount_opt.unwrap_or(order.amount);
    if (received_amount - order.amount).abs() > 0.01 {
        log::error!(
            "[FreeKassa] Несовпадение суммы! Заказ {}, ожидали {}, пришло {}",
            order.id,
            order.amount,
            received_amount
        );
        return Err((StatusCode::BAD_REQUEST, "Amount mismatch".to_string()));
    }

    let now_utc = Utc::now();

    // 1. Запись транзакции аудита (с дампом тела)
    let new_tx = transactions::ActiveModel {
        id: Set(Uuid::new_v4()),
        order_id: Set(Some(order.id)),
        payment_system: Set(PaymentSystem::FreeKassa),
        external_tx_id: Set(external_tx_id),
        amount_received: Set(received_amount),
        raw_request: Set(raw_request),
        created_at: Set(now_utc),
    };
    new_tx
        .insert(&txn)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // 2. Обновление статуса заказа
    let mut order_active: orders::ActiveModel = order.clone().into();
    order_active.status = Set(OrderStatus::Paid);
    order_active.updated_at = Set(now_utc);
    order_active
        .update(&txn)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // 3. Начисление услуги покупателю
    let product = products::Entity::find_by_id(order.product_id)
        .one(&txn)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "Product not found".to_string()))?;

    if order.is_gift {
        let gift_code = format!(
            "ANET-GIFT-{}",
            &Uuid::new_v4().to_string()[..8].to_uppercase()
        );
        let new_voucher = vouchers::ActiveModel {
            id: Set(Uuid::new_v4()),
            code: Set(gift_code),
            product_id: Set(product.id),
            buyer_user_id: Set(Some(order.user_id)),
            claimed_by_user_id: Set(None),
            status: Set(VoucherStatus::Created),
            metadata: Set(order.metadata.clone()),
            claimed_at: Set(None),
            created_at: Set(now_utc),
        };
        new_voucher
            .insert(&txn)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    } else {
        match product.product_type {
            ProductType::GroupSubscription => {
                if let Some(target_group_id) = product.target_id {
                    let user = users::Entity::find_by_id(order.user_id)
                        .one(&txn)
                        .await
                        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
                        .ok_or_else(|| (StatusCode::NOT_FOUND, "User not found".to_string()))?;

                    let mut user_active: users::ActiveModel = user.clone().into();
                    user_active.group_id = Set(Some(target_group_id));

                    // Если продление того же активного тарифа
                    if user.group_id == Some(target_group_id) && user.expires_at.is_some() {
                        let group = crate::entities::groups::Entity::find_by_id(target_group_id)
                            .one(&txn)
                            .await
                            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
                            .ok_or_else(|| (StatusCode::NOT_FOUND, "Group not found".to_string()))?;

                        let cur_exp = user.expires_at.unwrap();
                        let base = if cur_exp > now_utc { cur_exp } else { now_utc };
                        let new_exp = base + chrono::Duration::days(group.duration_days as i64);
                        user_active.expires_at = Set(Some(new_exp));
                    } else {
                        // Новый тариф: сбрасываем activated_at для Smart Activation при первом сетевом входе
                        user_active.activated_at = Set(None);
                        user_active.expires_at = Set(None);
                    }

                    user_active.updated_at = Set(now_utc.naive_utc());
                    user_active
                        .update(&txn)
                        .await
                        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
                }
            }
            ProductType::RateExtension => {
                log::info!(
                    "[FreeKassa] Rate extension applied for user {}",
                    order.user_id
                );
            }
            ProductType::Feature => {
                log::info!("[FreeKassa] Feature unlocked for user {}", order.user_id);
            }
        }
    }

    txn.commit()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    log::info!(
        "[FreeKassa] Заказ {} успешно оплачен и начислен",
        order.id
    );
    Ok(())
}

/// Обработчик входящего вебхука FreeKassa: POST /billing/freekassa/notify
#[handler]
pub async fn freekassa_notify_handler(
    remote_addr: &RemoteAddr,
    headers: &HeaderMap,
    form: Form<FkNotifyForm>,
    db: Data<&DatabaseConnection>,
) -> poem::Result<Response> {
    // 1. Проверка IP-адреса отправителя (с учетом Nginx X-Real-IP / X-Forwarded-For)
    let client_ip = extract_client_ip(remote_addr, headers);
    let is_trusted_ip = FK_TRUSTED_IPS.iter().any(|&ip| ip == client_ip);
    let allow_dev = crate::config::get().app_env == "development";

    if !is_trusted_ip && !allow_dev {
        log::warn!(
            "[FreeKassa Webhook] Отклонен запрос с недоверенного IP: {}",
            client_ip
        );
        return Err(poem::Error::from_string(
            "Forbidden IP",
            StatusCode::FORBIDDEN,
        ));
    }

    let fk = &crate::config::get().billing.freekassa;
    if fk.shop_id.trim().is_empty() || fk.secret2.trim().is_empty() {
        log::error!("[FreeKassa Webhook] Не настроены FK_SHOP_ID или FK_SECRET2 в .env / EnvironmentFile");
        return Err(poem::Error::from_string(
            "Misconfigured",
            StatusCode::INTERNAL_SERVER_ERROR,
        ));
    }

    if form.merchant_id.trim() != fk.shop_id.trim() {
        log::warn!(
            "[FreeKassa Webhook] Неверный MERCHANT_ID: got {}, expected {}",
            form.merchant_id,
            fk.shop_id
        );
        return Err(poem::Error::from_string(
            "Merchant mismatch",
            StatusCode::BAD_REQUEST,
        ));
    }

    // 2. Проверка MD5 подписи: merchant_id:amount:secret2:order_id
    // КРИТИЧЕСКИ ВАЖНО: form.amount берется строго как сырая строка!
    let sign_str = format!(
        "{}:{}:{}:{}",
        form.merchant_id, form.amount, fk.secret2, form.merchant_order_id
    );
    let expected_sign = md5_hex(sign_str.as_bytes());

    if form.sign.to_lowercase() != expected_sign {
        log::warn!(
            "[FreeKassa Webhook] Несовпадение подписи! Got: {}, expected: {}",
            form.sign,
            expected_sign
        );
        return Err(poem::Error::from_string(
            "Signature mismatch",
            StatusCode::BAD_REQUEST,
        ));
    }

    let order_uuid = Uuid::parse_str(&form.merchant_order_id)
        .map_err(|_| poem::Error::from_string("Invalid order ID", StatusCode::BAD_REQUEST))?;

    let received_amount: f64 = form
        .amount
        .parse()
        .map_err(|_| poem::Error::from_string("Invalid amount", StatusCode::BAD_REQUEST))?;

    let raw_request_json = serde_json::json!({
        "merchant_id": form.merchant_id,
        "amount": form.amount,
        "merchant_order_id": form.merchant_order_id,
        "sign": form.sign,
        "intid": form.intid,
        "client_ip": client_ip,
    });

    let external_tx_id = form
        .intid
        .clone()
        .unwrap_or_else(|| format!("fk_{}", Utc::now().timestamp()));

    fulfill_order(
        db.0,
        order_uuid,
        external_tx_id,
        Some(received_amount),
        raw_request_json,
    )
    .await
    .map_err(|(code, msg)| poem::Error::from_string(msg, code))?;

    Ok(Response::builder().status(StatusCode::OK).body("YES"))
}

// ----------------------------------------------------------------------------
// Фоновый крон-воркер сверки зависших заказов (getOrders HMAC-SHA256)
// ----------------------------------------------------------------------------

#[derive(Deserialize, Debug)]
pub struct FkOrdersApiResponse {
    pub r#type: String,
    #[serde(default)]
    pub orders: Option<Vec<FkOrderRecord>>,
    #[serde(default)]
    pub message: Option<String>,
}

#[derive(Deserialize, Debug, Serialize)]
pub struct FkOrderRecord {
    pub id: i64,
    pub merchant_order_id: String,
    pub status: i32,
    pub amount: f64,
}

pub async fn cron_sync_freekassa(db: DatabaseConnection) {
    let fk = &crate::config::get().billing.freekassa;
    let shop_id = fk.shop_id.trim().to_string();
    let api_key = fk.api_key.trim().to_string();
    let sync_interval_secs = fk.sync_interval_secs.max(30);
    let pending_threshold_mins = fk.pending_threshold_mins.max(1);

    if shop_id.is_empty() || api_key.is_empty() {
        log::warn!(
            "[FreeKassa Sync] [billing.freekassa] shop_id или api_key не заданы, воркер отключен"
        );
        return;
    }

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();
    let orders_endpoint = format!("{}/orders", fk.api_url.trim_end_matches('/'));

    loop {
        sleep(Duration::from_secs(sync_interval_secs)).await;

        let threshold = Utc::now() - ChronoDuration::minutes(pending_threshold_mins);

        let pending_orders = match orders::Entity::find()
            .filter(orders::Column::Status.eq(OrderStatus::Pending))
            .filter(orders::Column::CreatedAt.lt(threshold))
            .all(&db)
            .await
        {
            Ok(orders) => orders,
            Err(e) => {
                log::error!("[FreeKassa Sync] DB error querying pending orders: {:?}", e);
                continue;
            }
        };

        for order in pending_orders {
            let nonce = Utc::now().timestamp_millis();
            let order_id_str = order.id.to_string();

            // Сортировка по ключам: nonce, orderId, shopId -> значения через "|"
            let sign_data = format!("{}|{}|{}", nonce, order_id_str, shop_id);
            let signature = hmac_sha256_hex(api_key.as_bytes(), sign_data.as_bytes());

            let request_body = serde_json::json!({
                "shopId": shop_id.parse::<i64>().unwrap_or(0),
                "nonce": nonce,
                "orderId": order_id_str,
                "signature": signature
            });

            let resp = client.post(&orders_endpoint).json(&request_body).send().await;

            match resp {
                Ok(res) => {
                    let text = res.text().await.unwrap_or_default();
                    match serde_json::from_str::<FkOrdersApiResponse>(&text) {
                        Ok(parsed) if parsed.r#type == "success" => {
                            if let Some(records) = parsed.orders {
                                if let Some(record) = records
                                    .iter()
                                    .find(|r| r.merchant_order_id == order_id_str)
                                {
                                    if record.status == 1 {
                                        log::info!(
                                            "[FreeKassa Sync] Заказ {} подтвержден как оплаченный шлюзом",
                                            order.id
                                        );
                                        let raw_json = serde_json::to_value(record).unwrap_or_default();
                                        if let Err((code, msg)) = fulfill_order(
                                            &db,
                                            order.id,
                                            format!("fk_sync_{}", record.id),
                                            Some(record.amount),
                                            raw_json,
                                        )
                                        .await
                                        {
                                            log::error!(
                                                "[FreeKassa Sync] Ошибка начисления заказа {}: {} ({})",
                                                order.id,
                                                msg,
                                                code
                                            );
                                        }
                                    } else if record.status == 8 || record.status == 9 {
                                        log::warn!(
                                            "[FreeKassa Sync] Заказ {} отменен шлюзом (status={})",
                                            order.id,
                                            record.status
                                        );
                                        let mut active: orders::ActiveModel = order.into();
                                        active.status = Set(OrderStatus::Cancelled);
                                        active.updated_at = Set(Utc::now());
                                        let _ = active.update(&db).await;
                                    }
                                }
                            }
                        }
                        Ok(parsed) => {
                            log::error!(
                                "[FreeKassa Sync] Gateway returned non-success response: {:?}",
                                parsed.message
                            );
                        }
                        Err(e) => {
                            log::error!(
                                "[FreeKassa Sync] Deserialization failure! Body: {}. Error: {}",
                                text,
                                e
                            );
                        }
                    }
                }
                Err(e) => {
                    log::error!(
                        "[FreeKassa Sync] Network error connecting to FreeKassa API: {}",
                        e
                    );
                }
            }
        }
    }
}
