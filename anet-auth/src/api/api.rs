use crate::api::dto::{Claims, NodePoolDto, NodePoolMemberDto, RouteMapDto, RouteRuleDto};
use crate::entities::{
    node_pool_members, node_pools, node_runtime_states, route_maps, route_rules, servers,
    sessions, user_node_pools, users,
};
use crate::route_compiler::{CompiledRouteConfig, RouteRuleSpec, compile_route_map};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::{RngCore, rngs::OsRng};
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, QueryOrder};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::env;
use uuid::Uuid;

pub fn hash_node_token(token: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes()))
}

pub fn generate_node_token() -> String {
    let mut bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

pub async fn node_token_is_valid(
    db: &DatabaseConnection,
    node_id: Uuid,
    token: &str,
) -> std::result::Result<bool, sea_orm::DbErr> {
    Ok(servers::Entity::find_by_id(node_id)
        .one(db)
        .await?
        .and_then(|node| node.control_token_hash)
        .is_some_and(|expected| expected == hash_node_token(token)))
}

pub async fn validate_admin_session(
    db: &DatabaseConnection,
    token_str: &str,
) -> std::result::Result<Uuid, String> {
    let secret = env::var("JWT_SECRET").unwrap_or_else(|_| "secret_na_chushpana".to_string());

    let token_data = jsonwebtoken::decode::<Claims>(
        token_str,
        &jsonwebtoken::DecodingKey::from_secret(secret.as_bytes()),
        &jsonwebtoken::Validation::default(),
    )
        .map_err(|_| "Сломанный или протухший JWT")?;

    let jti = Uuid::parse_str(&token_data.claims.jti).map_err(|_| "Invalid JTI Format")?;

    let session_in_db = sessions::Entity::find_by_id(jti)
        .one(db)
        .await
        .map_err(|_| "Database Exception")?;

    match session_in_db {
        Some(sess) => {
            if sess.expires_at < chrono::Utc::now().naive_utc() {
                return Err("Сессия в БД истекла".to_string());
            }
            Ok(sess.admin_id)
        }
        None => Err("Отказ! Сессия отозвана".to_string()),
    }
}

pub fn cumulative_delta(previous: i64, current: i64) -> i64 {
    if current >= previous {
        current - previous
    } else {
        current
    }
}

/// Декларативный in-memory реестр живых сессий по отчётам нод:
/// `node_id -> (last_updated_instant, HashMap<fingerprint, (session_count, oldest_created_at)>)`
struct NodeLiveSnapshot {
    updated_at: std::time::Instant,
    counts: HashMap<String, (u32, u64)>,
}

static LIVE_NODE_SESSIONS: std::sync::OnceLock<std::sync::Mutex<HashMap<Uuid, NodeLiveSnapshot>>> =
    std::sync::OnceLock::new();

const LIVE_NODE_TTL: std::time::Duration = std::time::Duration::from_secs(45);

fn live_sessions_map() -> &'static std::sync::Mutex<HashMap<Uuid, NodeLiveSnapshot>> {
    LIVE_NODE_SESSIONS.get_or_init(|| std::sync::Mutex::new(HashMap::new()))
}

/// Обновляет снимок живых сессий от конкретной ноды и возвращает агрегированную сумму
/// живых сессий по всем активным нодам (ноды, молчащие > 45с, автоматически исключаются).
pub fn update_node_live_sessions(
    node_id: Uuid,
    node_counts: Vec<anet_common::dto::NodeSessionCountItem>,
) -> HashMap<String, i32> {
    let mut guard = live_sessions_map().lock().unwrap();
    let now = std::time::Instant::now();
    guard.retain(|_, snap| now.duration_since(snap.updated_at) <= LIVE_NODE_TTL);

    let mut map = HashMap::with_capacity(node_counts.len());
    for item in node_counts {
        if item.count > 0 && !item.fingerprint.is_empty() {
            map.insert(item.fingerprint, (item.count, item.oldest_created_at));
        }
    }
    guard.insert(
        node_id,
        NodeLiveSnapshot {
            updated_at: now,
            counts: map,
        },
    );

    let mut totals: HashMap<String, i32> = HashMap::new();
    for snap in guard.values() {
        for (fp, &(cnt, _)) in &snap.counts {
            *totals.entry(fp.clone()).or_insert(0) += cnt as i32;
        }
    }
    totals
}

/// Возвращает точное число живых сессий пользователя по декларативным отчётам живых нод,
/// если хотя бы одна нода присылает телеметрию.
pub fn get_live_sessions_for_fingerprint(fingerprint: &str) -> Option<i32> {
    let mut guard = live_sessions_map().lock().unwrap();
    let now = std::time::Instant::now();
    guard.retain(|_, snap| now.duration_since(snap.updated_at) <= LIVE_NODE_TTL);
    if guard.is_empty() {
        return None;
    }
    let total: u32 = guard
        .values()
        .filter_map(|snap| snap.counts.get(fingerprint).map(|&(cnt, _)| cnt))
        .sum();
    Some(total as i32)
}

/// Возвращает точное число живых сессий пользователя на конкретной ноде `node_id`,
/// если от этой ноды есть актуальный декларативный снимок (не старше 45с).
pub fn get_live_node_sessions_for_fingerprint(node_id: Uuid, fingerprint: &str) -> Option<i32> {
    let mut guard = live_sessions_map().lock().unwrap();
    let now = std::time::Instant::now();
    guard.retain(|_, snap| now.duration_since(snap.updated_at) <= LIVE_NODE_TTL);
    let snap = guard.get(&node_id)?;
    let cnt = snap.counts.get(fingerprint).map(|&(c, _)| c).unwrap_or(0);
    Some(cnt as i32)
}

/// Точечно обновляет число живых сессий одного `fingerprint` на конкретной ноде `node_id`
/// (используется при `/check_access` для мгновенной синхронизации до прихода периодического heartbeat).
pub fn set_live_node_session_for_fingerprint(node_id: Uuid, fingerprint: &str, count: u32) {
    if fingerprint.is_empty() {
        return;
    }
    let mut guard = live_sessions_map().lock().unwrap();
    let now = std::time::Instant::now();
    guard.retain(|_, snap| now.duration_since(snap.updated_at) <= LIVE_NODE_TTL);
    let snap = guard.entry(node_id).or_insert_with(|| NodeLiveSnapshot {
        updated_at: now,
        counts: HashMap::new(),
    });
    snap.updated_at = now;
    if count == 0 {
        snap.counts.remove(fingerprint);
    } else {
        let existing_oldest = snap.counts.get(fingerprint).map(|&(_, ts)| ts).unwrap_or(0);
        snap.counts
            .insert(fingerprint.to_string(), (count, existing_oldest));
    }
}

/// Очищает протухшие снимки нод (> 45с) и возвращает агрегированную карту живых сессий,
/// если реестр `LIVE_NODE_SESSIONS` уже инициализирован хотя бы одной живой нодой.
pub fn prune_stale_live_sessions() -> Option<HashMap<String, i32>> {
    let mut guard = live_sessions_map().lock().unwrap();
    let now = std::time::Instant::now();
    guard.retain(|_, snap| now.duration_since(snap.updated_at) <= LIVE_NODE_TTL);
    if guard.is_empty() {
        return None;
    }
    let mut totals: HashMap<String, i32> = HashMap::new();
    for snap in guard.values() {
        for (fp, &(cnt, _)) in &snap.counts {
            *totals.entry(fp.clone()).or_insert(0) += cnt as i32;
        }
    }
    Some(totals)
}

/// Приводит таблицу `active_sessions` в БД в точное соответствие с декларативной картой `live_totals`.
/// Для нод, которые ещё не успели прислать первый отчёт после рестарта `anet-auth`, учитывает
/// свежие записи `traffic_totals` (за последние 45с), чтобы избежать просадки счётчика на холодном старте.
pub async fn sync_active_sessions_db<C: sea_orm::ConnectionTrait>(
    db: &C,
    live_totals: &HashMap<String, i32>,
) {
    use sea_orm::{ActiveModelTrait, IntoActiveModel, Set};
    let now = chrono::Utc::now().naive_utc();

    let known_nodes: HashSet<Uuid> = {
        let guard = live_sessions_map().lock().unwrap();
        guard.keys().copied().collect()
    };

    let mut effective_totals = live_totals.clone();
    let recent_threshold = now - chrono::Duration::seconds(45);
    if let Ok(recent_totals) = crate::entities::traffic_totals::Entity::find()
        .filter(crate::entities::traffic_totals::Column::UpdatedAt.gte(recent_threshold))
        .all(db)
        .await
    {
        for row in recent_totals {
            if !known_nodes.contains(&row.server_id) && !row.fingerprint.is_empty() {
                *effective_totals.entry(row.fingerprint).or_insert(0) += 1;
            }
        }
    }

    match (
        crate::entities::active_sessions::Entity::find().all(db).await,
        users::Entity::find().all(db).await,
    ) {
        (Ok(all_active_rows), Ok(all_users)) => {
            let mut existing_by_user_id: HashMap<Uuid, crate::entities::active_sessions::Model> =
                all_active_rows
                    .into_iter()
                    .map(|r| (r.user_id, r))
                    .collect();

            for user in all_users {
                let expected = effective_totals.get(&user.fingerprint).copied().unwrap_or(0);
                if let Some(row) = existing_by_user_id.remove(&user.id) {
                    if row.sessions != expected {
                        let mut editable = row.into_active_model();
                        editable.sessions = Set(expected);
                        editable.updated_at = Set(now);
                        if let Err(e) = editable.update(db).await {
                            log::warn!("[SessionsSync] Failed to update active_sessions for user {}: {}", user.id, e);
                        }
                    }
                } else if expected > 0 {
                    let new_sess = crate::entities::active_sessions::ActiveModel {
                        id: Set(Uuid::new_v4()),
                        user_id: Set(user.id),
                        sessions: Set(expected),
                        created_at: Set(now),
                        updated_at: Set(now),
                    };
                    if let Err(e) = new_sess.insert(db).await {
                        log::warn!("[SessionsSync] Failed to insert active_sessions for user {}: {}", user.id, e);
                    }
                }
            }

            // На случай осиротевших строк в active_sessions — обнуляем их
            for (_, orphan_row) in existing_by_user_id {
                if orphan_row.sessions != 0 {
                    let mut editable = orphan_row.into_active_model();
                    editable.sessions = Set(0);
                    editable.updated_at = Set(now);
                    let _ = editable.update(db).await;
                }
            }
        }
        (Err(e), _) | (_, Err(e)) => {
            log::warn!("[SessionsSync] Failed to query active_sessions/users for sync: {}", e);
        }
    }
}

pub async fn user_pool_ids(db: &DatabaseConnection, user_id: Uuid) -> Vec<Uuid> {
    user_node_pools::Entity::find()
        .filter(user_node_pools::Column::UserId.eq(user_id))
        .all(db)
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|link| link.pool_id)
        .collect()
}

pub async fn user_route_map_id(db: &DatabaseConnection, user_id: Uuid) -> Option<Uuid> {
    users::Entity::find_by_id(user_id)
        .one(db)
        .await
        .ok()
        .flatten()
        .and_then(|user| user.route_map_id)
}

pub async fn load_pool_dto(
    db: &DatabaseConnection,
    pool: node_pools::Model,
) -> std::result::Result<NodePoolDto, sea_orm::DbErr> {
    let members = node_pool_members::Entity::find()
        .filter(node_pool_members::Column::PoolId.eq(pool.id))
        .all(db)
        .await?
        .into_iter()
        .map(|member| NodePoolMemberDto {
            server_id: member.server_id,
            protocol: member.protocol,
            port_or_url: member.port_or_url,
            wrtc_mode: member.wrtc_mode,
            doh_mode: member.doh_mode,
            weight: member.weight.max(1) as i32,
        })
        .collect();
    Ok(NodePoolDto {
        id: pool.id,
        name: pool.name,
        strategy: pool.strategy,
        is_active: pool.is_active,
        members,
    })
}

pub async fn load_route_map_dto(
    db: &DatabaseConnection,
    map: route_maps::Model,
) -> std::result::Result<RouteMapDto, sea_orm::DbErr> {
    let rules = route_rules::Entity::find()
        .filter(route_rules::Column::RouteMapId.eq(map.id))
        .order_by_asc(route_rules::Column::Position)
        .all(db)
        .await?
        .into_iter()
        .map(|rule| RouteRuleDto {
            id: Some(rule.id),
            position: rule.position.max(0) as i32,
            match_type: rule.match_type,
            match_value: rule.match_value,
            action: rule.action,
        })
        .collect();
    Ok(RouteMapDto {
        id: map.id,
        name: map.name,
        description: map.description,
        default_action: map.default_action,
        is_active: map.is_active,
        revision: map.revision.max(0) as i64,
        rules,
    })
}

pub async fn resolve_client_servers(
    db: &DatabaseConnection,
    user_id: Uuid,
    direct_servers: Vec<servers::Model>,
) -> std::result::Result<Vec<servers::Model>, sea_orm::DbErr> {
    let links = user_node_pools::Entity::find()
        .filter(user_node_pools::Column::UserId.eq(user_id))
        .order_by_asc(user_node_pools::Column::PoolId)
        .all(db)
        .await?;
    let mut resolved = Vec::new();
    let mut included = HashSet::new();
    let now = chrono::Utc::now().naive_utc();

    for link in links {
        let Some(pool) = node_pools::Entity::find_by_id(link.pool_id).one(db).await? else {
            continue;
        };
        if !pool.is_active {
            continue;
        }
        let members = node_pool_members::Entity::find()
            .filter(node_pool_members::Column::PoolId.eq(pool.id))
            .all(db)
            .await?;
        let member_ids: Vec<_> = members.iter().map(|member| member.server_id).collect();
        if member_ids.is_empty() {
            continue;
        }
        let pool_servers = servers::Entity::find()
            .filter(servers::Column::Id.is_in(member_ids.clone()))
            .all(db)
            .await?;
        let runtime_by_id: HashMap<_, _> = node_runtime_states::Entity::find()
            .filter(node_runtime_states::Column::ServerId.is_in(member_ids))
            .all(db)
            .await?
            .into_iter()
            .map(|runtime| (runtime.server_id, runtime))
            .collect();
        let weight_by_id: HashMap<_, _> = members
            .into_iter()
            .map(|member| (member.server_id, member.weight.max(1) as i32))
            .collect();
        let mut server_by_id: HashMap<_, _> = pool_servers
            .into_iter()
            .filter(|server| server.is_active)
            .filter(|server| {
                runtime_by_id.get(&server.id).is_some_and(|runtime| {
                    runtime.accepting_connections
                        && now
                        .signed_duration_since(runtime.last_seen_at)
                        .num_seconds()
                        <= 45
                })
            })
            .map(|server| (server.id, server))
            .collect();
        let mut candidates: Vec<_> = server_by_id
            .keys()
            .map(|server_id| crate::balancer::BalanceCandidate {
                server_id: *server_id,
                weight: weight_by_id.get(server_id).copied().unwrap_or(1).max(1) as u32,
                active_connections: runtime_by_id
                    .get(server_id)
                    .map(|runtime| runtime.active_connections.max(0) as u64)
                    .unwrap_or_default(),
            })
            .collect();
        crate::balancer::order_candidates(&pool.strategy, user_id, pool.id, &mut candidates);
        for candidate in candidates {
            if included.insert(candidate.server_id) {
                if let Some(server) = server_by_id.remove(&candidate.server_id) {
                    resolved.push(server);
                }
            }
        }
    }

    for server in direct_servers {
        if server.is_active && included.insert(server.id) {
            resolved.push(server);
        }
    }
    Ok(resolved)
}

pub async fn compiled_routes_for_user(
    db: &DatabaseConnection,
    user_id: Uuid,
) -> std::result::Result<Option<CompiledRouteConfig>, String> {
    let Some(user) = users::Entity::find_by_id(user_id)
        .one(db)
        .await
        .map_err(|e| e.to_string())?
    else {
        return Ok(None);
    };
    let Some(route_map_id) = user.route_map_id else {
        return Ok(None);
    };
    let Some(map) = route_maps::Entity::find_by_id(route_map_id)
        .one(db)
        .await
        .map_err(|e| e.to_string())?
    else {
        return Ok(None);
    };
    if !map.is_active {
        return Ok(None);
    }
    let rules = route_rules::Entity::find()
        .filter(route_rules::Column::RouteMapId.eq(map.id))
        .order_by_asc(route_rules::Column::Position)
        .all(db)
        .await
        .map_err(|e| e.to_string())?;
    let specs: Vec<_> = rules
        .into_iter()
        .map(|rule| RouteRuleSpec {
            match_type: rule.match_type,
            match_value: rule.match_value,
            action: rule.action,
        })
        .collect();
    compile_route_map(&map.default_action, &specs).map(Some)
}

pub fn get_qr_html_page(config_url: &str, user_name: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ANet VPN Connection</title>
    <style>
        body {{
            background-color: #050505;
            color: #e2e8f0;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
            margin: 0;
            padding: 16px;
            box-sizing: border-box;
        }}
        .card {{
            background: #0a0a0a;
            border: 1px solid #1f1f23;
            border-radius: 12px;
            padding: 32px;
            text-align: center;
            max-width: 420px;
            width: 100%;
            box-shadow: 0 8px 32px rgba(0,0,0,0.5);
        }}
        h1 {{
            color: #18a058;
            font-size: 24px;
            margin-top: 0;
            margin-bottom: 8px;
            font-family: monospace;
            letter-spacing: 0.5px;
        }}
        p {{
            color: #94a3b8;
            font-size: 14px;
            line-height: 1.5;
            margin-bottom: 24px;
        }}
        .qr-container {{
            background: white;
            padding: 16px;
            border-radius: 8px;
            display: inline-block;
            margin-bottom: 24px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.1);
        }}
        .qr-container img {{
            display: block;
            width: 200px;
            height: 200px;
        }}
        .btn {{
            display: block;
            background-color: #18a058;
            color: white;
            text-decoration: none;
            padding: 12px 24px;
            border-radius: 6px;
            font-weight: 600;
            font-size: 15px;
            transition: background-color 0.15s ease-in-out;
            margin-bottom: 16px;
            border: none;
            cursor: pointer;
            width: 100%;
            box-sizing: border-box;
        }}
        .btn:hover {{
            background-color: #148043;
        }}
        .input-group {{
            display: flex;
            background: #121214;
            border: 1px solid #1f1f23;
            border-radius: 6px;
            padding: 4px;
            margin-top: 16px;
        }}
        .input-group input {{
            flex: 1;
            background: transparent;
            border: none;
            color: #cbd5e1;
            font-family: monospace;
            font-size: 12px;
            padding: 8px;
            outline: none;
            width: 100%;
        }}
        .btn-copy {{
            background: #222;
            border: 1px solid #333;
            color: #cbd5e1;
            padding: 6px 12px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 12px;
            transition: all 0.1s;
        }}
        .btn-copy:hover {{
            background: #333;
            color: white;
        }}
    </style>
</head>
<body>
    <div class="card">
        <h1>ANet VPN for {user_name}</h1>
        <p>Отсканируй QR-код приложением ANet, или скачай файл конфигурации прямо на свой компьютер.</p>

        <div class="qr-container">
            <img src="https://api.qrserver.com/v1/create-qr-code/?size=200x200&data={config_url}" alt="Config QR" />
        </div>

        <a href="{config_url}" class="btn">Download client.toml</a>

        <div class="input-group">
            <input type="text" readonly id="link-input" value="{config_url}" />
            <button class="btn-copy" onclick="copyLink()">Copy</button>
        </div>
    </div>
    <script>
        function copyLink() {{
            var copyText = document.getElementById("link-input");
            copyText.select();
            copyText.setSelectionRange(0, 99999);
            navigator.clipboard.writeText(copyText.value);

            var btn = document.querySelector(".btn-copy");
            btn.textContent = "Copied!";
            setTimeout(function() {{
                btn.textContent = "Copy";
            }}, 2000);
        }}
    </script>
</body>
</html>"#,
        config_url = config_url
    )
}
