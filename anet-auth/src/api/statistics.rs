use crate::api::api::{cumulative_delta, validate_admin_session};
use crate::api::dto::{
    ActiveConnectionDto, AdminToken, GetNodeTrafficStatsResponse, GetTrafficHistoryResponse,
    GetUserTrafficStatsResponse, NodeTrafficReport, TrafficHistoryPointDto, TrafficReportResponse,
    UserTrafficStatDto, NodeTrafficStatDto,
};
use crate::entities::{servers, traffic_hourly, traffic_totals, users};
use chrono::{NaiveDateTime, Timelike};
use poem_openapi::{param::Query, payload::Json, OpenApi};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, IntoActiveModel, Set,
    QueryFilter, QueryOrder, TransactionTrait,
};
use std::collections::HashMap;
use uuid::Uuid;

pub struct StatisticsApi {
    pub db: DatabaseConnection,
}

#[OpenApi]
impl StatisticsApi {
    /// Принять накопительные счётчики полезного VPN-трафика от ноды
    #[oai(path = "/control/nodes/traffic", method = "post")]
    async fn report_node_traffic(
        &self,
        #[oai(name = "X-Node-Token")] node_token: poem_openapi::param::Header<String>,
        req: Json<NodeTrafficReport>,
    ) -> TrafficReportResponse {
        let node_id = match Uuid::parse_str(&req.0.node_id) {
            Ok(id) => id,
            Err(_) => {
                return TrafficReportResponse::BadRequest(Json("Invalid node_id".to_string()));
            }
        };
        match crate::api::api::node_token_is_valid(&self.db, node_id, &node_token.0).await {
            Ok(true) => {}
            Ok(false) => {
                return TrafficReportResponse::Unauthorized(Json(
                    "Invalid node credential".to_string(),
                ));
            }
            Err(e) => return TrafficReportResponse::Error(Json(e.to_string())),
        }
        if req.0.boot_id.is_empty() || req.0.boot_id.len() > 128 || req.0.samples.len() > 10_000 {
            return TrafficReportResponse::BadRequest(Json("Invalid traffic report".to_string()));
        }
        match servers::Entity::find_by_id(node_id).one(&self.db).await {
            Ok(Some(_)) => {}
            Ok(None) => return TrafficReportResponse::NotFound(Json("Node not found".to_string())),
            Err(e) => return TrafficReportResponse::Error(Json(e.to_string())),
        }

        let txn = match self.db.begin().await {
            Ok(txn) => txn,
            Err(e) => return TrafficReportResponse::Error(Json(e.to_string())),
        };
        let now = chrono::Utc::now().naive_utc();

        let minute = (now.minute() / 15) * 15;
        let bucket_start = now
            .date()
            .and_hms_opt(now.hour(), minute, 0)
            .expect("valid bucket");

        for sample in req.0.samples {
            if sample.fingerprint.is_empty() {
                return TrafficReportResponse::BadRequest(Json("Empty fingerprint".to_string()));
            }

            let raw_proto = sample.protocol.clone().unwrap_or_else(|| "quic".to_string());
            let protocol = crate::entities::ProtocolType::from_str(&raw_proto);

            let user_id = match sample.user_id {
                Some(id) => match Uuid::parse_str(&id) {
                    Ok(id) => Some(id),
                    Err(_) => {
                        return TrafficReportResponse::BadRequest(Json(
                            "Invalid user_id".to_string(),
                        ));
                    }
                },
                None => None,
            };
            let rx_bytes = sample.rx_bytes.min(u64::MAX) as i64;
            let tx_bytes = sample.tx_bytes.min(u64::MAX) as i64;

            let existing = match traffic_totals::Entity::find()
                .filter(traffic_totals::Column::ServerId.eq(node_id))
                .filter(traffic_totals::Column::BootId.eq(&req.0.boot_id))
                .filter(traffic_totals::Column::Fingerprint.eq(&sample.fingerprint))
                .filter(traffic_totals::Column::Protocol.eq(protocol))
                .one(&txn)
                .await
            {
                Ok(existing) => existing,
                Err(e) => return TrafficReportResponse::Error(Json(e.to_string())),
            };

            let (rx_delta, tx_delta, total_result) = if let Some(existing) = existing {
                let rx_delta = cumulative_delta(existing.rx_bytes, rx_bytes);
                let tx_delta = cumulative_delta(existing.tx_bytes, tx_bytes);
                let mut total = existing.into_active_model();
                total.rx_bytes = Set(rx_bytes as i64);
                total.tx_bytes = Set(tx_bytes as i64);
                total.user_id = Set(user_id);
                total.updated_at = Set(now);
                (rx_delta, tx_delta, total.update(&txn).await.map(|_| ()))
            } else {
                let result = traffic_totals::ActiveModel {
                    id: Set(Uuid::new_v4()),
                    server_id: Set(node_id),
                    boot_id: Set(req.0.boot_id.clone()),
                    user_id: Set(user_id),
                    fingerprint: Set(sample.fingerprint.clone()),
                    rx_bytes: Set(rx_bytes),
                    tx_bytes: Set(tx_bytes),
                    protocol: Set(protocol),
                    updated_at: Set(now),
                }
                    .insert(&txn)
                    .await
                    .map(|_| ());
                (rx_bytes, tx_bytes, result)
            };
            if let Err(e) = total_result {
                return TrafficReportResponse::Error(Json(e.to_string()));
            }

            if rx_delta == 0 && tx_delta == 0 {
                continue;
            }
            let hourly = match traffic_hourly::Entity::find()
                .filter(traffic_hourly::Column::BucketStart.eq(bucket_start))
                .filter(traffic_hourly::Column::ServerId.eq(node_id))
                .filter(traffic_hourly::Column::Fingerprint.eq(&sample.fingerprint))
                .filter(traffic_hourly::Column::Protocol.eq(protocol))
                .one(&txn)
                .await
            {
                Ok(hourly) => hourly,
                Err(e) => return TrafficReportResponse::Error(Json(e.to_string())),
            };
            let hourly_result = if let Some(hourly) = hourly {
                let mut aggregate = hourly.into_active_model();
                aggregate.rx_bytes = Set(aggregate.rx_bytes.as_ref().saturating_add(rx_delta));
                aggregate.tx_bytes = Set(aggregate.tx_bytes.as_ref().saturating_add(tx_delta));
                aggregate.user_id = Set(user_id);
                aggregate.updated_at = Set(now);
                aggregate.update(&txn).await.map(|_| ())
            } else {
                traffic_hourly::ActiveModel {
                    id: Set(Uuid::new_v4()),
                    bucket_start: Set(bucket_start),
                    server_id: Set(node_id),
                    user_id: Set(user_id),
                    fingerprint: Set(sample.fingerprint),
                    rx_bytes: Set(rx_delta),
                    tx_bytes: Set(tx_delta),
                    protocol: Set(protocol),
                    updated_at: Set(now),
                }
                    .insert(&txn)
                    .await
                    .map(|_| ())
            };
            if let Err(e) = hourly_result {
                return TrafficReportResponse::Error(Json(e.to_string()));
            }
        }
        match txn.commit().await {
            Ok(()) => TrafficReportResponse::Accepted,
            Err(e) => TrafficReportResponse::Error(Json(e.to_string())),
        }
    }

    /// Суммарная статистика потребления трафика нодами
    #[oai(path = "/statistics/nodes", method = "get")]
    async fn get_node_traffic_stats(&self, auth: AdminToken) -> GetNodeTrafficStatsResponse {
        if let Err(err) = validate_admin_session(&self.db, &auth.0.token).await {
            return GetNodeTrafficStatsResponse::Unauthorized(Json(err));
        }
        let nodes = match servers::Entity::find().all(&self.db).await {
            Ok(nodes) => nodes,
            Err(e) => return GetNodeTrafficStatsResponse::Error(Json(e.to_string())),
        };
        let totals = match traffic_totals::Entity::find().all(&self.db).await {
            Ok(totals) => totals,
            Err(e) => return GetNodeTrafficStatsResponse::Error(Json(e.to_string())),
        };
        let mut aggregate: HashMap<Uuid, (i64, i64)> = HashMap::new();
        for total in totals {
            let entry = aggregate.entry(total.server_id).or_default();
            entry.0 = entry.0.saturating_add(total.rx_bytes.max(0) as i64);
            entry.1 = entry.1.saturating_add(total.tx_bytes.max(0) as i64);
        }
        GetNodeTrafficStatsResponse::Ok(Json(
            nodes
                .into_iter()
                .map(|node| {
                    let (rx_bytes, tx_bytes) = aggregate.get(&node.id).copied().unwrap_or_default();
                    NodeTrafficStatDto {
                        node_id: node.id,
                        name: node.name,
                        rx_bytes,
                        tx_bytes,
                    }
                })
                .collect(),
        ))
    }

    /// Суммарная статистика трафика в разрезе пользователей
    #[oai(path = "/statistics/users", method = "get")]
    async fn get_user_traffic_stats(&self, auth: AdminToken) -> GetUserTrafficStatsResponse {
        if let Err(err) = validate_admin_session(&self.db, &auth.0.token).await {
            return GetUserTrafficStatsResponse::Unauthorized(Json(err));
        }
        let user_models = match users::Entity::find().all(&self.db).await {
            Ok(users) => users,
            Err(e) => return GetUserTrafficStatsResponse::Error(Json(e.to_string())),
        };
        let users_by_id: HashMap<Uuid, users::Model> =
            user_models.into_iter().map(|u| (u.id, u)).collect();
        let totals = match traffic_totals::Entity::find().all(&self.db).await {
            Ok(totals) => totals,
            Err(e) => return GetUserTrafficStatsResponse::Error(Json(e.to_string())),
        };
        let mut aggregate: HashMap<String, UserTrafficStatDto> = HashMap::new();
        for total in totals {
            let entry = aggregate.entry(total.fingerprint.clone()).or_insert_with(|| {
                let user = total.user_id.and_then(|id| users_by_id.get(&id));
                UserTrafficStatDto {
                    user_id: total.user_id,
                    uid: user.and_then(|u| u.uid.clone()),
                    fingerprint: total.fingerprint.clone(),
                    rx_bytes: 0,
                    tx_bytes: 0,
                }
            });
            entry.rx_bytes = entry.rx_bytes.saturating_add(total.rx_bytes.max(0) as i64);
            entry.tx_bytes = entry.tx_bytes.saturating_add(total.tx_bytes.max(0) as i64);
        }
        let mut stats: Vec<_> = aggregate.into_values().collect();
        stats.sort_by_key(|item| std::cmp::Reverse(item.rx_bytes.saturating_add(item.tx_bytes)));
        GetUserTrafficStatsResponse::Ok(Json(stats))
    }

    /// График истории трафика по 15-минутным бакетам
    #[oai(path = "/statistics/traffic/history", method = "get")]
    async fn get_traffic_history(
        &self,
        auth: AdminToken,
        hours: Query<Option<u32>>,
        server_id: Query<Option<Uuid>>,
        user_id: Query<Option<Uuid>>,
        fingerprint: Query<Option<String>>,
        protocol: Query<Option<String>>,
    ) -> GetTrafficHistoryResponse {
        if let Err(err) = validate_admin_session(&self.db, &auth.0.token).await {
            return GetTrafficHistoryResponse::Unauthorized(Json(err));
        }
        let hours = hours.0.unwrap_or(24).clamp(1, 24 * 90);
        let now = chrono::Utc::now().naive_utc();

        let step_minutes = 15;
        let total_steps = (hours * 60) / step_minutes;

        let current_minute = (now.minute() / step_minutes) * step_minutes;
        let current_bucket = now
            .date()
            .and_hms_opt(now.hour(), current_minute, 0)
            .expect("valid hour");

        let first_bucket = current_bucket
            - chrono::Duration::minutes((total_steps - 1) as i64 * step_minutes as i64);

        let mut query = traffic_hourly::Entity::find()
            .filter(traffic_hourly::Column::BucketStart.gte(first_bucket));

        if let Some(srv_id) = server_id.0 {
            query = query.filter(traffic_hourly::Column::ServerId.eq(srv_id));
        }
        if let Some(usr_id) = user_id.0 {
            query = query.filter(traffic_hourly::Column::UserId.eq(usr_id));
        }
        if let Some(ref fp) = fingerprint.0 {
            if !fp.trim().is_empty() {
                query = query.filter(traffic_hourly::Column::Fingerprint.eq(fp));
            }
        }
        if let Some(ref proto) = protocol.0 {
            if !proto.trim().is_empty() {
                let db_proto = crate::entities::ProtocolType::from_str(proto);
                query = query.filter(traffic_hourly::Column::Protocol.eq(db_proto));
            }
        }

        let rows = match query
            .order_by_asc(traffic_hourly::Column::BucketStart)
            .all(&self.db)
            .await
        {
            Ok(rows) => rows,
            Err(e) => return GetTrafficHistoryResponse::Error(Json(e.to_string())),
        };

        let mut aggregate: HashMap<NaiveDateTime, (i64, i64)> = HashMap::new();
        for row in rows {
            let entry = aggregate.entry(row.bucket_start).or_default();
            entry.0 = entry.0.saturating_add(row.rx_bytes.max(0) as i64);
            entry.1 = entry.1.saturating_add(row.tx_bytes.max(0) as i64);
        }

        let points = (0..total_steps)
            .map(|offset| {
                let bucket = first_bucket
                    + chrono::Duration::minutes(offset as i64 * step_minutes as i64);
                let (rx_bytes, tx_bytes) = aggregate.get(&bucket).copied().unwrap_or_default();
                TrafficHistoryPointDto {
                    bucket_start: bucket.and_utc().to_rfc3339(),
                    rx_bytes,
                    tx_bytes,
                }
            })
            .collect();

        GetTrafficHistoryResponse::Ok(Json(points))
    }

    /// Активные соединения (sessions) в реальном времени
    #[oai(path = "/statistics/active-connections", method = "get")]
    async fn get_active_connections(
        &self,
        auth: AdminToken,
    ) -> Result<Json<Vec<ActiveConnectionDto>>, poem::Error> {
        if let Err(err) = validate_admin_session(&self.db, &auth.0.token).await {
            return Err(poem::Error::from_string(
                err,
                poem::http::StatusCode::UNAUTHORIZED,
            ));
        }

        let now = chrono::Utc::now().naive_utc();
        let threshold = now - chrono::Duration::seconds(90);

        let mut active_totals = crate::entities::traffic_totals::Entity::find()
            .filter(crate::entities::traffic_totals::Column::UpdatedAt.gte(threshold))
            .all(&self.db)
            .await
            .map_err(poem::error::InternalServerError)?;

        active_totals.sort_by(|a, b| b.updated_at.cmp(&a.updated_at));

        let mut user_connection_limits: HashMap<Uuid, i32> = HashMap::new();
        let mut added_user_counts: HashMap<Uuid, i32> = HashMap::new();
        let mut dtos = Vec::new();

        for total in active_totals {
            let Some(user_id) = total.user_id else {
                continue;
            };

            let max_allowed_connections =
                if let Some(&count) = user_connection_limits.get(&user_id) {
                    count
                } else {
                    let sessions_in_db = crate::entities::active_sessions::Entity::find()
                        .filter(crate::entities::active_sessions::Column::UserId.eq(user_id))
                        .one(&self.db)
                        .await
                        .map_err(poem::error::InternalServerError)?
                        .map(|s| s.sessions)
                        .unwrap_or(1) as i32;

                    let limit = sessions_in_db.max(1);
                    user_connection_limits.insert(user_id, limit);
                    limit
                };

            let already_added = added_user_counts.entry(user_id).or_insert(0);

            if *already_added >= max_allowed_connections {
                continue;
            }

            *already_added += 1;

            let username = crate::entities::users::Entity::find_by_id(user_id)
                .one(&self.db)
                .await
                .map_err(poem::error::InternalServerError)?
                .and_then(|u| u.uid)
                .unwrap_or_else(|| "Unknown".to_string());

            let server_name = crate::entities::servers::Entity::find_by_id(total.server_id)
                .one(&self.db)
                .await
                .map_err(poem::error::InternalServerError)?
                .map(|s| s.name)
                .unwrap_or_else(|| "Unknown Server".to_string());

            dtos.push(ActiveConnectionDto {
                user_id,
                username,
                server_id: total.server_id,
                server_name,
                rx_bytes: total.rx_bytes.max(0) as i64,
                tx_bytes: total.tx_bytes.max(0) as i64,
                connection_count: max_allowed_connections,
                protocol: total.protocol.as_str().to_string(),
            });
        }

        Ok(Json(dtos))
    }
}
