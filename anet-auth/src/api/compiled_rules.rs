//! Публичный API-эндпоинт для выдачи скомпилированных правил .abc (Zero-Copy кэш).
//! Аутентификация не требуется. Поддерживается валидация по ETag (304 Not Modified).

use anet_filter_core::{RoutingCacheCompiler, RuleAction};
use poem_openapi::{
    param::Header, param::Path, payload::Binary, payload::PlainText, ApiResponse, OpenApi,
};
use sea_orm::{ColumnTrait, Condition, DatabaseConnection, EntityTrait, QueryFilter};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::entities::{admin_custom_overrides, route_maps, route_rules};

#[derive(ApiResponse)]
pub enum CompiledRulesResponse {
    #[oai(status = 200, content_type = "application/octet-stream")]
    Ok(
        Binary<Vec<u8>>,
        #[oai(header = "ETag")] String,
    ),
    #[oai(status = 304)]
    NotModified,
    #[oai(status = 404)]
    NotFound(PlainText<String>),
    #[oai(status = 500)]
    Error(PlainText<String>),
}

pub struct CompiledRulesApi {
    pub db: DatabaseConnection,
}

impl CompiledRulesApi {
    async fn compile_and_serve(
        &self,
        route_map_id: Option<Uuid>,
        if_none_match: Option<String>,
    ) -> CompiledRulesResponse {
        let default_action = if let Some(map_id) = route_map_id {
            match route_maps::Entity::find_by_id(map_id).one(&self.db).await {
                Ok(Some(map)) => RuleAction::from_str_loose(&map.default_action).unwrap_or(RuleAction::Proxy),
                Ok(None) => return CompiledRulesResponse::NotFound(PlainText("Route map not found".to_string())),
                Err(e) => return CompiledRulesResponse::Error(PlainText(e.to_string())),
            }
        } else {
            RuleAction::Proxy
        };

        let mut compiler = RoutingCacheCompiler::new(default_action);

        // Загружаем правила из route_rules
        if let Some(map_id) = route_map_id {
            if let Ok(rules) = route_rules::Entity::find()
                .filter(route_rules::Column::RouteMapId.eq(map_id))
                .all(&self.db)
                .await
            {
                for rule in rules {
                    let action = RuleAction::from_str_loose(&rule.action).unwrap_or(RuleAction::Direct);
                    match rule.match_type.as_str() {
                        "cidr" | "ip" => {
                            let _ = compiler.add_provider_ips(&rule.match_value, action);
                        }
                        "domain" => {
                            compiler.add_admin_domain_override(&rule.match_value, action);
                        }
                        _ => {}
                    }
                }
            }
        }

        // Загружаем административные исключения (admin_custom_overrides)
        let mut override_query = admin_custom_overrides::Entity::find()
            .filter(admin_custom_overrides::Column::IsActive.eq(true));

        if let Some(map_id) = route_map_id {
            let condition = Condition::any()
                .add(admin_custom_overrides::Column::RouteMapId.eq(map_id))
                .add(admin_custom_overrides::Column::RouteMapId.is_null());
            override_query = override_query.filter(condition);
        } else {
            override_query = override_query.filter(admin_custom_overrides::Column::RouteMapId.is_null());
        }

        if let Ok(overrides) = override_query.all(&self.db).await {
            for ov in overrides {
                let action = match ov.category.as_str() {
                    "custom_block" | "block" => RuleAction::Block,
                    "custom_direct" | "direct" => RuleAction::Direct,
                    _ => RuleAction::Proxy,
                };

                match ov.rule_type.as_str() {
                    "cidr" | "ip" => compiler.add_admin_ip_override(&ov.pattern, action),
                    _ => compiler.add_admin_domain_override(&ov.pattern, action),
                }
            }
        }

        // Компилируем в бинарный формат .abc
        let bytes = match compiler.compile_to_bytes() {
            Ok(b) => b,
            Err(e) => return CompiledRulesResponse::Error(PlainText(format!("Compilation error: {e}"))),
        };

        // Считаем SHA-256 хэш как ETag
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        let etag = format!("\"{:x}\"", hasher.finalize());

        // Проверяем If-None-Match
        if let Some(client_etag) = if_none_match {
            if client_etag.trim() == etag {
                return CompiledRulesResponse::NotModified;
            }
        }

        CompiledRulesResponse::Ok(Binary(bytes), etag)
    }
}

#[OpenApi]
impl CompiledRulesApi {
    /// Получение скомпилированных правил (.abc) по умолчанию
    #[oai(path = "/routing/compiled-rules", method = "get")]
    async fn get_default_compiled_rules(
        &self,
        #[oai(name = "If-None-Match")] if_none_match: Header<Option<String>>,
    ) -> CompiledRulesResponse {
        self.compile_and_serve(None, if_none_match.0).await
    }

    /// Получение скомпилированных правил (.abc) для конкретного профиля
    #[oai(path = "/routing/compiled-rules/:route_map_id", method = "get")]
    async fn get_compiled_rules_by_id(
        &self,
        route_map_id: Path<Uuid>,
        #[oai(name = "If-None-Match")] if_none_match: Header<Option<String>>,
    ) -> CompiledRulesResponse {
        self.compile_and_serve(Some(route_map_id.0), if_none_match.0).await
    }
}
