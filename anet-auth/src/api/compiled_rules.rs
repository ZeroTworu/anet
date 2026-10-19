//! Публичный API-эндпоинт для выдачи скомпилированных правил .abc (Zero-Copy кэш).
//! Аутентификация не требуется. Поддерживается валидация по ETag (304 Not Modified)
//! и серверное кэширование скомпилированных бинарных артефактов в памяти.

use anet_filter_core::{RoutingCacheCompiler, RuleAction};
use poem_openapi::{
    param::Header, param::Path, payload::Binary, payload::PlainText, ApiResponse, OpenApi,
};
use sea_orm::{ColumnTrait, Condition, DatabaseConnection, EntityTrait, QueryFilter, QueryOrder};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::compiler_worker::{
    get_cached_abc, get_provider_cache_dir, put_cached_abc, CachedAbcArtifact,
};
use crate::entities::admin_custom_overrides::{self, OverrideType};
use crate::entities::route_rules::RouteMatchKind;
use crate::entities::{route_maps, route_rules, rule_provider_items, rule_providers};

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
    async fn load_provider_into_compiler(
        &self,
        compiler: &mut RoutingCacheCompiler,
        provider: &rule_providers::Model,
        action: RuleAction,
    ) {
        let items = rule_provider_items::Entity::find()
            .filter(rule_provider_items::Column::ProviderId.eq(provider.id))
            .order_by_asc(rule_provider_items::Column::Id)
            .all(&self.db)
            .await
            .unwrap_or_default();

        if !items.is_empty() {
            let values = items.into_iter().map(|i| i.rule_value);
            match provider.provider_type {
                rule_providers::ProviderType::DomainList => {
                    compiler.add_provider_domain_items(values, action);
                }
                rule_providers::ProviderType::IpList => {
                    compiler.add_provider_ip_items(values, action);
                }
            }
        } else {
            // Резервное чтение с диска, если таблица rule_provider_items ещё не заполнена
            let file_path = get_provider_cache_dir().join(format!("{}.txt", provider.id));
            if let Ok(content) = std::fs::read_to_string(file_path) {
                match provider.provider_type {
                    rule_providers::ProviderType::DomainList => {
                        compiler.add_provider_domains(&content, action);
                    }
                    rule_providers::ProviderType::IpList => {
                        compiler.add_provider_ips(&content, action);
                    }
                }
            }
        }
    }

    async fn compile_and_serve(
        &self,
        route_map_id: Option<Uuid>,
        if_none_match: Option<String>,
    ) -> CompiledRulesResponse {
        // 0. Проверяем скомпилированный in-memory кэш .abc
        if let Some(cached) = get_cached_abc(route_map_id) {
            if let Some(client_etag) = &if_none_match {
                if client_etag.trim() == cached.etag {
                    return CompiledRulesResponse::NotModified;
                }
            }
            return CompiledRulesResponse::Ok(Binary(cached.bytes), cached.etag);
        }

        let default_action = if let Some(map_id) = route_map_id {
            match route_maps::Entity::find_by_id(map_id).one(&self.db).await {
                Ok(Some(map)) => {
                    RuleAction::from_str_loose(&map.default_action).unwrap_or(RuleAction::Proxy)
                }
                Ok(None) => {
                    return CompiledRulesResponse::NotFound(PlainText(
                        "Route map not found".to_string(),
                    ))
                }
                Err(e) => return CompiledRulesResponse::Error(PlainText(e.to_string())),
            }
        } else {
            RuleAction::Proxy
        };

        let mut compiler = RoutingCacheCompiler::new(default_action);

        // 1. Загружаем все активные провайдеры правил (глобальные + привязанные к route_map_id)
        let mut provider_query = rule_providers::Entity::find()
            .filter(rule_providers::Column::IsActive.eq(true));

        if let Some(map_id) = route_map_id {
            let cond = Condition::any()
                .add(rule_providers::Column::RouteMapId.eq(map_id))
                .add(rule_providers::Column::RouteMapId.is_null());
            provider_query = provider_query.filter(cond);
        } else {
            provider_query = provider_query.filter(rule_providers::Column::RouteMapId.is_null());
        }

        if let Ok(providers) = provider_query.all(&self.db).await {
            for provider in &providers {
                let action = RuleAction::from(provider.action);
                self.load_provider_into_compiler(&mut compiler, provider, action)
                    .await;
            }
        }

        // 2. Загружаем правила из route_rules (для конкретного профиля либо всех активных карт, если профиль не задан)
        let rules_list = if let Some(map_id) = route_map_id {
            route_rules::Entity::find()
                .filter(route_rules::Column::RouteMapId.eq(map_id))
                .order_by_asc(route_rules::Column::Position)
                .all(&self.db)
                .await
                .unwrap_or_default()
        } else {
            Vec::new()
        };

        for rule in rules_list {
            if let Some(kind) = rule.match_kind() {
                let action = rule.rule_action();
                match kind {
                    RouteMatchKind::Cidr => {
                        let _ = compiler.add_provider_ips(&rule.match_value, action);
                    }
                    RouteMatchKind::Domain => {
                        compiler.add_admin_domain_override(&rule.match_value, action);
                    }
                    RouteMatchKind::RuleProvider => {
                        if let Ok(provider_id) = Uuid::parse_str(rule.match_value.trim()) {
                            if let Ok(Some(provider)) =
                                rule_providers::Entity::find_by_id(provider_id)
                                    .one(&self.db)
                                    .await
                            {
                                self.load_provider_into_compiler(&mut compiler, &provider, action)
                                    .await;
                            }
                        }
                    }
                    RouteMatchKind::Application => {}
                }
            }
        }

        // 3. Загружаем административные исключения (admin_custom_overrides) — высший серверный приоритет
        let mut override_query = admin_custom_overrides::Entity::find()
            .filter(admin_custom_overrides::Column::IsActive.eq(true));

        if let Some(map_id) = route_map_id {
            let condition = Condition::any()
                .add(admin_custom_overrides::Column::RouteMapId.eq(map_id))
                .add(admin_custom_overrides::Column::RouteMapId.is_null());
            override_query = override_query.filter(condition);
        } else {
            override_query =
                override_query.filter(admin_custom_overrides::Column::RouteMapId.is_null());
        }

        if let Ok(overrides) = override_query.all(&self.db).await {
            for ov in overrides {
                let action = RuleAction::from(ov.category);
                match ov.rule_type {
                    OverrideType::IpNet => compiler.add_admin_ip_override(&ov.pattern, action),
                    OverrideType::Domain | OverrideType::SubdomainWildcard => {
                        compiler.add_admin_domain_override(&ov.pattern, action);
                    }
                }
            }
        }

        // 4. Компилируем в бинарный формат .abc
        let bytes = match compiler.compile_to_bytes() {
            Ok(b) => b,
            Err(e) => {
                return CompiledRulesResponse::Error(PlainText(format!("Compilation error: {e}")))
            }
        };

        // 5. Считаем SHA-256 хэш как ETag и сохраняем в in-memory кэш
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        let etag = format!("\"{:x}\"", hasher.finalize());

        put_cached_abc(
            route_map_id,
            CachedAbcArtifact {
                etag: etag.clone(),
                bytes: bytes.clone(),
            },
        );

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
        self.compile_and_serve(Some(route_map_id.0), if_none_match.0)
            .await
    }
}
