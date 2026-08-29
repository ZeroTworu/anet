use crate::api::api::{load_route_map_dto, validate_admin_session};
use crate::api::dto::{
    AdminToken, DeleteRouteMapResponse, GetRouteMapsResponse, SaveRouteMapRequest,
    SaveRouteMapResponse
};
use crate::entities::{route_maps, route_rules};
use crate::route_compiler::{compile_route_map, RouteRuleSpec};
use chrono::Utc;
use poem_openapi::{payload::Json, OpenApi};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, IntoActiveModel, Set,
    QueryFilter, QueryOrder, TransactionTrait,
};
use uuid::Uuid;

pub struct RouteMapsApi {
    pub db: DatabaseConnection,
}

fn validate_route_map_request(req: &SaveRouteMapRequest) -> std::result::Result<(), String> {
    if req.name.trim().is_empty() {
        return Err("Route map name cannot be empty".to_string());
    }
    let specs: Vec<_> = req
        .rules
        .iter()
        .map(|rule| RouteRuleSpec {
            match_type: rule.match_type.clone(),
            match_value: rule.match_value.clone(),
            action: rule.action.clone(),
        })
        .collect();
    compile_route_map(&req.default_action, &specs).map(|_| ())
}

#[OpenApi]
impl RouteMapsApi {
    #[oai(path = "/route-maps", method = "get")]
    async fn get_route_maps(&self, auth: AdminToken) -> GetRouteMapsResponse {
        if let Err(err) = validate_admin_session(&self.db, &auth.0.token).await {
            return GetRouteMapsResponse::Unauthorized(Json(err));
        }
        let maps = match route_maps::Entity::find()
            .order_by_asc(route_maps::Column::Name)
            .all(&self.db)
            .await
        {
            Ok(maps) => maps,
            Err(e) => return GetRouteMapsResponse::Error(Json(e.to_string())),
        };
        let mut result = Vec::with_capacity(maps.len());
        for map in maps {
            match load_route_map_dto(&self.db, map).await {
                Ok(map) => result.push(map),
                Err(e) => return GetRouteMapsResponse::Error(Json(e.to_string())),
            }
        }
        GetRouteMapsResponse::Ok(Json(result))
    }

    #[oai(path = "/route-maps", method = "post")]
    async fn create_route_map(
        &self,
        auth: AdminToken,
        req: Json<SaveRouteMapRequest>,
    ) -> SaveRouteMapResponse {
        if let Err(err) = validate_admin_session(&self.db, &auth.0.token).await {
            return SaveRouteMapResponse::Unauthorized(Json(err));
        }
        if let Err(error) = validate_route_map_request(&req.0) {
            return SaveRouteMapResponse::BadRequest(Json(error));
        }
        let txn = match self.db.begin().await {
            Ok(txn) => txn,
            Err(e) => return SaveRouteMapResponse::Error(Json(e.to_string())),
        };
        let now = Utc::now().naive_utc();
        let map = match (route_maps::ActiveModel {
            id: Set(Uuid::new_v4()),
            name: Set(req.0.name.trim().to_string()),
            description: Set(req.0.description.clone()),
            default_action: Set(req.0.default_action.clone()),
            is_active: Set(req.0.is_active.unwrap_or(true)),
            revision: Set(1),
            created_at: Set(now),
            updated_at: Set(now),
        })
            .insert(&txn)
            .await
        {
            Ok(map) => map,
            Err(e) => return SaveRouteMapResponse::Error(Json(e.to_string())),
        };
        for (position, rule) in req.0.rules.iter().enumerate() {
            if let Err(e) = (route_rules::ActiveModel {
                id: Set(Uuid::new_v4()),
                route_map_id: Set(map.id),
                position: Set(position as i32),
                match_type: Set(rule.match_type.clone()),
                match_value: Set(rule.match_value.clone()),
                action: Set(rule.action.clone()),
            })
                .insert(&txn)
                .await
            {
                return SaveRouteMapResponse::Error(Json(e.to_string()));
            }
        }
        if let Err(e) = txn.commit().await {
            return SaveRouteMapResponse::Error(Json(e.to_string()));
        }
        match load_route_map_dto(&self.db, map).await {
            Ok(map) => SaveRouteMapResponse::Ok(Json(map)),
            Err(e) => SaveRouteMapResponse::Error(Json(e.to_string())),
        }
    }

    #[oai(path = "/route-maps/:id", method = "patch")]
    async fn update_route_map(
        &self,
        auth: AdminToken,
        id: poem_openapi::param::Path<Uuid>,
        req: Json<SaveRouteMapRequest>,
    ) -> SaveRouteMapResponse {
        if let Err(err) = validate_admin_session(&self.db, &auth.0.token).await {
            return SaveRouteMapResponse::Unauthorized(Json(err));
        }
        if let Err(error) = validate_route_map_request(&req.0) {
            return SaveRouteMapResponse::BadRequest(Json(error));
        }
        let existing = match route_maps::Entity::find_by_id(id.0).one(&self.db).await {
            Ok(Some(map)) => map,
            Ok(None) => {
                return SaveRouteMapResponse::NotFound(Json("Route map not found".to_string()));
            }
            Err(e) => return SaveRouteMapResponse::Error(Json(e.to_string())),
        };
        let txn = match self.db.begin().await {
            Ok(txn) => txn,
            Err(e) => return SaveRouteMapResponse::Error(Json(e.to_string())),
        };
        let mut map = existing.into_active_model();
        map.name = Set(req.0.name.trim().to_string());
        map.description = Set(req.0.description.clone());
        map.default_action = Set(req.0.default_action.clone());
        map.is_active = Set(req.0.is_active.unwrap_or(true));
        map.revision = Set(map.revision.as_ref().saturating_add(1));
        map.updated_at = Set(Utc::now().naive_utc());
        let saved = match map.update(&txn).await {
            Ok(map) => map,
            Err(e) => return SaveRouteMapResponse::Error(Json(e.to_string())),
        };
        if let Err(e) = route_rules::Entity::delete_many()
            .filter(route_rules::Column::RouteMapId.eq(id.0))
            .exec(&txn)
            .await
        {
            return SaveRouteMapResponse::Error(Json(e.to_string()));
        }
        for (position, rule) in req.0.rules.iter().enumerate() {
            if let Err(e) = (route_rules::ActiveModel {
                id: Set(Uuid::new_v4()),
                route_map_id: Set(id.0),
                position: Set(position as i32),
                match_type: Set(rule.match_type.clone()),
                match_value: Set(rule.match_value.clone()),
                action: Set(rule.action.clone()),
            })
                .insert(&txn)
                .await
            {
                return SaveRouteMapResponse::Error(Json(e.to_string()));
            }
        }
        if let Err(e) = txn.commit().await {
            return SaveRouteMapResponse::Error(Json(e.to_string()));
        }
        match load_route_map_dto(&self.db, saved).await {
            Ok(map) => SaveRouteMapResponse::Ok(Json(map)),
            Err(e) => SaveRouteMapResponse::Error(Json(e.to_string())),
        }
    }

    #[oai(path = "/route-maps/:id", method = "delete")]
    async fn delete_route_map(
        &self,
        auth: AdminToken,
        id: poem_openapi::param::Path<Uuid>,
    ) -> DeleteRouteMapResponse {
        if let Err(err) = validate_admin_session(&self.db, &auth.0.token).await {
            return DeleteRouteMapResponse::Unauthorized(Json(err));
        }
        match route_maps::Entity::delete_by_id(id.0).exec(&self.db).await {
            Ok(result) if result.rows_affected > 0 => DeleteRouteMapResponse::Deleted,
            Ok(_) => DeleteRouteMapResponse::NotFound(Json("Route map not found".to_string())),
            Err(e) => DeleteRouteMapResponse::Error(Json(e.to_string())),
        }
    }
}
