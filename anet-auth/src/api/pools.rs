use crate::api::api::{load_pool_dto, validate_admin_session};
use crate::api::dto::{
    AdminToken, DeleteNodePoolResponse, GetNodePoolsResponse, SaveNodePoolRequest,
    SaveNodePoolResponse,
};
use crate::entities::{node_pool_members, node_pools};
use chrono::Utc;
use poem_openapi::{payload::Json, OpenApi};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, IntoActiveModel, Set,
    QueryFilter, QueryOrder, TransactionTrait,
};
use std::collections::HashSet;
use uuid::Uuid;

pub struct PoolsApi {
    pub db: DatabaseConnection,
}

fn validate_pool_request(req: &SaveNodePoolRequest) -> std::result::Result<(), String> {
    if req.name.trim().is_empty() {
        return Err("Pool name cannot be empty".to_string());
    }
    if req.strategy != "weighted" && req.strategy != "least_connections" {
        return Err("Strategy must be weighted or least_connections".to_string());
    }
    if req
        .members
        .iter()
        .any(|member| member.weight == 0 || member.weight > 10_000)
    {
        return Err("Member weight must be between 1 and 10000".to_string());
    }
    let unique: HashSet<_> = req.members.iter().map(|member| member.server_id).collect();
    if unique.len() != req.members.len() {
        return Err("Pool contains duplicate nodes".to_string());
    }
    Ok(())
}

#[OpenApi]
impl PoolsApi {
    #[oai(path = "/pools", method = "get")]
    async fn get_node_pools(&self, auth: AdminToken) -> GetNodePoolsResponse {
        if let Err(err) = validate_admin_session(&self.db, &auth.0.token).await {
            return GetNodePoolsResponse::Unauthorized(Json(err));
        }
        let pools = match node_pools::Entity::find()
            .order_by_asc(node_pools::Column::Name)
            .all(&self.db)
            .await
        {
            Ok(pools) => pools,
            Err(e) => return GetNodePoolsResponse::Error(Json(e.to_string())),
        };
        let mut result = Vec::with_capacity(pools.len());
        for pool in pools {
            match load_pool_dto(&self.db, pool).await {
                Ok(pool) => result.push(pool),
                Err(e) => return GetNodePoolsResponse::Error(Json(e.to_string())),
            }
        }
        GetNodePoolsResponse::Ok(Json(result))
    }

    #[oai(path = "/pools", method = "post")]
    async fn create_node_pool(
        &self,
        auth: AdminToken,
        req: Json<SaveNodePoolRequest>,
    ) -> SaveNodePoolResponse {
        if let Err(err) = validate_admin_session(&self.db, &auth.0.token).await {
            return SaveNodePoolResponse::Unauthorized(Json(err));
        }
        if let Err(error) = validate_pool_request(&req.0) {
            return SaveNodePoolResponse::BadRequest(Json(error));
        }
        let txn = match self.db.begin().await {
            Ok(txn) => txn,
            Err(e) => return SaveNodePoolResponse::Error(Json(e.to_string())),
        };
        let now = Utc::now().naive_utc();
        let pool = match (node_pools::ActiveModel {
            id: Set(Uuid::new_v4()),
            name: Set(req.0.name.trim().to_string()),
            strategy: Set(req.0.strategy.clone()),
            is_active: Set(req.0.is_active.unwrap_or(true)),
            created_at: Set(now),
            updated_at: Set(now),
        })
            .insert(&txn)
            .await
        {
            Ok(pool) => pool,
            Err(e) => return SaveNodePoolResponse::Error(Json(e.to_string())),
        };
        for member in &req.0.members {
            if let Err(e) = (node_pool_members::ActiveModel {
                pool_id: Set(pool.id),
                server_id: Set(member.server_id),
                weight: Set(member.weight),
            })
                .insert(&txn)
                .await
            {
                return SaveNodePoolResponse::Error(Json(e.to_string()));
            }
        }
        if let Err(e) = txn.commit().await {
            return SaveNodePoolResponse::Error(Json(e.to_string()));
        }
        match load_pool_dto(&self.db, pool).await {
            Ok(pool) => SaveNodePoolResponse::Ok(Json(pool)),
            Err(e) => SaveNodePoolResponse::Error(Json(e.to_string())),
        }
    }

    #[oai(path = "/pools/:id", method = "patch")]
    async fn update_node_pool(
        &self,
        auth: AdminToken,
        id: poem_openapi::param::Path<Uuid>,
        req: Json<SaveNodePoolRequest>,
    ) -> SaveNodePoolResponse {
        if let Err(err) = validate_admin_session(&self.db, &auth.0.token).await {
            return SaveNodePoolResponse::Unauthorized(Json(err));
        }
        if let Err(error) = validate_pool_request(&req.0) {
            return SaveNodePoolResponse::BadRequest(Json(error));
        }
        let existing = match node_pools::Entity::find_by_id(id.0).one(&self.db).await {
            Ok(Some(pool)) => pool,
            Ok(None) => return SaveNodePoolResponse::NotFound(Json("Pool not found".to_string())),
            Err(e) => return SaveNodePoolResponse::Error(Json(e.to_string())),
        };
        let txn = match self.db.begin().await {
            Ok(txn) => txn,
            Err(e) => return SaveNodePoolResponse::Error(Json(e.to_string())),
        };
        let mut pool = existing.into_active_model();
        pool.name = Set(req.0.name.trim().to_string());
        pool.strategy = Set(req.0.strategy.clone());
        pool.is_active = Set(req.0.is_active.unwrap_or(true));
        pool.updated_at = Set(Utc::now().naive_utc());
        let saved = match pool.update(&txn).await {
            Ok(pool) => pool,
            Err(e) => return SaveNodePoolResponse::Error(Json(e.to_string())),
        };
        if let Err(e) = node_pool_members::Entity::delete_many()
            .filter(node_pool_members::Column::PoolId.eq(id.0))
            .exec(&txn)
            .await
        {
            return SaveNodePoolResponse::Error(Json(e.to_string()));
        }
        for member in &req.0.members {
            if let Err(e) = (node_pool_members::ActiveModel {
                pool_id: Set(id.0),
                server_id: Set(member.server_id),
                weight: Set(member.weight),
            })
                .insert(&txn)
                .await
            {
                return SaveNodePoolResponse::Error(Json(e.to_string()));
            }
        }
        if let Err(e) = txn.commit().await {
            return SaveNodePoolResponse::Error(Json(e.to_string()));
        }
        match load_pool_dto(&self.db, saved).await {
            Ok(pool) => SaveNodePoolResponse::Ok(Json(pool)),
            Err(e) => SaveNodePoolResponse::Error(Json(e.to_string())),
        }
    }

    #[oai(path = "/pools/:id", method = "delete")]
    async fn delete_node_pool(
        &self,
        auth: AdminToken,
        id: poem_openapi::param::Path<Uuid>,
    ) -> DeleteNodePoolResponse {
        if let Err(err) = validate_admin_session(&self.db, &auth.0.token).await {
            return DeleteNodePoolResponse::Unauthorized(Json(err));
        }
        match node_pools::Entity::delete_by_id(id.0).exec(&self.db).await {
            Ok(result) if result.rows_affected > 0 => DeleteNodePoolResponse::Deleted,
            Ok(_) => DeleteNodePoolResponse::NotFound(Json("Pool not found".to_string())),
            Err(e) => DeleteNodePoolResponse::Error(Json(e.to_string())),
        }
    }
}
