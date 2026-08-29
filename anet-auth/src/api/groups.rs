use crate::api::api::validate_admin_session;
use crate::api::dto::{
    AdminToken, DeleteGroupResponse, GetGroupsResponse, GroupDto, SaveGroupRequest,
    SaveGroupResponse,
};
use crate::entities::{groups, users};
use chrono::Utc;
use poem_openapi::{payload::Json, OpenApi};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, IntoActiveModel, Set,
    QueryFilter, QueryOrder, TransactionTrait,
};
use uuid::Uuid;

pub struct GroupsApi {
    pub db: DatabaseConnection,
}

fn validate_group_request(req: &SaveGroupRequest) -> std::result::Result<(), String> {
    if req.name.trim().is_empty() {
        return Err("Group name cannot be empty".to_string());
    }
    Ok(())
}

fn map_group_model_to_dto(group: groups::Model, user_ids: Vec<Uuid>) -> GroupDto {
    GroupDto {
        id: group.id,
        name: group.name,
        traffic_limit: group.traffic_limit,
        speed_limit: group.speed_limit,
        sessions_limit: group.sessions_limit,
        duration_days: group.duration_days,
        user_ids,
        created_at: group.created_at.and_utc().to_rfc3339(),
        updated_at: group.updated_at.and_utc().to_rfc3339(),
    }
}

async fn group_user_ids(db: &DatabaseConnection, group_id: Uuid) -> Vec<Uuid> {
    users::Entity::find()
        .filter(users::Column::GroupId.eq(group_id))
        .all(db)
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|u| u.id)
        .collect()
}

#[OpenApi]
impl GroupsApi {
    #[oai(path = "/groups", method = "get")]
    async fn get_user_groups(&self, auth: AdminToken) -> GetGroupsResponse {
        if let Err(err) = validate_admin_session(&self.db, &auth.0.token).await {
            return GetGroupsResponse::Unauthorized(Json(err));
        }
        match crate::entities::groups::Entity::find()
            .order_by_asc(crate::entities::groups::Column::Name)
            .all(&self.db)
            .await
        {
            Ok(list) => {
                let mut dtos = Vec::new();
                for group in list {
                    let user_ids = group_user_ids(&self.db, group.id).await;
                    dtos.push(map_group_model_to_dto(group, user_ids));
                }
                GetGroupsResponse::Ok(Json(dtos))
            }
            Err(e) => GetGroupsResponse::Error(Json(e.to_string())),
        }
    }

    #[oai(path = "/groups", method = "post")]
    async fn create_user_group(
        &self,
        auth: AdminToken,
        req: Json<SaveGroupRequest>,
    ) -> SaveGroupResponse {
        if let Err(err) = validate_admin_session(&self.db, &auth.0.token).await {
            return SaveGroupResponse::Unauthorized(Json(err));
        }
        if let Err(error) = validate_group_request(&req.0) {
            return SaveGroupResponse::BadRequest(Json(error));
        }

        let txn = match self.db.begin().await {
            Ok(txn) => txn,
            Err(e) => return SaveGroupResponse::Error(Json(e.to_string())),
        };

        let now = Utc::now().naive_utc();
        let group_id = Uuid::new_v4();

        let new_group = crate::entities::groups::ActiveModel {
            id: Set(group_id),
            name: Set(req.0.name.trim().to_string()),
            traffic_limit: Set(req.0.traffic_limit as i64),
            speed_limit: Set(req.0.speed_limit as i32),
            sessions_limit: Set(req.0.sessions_limit as i32),
            duration_days: Set(req.0.duration_days as i32),
            created_at: Set(now),
            updated_at: Set(now),
        };

        let group = match new_group.insert(&txn).await {
            Ok(g) => g,
            Err(e) => {
                let _ = txn.rollback().await;
                return SaveGroupResponse::Error(Json(e.to_string()));
            }
        };

        if let Some(ref user_ids) = req.0.user_ids {
            if let Err(e) = users::Entity::update_many()
                .col_expr(users::Column::GroupId, sea_orm::sea_query::Expr::value(Some(group_id)))
                .filter(users::Column::Id.is_in(user_ids.clone()))
                .exec(&txn)
                .await
            {
                let _ = txn.rollback().await;
                return SaveGroupResponse::Error(Json(e.to_string()));
            }
        }

        if let Err(e) = txn.commit().await {
            return SaveGroupResponse::Error(Json(e.to_string()));
        }

        let final_user_ids = group_user_ids(&self.db, group_id).await;
        SaveGroupResponse::Ok(Json(map_group_model_to_dto(group, final_user_ids)))
    }

    #[oai(path = "/groups/:id", method = "patch")]
    async fn update_user_group(
        &self,
        auth: AdminToken,
        id: poem_openapi::param::Path<Uuid>,
        req: Json<SaveGroupRequest>,
    ) -> SaveGroupResponse {
        if let Err(err) = validate_admin_session(&self.db, &auth.0.token).await {
            return SaveGroupResponse::Unauthorized(Json(err));
        }
        if let Err(error) = validate_group_request(&req.0) {
            return SaveGroupResponse::BadRequest(Json(error));
        }

        let txn = match self.db.begin().await {
            Ok(txn) => txn,
            Err(e) => return SaveGroupResponse::Error(Json(e.to_string())),
        };

        let existing = match crate::entities::groups::Entity::find_by_id(id.0).one(&txn).await {
            Ok(Some(g)) => g,
            Ok(None) => {
                let _ = txn.rollback().await;
                return SaveGroupResponse::NotFound(Json("Group not found".to_string()));
            }
            Err(e) => {
                let _ = txn.rollback().await;
                return SaveGroupResponse::Error(Json(e.to_string()));
            }
        };

        let mut active = existing.into_active_model();
        active.name = Set(req.0.name.trim().to_string());
        active.traffic_limit = Set(req.0.traffic_limit as i64);
        active.speed_limit = Set(req.0.speed_limit as i32);
        active.sessions_limit = Set(req.0.sessions_limit as i32);
        active.duration_days = Set(req.0.duration_days as i32);
        active.updated_at = Set(Utc::now().naive_utc());

        let group = match active.update(&txn).await {
            Ok(g) => g,
            Err(e) => {
                let _ = txn.rollback().await;
                return SaveGroupResponse::Error(Json(e.to_string()));
            }
        };

        if let Some(ref user_ids) = req.0.user_ids {
            if let Err(e) = users::Entity::update_many()
                .col_expr(users::Column::GroupId, sea_orm::sea_query::Expr::value(None::<Uuid>))
                .filter(users::Column::GroupId.eq(id.0))
                .exec(&txn)
                .await
            {
                let _ = txn.rollback().await;
                return SaveGroupResponse::Error(Json(e.to_string()));
            }

            if let Err(e) = users::Entity::update_many()
                .col_expr(users::Column::GroupId, sea_orm::sea_query::Expr::value(Some(id.0)))
                .filter(users::Column::Id.is_in(user_ids.clone()))
                .exec(&txn)
                .await
            {
                let _ = txn.rollback().await;
                return SaveGroupResponse::Error(Json(e.to_string()));
            }
        }

        if let Err(e) = txn.commit().await {
            return SaveGroupResponse::Error(Json(e.to_string()));
        }

        let final_user_ids = group_user_ids(&self.db, id.0).await;
        SaveGroupResponse::Ok(Json(map_group_model_to_dto(group, final_user_ids)))
    }

    #[oai(path = "/groups/:id", method = "delete")]
    async fn delete_user_group(
        &self,
        auth: AdminToken,
        id: poem_openapi::param::Path<Uuid>,
    ) -> DeleteGroupResponse {
        if let Err(err) = validate_admin_session(&self.db, &auth.0.token).await {
            return DeleteGroupResponse::Unauthorized(Json(err));
        }
        match crate::entities::groups::Entity::delete_by_id(id.0).exec(&self.db).await {
            Ok(res) if res.rows_affected > 0 => DeleteGroupResponse::Deleted,
            Ok(_) => DeleteGroupResponse::NotFound(Json("Group not found".to_string())),
            Err(e) => DeleteGroupResponse::Error(Json(e.to_string())),
        }
    }
}
