use crate::api::api::validate_admin_session;
use crate::api::dto::{
    AddGroupMemberRequest, AdminToken, DeleteGroupResponse, GetGroupsResponse, GroupDto,
    PaginatedUsers, SaveGroupRequest, SaveGroupResponse,
};
use crate::entities::{groups, users};
use chrono::Utc;
use poem_openapi::{param::Query, payload::Json, ApiResponse, OpenApi};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, IntoActiveModel, Set,
    QueryFilter, QueryOrder, QuerySelect, PaginatorTrait
};
use std::collections::HashMap;
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

fn map_group_model_to_dto(group: groups::Model, user_count: i64) -> GroupDto {
    GroupDto {
        id: group.id,
        name: group.name,
        traffic_limit: group.traffic_limit,
        speed_limit: group.speed_limit,
        sessions_limit: group.sessions_limit,
        duration_days: group.duration_days,
        user_count,
        created_at: group.created_at.and_utc().to_rfc3339(),
        updated_at: group.updated_at.and_utc().to_rfc3339(),
    }
}

#[derive(ApiResponse)]
pub enum GetGroupResponse {
    #[oai(status = 200)]
    Ok(Json<GroupDto>),
    #[oai(status = 401)]
    Unauthorized(Json<String>),
    #[oai(status = 404)]
    NotFound(Json<String>),
    #[oai(status = 500)]
    Error(Json<String>),
}

#[derive(ApiResponse)]
pub enum GetGroupMembersResponse {
    #[oai(status = 200)]
    Ok(Json<PaginatedUsers>),
    #[oai(status = 401)]
    Unauthorized(Json<String>),
    #[oai(status = 500)]
    Error(Json<String>),
}

#[derive(ApiResponse)]
pub enum AddGroupMemberResponse {
    #[oai(status = 200)]
    Ok,
    #[oai(status = 401)]
    Unauthorized(Json<String>),
    #[oai(status = 404)]
    NotFound(Json<String>),
    #[oai(status = 500)]
    Error(Json<String>),
}

#[derive(ApiResponse)]
pub enum RemoveGroupMemberResponse {
    #[oai(status = 204)]
    Ok,
    #[oai(status = 401)]
    Unauthorized(Json<String>),
    #[oai(status = 404)]
    NotFound(Json<String>),
    #[oai(status = 500)]
    Error(Json<String>),
}

#[OpenApi]
impl GroupsApi {
    /// Получить список всех групп с количеством участников
    #[oai(path = "/groups", method = "get")]
    async fn get_user_groups(&self, auth: AdminToken) -> GetGroupsResponse {
        if let Err(err) = validate_admin_session(&self.db, &auth.0.token).await {
            return GetGroupsResponse::Unauthorized(Json(err));
        }

        let list = match crate::entities::groups::Entity::find()
            .order_by_asc(crate::entities::groups::Column::Name)
            .all(&self.db)
            .await
        {
            Ok(list) => list,
            Err(e) => return GetGroupsResponse::Error(Json(e.to_string())),
        };

        let counts_result = users::Entity::find()
            .select_only()
            .column(users::Column::GroupId)
            .column_as(users::Column::Id.count(), "user_count")
            .filter(users::Column::GroupId.is_not_null())
            .group_by(users::Column::GroupId)
            .into_tuple::<(Option<Uuid>, i64)>()
            .all(&self.db)
            .await;

        let counts_map: HashMap<Uuid, i64> = match counts_result {
            Ok(counts) => counts
                .into_iter()
                .filter_map(|(g_id, count)| g_id.map(|id| (id, count)))
                .collect(),
            Err(e) => return GetGroupsResponse::Error(Json(e.to_string())),
        };

        let dtos = list
            .into_iter()
            .map(|group| {
                let user_count = counts_map.get(&group.id).copied().unwrap_or(0);
                map_group_model_to_dto(group, user_count)
            })
            .collect();

        GetGroupsResponse::Ok(Json(dtos))
    }

    /// Получить базовую информацию об одной конкретной группе по ID
    #[oai(path = "/groups/:id", method = "get")]
    async fn get_group(
        &self,
        auth: AdminToken,
        id: poem_openapi::param::Path<Uuid>,
    ) -> GetGroupResponse {
        if let Err(err) = validate_admin_session(&self.db, &auth.0.token).await {
            return GetGroupResponse::Unauthorized(Json(err));
        }

        let group = match crate::entities::groups::Entity::find_by_id(id.0).one(&self.db).await {
            Ok(Some(g)) => g,
            Ok(None) => return GetGroupResponse::NotFound(Json("Group not found".to_string())),
            Err(e) => return GetGroupResponse::Error(Json(e.to_string())),
        };

        let count = match users::Entity::find()
            .filter(users::Column::GroupId.eq(id.0))
            .count(&self.db)
            .await
        {
            Ok(c) => c as i64,
            Err(e) => return GetGroupResponse::Error(Json(e.to_string())),
        };

        GetGroupResponse::Ok(Json(map_group_model_to_dto(group, count)))
    }

    /// Получить лениво загружаемый, пагинируемый список участников группы
    #[oai(path = "/groups/:id/members", method = "get")]
    async fn get_group_members(
        &self,
        auth: AdminToken,
        id: poem_openapi::param::Path<Uuid>,
        from: Query<Option<i64>>,
        limit: Query<Option<i64>>,
        search: Query<Option<String>>,
    ) -> GetGroupMembersResponse {
        if let Err(err) = validate_admin_session(&self.db, &auth.0.token).await {
            return GetGroupMembersResponse::Unauthorized(Json(err));
        }

        let offset = from.0.unwrap_or(0) as u64;
        let page_size = limit.0.unwrap_or(50) as u64;

        let mut query = users::Entity::find()
            .filter(users::Column::GroupId.eq(id.0))
            .find_also_related(crate::entities::rates::Entity);

        if let Some(ref s) = search.0 {
            if !s.trim().is_empty() {
                let pattern = format!("%{}%", s.trim());
                query = query.filter(
                    sea_orm::Condition::any()
                        .add(users::Column::Uid.ilike(&pattern))
                        .add(users::Column::Fingerprint.ilike(&pattern))
                );
            }
        }

        let count = match query.clone().count(&self.db).await {
            Ok(c) => c as i64,
            Err(e) => return GetGroupMembersResponse::Error(Json(e.to_string())),
        };

        let members = match query
            .order_by_desc(users::Column::CreatedAt)
            .offset(offset)
            .limit(page_size)
            .all(&self.db)
            .await
        {
            Ok(list) => list,
            Err(e) => return GetGroupMembersResponse::Error(Json(e.to_string())),
        };

        let mut dto_list = Vec::new();
        for (m, r) in members {
            dto_list.push(crate::api::dto::VpnUserDto {
                id: m.id,
                fingerprint: m.fingerprint,
                uid: m.uid,
                is_active: m.is_active,
                created_at: m.created_at.format("%Y-%m-%d %H:%M:%S").to_string(),
                rate: r.map(|rate_model| crate::api::dto::RateDto {
                    id: rate_model.id,
                    sessions: rate_model.sessions as i32,
                    date_end: rate_model.date_end.format("%Y-%m-%d-%H:%M").to_string(),
                }),
                static_ip: m.static_ip.map(|ip| ip.parse().ok()).flatten(),
                server_ids: Vec::new(),        
                pool_ids: Vec::new(),         
                route_map_id: m.route_map_id,  
                group_id: m.group_id,
            });
        }

        GetGroupMembersResponse::Ok(Json(PaginatedUsers {
            total: count,
            items: dto_list,
        }))
    }

    /// Добавить (привязать) пользователя к группе
    #[oai(path = "/groups/:id/members", method = "post")]
    async fn add_member_to_group(
        &self,
        auth: AdminToken,
        id: poem_openapi::param::Path<Uuid>,
        req: Json<AddGroupMemberRequest>,
    ) -> AddGroupMemberResponse {
        if let Err(err) = validate_admin_session(&self.db, &auth.0.token).await {
            return AddGroupMemberResponse::Unauthorized(Json(err));
        }

        let user = match users::Entity::find_by_id(req.0.user_id).one(&self.db).await {
            Ok(Some(u)) => u,
            Ok(None) => return AddGroupMemberResponse::NotFound(Json("User not found".to_string())),
            Err(e) => return AddGroupMemberResponse::Error(Json(e.to_string())),
        };

        let mut active = user.into_active_model();
        active.group_id = Set(Some(id.0));
        active.updated_at = Set(Utc::now().naive_utc());

        match active.update(&self.db).await {
            Ok(_) => AddGroupMemberResponse::Ok,
            Err(e) => AddGroupMemberResponse::Error(Json(e.to_string())),
        }
    }

    /// Исключить пользователя из группы (сброс group_id в null)
    #[oai(path = "/groups/:id/members/:user_id", method = "delete")]
    async fn remove_member_from_group(
        &self,
        auth: AdminToken,
        _id: poem_openapi::param::Path<Uuid>,
        user_id: poem_openapi::param::Path<Uuid>,
    ) -> RemoveGroupMemberResponse {
        if let Err(err) = validate_admin_session(&self.db, &auth.0.token).await {
            return RemoveGroupMemberResponse::Unauthorized(Json(err));
        }

        let user = match users::Entity::find_by_id(user_id.0).one(&self.db).await {
            Ok(Some(u)) => u,
            Ok(None) => return RemoveGroupMemberResponse::NotFound(Json("User not found".to_string())),
            Err(e) => return RemoveGroupMemberResponse::Error(Json(e.to_string())),
        };

        let mut active = user.into_active_model();
        active.group_id = Set(None);
        active.updated_at = Set(Utc::now().naive_utc());

        match active.update(&self.db).await {
            Ok(_) => RemoveGroupMemberResponse::Ok,
            Err(e) => RemoveGroupMemberResponse::Error(Json(e.to_string())),
        }
    }

    /// Создать пустую группу
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

        match new_group.insert(&self.db).await {
            Ok(group) => SaveGroupResponse::Ok(Json(map_group_model_to_dto(group, 0))),
            Err(e) => SaveGroupResponse::Error(Json(e.to_string())),
        }
    }

    /// Обновить исключительно основные параметры группы
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

        let existing = match crate::entities::groups::Entity::find_by_id(id.0).one(&self.db).await {
            Ok(Some(g)) => g,
            Ok(None) => return SaveGroupResponse::NotFound(Json("Group not found".to_string())),
            Err(e) => return SaveGroupResponse::Error(Json(e.to_string())),
        };

        let mut active = existing.into_active_model();
        active.name = Set(req.0.name.trim().to_string());
        active.traffic_limit = Set(req.0.traffic_limit as i64);
        active.speed_limit = Set(req.0.speed_limit as i32);
        active.sessions_limit = Set(req.0.sessions_limit as i32);
        active.duration_days = Set(req.0.duration_days as i32);
        active.updated_at = Set(Utc::now().naive_utc());

        let count = match users::Entity::find()
            .filter(users::Column::GroupId.eq(id.0))
            .count(&self.db)
            .await
        {
            Ok(c) => c as i64,
            Err(e) => return SaveGroupResponse::Error(Json(e.to_string())),
        };

        match active.update(&self.db).await {
            Ok(group) => SaveGroupResponse::Ok(Json(map_group_model_to_dto(group, count))),
            Err(e) => SaveGroupResponse::Error(Json(e.to_string())),
        }
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
