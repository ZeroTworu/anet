use std::collections::HashMap;
use crate::api::api::{generate_node_token, hash_node_token, node_token_is_valid, validate_admin_session};
use crate::api::dto::{
    AdminToken, CreateAdmissionCommandRequest, CreateNodeCommandResponse, CreateServerRequest,
    GetNodeCommandStatusResponse, GetNodeCommandsResponse, GetServersResponse, NodeCommandResultResponse,
    NodeCommandResultRequest, NodeCommandStatusDto, NodeCredentialDto, RotateNodeCredentialResponse, ServerDto, NodeRuntimeDto, NodeCommand
};
use crate::entities::{node_commands, node_runtime_states, servers};
use chrono::{NaiveDateTime, Utc};
use poem_openapi::{param::Query, payload::Json, OpenApi};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, IntoActiveModel, Set, QueryFilter, QueryOrder
};
use uuid::Uuid;

pub struct ServersApi {
    pub db: DatabaseConnection,
}

#[OpenApi]
impl ServersApi {
    /// Регистрация нового физического VPN-сервера (ноды) в системе
    #[oai(path = "/servers", method = "post")]
    async fn create_server(
        &self,
        auth: AdminToken,
        req: Json<CreateServerRequest>,
    ) -> poem::Result<Json<ServerDto>, poem::Error> {
        if let Err(err) = validate_admin_session(&self.db, &auth.0.token).await {
            return Err(poem::Error::from_string(
                err,
                poem::http::StatusCode::UNAUTHORIZED,
            ));
        }

        let server_id = Uuid::new_v4();
        let new_server = servers::ActiveModel {
            id: Set(server_id),
            name: Set(req.0.name.clone()),
            address: Set(String::new()),
            public_key: Set(req.0.public_key.clone()),
            quic_port: Set(req.0.quic_port),
            ssh_port: Set(req.0.ssh_port),
            vnc_port: Set(req.0.vnc_port),
            websocket_url: Set(req.0.websocket_url.clone()),
            ssh_user: Set(req.0.ssh_user.clone()),
            is_active: Set(req.0.is_active.unwrap_or(true)),
            control_token_hash: Set(None),
            created_at: Set(Utc::now().naive_utc()),
            updated_at: Set(Utc::now().naive_utc()),
        };

        match new_server.insert(&self.db).await {
            Ok(saved) => Ok(Json(ServerDto {
                id: saved.id,
                name: saved.name,
                address: saved.address,
                public_key: saved.public_key,
                quic_port: saved.quic_port,
                ssh_port: saved.ssh_port,
                vnc_port: saved.vnc_port,
                websocket_url: saved.websocket_url,
                ssh_user: saved.ssh_user,
                is_active: saved.is_active,
                has_control_credential: saved.control_token_hash.is_some(),
                runtime: None,
            })),
            Err(e) => Err(poem::error::InternalServerError(e)),
        }
    }

    /// Настройки сервера: Обновление параметров, портов и статуса активности (PATCH)
    #[oai(path = "/servers/:id", method = "patch")]
    async fn update_server(
        &self,
        auth: AdminToken,
        id: poem_openapi::param::Path<Uuid>,
        req: Json<crate::api::dto::UpdateServerRequest>,
    ) -> crate::api::dto::UpdateServerApiResult {
        if let Err(err) = validate_admin_session(&self.db, &auth.0.token).await {
            return crate::api::dto::UpdateServerApiResult::Unauthorized(Json(err));
        }

        let server_model = match servers::Entity::find_by_id(id.0).one(&self.db).await {
            Ok(Some(s)) => s,
            Ok(None) => {
                return crate::api::dto::UpdateServerApiResult::NotFound(Json("Сервер не найден".to_string()));
            }
            Err(e) => return crate::api::dto::UpdateServerApiResult::Error(Json(e.to_string())),
        };

        let mut active_model = server_model.clone().into_active_model();
        let mut changed = false;

        if let Some(name) = req.0.name {
            active_model.name = Set(name);
            changed = true;
        }
        if let Some(address) = req.0.address {
            active_model.address = Set(address);
            changed = true;
        }
        if let Some(pub_key) = req.0.public_key {
            active_model.public_key = Set(pub_key);
            changed = true;
        }
        if let Some(quic_port) = req.0.quic_port {
            active_model.quic_port = Set(quic_port);
            changed = true;
        }
        if let Some(ssh_port) = req.0.ssh_port {
            active_model.ssh_port = Set(ssh_port);
            changed = true;
        }
        if let Some(vnc_port) = req.0.vnc_port {
            active_model.vnc_port = Set(vnc_port);
            changed = true;
        }
        if let Some(websocket_url) = req.0.websocket_url {
            active_model.websocket_url = Set(websocket_url);
            changed = true;
        }
        if let Some(user) = req.0.ssh_user {
            active_model.ssh_user = Set(user);
            changed = true;
        }
        if let Some(is_active) = req.0.is_active {
            active_model.is_active = Set(is_active);
            changed = true;
        }

        if changed {
            active_model.updated_at = Set(Utc::now().naive_utc());
            match active_model.update(&self.db).await {
                Ok(saved) => crate::api::dto::UpdateServerApiResult::Ok(Json(ServerDto {
                    id: saved.id,
                    name: saved.name,
                    address: saved.address,
                    public_key: saved.public_key,
                    quic_port: saved.quic_port,
                    ssh_port: saved.ssh_port,
                    vnc_port: saved.vnc_port,
                    websocket_url: saved.websocket_url,
                    ssh_user: saved.ssh_user,
                    is_active: saved.is_active,
                    has_control_credential: saved.control_token_hash.is_some(),
                    runtime: None,
                })),
                Err(e) => crate::api::dto::UpdateServerApiResult::Error(Json(e.to_string())),
            }
        } else {
            crate::api::dto::UpdateServerApiResult::Ok(Json(ServerDto {
                id: server_model.id,
                name: server_model.name,
                address: server_model.address,
                public_key: server_model.public_key,
                quic_port: server_model.quic_port,
                ssh_port: server_model.ssh_port,
                vnc_port: server_model.vnc_port,
                websocket_url: server_model.websocket_url,
                ssh_user: server_model.ssh_user,
                is_active: server_model.is_active,
                has_control_credential: server_model.control_token_hash.is_some(),
                runtime: None,
            }))
        }
    }

    /// Получить список всех зарегистрированных VPN-нод
    #[oai(path = "/servers", method = "get")]
    async fn get_servers(&self, auth: AdminToken) -> GetServersResponse {
        if let Err(err) = validate_admin_session(&self.db, &auth.0.token).await {
            return GetServersResponse::Unauthorized(Json(err));
        }

        match servers::Entity::find().all(&self.db).await {
            Ok(list) => {
                let runtime_by_server: HashMap<Uuid, node_runtime_states::Model> =
                    match node_runtime_states::Entity::find().all(&self.db).await {
                        Ok(states) => states
                            .into_iter()
                            .map(|state| (state.server_id, state))
                            .collect(),
                        Err(e) => return GetServersResponse::Error(Json(e.to_string())),
                    };
                let now = Utc::now().naive_utc();
                let dtos = list
                    .into_iter()
                    .map(|s| ServerDto {
                        runtime: runtime_by_server.get(&s.id).map(|state| NodeRuntimeDto {
                            status: if now.signed_duration_since(state.last_seen_at).num_seconds()
                                <= 45
                            {
                                "online".to_string()
                            } else {
                                "offline".to_string()
                            },
                            last_seen_at: state.last_seen_at.and_utc().to_rfc3339(),
                            version: state.version.clone(),
                            uptime_seconds: state.uptime_seconds.max(0) as i64,
                            active_connections: state.active_connections.max(0) as i64,
                            accepting_connections: state.accepting_connections,
                        }),
                        id: s.id,
                        name: s.name,
                        address: s.address,
                        public_key: s.public_key,
                        quic_port: s.quic_port,
                        ssh_port: s.ssh_port,
                        vnc_port: s.vnc_port,
                        websocket_url: s.websocket_url,
                        ssh_user: s.ssh_user,
                        is_active: s.is_active,
                        has_control_credential: s.control_token_hash.is_some(),
                    })
                    .collect();
                GetServersResponse::Ok(Json(dtos))
            }
            Err(e) => GetServersResponse::Error(Json(e.to_string())),
        }
    }

    /// Поставить в очередь команду включения или выключения новых подключений.
    #[oai(path = "/servers/:id/commands/admission", method = "post")]
    async fn create_admission_command(
        &self,
        auth: AdminToken,
        id: poem_openapi::param::Path<Uuid>,
        req: Json<CreateAdmissionCommandRequest>,
    ) -> CreateNodeCommandResponse {
        if let Err(err) = validate_admin_session(&self.db, &auth.0.token).await {
            return CreateNodeCommandResponse::Unauthorized(Json(err));
        }
        match servers::Entity::find_by_id(id.0).one(&self.db).await {
            Ok(Some(_)) => {}
            Ok(None) => {
                return CreateNodeCommandResponse::NotFound(Json("Node not found".to_string()));
            }
            Err(e) => return CreateNodeCommandResponse::Error(Json(e.to_string())),
        }

        let command_id = Uuid::new_v4();
        let command = node_commands::ActiveModel {
            id: Set(command_id),
            server_id: Set(id.0),
            command_type: Set("set_accepting_connections".to_string()),
            accepting_connections: Set(Some(req.0.accepting_connections)),
            status: Set("pending".to_string()),
            created_at: Set(Utc::now().naive_utc()),
            started_at: Set(None),
            completed_at: Set(None),
            error: Set(None),
        };
        match command.insert(&self.db).await {
            Ok(saved) => CreateNodeCommandResponse::Created(Json(NodeCommand {
                command_id: saved.id.to_string(),
                command_type: saved.command_type,
                accepting_connections: saved.accepting_connections,
            })),
            Err(e) => CreateNodeCommandResponse::Error(Json(e.to_string())),
        }
    }

    /// Получить состояние ранее поставленной управляющей команды.
    #[oai(path = "/servers/:server_id/commands/:command_id", method = "get")]
    async fn get_node_command_status(
        &self,
        auth: AdminToken,
        server_id: poem_openapi::param::Path<Uuid>,
        command_id: poem_openapi::param::Path<Uuid>,
    ) -> GetNodeCommandStatusResponse {
        if let Err(err) = validate_admin_session(&self.db, &auth.0.token).await {
            return GetNodeCommandStatusResponse::Unauthorized(Json(err));
        }

        match node_commands::Entity::find_by_id(command_id.0)
            .one(&self.db)
            .await
        {
            Ok(Some(command)) if command.server_id == server_id.0 => {
                GetNodeCommandStatusResponse::Ok(Json(NodeCommandStatusDto {
                    command_id: command.id,
                    server_id: command.server_id,
                    command_type: command.command_type,
                    status: command.status,
                    accepting_connections: command.accepting_connections,
                    created_at: command.created_at.and_utc().to_rfc3339(),
                    started_at: command.started_at.map(|value| value.and_utc().to_rfc3339()),
                    completed_at: command
                        .completed_at
                        .map(|value| value.and_utc().to_rfc3339()),
                    error: command.error,
                }))
            }
            Ok(Some(_)) | Ok(None) => {
                GetNodeCommandStatusResponse::NotFound(Json("Command not found".to_string()))
            }
            Err(e) => GetNodeCommandStatusResponse::Error(Json(e.to_string())),
        }
    }

    /// Выпустить новый индивидуальный credential ноды. Секрет возвращается только один раз.
    #[oai(path = "/servers/:id/credentials", method = "post")]
    async fn rotate_node_credential(
        &self,
        auth: AdminToken,
        id: poem_openapi::param::Path<Uuid>,
    ) -> RotateNodeCredentialResponse {
        if let Err(err) = validate_admin_session(&self.db, &auth.0.token).await {
            return RotateNodeCredentialResponse::Unauthorized(Json(err));
        }

        let node = match servers::Entity::find_by_id(id.0).one(&self.db).await {
            Ok(Some(node)) => node,
            Ok(None) => {
                return RotateNodeCredentialResponse::NotFound(Json("Node not found".to_string()));
            }
            Err(e) => return RotateNodeCredentialResponse::Error(Json(e.to_string())),
        };
        let token = generate_node_token();
        let mut active = node.into_active_model();
        active.control_token_hash = Set(Some(hash_node_token(&token)));
        active.updated_at = Set(Utc::now().naive_utc());
        match active.update(&self.db).await {
            Ok(_) => RotateNodeCredentialResponse::Ok(Json(NodeCredentialDto {
                node_id: id.0,
                token,
            })),
            Err(e) => RotateNodeCredentialResponse::Error(Json(e.to_string())),
        }
    }

    /// Забрать следующую ожидающую команду. Вызов выполняется самой нодой.
    #[oai(path = "/control/nodes/commands", method = "get")]
    async fn get_node_commands(
        &self,
        #[oai(name = "X-Node-Token")] node_token: poem_openapi::param::Header<String>,
        node_id: Query<String>,
    ) -> GetNodeCommandsResponse {
        let node_id = match Uuid::parse_str(&node_id.0) {
            Ok(id) => id,
            Err(_) => {
                return GetNodeCommandsResponse::BadRequest(Json("Invalid node_id".to_string()));
            }
        };
        match node_token_is_valid(&self.db, node_id, &node_token.0).await {
            Ok(true) => {}
            Ok(false) => {
                return GetNodeCommandsResponse::Unauthorized(Json(
                    "Invalid node credential".to_string(),
                ));
            }
            Err(e) => return GetNodeCommandsResponse::Error(Json(e.to_string())),
        }
        match servers::Entity::find_by_id(node_id).one(&self.db).await {
            Ok(Some(_)) => {}
            Ok(None) => {
                return GetNodeCommandsResponse::NotFound(Json("Node not found".to_string()));
            }
            Err(e) => return GetNodeCommandsResponse::Error(Json(e.to_string())),
        }

        let stale_before = Utc::now().naive_utc() - chrono::Duration::seconds(60);
        if let Err(e) = node_commands::Entity::update_many()
            .col_expr(
                node_commands::Column::Status,
                sea_orm::sea_query::Expr::value("pending"),
            )
            .col_expr(
                node_commands::Column::StartedAt,
                sea_orm::sea_query::Expr::value(Option::<NaiveDateTime>::None),
            )
            .filter(node_commands::Column::ServerId.eq(node_id))
            .filter(node_commands::Column::Status.eq("running"))
            .filter(node_commands::Column::StartedAt.lt(stale_before))
            .exec(&self.db)
            .await
        {
            return GetNodeCommandsResponse::Error(Json(e.to_string()));
        }

        let pending = match node_commands::Entity::find()
            .filter(node_commands::Column::ServerId.eq(node_id))
            .filter(node_commands::Column::Status.eq("pending"))
            .order_by_asc(node_commands::Column::CreatedAt)
            .one(&self.db)
            .await
        {
            Ok(command) => command,
            Err(e) => return GetNodeCommandsResponse::Error(Json(e.to_string())),
        };

        let Some(command) = pending else {
            return GetNodeCommandsResponse::Ok(Json(Vec::new()));
        };
        let mut claimed = command.into_active_model();
        claimed.status = Set("running".to_string());
        claimed.started_at = Set(Some(Utc::now().naive_utc()));
        match claimed.update(&self.db).await {
            Ok(saved) => GetNodeCommandsResponse::Ok(Json(vec![NodeCommand {
                command_id: saved.id.to_string(),
                command_type: saved.command_type,
                accepting_connections: saved.accepting_connections,
            }])),
            Err(e) => GetNodeCommandsResponse::Error(Json(e.to_string())),
        }
    }

    /// Зафиксировать результат выполнения команды нодой.
    #[oai(path = "/control/nodes/commands/:id/result", method = "post")]
    async fn complete_node_command(
        &self,
        #[oai(name = "X-Node-Token")] node_token: poem_openapi::param::Header<String>,
        id: poem_openapi::param::Path<Uuid>,
        req: Json<NodeCommandResultRequest>,
    ) -> NodeCommandResultResponse {
        let node_id = match Uuid::parse_str(&req.0.node_id) {
            Ok(id) => id,
            Err(_) => {
                return NodeCommandResultResponse::BadRequest(Json("Invalid node_id".to_string()));
            }
        };
        match node_token_is_valid(&self.db, node_id, &node_token.0).await {
            Ok(true) => {}
            Ok(false) => {
                return NodeCommandResultResponse::Unauthorized(Json(
                    "Invalid node credential".to_string(),
                ));
            }
            Err(e) => return NodeCommandResultResponse::Error(Json(e.to_string())),
        }
        let command = match node_commands::Entity::find_by_id(id.0).one(&self.db).await {
            Ok(Some(command)) => command,
            Ok(None) => {
                return NodeCommandResultResponse::NotFound(Json("Command not found".to_string()));
            }
            Err(e) => return NodeCommandResultResponse::Error(Json(e.to_string())),
        };
        if command.server_id != node_id {
            return NodeCommandResultResponse::Conflict(Json(
                "Command belongs to another node".to_string(),
            ));
        }
        if command.status == "succeeded" || command.status == "failed" {
            return NodeCommandResultResponse::Accepted;
        }

        let mut completed = command.into_active_model();
        completed.status = Set(if req.0.succeeded {
            "succeeded"
        } else {
            "failed"
        }
            .to_string());
        completed.completed_at = Set(Some(Utc::now().naive_utc()));
        completed.error = Set(req.0.error);
        match completed.update(&self.db).await {
            Ok(_) => NodeCommandResultResponse::Accepted,
            Err(e) => NodeCommandResultResponse::Error(Json(e.to_string())),
        }
    }
}
