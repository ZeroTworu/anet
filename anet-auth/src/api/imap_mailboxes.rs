//! API управления пулом почтовых ящиков IMAP для панели администратора.

use chrono::Utc;
use poem_openapi::{
    param::Path, payload::Json, ApiResponse, Object, OpenApi,
};
use sea_orm::{
    ActiveModelTrait, DatabaseConnection, EntityTrait, QueryOrder, Set,
};
use uuid::Uuid;

use crate::api::api::validate_admin_session;
use crate::api::dto::AdminToken;
use crate::crypto::DbEncryptor;
use crate::entities::imap_mailboxes;

#[derive(Object, Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ImapMailboxDto {
    pub id: Uuid,
    pub host: String,
    pub port: i32,
    pub email: String,
    pub has_client_password: bool,
    pub has_server_password: bool,
    pub is_active: bool,
    pub created_at: String,
    pub updated_at: String,
}

impl From<imap_mailboxes::Model> for ImapMailboxDto {
    fn from(m: imap_mailboxes::Model) -> Self {
        Self {
            id: m.id,
            host: m.host,
            port: m.port,
            email: m.email,
            has_client_password: !m.client_password_encrypted.is_empty(),
            has_server_password: m.server_password_encrypted.as_ref().map(|s| !s.is_empty()).unwrap_or(false),
            is_active: m.is_active,
            created_at: m.created_at.format("%Y-%m-%d %H:%M:%S").to_string(),
            updated_at: m.updated_at.format("%Y-%m-%d %H:%M:%S").to_string(),
        }
    }
}

#[derive(Object, Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CreateImapMailboxRequest {
    pub host: String,
    pub port: i32,
    pub email: String,
    pub client_password: String,
    pub server_password: Option<String>,
    pub is_active: bool,
}

#[derive(Object, Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct UpdateImapMailboxRequest {
    pub host: String,
    pub port: i32,
    pub email: String,
    pub client_password: Option<String>,
    pub server_password: Option<String>,
    pub is_active: bool,
}

#[derive(ApiResponse)]
pub enum GetMailboxesResponse {
    #[oai(status = 200)]
    Ok(Json<Vec<ImapMailboxDto>>),
    #[oai(status = 401)]
    Unauthorized(Json<String>),
    #[oai(status = 500)]
    Error(Json<String>),
}

#[derive(ApiResponse)]
pub enum SaveMailboxResponse {
    #[oai(status = 200)]
    Ok(Json<ImapMailboxDto>),
    #[oai(status = 400)]
    BadRequest(Json<String>),
    #[oai(status = 401)]
    Unauthorized(Json<String>),
    #[oai(status = 404)]
    NotFound(Json<String>),
    #[oai(status = 500)]
    Error(Json<String>),
}

#[derive(ApiResponse)]
pub enum DeleteMailboxResponse {
    #[oai(status = 200)]
    Ok(Json<bool>),
    #[oai(status = 401)]
    Unauthorized(Json<String>),
    #[oai(status = 404)]
    NotFound(Json<String>),
    #[oai(status = 500)]
    Error(Json<String>),
}

pub struct ImapMailboxesApi {
    pub db: DatabaseConnection,
}

#[OpenApi]
impl ImapMailboxesApi {
    /// Получить список всех настроенных почтовых ящиков IMAP
    #[oai(path = "/mailboxes", method = "get")]
    async fn list_mailboxes(
        &self,
        auth: AdminToken,
    ) -> GetMailboxesResponse {
        if let Err(e) = validate_admin_session(&self.db, &auth.0.token).await {
            return GetMailboxesResponse::Unauthorized(Json(e));
        }

        match imap_mailboxes::Entity::find()
            .order_by_desc(imap_mailboxes::Column::CreatedAt)
            .all(&self.db)
            .await
        {
            Ok(mailboxes) => {
                let dtos = mailboxes.into_iter().map(ImapMailboxDto::from).collect();
                GetMailboxesResponse::Ok(Json(dtos))
            }
            Err(e) => GetMailboxesResponse::Error(Json(format!("Database error: {e}"))),
        }
    }

    /// Создать новую запись почтового ящика IMAP
    #[oai(path = "/mailboxes", method = "post")]
    async fn create_mailbox(
        &self,
        auth: AdminToken,
        body: Json<CreateImapMailboxRequest>,
    ) -> SaveMailboxResponse {
        if let Err(e) = validate_admin_session(&self.db, &auth.0.token).await {
            return SaveMailboxResponse::Unauthorized(Json(e));
        }

        let req = body.0;
        let host = req.host.trim().to_string();
        let email = req.email.trim().to_string();
        let client_pwd = req.client_password.trim();

        if host.is_empty() || email.is_empty() || client_pwd.is_empty() {
            return SaveMailboxResponse::BadRequest(Json(
                "Host, email and client_password are required".to_string(),
            ));
        }

        let encryptor = DbEncryptor::new();
        let enc_client_pwd = match encryptor.encrypt(client_pwd) {
            Ok(val) => val,
            Err(e) => return SaveMailboxResponse::Error(Json(format!("Encryption error: {e}"))),
        };

        let enc_server_pwd = if let Some(ref sp) = req.server_password {
            let trimmed = sp.trim();
            if !trimmed.is_empty() {
                match encryptor.encrypt(trimmed) {
                    Ok(val) => Some(val),
                    Err(e) => return SaveMailboxResponse::Error(Json(format!("Encryption error: {e}"))),
                }
            } else {
                None
            }
        } else {
            None
        };

        let now = Utc::now().naive_utc();
        let new_model = imap_mailboxes::ActiveModel {
            id: Set(Uuid::new_v4()),
            host: Set(host),
            port: Set(if req.port > 0 { req.port } else { 993 }),
            email: Set(email),
            client_password_encrypted: Set(enc_client_pwd),
            server_password_encrypted: Set(enc_server_pwd),
            is_active: Set(req.is_active),
            created_at: Set(now),
            updated_at: Set(now),
        };

        match new_model.insert(&self.db).await {
            Ok(saved) => SaveMailboxResponse::Ok(Json(ImapMailboxDto::from(saved))),
            Err(e) => SaveMailboxResponse::Error(Json(format!("Failed to insert mailbox: {e}"))),
        }
    }

    /// Обновить существующую запись почтового ящика IMAP
    #[oai(path = "/mailboxes/:id", method = "put")]
    async fn update_mailbox(
        &self,
        auth: AdminToken,
        id: Path<Uuid>,
        body: Json<UpdateImapMailboxRequest>,
    ) -> SaveMailboxResponse {
        if let Err(e) = validate_admin_session(&self.db, &auth.0.token).await {
            return SaveMailboxResponse::Unauthorized(Json(e));
        }

        let existing = match imap_mailboxes::Entity::find_by_id(id.0).one(&self.db).await {
            Ok(Some(m)) => m,
            Ok(None) => return SaveMailboxResponse::NotFound(Json("Mailbox not found".to_string())),
            Err(e) => return SaveMailboxResponse::Error(Json(format!("Database error: {e}"))),
        };

        let req = body.0;
        let encryptor = DbEncryptor::new();

        let mut active: imap_mailboxes::ActiveModel = existing.into();
        active.host = Set(req.host.trim().to_string());
        active.port = Set(if req.port > 0 { req.port } else { 993 });
        active.email = Set(req.email.trim().to_string());
        active.is_active = Set(req.is_active);
        active.updated_at = Set(Utc::now().naive_utc());

        if let Some(ref cp) = req.client_password {
            let trimmed = cp.trim();
            if !trimmed.is_empty() {
                match encryptor.encrypt(trimmed) {
                    Ok(val) => active.client_password_encrypted = Set(val),
                    Err(e) => return SaveMailboxResponse::Error(Json(format!("Encryption error: {e}"))),
                }
            }
        }

        if let Some(ref sp) = req.server_password {
            let trimmed = sp.trim();
            if !trimmed.is_empty() {
                match encryptor.encrypt(trimmed) {
                    Ok(val) => active.server_password_encrypted = Set(Some(val)),
                    Err(e) => return SaveMailboxResponse::Error(Json(format!("Encryption error: {e}"))),
                }
            } else {
                active.server_password_encrypted = Set(None);
            }
        }

        match active.update(&self.db).await {
            Ok(updated) => SaveMailboxResponse::Ok(Json(ImapMailboxDto::from(updated))),
            Err(e) => SaveMailboxResponse::Error(Json(format!("Failed to update mailbox: {e}"))),
        }
    }

    /// Удалить почтовый ящик
    #[oai(path = "/mailboxes/:id", method = "delete")]
    async fn delete_mailbox(
        &self,
        auth: AdminToken,
        id: Path<Uuid>,
    ) -> DeleteMailboxResponse {
        if let Err(e) = validate_admin_session(&self.db, &auth.0.token).await {
            return DeleteMailboxResponse::Unauthorized(Json(e));
        }

        match imap_mailboxes::Entity::delete_by_id(id.0).exec(&self.db).await {
            Ok(res) => {
                if res.rows_affected > 0 {
                    DeleteMailboxResponse::Ok(Json(true))
                } else {
                    DeleteMailboxResponse::NotFound(Json("Mailbox not found".to_string()))
                }
            }
            Err(e) => DeleteMailboxResponse::Error(Json(format!("Failed to delete: {e}"))),
        }
    }
}
