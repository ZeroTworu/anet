use poem_openapi::{ApiResponse, Object, SecurityScheme, auth::Bearer, payload::Json, payload::PlainText};
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

// Реэкспортируем общие DTO-структуры из anet-common
pub use anet_common::dto::{
    CheckAccessRequest, CheckAccessResponse, SessionEventRequest
};

/// [ VPN Server Management Area ]
#[derive(Object, Debug, Clone, Serialize, Deserialize)]
pub struct ServerDto {
    pub id: uuid::Uuid,
    pub name: String,
    pub address: String,
    pub public_key: String,
    pub quic_port: Option<i32>,
    pub ssh_port: Option<i32>,
    pub vnc_port: Option<i32>,
    pub ssh_user: Option<String>,
    pub is_active: bool,
}

#[derive(Object, Debug, Clone, Serialize, Deserialize)]
pub struct CreateServerRequest {
    pub name: String,
    pub address: String,
    pub public_key: String,
    pub quic_port: Option<i32>,
    pub ssh_port: Option<i32>,
    pub vnc_port: Option<i32>,
    pub ssh_user: Option<String>,
    pub is_active: Option<bool>,
}

#[derive(ApiResponse)]
pub enum GetServersResponse {
    #[oai(status = 200, content_type = "application/json")]
    Ok(Json<Vec<ServerDto>>),
    #[oai(status = 401, content_type = "application/json")]
    Unauthorized(Json<String>),
    #[oai(status = 500, content_type = "application/json")]
    Error(Json<String>),
}

//  DTO для PATCH-запросов обновления сервера
#[derive(Object, Debug, Clone, Serialize, Deserialize)]
pub struct UpdateServerRequest {
    pub name: Option<String>,
    pub address: Option<String>,
    pub public_key: Option<String>,
    pub quic_port: Option<Option<i32>>,
    pub ssh_port: Option<Option<i32>>,
    pub vnc_port: Option<Option<i32>>,
    pub ssh_user: Option<Option<String>>,
    pub is_active: Option<bool>,
}

#[derive(ApiResponse)]
pub enum UpdateServerApiResult {
    #[oai(status = 200)]
    Ok(Json<ServerDto>),
    #[oai(status = 401)]
    Unauthorized(Json<String>),
    #[oai(status = 404)]
    NotFound(Json<String>),
    #[oai(status = 500)]
    Error(Json<String>),
}


/// [ VPN Core Communication: Session Lifecycle ]
#[derive(Object)]
pub struct SessionEventRequestLocal {
    pub fingerprint: String,
}

#[derive(ApiResponse)]
pub enum SessionEventResponse {
    #[oai(status = 200)]
    Ok,
    #[oai(status = 404)]
    NotFound,
    #[oai(status = 500)]
    Error,
}

/// [ Authentication Area ]
#[derive(Object)]
pub struct LoginRequest {
    #[oai(validator(max_length = 100))]
    pub login: String,
    pub password: String,
}

#[derive(Object)]
pub struct AuthTokens {
    pub access_token: String,
}

#[derive(ApiResponse)]
pub enum LoginResponse {
    #[oai(status = 200)]
    Ok(Json<AuthTokens>),
    #[oai(status = 401)]
    Unauthorized(Json<String>),
    #[oai(status = 500)]
    Error,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub jti: String,
    pub sub: String,
    pub exp: usize,
}

/// [ User Management Area ]
#[derive(SecurityScheme)]
#[oai(ty = "bearer", bearer_format = "jwt")]
pub struct AdminToken(pub Bearer);

#[derive(Object, Debug, Serialize, Deserialize, Clone)]
pub struct RateReqDto {
    pub sessions: u32,
    pub date_end: String,
}

#[derive(Object, Debug, Serialize, Deserialize, Clone)]
pub struct RateDto {
    pub id: uuid::Uuid,
    pub sessions: u32,
    pub date_end: String,
}

#[derive(Object)]
pub struct VpnUserDto {
    pub id: uuid::Uuid,
    pub fingerprint: String,
    pub uid: Option<String>,
    pub is_active: bool,
    pub created_at: String,
    pub rate: Option<RateDto>,
    pub static_ip: Option<Ipv4Addr>,
    pub server_ids: Vec<uuid::Uuid>,
}

#[derive(Object)]
pub struct PaginatedUsers {
    pub total: u64,
    pub items: Vec<VpnUserDto>,
}

#[derive(ApiResponse)]
pub enum GetUsersResponse {
    #[oai(status = 200)]
    Ok(Json<PaginatedUsers>),
    #[oai(status = 401)]
    Unauthorized(Json<String>),
    #[oai(status = 500)]
    Error(Json<String>),
}

#[derive(ApiResponse)]
pub enum GetUserApiResult {
    #[oai(status = 200)]
    Ok(Json<VpnUserDto>),
    #[oai(status = 401)]
    Unauthorized(Json<String>),
    #[oai(status = 404)]
    NotFound(Json<String>),
    #[oai(status = 500)]
    Error(Json<String>),
}

#[derive(Object)]
pub struct AddUserRequest {
    pub uid: String,
    pub rate: Option<RateReqDto>,
    pub server_ids: Option<Vec<uuid::Uuid>>,
}

#[derive(Object)]
pub struct AddUserResponse {
    pub id: uuid::Uuid,
    pub uid: String,
    pub fingerprint: String,
    pub private_key: String,
    pub public_key: String,
    pub rate: Option<RateDto>,
}

#[derive(ApiResponse)]
pub enum AddUserApiResult {
    #[oai(status = 200)]
    Ok(Json<AddUserResponse>),
    #[oai(status = 401)]
    Unauthorized(Json<String>),
    #[oai(status = 500)]
    Error(Json<String>),
}

#[derive(Object)]
pub struct UpdateUserRequest {
    pub uid: Option<String>,
    pub is_active: Option<bool>,
    pub static_ip: Option<String>,
    pub server_ids: Option<Vec<uuid::Uuid>>,
}

#[derive(ApiResponse)]
pub enum UpdateUserApiResult {
    #[oai(status = 200)]
    Ok(Json<VpnUserDto>),
    #[oai(status = 400)]
    BadRequest(Json<String>),
    #[oai(status = 401)]
    Unauthorized(Json<String>),
    #[oai(status = 404)]
    NotFound(Json<String>),
    #[oai(status = 500)]
    Error(Json<String>),
}

#[derive(Object)]
pub struct UpdateRateRequest {
    pub sessions: Option<u32>,
    pub date_end: Option<String>,
}

#[derive(ApiResponse)]
pub enum UpdateRateApiResult {
    #[oai(status = 200)]
    Ok(Json<RateDto>),
    #[oai(status = 400)]
    BadRequest(Json<String>),
    #[oai(status = 401)]
    Unauthorized(Json<String>),
    #[oai(status = 404)]
    NotFound(Json<String>),
    #[oai(status = 500)]
    Error(Json<String>),
}

#[derive(Object)]
pub struct AddRateRequest {
    pub sessions: Option<u32>,
    pub date_end: Option<String>,
}

#[derive(ApiResponse)]
pub enum AddRateApiResult {
    #[oai(status = 200)]
    Ok(Json<RateDto>),
    #[oai(status = 400)]
    BadRequest(Json<String>),
    #[oai(status = 401)]
    Unauthorized(Json<String>),
    #[oai(status = 404)]
    NotFound(Json<String>),
    #[oai(status = 500)]
    Error(Json<String>),
}

#[derive(Object)]
pub struct RegenerateUserResponse {
    pub id: uuid::Uuid,
    pub uid: Option<String>,
    pub fingerprint: String,
    pub private_key: String,
    pub public_key: String,
}

#[derive(ApiResponse)]
pub enum RegenerateUserApiResult {
    #[oai(status = 200)]
    Ok(Json<RegenerateUserResponse>),
    #[oai(status = 401)]
    Unauthorized(Json<String>),
    #[oai(status = 404)]
    NotFound(Json<String>),
    #[oai(status = 500)]
    Error(Json<String>),
}


#[derive(ApiResponse)]
pub enum DownloadConfigResponse {
    /// Возвращает сгенерированный файл конфигурации в виде вложения
    #[oai(status = 200, content_type = "application/octet-stream")]
    Ok(
        PlainText<String>, // <--- ПЕРВЫЙ АРГУМЕНТ: ТЕЛО ФАЙЛА (Payload)
        #[oai(header = "Content-Disposition")] String,
    ),
    #[oai(status = 404, content_type = "application/json")]
    NotFound(Json<String>),
    #[oai(status = 500, content_type = "application/json")]
    Error(Json<String>),
}

#[derive(ApiResponse)]
pub enum QrPageResponse {
    /// Возвращает готовую HTML-страницу с QR-кодом и кнопкой скачивания
    #[oai(status = 200, content_type = "text/html")]
    Ok(PlainText<String>),
    #[oai(status = 404, content_type = "application/json")]
    NotFound(Json<String>),
    #[oai(status = 500, content_type = "application/json")]
    Error(Json<String>),
}
