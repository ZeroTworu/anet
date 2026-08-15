use poem_openapi::{
    ApiResponse, Object, SecurityScheme, auth::Bearer, payload::Json, payload::PlainText,
};
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

// Реэкспортируем общие DTO-структуры из anet-common
pub use anet_common::dto::{
    CheckAccessRequest, CheckAccessResponse, NodeCommand, NodeCommandResultRequest,
    NodeHeartbeatRequest, NodeTrafficReport, SessionEventRequest,
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
    pub websocket_url: Option<String>,
    pub ssh_user: Option<String>,
    pub is_active: bool,
    pub has_control_credential: bool,
    pub runtime: Option<NodeRuntimeDto>,
}

#[derive(Object, Debug, Clone, Serialize, Deserialize)]
pub struct NodeRuntimeDto {
    pub status: String,
    pub last_seen_at: String,
    pub version: String,
    pub uptime_seconds: u64,
    pub active_connections: u64,
    pub accepting_connections: bool,
}

#[derive(ApiResponse)]
pub enum NodeHeartbeatResponse {
    #[oai(status = 204)]
    Accepted,
    #[oai(status = 400)]
    BadRequest(Json<String>),
    #[oai(status = 401)]
    Unauthorized(Json<String>),
    #[oai(status = 404)]
    NotFound(Json<String>),
    #[oai(status = 500)]
    Error(Json<String>),
}

#[derive(Object, Debug, Clone, Serialize, Deserialize)]
pub struct CreateAdmissionCommandRequest {
    pub accepting_connections: bool,
}

#[derive(ApiResponse)]
pub enum CreateNodeCommandResponse {
    #[oai(status = 201)]
    Created(Json<NodeCommand>),
    #[oai(status = 401)]
    Unauthorized(Json<String>),
    #[oai(status = 404)]
    NotFound(Json<String>),
    #[oai(status = 500)]
    Error(Json<String>),
}

#[derive(Object, Debug, Clone, Serialize, Deserialize)]
pub struct NodeCommandStatusDto {
    pub command_id: uuid::Uuid,
    pub server_id: uuid::Uuid,
    pub command_type: String,
    pub status: String,
    pub accepting_connections: Option<bool>,
    pub created_at: String,
    pub started_at: Option<String>,
    pub completed_at: Option<String>,
    pub error: Option<String>,
}

#[derive(ApiResponse)]
pub enum GetNodeCommandStatusResponse {
    #[oai(status = 200)]
    Ok(Json<NodeCommandStatusDto>),
    #[oai(status = 401)]
    Unauthorized(Json<String>),
    #[oai(status = 404)]
    NotFound(Json<String>),
    #[oai(status = 500)]
    Error(Json<String>),
}

#[derive(ApiResponse)]
pub enum GetNodeCommandsResponse {
    #[oai(status = 200)]
    Ok(Json<Vec<NodeCommand>>),
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
pub enum NodeCommandResultResponse {
    #[oai(status = 204)]
    Accepted,
    #[oai(status = 400)]
    BadRequest(Json<String>),
    #[oai(status = 401)]
    Unauthorized(Json<String>),
    #[oai(status = 404)]
    NotFound(Json<String>),
    #[oai(status = 409)]
    Conflict(Json<String>),
    #[oai(status = 500)]
    Error(Json<String>),
}

#[derive(ApiResponse)]
pub enum TrafficReportResponse {
    #[oai(status = 204)]
    Accepted,
    #[oai(status = 400)]
    BadRequest(Json<String>),
    #[oai(status = 401)]
    Unauthorized(Json<String>),
    #[oai(status = 404)]
    NotFound(Json<String>),
    #[oai(status = 500)]
    Error(Json<String>),
}

#[derive(Object, Debug, Clone, Serialize, Deserialize)]
pub struct NodeCredentialDto {
    pub node_id: uuid::Uuid,
    pub token: String,
}

#[derive(ApiResponse)]
pub enum RotateNodeCredentialResponse {
    #[oai(status = 200)]
    Ok(Json<NodeCredentialDto>),
    #[oai(status = 401)]
    Unauthorized(Json<String>),
    #[oai(status = 404)]
    NotFound(Json<String>),
    #[oai(status = 500)]
    Error(Json<String>),
}

#[derive(Object, Debug, Clone, Serialize, Deserialize)]
pub struct NodeTrafficStatDto {
    pub node_id: uuid::Uuid,
    pub name: String,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

#[derive(Object, Debug, Clone, Serialize, Deserialize)]
pub struct UserTrafficStatDto {
    pub user_id: Option<uuid::Uuid>,
    pub uid: Option<String>,
    pub fingerprint: String,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

#[derive(ApiResponse)]
pub enum GetNodeTrafficStatsResponse {
    #[oai(status = 200)]
    Ok(Json<Vec<NodeTrafficStatDto>>),
    #[oai(status = 401)]
    Unauthorized(Json<String>),
    #[oai(status = 500)]
    Error(Json<String>),
}

#[derive(ApiResponse)]
pub enum GetUserTrafficStatsResponse {
    #[oai(status = 200)]
    Ok(Json<Vec<UserTrafficStatDto>>),
    #[oai(status = 401)]
    Unauthorized(Json<String>),
    #[oai(status = 500)]
    Error(Json<String>),
}

#[derive(Object, Debug, Clone, Serialize, Deserialize)]
pub struct TrafficHistoryPointDto {
    pub bucket_start: String,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

#[derive(ApiResponse)]
pub enum GetTrafficHistoryResponse {
    #[oai(status = 200)]
    Ok(Json<Vec<TrafficHistoryPointDto>>),
    #[oai(status = 401)]
    Unauthorized(Json<String>),
    #[oai(status = 500)]
    Error(Json<String>),
}

#[derive(Object, Debug, Clone, Serialize, Deserialize)]
pub struct CreateServerRequest {
    pub name: String,
    pub address: String,
    pub public_key: String,
    pub quic_port: Option<i32>,
    pub ssh_port: Option<i32>,
    pub vnc_port: Option<i32>,
    pub websocket_url: Option<String>,
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
    pub websocket_url: Option<Option<String>>,
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
    pub pool_ids: Vec<uuid::Uuid>,
    pub route_map_id: Option<uuid::Uuid>,
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
    pub pool_ids: Option<Vec<uuid::Uuid>>,
    pub route_map_id: Option<uuid::Uuid>,
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
    pub pool_ids: Option<Vec<uuid::Uuid>>,
    pub route_map_id: Option<uuid::Uuid>,
    pub clear_route_map: Option<bool>,
}

#[derive(Object, Debug, Clone, Serialize, Deserialize)]
pub struct RouteRuleDto {
    pub id: Option<uuid::Uuid>,
    pub position: u32,
    pub match_type: String,
    pub match_value: String,
    pub action: String,
}

#[derive(Object, Debug, Clone, Serialize, Deserialize)]
pub struct RouteMapDto {
    pub id: uuid::Uuid,
    pub name: String,
    pub description: String,
    pub default_action: String,
    pub is_active: bool,
    pub revision: u64,
    pub rules: Vec<RouteRuleDto>,
}

#[derive(Object, Debug, Clone, Serialize, Deserialize)]
pub struct SaveRouteMapRequest {
    pub name: String,
    pub description: String,
    pub default_action: String,
    pub is_active: Option<bool>,
    pub rules: Vec<RouteRuleDto>,
}

#[derive(ApiResponse)]
pub enum GetRouteMapsResponse {
    #[oai(status = 200)]
    Ok(Json<Vec<RouteMapDto>>),
    #[oai(status = 401)]
    Unauthorized(Json<String>),
    #[oai(status = 500)]
    Error(Json<String>),
}

#[derive(ApiResponse)]
pub enum SaveRouteMapResponse {
    #[oai(status = 200)]
    Ok(Json<RouteMapDto>),
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
pub enum DeleteRouteMapResponse {
    #[oai(status = 204)]
    Deleted,
    #[oai(status = 401)]
    Unauthorized(Json<String>),
    #[oai(status = 404)]
    NotFound(Json<String>),
    #[oai(status = 500)]
    Error(Json<String>),
}

#[derive(Object, Debug, Clone, Serialize, Deserialize)]
pub struct NodePoolMemberDto {
    pub server_id: uuid::Uuid,
    pub weight: u32,
}

#[derive(Object, Debug, Clone, Serialize, Deserialize)]
pub struct NodePoolDto {
    pub id: uuid::Uuid,
    pub name: String,
    pub strategy: String,
    pub is_active: bool,
    pub members: Vec<NodePoolMemberDto>,
}

#[derive(Object, Debug, Clone, Serialize, Deserialize)]
pub struct SaveNodePoolRequest {
    pub name: String,
    pub strategy: String,
    pub is_active: Option<bool>,
    pub members: Vec<NodePoolMemberDto>,
}

#[derive(ApiResponse)]
pub enum GetNodePoolsResponse {
    #[oai(status = 200)]
    Ok(Json<Vec<NodePoolDto>>),
    #[oai(status = 401)]
    Unauthorized(Json<String>),
    #[oai(status = 500)]
    Error(Json<String>),
}

#[derive(ApiResponse)]
pub enum SaveNodePoolResponse {
    #[oai(status = 200)]
    Ok(Json<NodePoolDto>),
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
pub enum DeleteNodePoolResponse {
    #[oai(status = 204)]
    Deleted,
    #[oai(status = 401)]
    Unauthorized(Json<String>),
    #[oai(status = 404)]
    NotFound(Json<String>),
    #[oai(status = 500)]
    Error(Json<String>),
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
