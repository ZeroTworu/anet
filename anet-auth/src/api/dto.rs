use poem_openapi::{ApiResponse, Object, SecurityScheme, auth::Bearer, payload::Json};
use serde::{Deserialize, Serialize};

/// [ VPN Core Communication ]
#[derive(Object)]
pub struct CheckAccessRequest {
    #[oai(validator(min_length = 10))]
    pub fingerprint: String,
}

#[derive(Object)]
pub struct CheckAccessResponse {
    pub allowed: bool,
    pub message: String,
}

#[derive(Object)]
pub struct SessionEventRequest {
    pub fingerprint: String,
}

#[derive(ApiResponse)]
pub enum SessionEventResponse {
    #[oai(status = 200)] Ok,
    #[oai(status = 404)] NotFound,
    #[oai(status = 500)] Error,
}

/// [ Authentication Area ]
#[derive(Object)]
pub struct LoginRequest {
    #[oai(validator(max_length = 100))]
    pub login: String,
    pub password: String,
}

#[derive(Object)]
pub struct AuthTokens { pub access_token: String }

#[derive(ApiResponse)]
pub enum LoginResponse {
    #[oai(status = 200)] Ok(Json<AuthTokens>),
    #[oai(status = 401)] Unauthorized(Json<String>),
    #[oai(status = 500)] Error,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims { pub jti: String, pub sub: String, pub exp: usize }

/// [ User Management Area ]
#[derive(SecurityScheme)]
#[oai(ty = "bearer", bearer_format = "jwt")]
pub struct AdminToken(pub Bearer);

#[derive(Object, Debug, Serialize, Deserialize, Clone)]
pub struct RateReqDto { pub sessions: u32, pub date_end: String }

#[derive(Object, Debug, Serialize, Deserialize, Clone)]
pub struct RateDto { pub id: uuid::Uuid, pub sessions: u32, pub date_end: String }

#[derive(Object)]
pub struct VpnUserDto {
    pub id: uuid::Uuid,
    pub fingerprint: String,
    pub uid: Option<String>,
    pub is_active: bool,
    pub created_at: String,
    pub rate: Option<RateDto>,
}

#[derive(Object)]
pub struct PaginatedUsers { pub total: u64, pub items: Vec<VpnUserDto> }

#[derive(ApiResponse)]
pub enum GetUsersResponse {
    #[oai(status = 200)] Ok(Json<PaginatedUsers>),
    #[oai(status = 401)] Unauthorized(Json<String>),
    #[oai(status = 500)] Error(Json<String>),
}

#[derive(ApiResponse)]
pub enum GetUserApiResult {
    #[oai(status = 200)] Ok(Json<VpnUserDto>),
    #[oai(status = 401)] Unauthorized(Json<String>),
    #[oai(status = 404)] NotFound(Json<String>),
    #[oai(status = 500)] Error(Json<String>),
}

#[derive(Object)]
pub struct AddUserRequest { pub uid: String, pub rate: Option<RateReqDto> }

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
    #[oai(status = 200)] Ok(Json<AddUserResponse>),
    #[oai(status = 401)] Unauthorized(Json<String>),
    #[oai(status = 500)] Error(Json<String>),
}

#[derive(Object)]
pub struct UpdateUserRequest { pub uid: Option<String>, pub is_active: Option<bool> }

#[derive(ApiResponse)]
pub enum UpdateUserApiResult {
    #[oai(status = 200)] Ok(Json<VpnUserDto>),
    #[oai(status = 400)] BadRequest(Json<String>),
    #[oai(status = 401)] Unauthorized(Json<String>),
    #[oai(status = 404)] NotFound(Json<String>),
    #[oai(status = 500)] Error(Json<String>),
}

#[derive(Object)]
pub struct UpdateRateRequest { pub sessions: Option<u32>, pub date_end: Option<String> }

#[derive(ApiResponse)]
pub enum UpdateRateApiResult {
    #[oai(status = 200)] Ok(Json<RateDto>),
    #[oai(status = 400)] BadRequest(Json<String>),
    #[oai(status = 401)] Unauthorized(Json<String>),
    #[oai(status = 404)] NotFound(Json<String>),
    #[oai(status = 500)] Error(Json<String>),
}

#[derive(Object)]
pub struct RegenerateUserResponse {
    pub id: uuid::Uuid, pub uid: Option<String>, pub fingerprint: String,
    pub private_key: String, pub public_key: String,
}

#[derive(ApiResponse)]
pub enum RegenerateUserApiResult {
    #[oai(status = 200)] Ok(Json<RegenerateUserResponse>),
    #[oai(status = 401)] Unauthorized(Json<String>),
    #[oai(status = 404)] NotFound(Json<String>),
    #[oai(status = 500)] Error(Json<String>),
}
