//! Сущность внешнего провайдера правил (DomainList / IpList).
use poem_openapi::Enum as OpenApiEnum;
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, EnumIter, DeriveActiveEnum, Serialize, Deserialize, OpenApiEnum,
)]
#[sea_orm(rs_type = "String", db_type = "Text")]
pub enum ProviderType {
    #[oai(rename = "domain")]
    #[serde(rename = "domain")]
    #[sea_orm(string_value = "domain")]
    DomainList,

    #[oai(rename = "ip")]
    #[serde(rename = "ip")]
    #[sea_orm(string_value = "ip")]
    IpList,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, EnumIter, DeriveActiveEnum, Serialize, Deserialize, OpenApiEnum,
)]
#[sea_orm(rs_type = "String", db_type = "Text")]
pub enum ProviderFormat {
    #[oai(rename = "plain")]
    #[serde(rename = "plain")]
    #[sea_orm(string_value = "plain")]
    PlainText,

    #[oai(rename = "v2ray")]
    #[serde(rename = "v2ray")]
    #[sea_orm(string_value = "v2ray")]
    V2RayDomain,

    #[oai(rename = "cidr")]
    #[serde(rename = "cidr")]
    #[sea_orm(string_value = "cidr")]
    CidrList,
}

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "rule_providers")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub name: String,
    pub description: String,
    pub provider_type: ProviderType,
    pub format: ProviderFormat,
    pub url: String,
    pub update_interval_hours: i32,
    pub last_fetched_at: Option<DateTime>,
    pub last_etag: Option<String>,
    pub item_count: i64,
    pub is_active: bool,
    pub created_at: DateTime,
    pub updated_at: DateTime,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
