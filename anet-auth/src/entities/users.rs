use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "users")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    #[sea_orm(unique, column_type = "Text")]
    pub fingerprint: String,
    #[sea_orm(column_type = "Text", nullable)]
    pub uid: Option<String>,
    pub is_active: bool,
    pub created_at: DateTime,
    pub updated_at: DateTime,
    pub static_ip: Option<String>,
    pub private_key: Option<String>,
    pub public_key: Option<String>,
    pub route_map_id: Option<Uuid>,
    pub group_id: Option<Uuid>,

    // ========================================================================
    // НОВЫЕ ПОЛЯ: Коммерческий модуль, Личный Кабинет & Smart Activation
    // ========================================================================
    /// Email пользователя для входа в Личный Кабинет
    #[sea_orm(unique, nullable)]
    pub email: Option<String>,
    /// Хэш пароля для авторизации в веб-интерфейсе
    #[sea_orm(nullable)]
    pub password_hash: Option<String>,
    /// Telegram ID для входа через Telegram Bot / Mini App (TMA)
    #[sea_orm(unique, nullable)]
    pub telegram_id: Option<i64>,
    /// Текущий рублевый/валютный баланс в системе
    pub balance: f64,
    /// Момент первой сетевой активности (Smart Activation через ASTP handshake)
    pub activated_at: Option<DateTimeUtc>,
    /// Момент окончания оплаченного периода действия тарифа
    pub expires_at: Option<DateTimeUtc>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(has_one = "super::rates::Entity")]
    Rate,
    #[sea_orm(has_one = "super::active_sessions::Entity")]
    ActiveSession,
    #[sea_orm(
        belongs_to = "super::route_maps::Entity",
        from = "Column::RouteMapId",
        to = "super::route_maps::Column::Id",
        on_update = "Cascade",
        on_delete = "SetNull"
    )]
    RouteMap,
    #[sea_orm(
        belongs_to = "super::groups::Entity",
        from = "Column::GroupId",
        to = "super::groups::Column::Id",
        on_update = "Cascade",
        on_delete = "SetNull"
    )]
    Group,
    /// Связь с историей оформленных заказов биллинга
    #[sea_orm(has_many = "super::orders::Entity")]
    Orders,
    /// Связь с ваучерами, купленными данным пользователем
    #[sea_orm(has_many = "super::vouchers::Entity")]
    BoughtVouchers,
}

impl Related<super::rates::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Rate.def()
    }
}

impl Related<super::active_sessions::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::ActiveSession.def()
    }
}

impl Related<super::route_maps::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::RouteMap.def()
    }
}

impl Related<super::groups::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Group.def()
    }
}

impl Related<super::servers::Entity> for Entity {
    fn to() -> RelationDef {
        super::user_servers::Relation::Server.def()
    }
    fn via() -> Option<RelationDef> {
        Some(super::user_servers::Relation::User.def().rev())
    }
}

impl Related<super::orders::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Orders.def()
    }
}

impl Related<super::vouchers::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::BoughtVouchers.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
