use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "verification_tokens")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    /// Привязка к существующему пользователю (для связки Telegram TMA -> Web-кабинет)
    pub user_id: Option<Uuid>,
    /// Email в нижнем регистре, на который отправлена ссылка подтверждения
    #[sea_orm(column_type = "Text")]
    pub email: String,
    /// SHA-256 хэш одноразового токена (в сыром виде токен хранится только в ссылке)
    #[sea_orm(unique, column_type = "Text")]
    pub token_hash: String,
    /// Срок годности токена (verification_token_ttl_mins)
    pub expires_at: DateTimeUtc,
    /// Время фактического использования токена (None = еще не использован)
    pub used_at: Option<DateTimeUtc>,
    /// Время создания токена
    pub created_at: DateTimeUtc,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::users::Entity",
        from = "Column::UserId",
        to = "super::users::Column::Id",
        on_update = "Cascade",
        on_delete = "Cascade"
    )]
    User,
}

impl Related<super::users::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::User.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
