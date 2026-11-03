//! Модель данных служебного почтового ящика в БД

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "imap_mailboxes")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    /// Адрес IMAP-сервера провайдера (например, imap.mail.ru)
    pub host: String,
    /// Порт IMAP-сервера (обычно 993 для IMAPS)
    pub port: i32,
    /// Логин (email) от почтового ящика
    pub email: String,
    /// Зашифрованный пароль приложения для КЛИЕНТОВ (шифруется через DbEncryptor::encrypt)
    pub client_password_encrypted: String,
    /// Опциональный отдельный зашифрованный пароль приложения для СЕРВЕРА
    pub server_password_encrypted: Option<String>,
    pub is_active: bool,
    pub created_at: DateTime,
    pub updated_at: DateTime,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
