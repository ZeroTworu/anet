//! Модуль типов данных, перечислений и структур состояния

use std::sync::Arc;
use anet_client_core::{
    client::AnetClient,
    updater::GithubRelease,
};

/// Состояние подключения к VPN
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum ConnectionState {
    Disconnected,
    Connecting,
    Connected,
}

/// Состояния для встроенного апдейтера
#[derive(Clone)]
pub enum UpdateStatus {
    Idle,
    Checking,
    Available(GithubRelease),
    Downloading(f32),
    ReadyToRestart,
    Error(String),
}

/// Результат фонового построения AnetClient с флагом необходимости перезапуска
pub enum ConfigLoadOutcome {
    Loaded { id: String, name: String, reconnect: bool },
    Failed { id: String, error: String },
}

/// Режим фильтрации трафика приложений
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum FilterMode {
    All,
    Include,
    Exclude,
}

/// Информация об одном запущенном процессе (Windows)
#[derive(Clone, Debug)]
pub struct ProcessItem {
    pub pid: u32,
    pub name: String,
    pub is_selected: bool,
}

/// Разделяемое между потоками состояние VPN клиента
pub struct SharedState {
    pub client: Option<Arc<AnetClient>>,
    pub state: ConnectionState,
}

/// Категории страницы настроек
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum SettingsCategory {
    General,
    Configs,
    PerApp,
    ExcludedAdds,
    Connection,
    Routing,
    Security,
    SplitTunnel,
    Updates,
}

impl SettingsCategory {
    pub fn title(&self) -> &'static str {
        match self {
            Self::General => "Основные настройки",
            Self::Configs => "Конфиги",
            Self::PerApp => "Туннелирование по приложениям",
            Self::ExcludedAdds => "Исключенные адреса",
            Self::Connection => "Сеть и подключение",
            Self::Routing => "Маршрутизация и DNS",
            Self::Security => "Безопасность и Kill Switch",
            Self::SplitTunnel => "Раздельное туннелирование",
            Self::Updates => "Обновления и о программе",
        }
    }

    pub fn icon(&self) -> &'static str {
        match self {
            Self::General => "⚙",
            Self::Configs => "⚙",
            Self::PerApp => "⚡",
            Self::ExcludedAdds => "⚡",
            Self::Connection => "⚡",
            Self::Routing => "🌐",
            Self::Security => "🛡",
            Self::SplitTunnel => "🔀",
            Self::Updates => "ℹ",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            Self::General => "Параметры автозапуска, сворачивания в трей и системных оповещений",
            Self::Configs => "Настройки конфигов",
            Self::PerApp => "Основные настройки",
            Self::ExcludedAdds => "Исключенные адреса",
            Self::Connection => "Транспортные протоколы (QUIC, AHTTP, SSH, WS), размер MTU и таймауты",
            Self::Routing => "Настройка DNS-серверов, шлюзов по умолчанию и списков исключений",
            Self::Security => "Kill Switch, защита от утечек DNS и WebRTC, шифрование трафика",
            Self::SplitTunnel => "Правила выборочного туннелирования трафика приложений",
            Self::Updates => "Проверка обновлений, информация о текущей версии и лицензии",
        }
    }
}
