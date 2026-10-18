//! Модуль типов данных, перечислений и структур состояния

use std::sync::Arc;
use anet_client_core::{
    client::AnetClient,
    updater::GithubRelease,
};
use eframe::egui;

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
    ServerUrl,
    PerApp,
    ExcludedAdds,
    Routing,
    Updates,
}

impl SettingsCategory {
    pub fn title(&self) -> &'static str {
        match self {
            Self::General => "Основные настройки",
            Self::Configs => "Конфиги",
            Self::ServerUrl => "Ссылка на конфигурацию",
            Self::PerApp => "Туннелирование по приложениям",
            Self::Routing => "Маршрутизация и DNS",
            Self::ExcludedAdds => "Исключенные адреса",            
            Self::Updates => "Обновления и о программе",
        }
    }

    pub fn icon(&self) -> egui::ImageSource<'static> {
        match self {
            Self::General => egui::include_image!("assets/general.svg"), // шестеренка из вашего дерева
            Self::Configs => egui::include_image!("assets/configs.svg"),
            Self::ServerUrl => egui::include_image!("assets/server_url.svg"),
            Self::PerApp => egui::include_image!("assets/per_app.svg"),
            Self::Routing => egui::include_image!("assets/routing.svg"),
            Self::ExcludedAdds => egui::include_image!("assets/excluded_adds.svg"),
            Self::Updates => egui::include_image!("assets/updates.svg"),
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            Self::General => "Параметры автозапуска, сворачивания в трей и системных оповещений",
            Self::Configs => "Список профилей, выбор активного конфига и импорт из файлов",
            Self::ServerUrl => "Просмотр, редактирование, проверка обновления и удаление персональной ссылки",
            Self::PerApp => "Выборочное туннелирование трафика для конкретных процессов (Windows)",
            Self::ExcludedAdds => "Список IP/CIDR/доменов, направляемых в обход VPN-туннеля",
            Self::Routing => "Настройка DNS-серверов, шлюзов по умолчанию и списков исключений",
            Self::Updates => "Проверка обновлений, информация о текущей версии и лицензии",
        }
    }
}