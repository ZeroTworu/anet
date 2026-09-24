// src/lib.rs

// Подключаем переменные сборки (GIT_TAG, COMMIT_HASH и т.д.)
include!(concat!(env!("OUT_DIR"), "/built.rs"));

// Объявляем все модули проекта в корне библиотеки
pub mod types;
pub mod utils;
pub mod theme;
pub mod events;
pub mod app;
pub mod ui;
pub mod icons;
pub(crate) mod config;
pub(crate) mod tray;
pub mod tun_factory;