# ANet: Сеть Друзей

![Build Status](https://img.shields.io/badge/build-passing-brightgreen)
![Language](https://img.shields.io/badge/rust-1.84%2B-orange)
![Protocol](https://img.shields.io/badge/protocol-ASTP_v0.5-blue)

**ANet** — это инструмент для организации приватного, защищенного информационного пространства между близкими людьми. Мы строим цифровые мосты там, где обычные пути недоступны.

Это не сервис. Это технология для связи тех, кто доверяет друг другу.

## Особенности

В основе проекта лежит собственный транспортный протокол **ASTP (ANet Secure Transport Protocol)**, разработанный с фокусом на:

*   **Приватность:** Полное сквозное шифрование (ChaCha20Poly1305 / X25519).
*   **Устойчивость:** Стабильная работа в сетях с высокими потерями пакетов и нестабильным соединением.
*   **Мимикрия:** Транспортный уровень неотличим от случайного шума (High-entropy UDP stream).
*   **Кроссплатформенность:** Клиенты для Linux, Windows и Android.

## Структура проекта

Проект написан на Rust и разделен на модули:

*   `anet-server` — Узел координации.
*   `anet-client-cli` — Консольный клиент для Linux/Headless систем.
*   `anet-client-gui` — Графический клиент (Windows/Linux) с минималистичным интерфейсом.
*   `anet-mobile` — Библиотека и JNI-биндинги для Android.
*   `anet-common` — Реализация протокола ASTP и криптографии.
*   `anet-keygen` — Утилита для генерации ключей доступа.

[Документация](./doc/README.md) | [Быстрый старт](./contrib/docs/anet.ru.md)

## Сборка

Требуется установленный Rust (cargo).

```bash
# Сборка всех компонентов
make all

# Сборка статичных бинарников с musl
make musl

# Сборка библиотеки для Android
make mob

# Сборка под macOS
# Build macOS CLI client
make macos

# Build macOS GUI client
make macos-gui

# Build universal macOS binaries (Intel + Apple Silicon)
make macos-universal

# Генерация сертификата для QUIC
make cert
```
[Android src](https://github.com/ZeroTworu/anet-android)


На J7: [Donate](https://dalink.to/rventomarika)