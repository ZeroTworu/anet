# ANet: Сеть Друзей

![Build Status](https://img.shields.io/badge/build-passing-brightgreen)
![Language](https://img.shields.io/badge/rust-1.84%2B-orange)
![Protocol](https://img.shields.io/badge/protocol-ASTP_v1.0-blue)

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

## 🚀 Быстрый старт

Запуск сервера в Docker и подключение клиента за несколько шагов:

### Простой режим (рекомендуется)

**Использует готовые бинарники — без компиляции Rust!**

1. **Сервер (Linux):** клонируйте репозиторий и запустите `sudo ./install.sh` — скрипт скачает готовые бинарники, сгенерирует конфиг и ключи, поднимет контейнер (порт 8443/UDP).
2. **Клиент:** на сервере выполните `./generate-client-config.sh --server-address IP:8443`, скопируйте `client-windows/client.toml` на ПК с клиентом.
3. **Подключение:** запустите клиент ANet в папке с `client.toml`.

```bash
# Быстрая установка
git clone https://github.com/AlphaO612/easy_anet.git
cd easy_anet
chmod +x install.sh
sudo ./install.sh --clients 2
```

**Время установки:** ~2-3 минуты (только загрузка бинарников)

### Сборка из исходников (опционально)

Если хотите собрать из Rust кода:

```bash
sudo ./install.sh --build-from-source --clients 2
```

**Время установки:** ~10-15 минут (компиляция Rust)

Подробно: [QUICK-START.md](QUICK-START.md)

---

### ⚡ Совсем ленивый вариант

Одна команда — скачать скрипт и запустить (на Linux-сервере):

```bash
curl -sSL https://github.com/AlphaO612/easy_anet/releases/download/v1.0/i-am-so-lazy.sh | sudo bash
```

Скрипт сам подтянет нужные файлы из релиза, выполнит установку и поднимет сервер. Подробности — в [i-am-so-lazy.sh](i-am-so-lazy.sh).

---

### Makefile команды

Для еще более простого управления используйте `make` (префикс `docker-`):

```bash
# Docker Server Deployment
make docker-help              # Показать команды
make docker-install           # Установка с бинарниками
make docker-install-source    # Установка со сборкой
make docker-start             # Запуск
make docker-stop              # Остановка
make docker-logs              # Логи
make docker-diagnose          # Диагностика
make docker-client IP=1.2.3.4 # client.toml

# Development (для разработчиков)
make all              # Сборка компонентов
make test             # Тесты
make musl             # Статичный бинарник
```

## 🔨 Сборка из исходников (для разработчиков)

Этот репозиторий (easy_anet) — обертка для упрощенного деплоя. Для самостоятельной сборки компонентов ANet:

1. Клонируйте основной репозиторий: `git clone https://github.com/ZeroTworu/anet.git`
2. Установите Rust (cargo)
3. Следуйте инструкциям в [ZeroTworu/anet](https://github.com/ZeroTworu/anet)

Готовые бинарники для всех платформ доступны в [Releases](https://github.com/ZeroTworu/anet/releases):
- **Linux Server** — `server_linux.zip`
- **Windows Client** — `client-windows_X.X.X.zip` (CLI + GUI + wintun.dll)
- **Linux Client** — `client-linux_X.X.X.zip`
- **macOS Client** — `client-macos_X.X.X.zip` (Universal binary)
- **Android Client** — [anet-android.apk](https://github.com/ZeroTworu/anet/releases)

Support the Chaos

Если ANet помог тебе — налей автору оригинала!

На водку разрабу: [Donate](https://dalink.to/rventomarika)

На булочки для Ханю: [Donate](https://dalink.to/rventomarika)

На J7: [Donate](https://dalink.to/rventomarika)