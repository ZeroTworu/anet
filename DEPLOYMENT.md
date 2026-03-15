# Руководство по развертыванию ANet VPN Server

Упрощенное развертывание ANet VPN сервера с использованием Docker.

## 📋 Содержание

1. [Быстрый старт](#быстрый-старт)
2. [Режимы установки](#режимы-установки)
3. [Управление сервером](#управление-сервером)
4. [Настройка клиентов](#настройка-клиентов)
5. [Устранение неполадок](#устранение-неполадок)

---

## 🚀 Быстрый старт

### Минимальные требования

- **OS**: Linux (Ubuntu 20.04+, Debian 11+, или аналог)
- **Docker**: 20.10+
- **Docker Compose**: 2.0+
- **RAM**: 512 MB минимум
- **Disk**: 200 MB свободного места

### Установка за 3 шага

```bash
# 1. Клонируйте репозиторий
git clone https://github.com/AlphaO612/easy_anet.git
cd easy_anet

# 2. Запустите установку (режим с бинарниками, по умолчанию)
chmod +x install.sh
sudo ./install.sh --clients 2 --bind 8443

# 3. Сгенерируйте конфиг для клиента
./generate-client-config.sh --server-address $(curl -s ifconfig.me):8443
```

**Готово!** Сервер запущен, клиентский конфиг в `client-windows/client.toml`

---

## 🔧 Режимы установки

### Режим 1: Готовые бинарники (рекомендуется)

**Преимущества:**
- ✅ Быстро (2-3 минуты)
- ✅ Не требует компиляции
- ✅ Не требует Rust toolchain
- ✅ Маленький Docker образ (~150 MB)

**Установка:**

```bash
sudo ./install.sh --clients 2
```

Или через Makefile:

```bash
make install
```

**Как работает:**
1. Скачивает последний релиз с GitHub
2. Распаковывает `anet-server` бинарник
3. Создает легковесный Docker образ
4. Генерирует конфиги и ключи
5. Запускает контейнер

---

### Режим 2: Сборка из исходников

**Преимущества:**
- ✅ Полный контроль над сборкой
- ✅ Можно модифицировать код
- ✅ Последняя версия из Git

**Недостатки:**
- ⏱️ Медленно (10-15 минут)
- 📦 Большой образ (~2+ GB)
- 🔧 Требует больше ресурсов

**Установка:**

```bash
sudo ./install.sh --build-from-source --clients 2
```

Или:

```bash
make install-source
```

**Как работает:**
1. Проверяет наличие исходников (клонирует если нужно)
2. Собирает Rust код внутри Docker
3. Создает образ с скомпилированными бинарниками
4. Генерирует конфиги и запускает

---

## 🎛️ Параметры установки

### Флаги для install.sh

| Флаг | Описание | Пример | По умолчанию |
|------|----------|--------|--------------|
| `--build-from-source` | Собрать из исходников | `--build-from-source` | Отключено (бинарники) |
| `--clients N` | Количество клиентских ключей | `--clients 5` | 1 |
| `--external-if IFACE` | Сетевой интерфейс для NAT | `--external-if eth0` | Автоопределение |
| `--bind PORT` | UDP порт сервера | `--bind 51820` | 8443 |

### Примеры

```bash
# Простая установка с 3 клиентами
sudo ./install.sh --clients 3

# Установка на нестандартный порт
sudo ./install.sh --clients 2 --bind 51820

# Сборка из исходников с указанием интерфейса
sudo ./install.sh --build-from-source --external-if ens3 --clients 5

# Минимальная установка (1 клиент, порт по умолчанию)
sudo ./install.sh
```

---

## 🎮 Управление сервером

### Через Makefile (рекомендуется)

```bash
make help          # Показать все команды
make install       # Установить сервер (бинарники)
make install-source # Установить (из исходников)
make start         # Запустить сервер
make stop          # Остановить сервер
make restart       # Перезапустить
make logs          # Смотреть логи (live)
make diagnose      # Запустить диагностику
make config        # Сгенерировать server.toml
make client IP=1.2.3.4 # Сгенерировать client.toml
make clean         # Остановить и удалить контейнеры
```

### Через Docker Compose

```bash
# Запуск/остановка
docker compose up -d              # Запустить (бинарники)
docker compose -f docker-compose.build.yml up -d  # Запустить (из исходников)
docker compose down               # Остановить
docker compose restart anet-server # Перезапустить

# Логи
docker compose logs -f anet-server      # Live логи
docker compose logs --tail 100 anet-server # Последние 100 строк

# Статус
docker compose ps                 # Статус контейнеров
docker ps | grep anet             # Статус через docker
```

### Через скрипты

```bash
./diagnose.sh                     # Полная диагностика
./generate-config.sh --clients 5  # Регенерация конфига
./generate-client-config.sh --server-address IP:PORT # Генерация client.toml
```

---

## 👥 Настройка клиентов

### 1. Генерация конфига

На сервере выполните:

```bash
./generate-client-config.sh --server-address YOUR_SERVER_IP:8443
```

Или через make:

```bash
make client IP=194.41.113.15
```

Для конкретного клиента (если их несколько):

```bash
./generate-client-config.sh --server-address IP:8443 --client 2
```

### 2. Копирование конфига

**Вариант A: SCP**

```bash
scp client-windows/client.toml user@client-pc:~/
```

**Вариант B: Вручную**

Скопируйте содержимое `client-windows/client.toml` на клиентскую машину.

### 3. Загрузка клиента

Скачайте клиент для вашей платформы из [releases](https://github.com/ZeroTworu/anet/releases):

- **Windows**: `client-windows_X.X.X.zip` (содержит CLI, GUI и wintun.dll)
- **Linux**: `client-linux_X.X.X.zip`
- **macOS**: `client-macos_X.X.X.zip` (Universal binary)
- **Android**: `anet-android-X.X.X.apk`

### 4. Запуск клиента

**Windows:**
```cmd
# GUI
anet-gui.exe

# CLI
anet-client.exe -c client.toml
```

**Linux/macOS:**
```bash
sudo ./anet-client -c client.toml
```

---

## 🔍 Диагностика

### Автоматическая диагностика

```bash
./diagnose.sh
```

Проверяет:
- Docker и Docker Compose
- Статус контейнера
- Конфигурацию (ключи, сертификаты)
- Сеть (TUN, порты, ip_forward)
- Firewall (iptables, UFW, firewalld)
- Логи на ошибки

### Ручная проверка

```bash
# Статус контейнера
docker ps | grep anet-server

# Порт открыт?
ss -ulnp | grep 8443

# TUN интерфейс создан?
ip link show anet-server

# IP forwarding включен?
cat /proc/sys/net/ipv4/ip_forward  # Должно быть 1

# iptables MASQUERADE
sudo iptables -t nat -L POSTROUTING -n | grep MASQUERADE

# Логи
docker compose logs --tail 50 anet-server
```

---

## 🐛 Устранение неполадок

### Контейнер не запускается

**Проблема**: `docker compose up -d` завершается с ошибкой

**Решение:**

```bash
# 1. Проверьте логи
docker compose logs anet-server

# 2. Проверьте конфиг
cat server/server.toml

# 3. Пересоздайте образ
docker compose down
docker rmi anet-server:latest
docker compose build --no-cache
docker compose up -d
```

---

### Порт 8443/UDP не слушает

**Проблема**: `ss -ulnp | grep 8443` ничего не показывает

**Решение:**

```bash
# 1. Проверьте, запущен ли контейнер
docker ps | grep anet

# 2. Проверьте bind_to в конфиге
grep bind_to server/server.toml

# 3. Проверьте, не занят ли порт другим процессом
sudo ss -ulnp | grep 8443

# 4. Попробуйте другой порт
./generate-config.sh --bind 51820
docker compose down && docker compose up -d
```

---

### Клиент не подключается

**Проблема**: Клиент выдает ошибку "Authentication failed"

**Решение:**

```bash
# 1. Проверьте, что fingerprint клиента в allowed_clients
grep -A5 allowed_clients server/server.toml
cat server/client-keys.txt  # Сравните fingerprint

# 2. Убедитесь, что ключи валидны
./test-keys-from-keys-file.sh
./test-client-keys.sh client-windows/client.toml

# 3. Регенерируйте client.toml
./generate-client-config.sh --server-address YOUR_IP:8443

# 4. Проверьте firewall на сервере
sudo ufw status
sudo ufw allow 8443/udp
```

---

### TUN интерфейс не создается

**Проблема**: В логах `Failed to create TUN device`

**Решение:**

```bash
# 1. Проверьте наличие /dev/net/tun
ls -la /dev/net/tun

# 2. Создайте если отсутствует
sudo mkdir -p /dev/net
sudo mknod /dev/net/tun c 10 200
sudo chmod 666 /dev/net/tun

# 3. Проверьте модуль tun
lsmod | grep tun
sudo modprobe tun

# 4. Перезапустите контейнер
docker compose restart anet-server
```

---

### Скачивание бинарников не работает

**Проблема**: Dockerfile не может скачать релиз с GitHub

**Решение:**

```bash
# 1. Проверьте доступ к GitHub
curl -I https://github.com

# 2. Используйте режим сборки из исходников
sudo ./install.sh --build-from-source

# 3. Или скачайте бинарники вручную:
# - Загрузите server_X.X.X.zip с https://github.com/ZeroTworu/anet/releases
# - Распакуйте и положите anet-server в какую-то папку
# - Измените Dockerfile чтобы использовать локальный файл
```

---

## 📊 Мониторинг

### Просмотр статистики

Сервер записывает статистику каждые N минут (настраивается в `server.toml` → `[stats]`).

```bash
# Логи со статистикой
docker compose logs | grep -i stats

# Или grep по пропускной способности
docker compose logs | grep -i 'bandwidth\|throughput'
```

### Prometheus/Grafana (опционально)

TODO: добавить поддержку Prometheus metrics endpoint

---

## 🔄 Обновление

### Обновление сервера

```bash
# 1. Остановите сервер
docker compose down

# 2. Обновите репозиторий
git pull

# 3. Пересоздайте образ
docker compose build --no-cache

# 4. Запустите
docker compose up -d
```

### Обновление клиентов

1. Скачайте новую версию клиента из [releases](https://github.com/ZeroTworu/anet/releases)
2. Замените старый бинарник
3. Убедитесь, что `client.toml` совместим (ключи не меняются)

---

## 🛡️ Безопасность

### Рекомендации

1. **Используйте firewall**: открывайте только порт сервера (8443/UDP)
2. **Регулярно обновляйте**: следите за новыми релизами
3. **Ограничьте allowed_clients**: добавляйте только доверенных клиентов
4. **Используйте сильные ключи**: не копируйте ключи из примеров
5. **Мониторьте логи**: проверяйте на подозрительную активность

### Firewall

```bash
# UFW
sudo ufw allow 8443/udp
sudo ufw enable

# firewalld
sudo firewall-cmd --add-port=8443/udp --permanent
sudo firewall-cmd --reload

# iptables
sudo iptables -A INPUT -p udp --dport 8443 -j ACCEPT
sudo iptables-save > /etc/iptables/rules.v4
```

---

## 📚 Дополнительные ресурсы

- [QUICK-START.md](QUICK-START.md) — краткая инструкция
- [MIGRATION.md](MIGRATION.md) — миграция со старой структуры
- [CHANGES.md](CHANGES.md) — список изменений
- [README.md](README.md) — общая информация о проекте
- [ANet GitHub](https://github.com/ZeroTworu/anet) — основной репозиторий

---

## 💬 Поддержка

- **Issues**: https://github.com/AlphaO612/easy_anet/issues
- **Telegram**: (если есть)
- **Email**: (если есть)

---

## 📄 Лицензия

Следует лицензии основного проекта [ANet](https://github.com/ZeroTworu/anet).
