# Настройка сервера

Руководство по развёртыванию VPN-сервера ANet.

## Требования

- ОС: Linux (рекомендуется), поддерживается также macOS
- Права суперпользователя (root) — необходимы для создания TUN-интерфейса
- Открытый UDP-порт (по умолчанию 8443)
- Установленный `openssl` — для генерации TLS-сертификата

## Получение бинарных файлов

Готовые сборки доступны на странице [релизов](https://github.com/ZeroTworu/anet/releases). Необходимы:

- `anet-server` — серверный компонент
- `anet-keygen` — утилита генерации ключей

Для сборки из исходного кода (требуется Rust toolchain):

```bash
make all       # стандартная сборка
make musl      # статическая сборка (x86_64-unknown-linux-musl)
```

## Пошаговая настройка

### Шаг 1. Генерация ключей подписи

```bash
./anet-keygen server
```

Вывод:

```text
=== ANet Server Signing Key ===

Private Signing Key (add to server.toml):
[crypto]
server_signing_key = "BGQGf36RKbzEQ6Ef68O0ScVA+tLeVoYcTAE61Mig1js="

Public Key (for client verification, optional):
iqo4UuQlbWN35Pyp5vQedTEt1FeKA+6wxYTVS/XzHww=
```

- `server_signing_key` — записывается в `server.toml` в секцию `[crypto]`
- `Public Key` — передаётся всем клиентам для настройки параметра `server_pub_key`

> Публичный ключ сервера критически важен для безопасности: он позволяет клиентам верифицировать подлинность сервера и защищает от атак типа Man-in-the-Middle.

### Шаг 2. Генерация TLS-сертификата для QUIC

```bash
openssl req -x509 -newkey ed25519 \
  -keyout key.pem -out cert.pem \
  -days 365 -nodes \
  -subj "/CN=alco" \
  -addext "subjectAltName = DNS:alco" \
  -addext "basicConstraints=critical,CA:FALSE" \
  -addext "keyUsage=digitalSignature,keyEncipherment"
```

> Значение `alco` в параметре `/CN=` является фиксированным идентификатором, используемым в QUIC-соединении. Изменение этого значения требует пересборки проекта.

Содержимое файлов `cert.pem` и `key.pem` вставляется в `server.toml` в секцию `[crypto]`.

Также можно использовать команду `make cert`, которая выполняет аналогичную операцию.

### Шаг 3. Создание конфигурационного файла

Шаблон конфигурации находится в `contrib/config/server.toml`. Скопируйте его и заполните обязательные параметры:

```toml
[network]
net = "10.0.0.0"
mask = "255.255.255.0"
gateway = "10.0.0.1"
self_ip = "10.0.0.2"
if_name = "anet-server"
mtu = 1300

[server]
bind_to = "0.0.0.0:8443"
external_if = "eth0"         # имя вашего внешнего сетевого интерфейса

[authentication]
allowed_clients = []          # отпечатки клиентов (см. раздел "Добавление клиентов")

[crypto]
quic_cert = """
-----BEGIN CERTIFICATE-----
... (содержимое cert.pem)
-----END CERTIFICATE-----
"""

quic_key = """
-----BEGIN PRIVATE KEY-----
... (содержимое key.pem)
-----END PRIVATE KEY-----
"""

server_signing_key = "..."    # из вывода anet-keygen server
```

### Шаг 4. Добавление клиентов

Сгенерируйте ключи для каждого клиента:

```bash
./anet-keygen client
```

Полученный отпечаток (fingerprint) добавьте в список `allowed_clients`:

```toml
[authentication]
allowed_clients = ["f+f9KfEh/kuAZUzLMT4z7A==", "другой_отпечаток=="]
```

После изменения списка клиентов необходим перезапуск сервера. Для управления пользователями без перезапуска используйте [сервер авторизации](auth-server.md).

### Шаг 5. Запуск сервера

```bash
sudo ./anet-server -c /path/to/server.toml
```

Для управления уровнем логирования используйте переменную окружения `RUST_LOG`:

```bash
sudo RUST_LOG=info ./anet-server -c /path/to/server.toml
```

Допустимые уровни: `error`, `warn`, `info`, `debug`, `trace`.

### Шаг 6. Настройка маршрутизации трафика

После запуска сервера необходимо настроить перенаправление трафика между TUN-интерфейсом и внешним сетевым интерфейсом на уровне операционной системы.

#### iptables (Ubuntu, Debian)

```bash
# Разрешить входящие пакеты на порт сервера
iptables -I INPUT -p udp --dport 8443 -j ACCEPT

# Перенаправление трафика из внешней сети в VPN
iptables -I FORWARD -i eth0 -o anet-server -j ACCEPT

# Перенаправление трафика из VPN во внешнюю сеть
iptables -I FORWARD -i anet-server -o eth0 -j ACCEPT

# Включение NAT (MASQUERADE)
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
```

Замените `eth0` на имя вашего внешнего интерфейса, `anet-server` — на значение `if_name` из конфигурации, `8443` — на значение порта из `bind_to`.

> Правила iptables не сохраняются после перезагрузки. Используйте `iptables-persistent` (Debian/Ubuntu) или аналогичный механизм для вашей ОС.
>
> Конфигурация iptables может существенно отличаться в зависимости от версии ОС и дистрибутива. Приведённые выше правила актуальны для Ubuntu 22.04.

#### nftables (современные дистрибутивы)

```bash
nft add table inet anet
nft add chain inet anet forward '{ type filter hook forward priority 0; policy accept; }'
nft add rule inet anet forward iifname "eth0" oifname "anet-server" accept
nft add rule inet anet forward iifname "anet-server" oifname "eth0" accept
nft add table ip nat
nft add chain ip nat postrouting '{ type nat hook postrouting priority 100; }'
nft add rule ip nat postrouting oifname "eth0" masquerade
```

### Шаг 7. Настройка systemd (опционально)

Готовые unit-файлы находятся в `contrib/systemd/`:

```bash
sudo cp contrib/systemd/anet-vpn.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable anet-vpn
sudo systemctl start anet-vpn
```

Отредактируйте unit-файл при необходимости, указав корректные пути к бинарному файлу и конфигурации.

## Справочник параметров конфигурации

### Секция `[network]`

| Параметр | Тип | По умолчанию | Описание |
| --- | --- | --- | --- |
| `net` | String | `"10.0.0.0"` | Базовый адрес VPN-подсети |
| `mask` | String | `"255.255.255.0"` | Маска подсети |
| `gateway` | String | `"10.0.0.1"` | IP-адрес шлюза для клиентов |
| `self_ip` | String | `"10.0.0.2"` | IP-адрес TUN-интерфейса сервера |
| `if_name` | String | `"anet-server"` | Имя TUN-интерфейса |
| `mtu` | u16 | `1400` | MTU TUN-интерфейса (должен быть меньше физического MTU) |

### Секция `[server]`

| Параметр | Тип | По умолчанию | Описание |
| --- | --- | --- | --- |
| `bind_to` | String | `"0.0.0.0:8443"` | Адрес и UDP-порт для прослушивания |
| `external_if` | String | `"eth0"` | Имя внешнего сетевого интерфейса |

### Секция `[authentication]`

| Параметр | Тип | По умолчанию | Описание |
| --- | --- | --- | --- |
| `allowed_clients` | Vec\<String\> | `[]` | Список разрешённых отпечатков клиентов (Base64) |
| `auth_servers` | Vec\<String\> | `[]` | URL-адреса серверов авторизации |
| `auth_server_token` | String | `""` | Токен для аутентификации запросов к серверу авторизации |

### Секция `[crypto]`

| Параметр | Тип | Описание |
| --- | --- | --- |
| `quic_cert` | String | TLS-сертификат в формате PEM (содержимое cert.pem) |
| `quic_key` | String | Приватный ключ TLS в формате PEM (содержимое key.pem) |
| `server_signing_key` | String | Приватный ключ подписи Ed25519 (Base64, из anet-keygen) |

### Секция `[stats]`

| Параметр | Тип | По умолчанию | Описание |
| --- | --- | --- | --- |
| `enabled` | bool | `false` | Включить периодический вывод статистики QUIC-соединений |
| `interval_minutes` | u64 | `1` | Интервал вывода статистики (минуты) |

### Секции `[stealth]` и `[quic_transport]`

Параметры идентичны клиентским. См. [Маскировка трафика](stealth.md) и [Настройка QUIC-транспорта](quic-tuning.md).
