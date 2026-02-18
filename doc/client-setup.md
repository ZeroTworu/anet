# Настройка клиента

Руководство по подключению к VPN-серверу ANet на различных платформах.

## Требования

- Права суперпользователя (root / администратор) — необходимы для создания TUN-интерфейса
- Клиент и сервер должны использовать совместимые версии протокола (совпадение второго числа версии: `v0.X.*`)

## Предварительные сведения

Для настройки клиента необходимо получить от администратора сервера:

1. **Адрес сервера** — IP или доменное имя с портом (например, `vpn.example.com:8443`)
2. **Публичный ключ сервера** — строка в формате Base64 (например, `iqo4UuQlbWN35Pyp5vQedTEt1FeKA+6wxYTVS/XzHww=`)

## Получение бинарных файлов

Готовые сборки доступны на странице [релизов](https://github.com/ZeroTworu/anet/releases):

| Платформа | Компонент | Описание |
| --- | --- | --- |
| Linux (x86_64, aarch64) | `anet-client` | Консольный клиент |
| Windows (x86_64) | `anet-client.exe` | Консольный клиент |
| Windows (x86_64) | `anet-client-gui.exe` | Графический клиент |
| macOS (Universal) | `anet-client` | Консольный клиент |
| macOS (Universal) | `ANet.app` | Графический клиент |
| Android | `anet.apk` | Мобильное приложение |

Для сборки из исходного кода:

```bash
make all              # Linux (динамическая линковка)
make musl             # Linux (статическая линковка)
make macos            # macOS CLI
make macos-gui        # macOS GUI
make macos-universal  # macOS Universal (Intel + Apple Silicon)
```

## Генерация клиентских ключей

```bash
./anet-keygen client
```

Вывод:

```text
=== ANet Client Keys ===

Private Key (add to client.toml):
[keys]
private_key = "QehLlLB5gNzceXAjjsl/1RQKeY97RVN8GBgHlfsHbn4="

Fingerprint (add to server.toml allowed_clients):
f+f9KfEh/kuAZUzLMT4z7A==

Public Key (for client verification, optional):
7IQrEFuiMAz02p2Pnx8tSd0698O8E/fjgAGzIo1xv/4=
```

- `private_key` — записывается в `client.toml` в секцию `[keys]`
- `Fingerprint` — передаётся администратору сервера для добавления в `allowed_clients` (или регистрации через `anet-auth`)

> Приватный ключ является конфиденциальным. Не передавайте его третьим лицам.

## Создание конфигурационного файла

Шаблон находится в `contrib/config/client.toml`. Минимальная конфигурация:

```toml
[main]
address = "vpn.example.com:8443"    # адрес сервера

[keys]
private_key = "QehLlLB5gNzceXAjjsl/1RQKeY97RVN8GBgHlfsHbn4="
server_pub_key = "iqo4UuQlbWN35Pyp5vQedTEt1FeKA+6wxYTVS/XzHww="
```

Остальные параметры имеют значения по умолчанию, достаточные для работы.

## Запуск

### Linux / macOS (CLI)

```bash
sudo ./anet-client -c /path/to/client.toml
```

Если флаг `-c` не указан, клиент ищет файл `client.toml` в текущей директории.

Управление уровнем логирования:

```bash
sudo RUST_LOG=info ./anet-client -c /path/to/client.toml
```

### Windows (GUI)

1. Запустите `anet-client-gui.exe` от имени администратора
2. Нажмите значок выбора конфигурации в правом верхнем углу интерфейса
3. Укажите путь к файлу `client.toml`
4. Путь к последнему использованному конфигурационному файлу сохраняется автоматически

> На Windows для работы TUN-интерфейса необходим драйвер `wintun.dll`. Он включён в архив релиза.

### Windows (CLI)

```batch
anet-client.exe -c C:\path\to\client.toml
```

Запуск от имени администратора обязателен.

### Android

1. Установите APK-файл из релиза
2. В приложении выберите конфигурационный файл
3. Приложение запросит разрешение на создание VPN-подключения

## Проверка подключения

После успешного подключения в логе отобразятся сообщения:

```text
[AUTH] Handshake completed successfully
[VPN] QUIC connection established
[VPN] TUN interface configured: 10.0.0.X
```

Для проверки:

```bash
# Проверка маршрутизации
ping 10.0.0.1            # шлюз VPN-сети

# Проверка выхода в интернет через VPN
curl ifconfig.me          # должен показать IP сервера
```

## Справочник параметров конфигурации

### Секция `[main]`

| Параметр | Тип | По умолчанию | Описание |
| --- | --- | --- | --- |
| `address` | String | `"127.0.0.1:443"` | Адрес и порт VPN-сервера |
| `tun_name` | String | `"anet-client"` | Имя TUN-интерфейса |
| `manual_routing` | bool | `false` | Ручное управление маршрутизацией (отключает автоматическую настройку маршрутов) |
| `route_for` | Vec\<String\> | `[]` | Белый список адресов для VPN (режим INCLUDE) |
| `exclude_route_for` | Vec\<String\> | `[]` | Чёрный список адресов, исключаемых из VPN (режим EXCLUDE) |
| `dns_server_list` | Vec\<String\> | `["1.1.1.1", "8.8.8.8"]` | DNS-серверы для резолвинга доменов в списках маршрутизации |

Подробнее о параметрах маршрутизации см. [Раздельное туннелирование](split-tunneling.md).

### Секция `[keys]`

| Параметр | Тип | Описание |
| --- | --- | --- |
| `private_key` | String | Приватный ключ клиента (Base64, из anet-keygen) |
| `server_pub_key` | String | Публичный ключ сервера (Base64, от администратора) |

### Секция `[stats]`

| Параметр | Тип | По умолчанию | Описание |
| --- | --- | --- | --- |
| `enabled` | bool | `false` | Включить периодический вывод статистики QUIC-соединения |
| `interval_minutes` | u64 | `1` | Интервал вывода статистики (минуты) |

### Секции `[stealth]` и `[quic_transport]`

См. [Маскировка трафика](stealth.md) и [Настройка QUIC-транспорта](quic-tuning.md).
