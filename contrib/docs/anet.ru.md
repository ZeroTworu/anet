# ANet: ЧЁКУДА?! (Руководство по эксплуатации)

Дока актуальна для `v0.6.2+` (включая каскадный failover, статический IP, WebUI, Docker-деплой и универсальную статистику).

Начнём с начала.

Если вы разворачиваете всю инфраструктуру — читать по порядку, если настраиваете клиент — переходите сразу к [Client](#client).

### Внимание!
Клиент и сервер (на Linux/macOS) должны запускаться от `root` или Администратора, иначе не хватит прав для создания TUN-интерфейса и управления таблицами маршрутизации!

Если вы не знаете Rust и не хотите собирать руками — **Все бинарники находятся [здесь](https://github.com/ZeroTworu/anet/releases)**.

Прежде чем начать — подумай, а оно тебе надо? Самый копеечный VPS обойдётся в 6$ в месяц (UPD: Есть ещё дешевле), это два месяца подписки на любой сторонний сервис!

---

## Server: Первичная настройка

* Качаем (или собираем, что лучше) — `anet-server` нужной нам версии, а также `anet-keygen`.
* Через `anet-keygen` генерируем приватный и публичный ключи сервера, пример:
```text
 ./anet-keygen server
 
 === ANet Server Signing Key ===

Private Signing Key (add to server.toml):
[crypto]
server_signing_key = "BGQGf36RKbzEQ6Ef68O0ScVA+tLeVoYcTAE61Mig1js="

Public Key (for client verification, optional):
iqo4UuQlbWN35Pyp5vQedTEt1FeKA+6wxYTVS/XzHww=
```
`Public Key` — сохраняем куда-нибудь на криптофлешку. На самом деле он ни фига не "optional"! Его мы будем раздавать клиентам, чтобы они могли убедиться, что говорят именно с вашим сервером.

* Создаём TLS сертификаты для QUIC (Не забудьте проверить наличие `openssl`, если нету - поставьте):
```bash
openssl req -x509 -newkey ed25519 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=alco" -addext "subjectAltName = DNS:alco" -addext "basicConstraints=critical,CA:FALSE" -addext "keyUsage=digitalSignature,keyEncipherment"
```
*(Сертификат по умолчанию — 365 дней, для `/CN=alco`. `alco` захардкожено в проекте).*

* Содержимое `cert.pem` кладём в `quic_cert = `, содержимое `key.pem` — в `quic_key = `, а приватный ключ от `anet-keygen` — в `server_signing_key = `.
* Настраиваем транспорты (UDP/TCP), подсети и маскировку в секциях `[server]`, `[network]`, `[stealth]`.

### SSH
Если сервер стартует не от `root`, а например по присету юнита из `contrib/systemd/`, то дефолтный `ssh_host_key = "/etc/ssh/ssh_host_rsa_key"` не подойдёт, т.к. прав нету, нужно создать отдельный `ssh key`.

Предположим всё лежит в `/opt/anet`.

* `ssh-keygen -t rsa -b 4096 -f /opt/anet/anet_ssh_host_key -N "" -q` - генерим ключ.
* `chmod 644 /opt/anet/anet_ssh_host_key /opt/anet/anet_ssh_host_key.pub` - меняем права
* в конфиге сервера `ssh_host_key = "/opt/anet/anet_ssh_host_key"`

PS. Внимательный Зоркий Джо, мог заметить в пресете `StateDirectory=anet` - ну, так если Зоркий Джо знает, что это, ему и другая версия инструкции не нужна.

### Запуск сервера и маршрутизация (ВАЖНО!)

После запуска сервера необходимо на уровне ОС настроить перенаправление трафика между `TUN` интерфейсом (по умолчанию `anet-server`) и вашим внешним интерфейсом (интернетом).

Пример для Ubuntu 22.04/24.04:

```bash
# Разрешаем входящие порты сервера (UDP для QUIC, TCP для SSH/VNC)
iptables -I INPUT -p udp --dport 8443 -j ACCEPT 
iptables -I INPUT -p tcp --dport 8222 -j ACCEPT 

# Перенаправляем трафик из внешнего мира в VPN и обратно
iptables -I FORWARD -i eth0 -o anet-server -j ACCEPT
iptables -I FORWARD -i anet-server -o eth0 -j ACCEPT

# Включаем NAT (Маскарадинг)
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
```
Также нужно включить IPv4 forwarding:
```bash
sudo sysctl -w net.ipv4.ip_forward=1
echo 'net.ipv4.ip_forward=1' | sudo tee /etc/sysctl.d/99-anet.conf
sudo sysctl --system
```
**ВАЖНО!** После `reboot` ваши правила iptables пропадут. Гуглите `iptables-persistent` или используйте `ufw`/`nftables` для сохранения.

---

## Server: Пользователи

Тут у нас два стула: быстрый («для меня и моей кошки») и энтерпрайз (через базу данных и API). Начнём с простого.

### Я и моя кошка (Локальный конфиг)

В конфиге сервера есть параметр: `allowed_clients = []` — сюда пишутся отпечатки (fingerprints) клиентов.

* Создаём клиента — `./anet-keygen client`:
```text
=== ANet Client Keys ===

Private Key (add to client.toml):
[keys]
private_key = "QehLlLB5gNzceXAjjsl/1RQKeY97RVN8GBgHlfsHbn4="

Fingerprint (add to server.toml allowed_clients):
f+f9KfEh/kuAZUzLMT4z7A==
```

* Полученный Fingerprint (`f+f9KfEh/kuAZUzLMT4z7A==`) вписываем в серверный конфиг: `allowed_clients = ["f+f9KfEh/kuAZUzLMT4z7A=="]`.
* **ВАЖНЫЙ момент!** Сервер после этого надо перезапустить.
* Приватный ключ отдаём кошке. Также не забудьте сказать кошке IP/Порт сервера и `Server Public Key`, полученный на этапе генерации ключей сервера.

---

## Client (Настройка кошки)

И так, у вас есть `private_key` (ваш), IP-адреса серверов, и `Server Public Key`.

* Качаем клиент **той же версии**, что и сервер.
* Открываем `client.toml` (шаблон в `contrib/config/client.toml`).
* Вместо старых одиночных полей `address` и `mode`, настраиваем **каскадный список серверов `[[servers]]`** (Failover).

### Как работает каскадный Failover:
Вы можете задать список из разных портов и типов транспорта (даже для одного и того же физического сервера). Клиент будет пытаться подключиться к ним по очереди.

Умный воркер контроля здоровья (`Health Monitor`) внутри клиента постоянно анализирует прохождение пакетов через TUN-мост и отрабатывает два сценария:
1. **DPI-Блэкхолинг на старте (Case 1)**: Соединение установлено, но в течение первых 8 секунд от сервера не прилетело ни одного ответного байта (ТСПУ глушит трафик). Клиент моментально рвет сессию и пробует следующую ноду.
2. **Внезапный обрыв потока (Case 2)**: Соединение успешно работало, но посреди сессии замолчало более чем на 15 секунд (блокировка «на лету» или обрыв связи). Клиент сбрасывает роуты, очищает DNS и переключается на резервный порт.

Пример настройки списка нод в `client.toml`:
```toml
# 1. Первая попытка: Сверхбыстрый UDP-транспорт (QUIC)
[[servers]]
address = "127.0.0.1:4519"
mode = "quic"
timeout_secs = 5 # Время ожидания хендшейка в секундах

# 2. Вторая попытка: Резервный TCP-транспорт (SSH)
[[servers]]
address = "127.0.0.1:822"
mode = "ssh"
ssh_user = "hanyuu"
timeout_secs = 6

# 3. Третья попытка: Маскировка под удаленный рабочий стол (VNC)
[[servers]]
address = "127.0.0.1:56678"
mode = "vnc"
timeout_secs = 8
```

### Универсальная статистика
В разделе `[stats]` можно включить мониторинг трафика. Наша статистика теперь **универсальна** — счетчики байт считываются прямо с моста виртуального адаптера, поэтому ты будешь видеть точные объемы и скорость передачи (`Total Rx / Tx`) для любого активного транспорта — будь то QUIC, SSH или VNC.

---

## Server: Кошка и котята (Продвинутая авторизация в Docker)

Перезапуск сервера при добавлении каждого пользователя — такое себе удовольствие, поэтому есть `anet-auth` и WEB UIйня под него, но она не обязательна, можно и консолькой пердолить.

Всю эту инфраструктуру (PostgreSQL, Бэкенд авторизации и Web-интерфейс) в продакшене можно развернуть буквально за 1 минуту с помощью **Docker Compose**.

1. Создай на сервере (например, в `/opt/anet/`) файл `docker-compose.yaml`:

```yaml
services:
  postgres:
    image: postgres:17-alpine
    container_name: anet-db
    environment:
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: password
      POSTGRES_DB: db
    volumes:
      - pg_data:/var/lib/postgresql/data
    ports:
      - "5557:5432"
    healthcheck:
      test: [ "CMD-SHELL", "pg_isready -U $$POSTGRES_USER -d $$POSTGRES_DB" ]
      interval: 2s
      timeout: 5s
      retries: 5
    restart: unless-stopped

  anet-auth:
    image: ghcr.io/zerotworu/anet-auth:latest
    container_name: anet-auth
    environment:
      - DATABASE_URL=postgres://postgres:password@postgres:5432/db
      - BIND_TO=0.0.0.0:3000
      - AUTH_BACKEND_KEY=super_secret_vpn_key_2025 # Ключ для связи основного сервера с бэкендом
      - JWT_SECRET=secret_na_chushpana
    depends_on:
      postgres:
        condition: service_healthy
    ports:
      - "3000:3000"
    restart: unless-stopped

  anet-webui:
    image: ghcr.io/zerotworu/anet-webui:latest
    container_name: anet-webui
    ports:
      - "80:80" # Твой панель управления теперь доступна на 80 порту!
    depends_on:
      - anet-auth
    restart: unless-stopped

volumes:
  pg_data:
```

2. Запусти стек одной командой:
```bash
docker compose up -d
```
3. Заходи в браузер на IP-адрес твоего сервера, авторизуйся, создавай пользователей и управляй их тарифами в реальном времени.

4. В конфиге **основного сервера** (`server.toml`) прописываем связь с контейнером бэкенда:
```toml
[authentication]
auth_servers = ["http://127.0.0.1:3000/api/v1"]
auth_server_token = "super_secret_vpn_key_2025"
```
5. Перезапускаем `anet-server` один раз. Теперь можно плодить клиентов через WebUI без перезагрузок VPN-сервера!

6. Консольные комманды для `anet-auth`:
   * `./anet-auth -a username` - добавляет пользователя `username`, без всяких ограничений. Как результат работы - выдаст его приватный и публичный ключи + фингерпринт.
   * `./anet-auth -a username --sessions N --date-end 2033-12-12-00:00` - добавляет пользователя `username`, с ограничением в N активных сессий и датой истечения доступа в 2033 году, 12 месяца, 12 числа в 00 часов, 00 минут. Вообще формат даты такой `YYYY-MM-DD-HH:MM`.
   * `./anet-auth --add-su superuser` - добавляет **админестратора** `superuser`, как в любом UNIX-like надо будет ввести пароль. Это нужно сделать **ОБЯЗАТЕЛЬНО** если хотите юзать WebUI.

---

## Тарифы, Лимиты и Статические IP (Enterprise Mode)

Если вы используете `anet-auth` (HTTP-бэкенд с базой данных), вам становится доступна гибкая система тарификации и привязки статических IP-адресов.

### Управление Статическими IP (Static IP)
В Web-интерфейсе для каждого пользователя можно задать фиксированный IP-адрес (например, `10.0.0.10`).
Когда этот клиент совершает хендшейк, `anet-server` запрашивает бэкенд, получает его `static_ip`, полностью минует стандартную процедуру динамического выделения из общего пула и принудительно закрепляет этот IP за сессией. Это идеальное решение для совместных игр с комрадами («под пивас») или обхода ограничений на удаленных серверах.

### Как работает контроль сессий:
1. **Проверка при входе (`CheckAccess`):**
   Когда клиент стучится на сервер, VPN-сервер делает запрос к `anet-auth`. Бэкенд проверяет три условия:
* **Активен ли юзер?** (Флаг `is_active` в WebUI). Если `false` — мгновенный бан.
* **Не протух ли ключ?** (Поле `date_end` в тарифах). Если текущее время больше даты окончания — отказ.
* **Есть ли свободные сессии?** Система смотрит, сколько устройств сейчас онлайн под этим фингерпринтом. Если `current_sessions >= limit` — отказ.

2. **Учет сессий:**
* Как только клиент успешно прошел хендшейк, сервер шлет запрос `/session/start`, и счетчик сессий в базе инкрементируется (+1).
* При штатном (или аварийном, благодаря каскадному сбросу) отключении клиента, сервер шлет `/session/stop`, и счетчик уменьшается (-1).

### Сообщения об ошибках (User Experience)

ANet — это вежливая система. Если пользователю отказано в доступе, он не увидит просто "Connection Timeout". Сервер отправит зашифрованный Protobuf-пакет `AuthDenyNotification`, который клиент (CLI или GUI) расшифрует и покажет пользователю.

**Типичные "отлупы":**
* `[CORE AUTH] Кол-во сессий для ключа достигло максимума` — значит, кто-то уже сидит под этим конфигом. Нужно либо докупать сессии, либо выключать другие устройства.
* `[CORE AUTH] Время действия ключа истекло` — пора платить по счетам.
* `[CORE AUTH] Banned` — администратор ограничил вам доступ.
