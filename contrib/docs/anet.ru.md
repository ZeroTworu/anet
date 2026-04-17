# ANet: ЧЁКУДА?! (Руководство по эксплуатации)

Дока актуальна для `v0.5.1+` (включая новые транспорты, GUI и маскировку трафика).

Начнём с начала.

Если вы разворачиваете всю инфраструктуру — читать по порядку, если настраиваете клиент — переходите сразу к [Client](#client).

### Внимание!
Клиент и сервер (на Linux/macOS) должны запускаться от `root` или Администратора, иначе не хватит прав для создания TUN-интерфейса и управления таблицами маршрутизации!

Если вы не знаете Rust и не хотите собирать руками — **Все бинарники находятся [здесь](https://github.com/ZeroTworu/anet/releases)**.

Прежде чем начать — подумай, а оно тебе надо? Самый копеечный VPS обойдётся в 6$ в месяц, это два месяца подписки на любой сторонний сервис!

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

И так, у вас есть `private_key` (ваш), IP сервера (`vpn.yandex.ru:8443`), и `Server Public Key`.

* Качаем клиент **той же версии**, что и сервер.
* Открываем `client.toml` (шаблон в `contrib/config/client.toml`).
* В `[main]` в `address` пишем адрес: `address = "vpn.yandex.ru:8443"`
* В `[keys]` в `private_key` вписываем **СВОЙ ПРИВАТНЫЙ КЛЮЧ**.
* В `[keys]` в `server_pub_key` вписываем **ПУБЛИЧНЫЙ КЛЮЧ СЕРВЕРА**.

### Выбор транспорта.
ANet поддерживает 3 вида транспорта для пробития файрволов и DPI:
В `client.toml` найдите секцию `[transport]`:
* `mode = "quic"` — Классический сверхбыстрый UDP транспорт.
* `mode = "ssh"` — Трафик маскируется под обычную SSH-сессию (TCP). Идеально для корпоративных сетей.
* `mode = "vnc"` — Трафик маскируется под удаленный рабочий стол VNC (RFB 3.8). Пробивает даже самую жесткую паранойю китайских фаерволов.

### Маскировка трафика (Stealth & DPI Bypass)
В секции `[stealth]` можно настроить обфускацию:
* `padding_step = 64` — Выравнивает размер пакетов, чтобы DPI не мог распознать паттерны (например, размер хендшейка Wireguard).
* `min_jitter_ns` / `max_jitter_ns` — Вносит случайные наносекундные задержки при отправке пакетов. Это ломает Timing-анализ у DPI оборудования, заставляя трафик выглядеть как обычный «шум».

### Split Tunneling (Маршрутизация)
В секции `[main]` можно выбрать, что пускать через VPN:
* Если заполнить `route_for = ["youtube.com", "instagram.com"]` — через VPN пойдут **только** эти сайты, всё остальное пойдет напрямую.
  * Помните про CDN! У того же youtube видео расположены совсем в другом месте, поэтому проще - настраивать  `exclude_route_for`. 
* Если оставить `route_for = []`, но заполнить `exclude_route_for = ["192.168.0.0/16", "sberbank.ru"]` — **весь** трафик пойдет через VPN, КРОМЕ этих сайтов и локальной сети.

### Запуск
* **CLI (Консоль):** Запускаем от `root`: `sudo ./anet-client -c client.toml`.
* **GUI (Окна/macOS):** Запускаем `anet-gui`. В интерфейсе жмем кнопку `➕ Добавить конфиг`, выбираем наш `client.toml` и жмем большую кнопку «Подключить». GUI умеет сворачиваться в трей и тихо висеть в фоне.

---

## Server: Кошка и котята (Продвинутая авторизация)

Перезапуск сервера при добавлении каждого пользователя — такое себе удовольствие.
Для этого есть `anet-auth` — HTTP Backend (REST API) и БД (PostgreSQL).

Логика сервера такая: сначала ищем фингерпринт локально в `allowed_clients`. Если нет — стучимся в базы из `auth_servers`. Если БД говорит "ОК" — пускаем, если нет — отлуп.

1. Поднимаем PostgreSQL. В `contrib/docker` есть готовый `docker-compose.infra.yaml`.
  * Закидываем на сервер, переименовываем в `docker-compose.yaml`, пишем `docker-compose up -d`.
2. Рядом с `anet-auth` создаем файл `.env` (копируем из `.env.example.auth`).
  * Пишем доступы к БД (`DATABASE_URL=postgres://user:password@localhost:5432/db`)
  * Придумываем `AUTH_BACKEND_KEY=super_secret_vpn_key_2025` — по этому ключу основной сервер будет стучаться в API.
3. Добавляем юзера через консоль: `./anet-auth -a "Koshka_Vasya"`. Утилита сама сгенерит ключи, положит фингерпринт в базу и выдаст вам готовые данные.
4. В конфиге **основного сервера** (`server.toml`) прописываем:
```toml
[authentication]
auth_servers = ["http://127.0.0.1:3000/api/v1"]
auth_server_token = "super_secret_vpn_key_2025"
```
5. Перезапускаем `anet-server` один раз. Теперь можно плодить клиентов через `./anet-auth -a` без перезагрузок VPN-сервера!