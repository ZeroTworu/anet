### ЧЁКУДА?!


Дока актуальна для `v0.5.1+` для остальных часть компонентов, таких как `anet-keygen` и `anet-auth` придётся собирать самостоятельно!


Начнём с начала. 

Если вы разворачиваете всю инфраструктуру - читать по порядку, если настраиваете клиент - то переходите сразу к [Client](#client).


### Внимание! Клиент и серрвер должны запускаться от root или "администратор" иначе не хватит прав для создания TUN интерфейса!

Если вы не знаете Rust и не хотите собирать руками - **Все бинари находятся [здесь](https://github.com/ZeroTworu/anet/releases)**


Прежде чем начать - подумай, а оно тебе надо? Самый копеечный VPS обойдётся в 6$ в месяц, это два месяца подписк на любой сторонний сервис!

#### Server: Первичная настройка.

* Качаем (или собираем, что лучше) - `anet-server` нужной нам версии, а также `anet-keygen`.
* Через `anet-keygen` генерируем приватный и публичный ключи сервера, пример:
```
 ./anet-keygen server
 
 === ANet Server Signing Key ===

Private Signing Key (add to server.toml):
[crypto]
server_signing_key = "BGQGf36RKbzEQ6Ef68O0ScVA+tLeVoYcTAE61Mig1js="

Public Key (for client verification, optional):
iqo4UuQlbWN35Pyp5vQedTEt1FeKA+6wxYTVS/XzHww=
```
`Public Key` - сохраняем куданить на криптофлешку, он на самом деле не фига не "optional"! Его мы будем раздавать клиентам.

* Через 

* `openssl req -x509 -newkey ed25519 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=alco" -addext "subjectAltName = DNS:alco" -addext "basicConstraints=critical,CA:FALSE" -addext "keyUsage=digitalSignature,keyEncipherment"
` 
создаём TLS сертификаты для QUIC (Не забудьте проверить наличие `openssl`, если нету - поставьте)
  * Сертификат по умолчанию - 365 днея, для `/CN=alco`, `alco` - захардкожено в проекте, но вполне меняется пересборкой.

* Соответственно содержимое `cert.pem` - кладём в `quic_cert =`, `key_pem` - в `quic_key = ` а то, что сгенерил `anet-keygen` - он сам пишет в какую секцию и какому параметру прописать.
* параметры секций `[network]`, `[stealth]` и `[quic_transport]`  - настраиваем по желанию.

* В принципе первичная настройка сервера завершена, пробуем запуститься.
* (актуально с v0.5.1+) После запуска сервера, необходимо уже на уровне системы настроить маршрутизацию трафика:
### Запуск сервера, внимание!

После запуска сервера, настройте двухсторонние перенаправление траффика между `TUN` интерфейсом и вашим внешним интерфейсом.

*обычно* это так, но зависит от OS (в примере - для Ubuntu 22.04 **И ЭТО ВАЖНО!**) где запущен сервер и чего *именно* вы хотите.

```
# Разрешаем входящие на порт сервера
iptables -I INPUT --dport <Server port> -j ACCEPT 

# Перенаправлям трафик из внешнего мира в VPN
iptables -I FORWARD -i <External Interface> -o <if_name from server config> -j ACCEPT

# Перенаправлям трафик из VPN в внешний мир
iptables -I FORWARD -i <if_name from server config> -o <External Interface> -j ACCEPT

# Включаем NAT
iptables -t nat -A POSTROUTING -o <External Interface> -j MASQUERADE
```
Также для Ubunutu нужно включить IPv4 forwarding, если команда `sysctl net.ipv4.ip_forward` выводит 0:
```
sudo sysctl -w net.ipv4.ip_forward=1
echo 'net.ipv4.ip_forward=1' | sudo tee /etc/sysctl.d/99-anet.conf
sudo sysctl --system
```

Если у вас иные задачи, другая OS (как показал опыт - в Ubunta 24.04 они **ДРУГИЕ**), то вы и так знаете что вы делаете и "куда жать что бы было весело".

Что бы узнать что у вас вообще стоит - выполните `cat /etc/os-release`.

**ВАЖНО!** После `reboot` ваши правила пропадут. Гуглите как в вашей OS сохранять их!


### Server: Пользователи

Тут у нас два стула - немного гиморный, но почти-как-в-энтерпрайз, и быстрый - "для меня и моей кошки".

Вначале рассмотрим второй, т.к. он проще.

#### Я и моя кошка.

В конфиге сервера есть параметр: `allowed_clients = []` - сюда пишутся отпечатки клиентов.

* Создаём первого клиента - `anet-keygen client`:
```aiignore
 ./anet-keygen client                         
=== ANet Client Keys ===

Private Key (add to client.toml):
[keys]
private_key = "QehLlLB5gNzceXAjjsl/1RQKeY97RVN8GBgHlfsHbn4="

Fingerprint (add to server.toml allowed_clients):
f+f9KfEh/kuAZUzLMT4z7A==

Public Key (for client verification, optional):
7IQrEFuiMAz02p2Pnx8tSd0698O8E/fjgAGzIo1xv/4=

Note: Keep private keys secure! Do not share them.
```

* Полученный Fingerprint, в нашем случае `f+f9KfEh/kuAZUzLMT4z7A==` вписываем в `allowed_clients = []`, будет `allowed_clients = ["f+f9KfEh/kuAZUzLMT4z7A=="]`.
* **ВАЖНЫЙ** момент! Сервер после этого надо перезапустить, что бы он перечитал конфиг и клиентов.
* `private_key = "QehLlLB5gNzceXAjjsl/1RQKeY97RVN8GBgHlfsHbn4="` отдаём кошке, так же не забудьте сказать кошке `address:port` сервера (это куда настроен `bind_to = ` и `Public Key` **сервера** который мы получили на втором шаге)

Самое время поговорить о `Client`, а к продвинутым настройкам пользователей перейдём в конце.

### Client

Вы - кошка, из предыдущей части, как настроить клиент под сервер?

И так, у вас есть: набор `private_key = "QehLlLB5gNzceXAjjsl/1RQKeY97RVN8GBgHlfsHbn4="` условный `vpn.yandex.ru:666` и `Server Public Key` который `iqo4UuQlbWN35Pyp5vQedTEt1FeKA+6wxYTVS/XzHww=`, куда сие пихать?

* Качаем (а лучше собираем) клиент **той же версии** что и сервер. Или хотя бы в рамках "протокольной совместимости" (вторая цифра в `v0.X.Y`) - `X` тут отвечает за совместимость протокола.
* Открываем `client.toml`  - шаблон всё там же в `contrib/config`.
* В `[main]` в `address = ""` пишем тот самый `vpn.yandex.ru:666` - `address = vpn.yandex.ru:666`
* В `[keys]` в `private_key = ""` **СВОЙ ПРИВАТНЫЙ КЛЮЧ** в нашём случае `"QehLlLB5gNzceXAjjsl/1RQKeY97RVN8GBgHlfsHbn4="` - получится то самое `private_key = "QehLlLB5gNzceXAjjsl/1RQKeY97RVN8GBgHlfsHbn4="`
* В `[keys]` в `server_pub_key = ""` **ПУБЛИЧНЫЙ КЛЮЧ СЕРВЕРА** в нашем случае `iqo4UuQlbWN35Pyp5vQedTEt1FeKA+6wxYTVS/XzHww=` - получаем `server_pub_key = "iqo4UuQlbWN35Pyp5vQedTEt1FeKA+6wxYTVS/XzHww="`
* **ВСЁ** первичная настройка клиента готова! Выбираем клиент по вкусу, пихаем ему конфиг, запускаем.
  * МОМЕНТ! Если вы используете консольный клиент - то конфиг должен лежать или рядом с бинарником, или мы должны указать полный путь до конфига через ключ `-c` - `./anet-client -c /home/koshka/koska.toml`

* У Windows GUI  / Android за выбор конфига отвечает "крест в круге" в правом верхнем углу, как там в macOS я хз, порт под мак делал не я. С другой стороны, я бы посмотрел на человека, который сие под маком будет юзать.

### Server: Кошка и котята.

Как можно заметить, перезапуск сервера после добавления / удаления каждого клиента - не лучшая идея.

Итак - `anet-auth` - HTTP Backend для аутентификации и создания пользователей.

В `server.toml` есть `auth_servers = []` здесь размещён список бакендов, куда пойдёт сервер, что бы узнать, а можно ли пользователю с таким то ключом подключаться. 

Если фингерпринт не найден или он отключен - пользователь идёт нафиг.

Логика такая, вначале проверяем наличие в `allowed_clients = []`, если нашли - пускаем. Если не нашли, и нет бакендов - отлуп, есть бакенды? обходим каждый и спрашиваем его про этот фингерпринт.

* Во первых - нам нужен PostgreSQL. Как вы его поставите и настроите - ваши проблемы, но в `contrib/docker` уже есть `compose-file` для него.
  * Гуглим как ставить `docker` под свою OS.
  * Закидываем `docker-compose.infra.yaml` из `contrib/docker` на сервер переименовав в `docker-compose.yaml` (`mv docker-compose.infra.yaml docker-compose.yaml`) (лучше туда же где и весь, ANet, что бы всё - в одном месте.)
  * При желании - редактируем меняя предустановленный логин / пароль / порт.
  * пишем `docker-compose up -d` для запуска контейнера в режиме демона.

* Как бы мы не поставили PostgreSQL, предпологаем что сейчас он запущен и работает. файл `.env.example.auth`, который лежит вместе с сервером, переименовываем просто в `.env`.
* Правим наш `.env`:

Сюда - параметры из `docker-compose.yaml`
```
DATABASE_URL=postgres://user:password@localhost:5432/anet_auth_db
```

Самое важное - "парольная фраза" по которой auth будет проверять, что на него стучится валидный VPN сервер, а не очередной китаец.
```
AUTH_BACKEND_KEY=super_secret_vpn_key_2025
```

Лучше не менять, что бы не был доступен из внешнего мира, уж слишком на коленке написано.
```
BIND_TO=127.0.0.1:3000
```

По сути `anet-auth` это примитивнейший CRUD с одной REST API точкой, которая по переданному фингерпринту ищет пользователя в БД и проверяет его активность.

* Добавляем нового пользователя - `./anet-auth -a <USERNAME>` - добавит в БД нового пользователя USERNAME и выдаст в консоль его ревизиты.
* В `server.toml` в `auth_servers = []` добавляем наш бакенд - `auth_servers = ["http://127.0.0.1:3000/api/v1"]`
* Перезапускаем `anet-server`, готово.
