### ЧЁКУДА?!
Начнём с начала. 

Если вы разворачиваете всю инфраструктуру - читать по порядку, если настраиваете клиент - то переходите сразу к [Client](#client).


### Внимание! Клиент и серрвер должны запускаться от root или "администратор" иначе не хватит прав для создания TUN интерфейса!

Если вы не знаете Rust и не хотите собирать руками - **Все бинари находятся [здесь](https://github.com/ZeroTworu/anet/releases)**


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

* Через `make cert` создаём TLS сертификаты для QUIC (Не забудьте забрать `Makefile` из репы и поставить `openssl`)
  * Сертификат по умолчанию - 365 днея, для `/CN=alco`, `alco` - захардкожено в проекте, но вполне меняется пересборкой.

* Соответственно содержимое `cert.pem` - кладём в `quic_cert =`, `key_pem` - в `quic_key = ` а то, что сгенерил `anet-keygen` - он сам пишет в какую секцию и какому параметру прописать.
* параметры секций `[network]`, `[stealth]` и `[quic_transport]`  - настраиваем по желанию.

* В принципе первичная настройка сервера завершена, пробуем запуститься.
* (актуально с v0.5.1+) После запуска сервера, необходимо уже на уровне системы настроить маршрутизацию трафика:
### Запуск сервера, внимание!

После запуска сервера, настройте двухсторонние перенаправление траффика между `TUN` интерфейсом и вашим внешним интерфейсом.

*обычно* это так, но зависит от OS где запущен сервер и чего *именно* вы хотите.

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
Если у вас иные задача, другая OS, то вы и так знаете что вы делаете и "куда жать что бы было весело".


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

В `server.toml` есть `auth_servers = []` здесь размещён список бакендов, куда пойдёт сервер, что бы узнать, а можно ли пользователю с таким то ключём подключаться. 

Если фингерпринт не найден или он отключен - пользователь идёт нафиг.

Логика такая, вначале проверяем наличие в `allowed_clients = []`, если нашли - пускаем. Если не нашли, и нет бакендов - отлуп, есть бакенды? обходим каждый и спрашиваем его про этот фингерпринт.