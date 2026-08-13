# anet-appfilter

Per-app split tunneling для Windows — то же, что `addAllowedApplication` /
`addDisallowedApplication` в Android-версии ANet, но для десктопа.

## Зачем и как это работает

IP-пакет не содержит имени процесса. Но ОС знает, какому процессу принадлежит
каждый сокет. Так делал Agnitum Outpost (kernel-драйвер TDI), так делает
Mullbad split-tunnel (WFP callout). Нам не нужно писать и подписывать свой
драйвер: [WinDivert](https://reqrypt.org/windivert.html) — это уже подписанный
kernel-драйвер с userspace-API.

Схема:

```
                 ┌─────────────── WinDivert Flow layer (sniff) ───────────┐
                 │  событие FlowEstablished: 5-tuple + process_id          │
                 ▼                                                         │
           ┌──────────┐   заполняет                                        │
           │ FlowMap  │◄─────────────── run_flow_tracker ──────────────────┘
           │ 5tuple→  │
           │ process  │
           └────┬─────┘
                │ читает
                ▼
   WinDivert Network layer ── run_packet_router ──┐
   (перехват исходящих)                           │
        для каждого пакета:                        │
        1. classify() → 5-tuple                    │
        2. FlowMap.lookup() → процесс              │
        3. policy.should_tunnel()?                 │
             да → в канал anet-client (→ QUIC)     │
             нет → WinDivertSend (напрямую)        │
                                                   │
   пакеты ИЗ QUIC ──► reinjector ──► WinDivertSend (inbound)
```

Пакеты «выбранных» приложений забираются из системного стека и уходят в
существующий транспорт ANet без единой правки в самом транспорте — потому что
[`AppFilter::start`] отдаёт ту же пару каналов `(Sender<Bytes>, Receiver<Bytes>)`,
что раньше отдавал `TunFactory::create_tun`. Это работает для ЛЮБОГО транспорта
(QUIC/SSH/VNC и будущих): все они читают/пишут сырые IP-пакеты через эти каналы
и не знают, откуда те берутся — из TUN или из WinDivert.

## Интеграция в anet-client (уже сделано)

Интеграция встроена в `anet-client-core`: метод `acquire_packet_source`
сам выбирает источник пакетов по конфигу. Ничего вызывать вручную не нужно —
достаточно задать per-app список в конфиге клиента:

```toml
[main]
# Windows per-app split tunneling.
# include-режим: в туннель идут ТОЛЬКО эти процессы.
per_app = ["firefox.exe", "telegram.exe"]
per_app_exclude = false

# exclude-режим (в туннель всё, КРОМЕ этих):
# per_app = ["steam.exe"]
# per_app_exclude = true
```

Пусто (`per_app = []`, по умолчанию) — обычный полный туннель через TUN,
поведение не меняется. На не-Windows платформах поле игнорируется.

Клиент при подключении:
1. складывает в bypass-набор все IP-литералы из `[[servers]]`;
2. резолвит адрес текущего сервера и добавляет фактический IP в bypass
   (покрывает домены и failover);
3. в per-app режиме НЕ трогает дефолтный маршрут и системный DNS —
   маршрутизацией занимается WinDivert на уровне пакетов.

## Self-traffic exclusion

Трафик к самому VPN-серверу никогда не заворачивается (иначе рекурсия).
Набор bypass-адресов наполняется из двух источников:
- статически — IP-литералы серверов из `[[servers]]`;
- динамически — фактический резолвнутый адрес при каждом подключении
  (домены, DNS round-robin, смена сервера при failover).

## Маршрутизация (важно!)

WinDivert решает, *какие* пакеты забрать, но не настраивает маршруты. Чтобы
перехваченный трафик реально ушёл в туннель и вернулся, нужно:

1. **IP VPN-сервера — bypass (уже сделано).** Пакеты к серверу ANet не
   попадают под перехват: клиент кладёт адреса серверов в bypass-набор
   статически (IP из конфига) и динамически (резолв при подключении).
   См. раздел «Self-traffic exclusion».

2. **TUN всё равно нужен** как приёмник обратного трафика: реинъекция делает
   вид, что пакет пришёл извне, а ядро должно знать маршрут к внутренним
   адресам туннеля. На практике проще всего поднять обычный TUN ANet (адрес
   из auth), но НЕ ставить его дефолтным шлюзом — маршрутизацией «кто в туннель»
   занимается appfilter, а не таблица маршрутов.

3. **DNS.** Как и на Android: резолвером часто выступает системный `svchost`,
   а не само приложение, поэтому DNS-запросы могут не попасть в per-app список.
   Простейшее решение — весь DNS (udp/tcp порт 53) заворачивать в туннель
   безусловно. Это отдельная строка в фильтре, если понадобится.

## Требования

- Права администратора (как и для TUN сейчас).
- Драйвер WinDivert: положить `WinDivert.dll` + `WinDivert64.sys` рядом с
  бинарём (или установить). Крейт `windivert-sys` умеет искать их в PATH/рядом.
- Только Windows. На других платформах крейт компилируется в пустышку,
  `AppFilter::start` возвращает ошибку — вызывающий код откатывается на TUN.

## Сборка и фичи

Per-app **выключен по умолчанию** — крейт собирается как заглушка без
зависимости от WinDivert. Это важно: обычная сборка (в т.ч. кросс-компиляция
`--target x86_64-pc-windows-gnu`) проходит без WinDivert SDK и без падения
build-скрипта `windivert-sys`.

```sh
# Обычная сборка GUI — БЕЗ per-app, WinDivert не нужен (работает как раньше):
cargo build --release --target x86_64-pc-windows-gnu --package anet-client-gui

# С per-app split tunneling. Нужны файлы WinDivert; путь к ним — через
# переменную окружения WINDIVERT_PATH (там лежат WinDivert.dll/.lib/.sys):
WINDIVERT_PATH=/path/to/windivert \
  cargo build --release --target x86_64-pc-windows-gnu \
  --package anet-client-gui --features per-app

# Либо собрать WinDivert из C-исходников (нужен clang), без готовых бинарников:
cargo build --release --package anet-client-gui \
  --features anet-client-core/anet-appfilter/vendored
```

Иерархия фич: `anet-client-gui/per-app` → `anet-client-core/per-app`
→ `anet-appfilter/windivert`. То есть достаточно включить `per-app` у верхнего
пакета. Без неё `per_app`-конфиг просто игнорируется и клиент идёт через TUN.
