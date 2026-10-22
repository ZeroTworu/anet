# Техническое задание: Реализация протокола ASTP-L (Anet Stream Transport Protocol - Lite) с поддержкой eBPF Offload

## 1. Общее описание и архитектура

**ASTP-L** — это гибридный транспортный протокол для VPN Anet, разделяющий жизненный цикл соединения на две фазы:

1. **Control Plane (Userspace):** Аутентификация, установка сессии (Handshake), обмен ключами (X25519 + ChaCha20-Poly1305), выделение IP-адреса, фоновая синхронизация статистики и периодическое обновление ключей (Rekeying). Выполняется стандартным Rust-сервером (`anet-server`) и клиентом (`anet-client` / `anet-client-core`).
2. **Data Plane (Kernelspace — eBPF):** Сверхбыстрая маршрутизация, инкапсуляция, декапсуляция и потоковое шифрование полезной нагрузки (IPv4-пакетов) непосредственно в ядре Linux на стороне сервера (и, опционально, Linux-клиента), минуя копирование памяти в Userspace (`Zero-Copy`).

**Цель:** Достижение гигабитных скоростей маршрутизации трафика при минимальной нагрузке на CPU сервера и нулевом джиттере (Jitter), с сохранением совместимости с уже реализованным в проекте eBPF-шейпером (`anet-ebpf` / `anet-ebpf-common`).

---

## 2. Спецификация протокола и структуры пакета

Протокол работает поверх **UDP** (IPv4). Порт сервера и IPv4-адрес сервера задаются в конфигурационном файле (`server.toml`) и пробрасываются в eBPF на этапе загрузки программ.

### 2.1. Формат пакета Data Plane (внешний)

После успешного хендшейка все пакеты данных имеют следующую структуру (начиная с L2 на физическом интерфейсе):

```text
+-----------------------------------------------------------------------+
| Ethernet Header (14 байт)                                             |
+-----------------------------------------------------------------------+
| Outer IPv4 Header (20 байт, без IP Options, IHL = 5)                  |
+-----------------------------------------------------------------------+
| Outer UDP Header (8 байт)                                             |
+-----------------------------------------------------------------------+
| ASTP-L Header: Sequence Number / Nonce (4 байта, u32, Big-Endian)     |
+-----------------------------------------------------------------------+
| Encrypted Payload: Внутренний IPv4 пакет (от 20 до MTU байт)          |
| Зашифрован потоковым шифром Xoroshiro128+ (XOR)                       |
+-----------------------------------------------------------------------+
```

* Суммарный размер инкапсуляции поверх внутреннего IPv4-пакета (Overhead): **`20 (Outer IPv4) + 8 (Outer UDP) + 4 (ASTP-L Seq) = 32 байта`**.
* **Важно для управляющих пакетов (Control Plane):** Если первые 4 байта UDP-пакета равны `0x00000000` (`Seq == 0`), это пакет **Handshake / Rekey / Control**. Такие пакеты eBPF-программа **НЕ обрабатывает**, а возвращает `XDP_PASS`, пропуская их в стандартный сетевой стек ОС в `anet-server` (Userspace UDP Socket). Пакеты данных всегда начинаются с `Seq >= 1`.

---

## 3. Архитектура eBPF и структуры данных (`anet-ebpf-common`)

Все общие структуры между Userspace (`anet-server`) и Kernelspace (`anet-ebpf`) размещаются в крейте `anet-ebpf-common`, имеют `#[repr(C)]`, явно выровнены без скрытых неинициализированных padding-байт (требование верификатора BPF при передаче ключей со стека) и реализуют `aya::Pod` (под `#[cfg(feature = "user")]`).

### 3.1. Глобальные константы (Global Config в `anet-ebpf`)

В `aya-ebpf = "0.2.1"` и Rust `edition = "2024"` для параметров, задаваемых загрузчиком из `server.toml`, используется обёртка `aya_ebpf::Global<T>` (с `read_volatile` внутри) и атрибут `#[unsafe(no_mangle)]`:

```rust
use aya_ebpf::Global;

/// UDP-порт ASTP-L в сетевом порядке байт (Big-Endian)
#[unsafe(no_mangle)]
static ASTPL_PORT: Global<u16> = Global::new(0);

/// Внешний IPv4-адрес сервера на eth0 в сетевом порядке байт (Big-Endian)
#[unsafe(no_mangle)]
static SERVER_IP: Global<u32> = Global::new(0);

/// Индекс физического интерфейса (eth0) для редиректа из TC Egress
#[unsafe(no_mangle)]
static ETH_IFINDEX: Global<u32> = Global::new(0);
```

Инициализация из `anet-server` (`aya = "0.14.0"`) выполняется через `EbpfLoader`:

```rust
let mut ebpf = aya::EbpfLoader::new()
    .override_global("ASTPL_PORT", &astpl_port.to_be(), true)
    .override_global("SERVER_IP", &u32::from(server_ipv4).to_be(), true)
    .override_global("ETH_IFINDEX", &eth_ifindex, true)
    .load(aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/anet-ebpf")))?;
```

### 3.2. Таблица №1: `ASTPL_INGRESS_MAP` (`BPF_MAP_TYPE_HASH`)

Используется `XDP`-программой на физическом интерфейсе (`eth0`) для верификации клиента, расшифровки входящего пакета и обновления его статистики.

* **Key (`OuterEndpoint`, 8 байт):**
  ```rust
  #[repr(C)]
  #[derive(Clone, Copy)]
  pub struct OuterEndpoint {
      pub src_ip: u32,   // Big-Endian (Network byte order)
      pub src_port: u16, // Big-Endian (Network byte order)
      pub _pad: u16,     // Явное выравнивание до 8 байт (всегда 0)
  }
  ```
* **Value (`IngressSessionData`, 32 байта):**
  ```rust
  #[repr(C)]
  #[derive(Clone, Copy)]
  pub struct IngressSessionData {
      pub crypto_seed: u64,   // 64-битный мастер-ключ сессии (RX/TX seed)
      pub rx_bytes: u64,      // Счётчик принятых байт (для синхронизации с ClientRegistry)
      pub last_seen_ns: u64,  // Таймстемп bpf_ktime_get_ns() последнего пакета
      pub assigned_ip: u32,   // Внутренний VPN IP клиента (Big-Endian, для anti-spoofing проверки)
      pub last_seq: u32,      // Последний принятый Seq
  }
  ```

### 3.3. Таблица №2: `ASTPL_EGRESS_MAP` (`BPF_MAP_TYPE_HASH`)

Используется `TC Egress`-программой на виртуальном интерфейсе (`tun0`), когда ответный пакет из интернета возвращается к клиенту.

* **Key (`u32`, 4 байта):** Внутренний IPv4-адрес назначения (`Inner Dst IP` — VPN IP клиента, Big-Endian).
* **Value (`EgressRoutingData`, 32 байта):**
  ```rust
  #[repr(C)]
  #[derive(Clone, Copy)]
  pub struct EgressRoutingData {
      pub crypto_seed: u64,   // 64-битный мастер-ключ сессии
      pub tx_bytes: u64,      // Счётчик отправленных байт (для синхронизации с ClientRegistry)
      pub last_seen_ns: u64,  // Таймстемп bpf_ktime_get_ns()
      pub dst_ip: u32,        // Реальный IP клиента в интернете (Big-Endian)
      pub tx_seq: u32,        // Счётчик исходящих пакетов (инкрементируется в eBPF, >= 1)
      pub dst_port: u16,      // Реальный UDP-порт клиента (Big-Endian)
      pub _pad: u16,          // Явное выравнивание (всегда 0)
  }
  ```

*(Для поддержки NAT traversal / смены порта клиентом на лету без потери маршрута можно хранить общий `SessionState` в `Array`/`HashMap` по индексу сессии, либо синхронизировать `dst_ip`/`dst_port` между Ingress и Egress картами).*

---

## 4. Криптографический примитив Data Plane (PRNG XOR)

Поскольку eBPF верификатор имеет жёсткие ограничения на количество инструкций и размер стека (512 байт), используется сверхбыстрый потоковый шифр на базе ГПСЧ **Xoroshiro128+** с привязкой к номеру пакета (`Seq`) и двухступенчатым прогревом состояния (warm-up), предотвращающим тривиальное восстановление `seed` по известному заголовку IPv4 (`0x4500...`) и открытому `seq`.

### 4.1. Реализация генератора (`no_std`, inline)

```rust
#[repr(C)]
pub struct Xoroshiro128Plus {
    s0: u64,
    s1: u64,
}

impl Xoroshiro128Plus {
    #[inline(always)]
    pub fn new(seed: u64, seq: u32) -> Self {
        let seq64 = seq as u64;
        let mut rng = Self {
            s0: seed ^ ((seq64 << 32) | (!seq64 & 0xFFFF_FFFF)),
            s1: seed.wrapping_add(0x9E37_79B9_7F4A_7C15).wrapping_mul(seq64 | 1),
        };
        // Обязательный прогрев (2 раунда), чтобы первый блок гаммы не был линейной суммой seed и seq
        let _ = rng.next_u64();
        let _ = rng.next_u64();
        rng
    }

    #[inline(always)]
    pub fn next_u64(&mut self) -> u64 {
        let s0 = self.s0;
        let mut s1 = self.s1;
        let result = s0.wrapping_add(s1);

        s1 ^= s0;
        self.s0 = s0.rotate_left(24) ^ s1 ^ (s1 << 16);
        self.s1 = s1.rotate_left(37);

        result
    }
}
```

### 4.2. Алгоритм шифрования/дешифрования в памяти пакета (In-Place)

* Обработка выполняется блоками по **8 байт (`u64`)** через `core::ptr::read_unaligned` / `write_unaligned` с явной проверкой границ `ptr + 8 <= data_end` на каждой итерации.
* Цикл должен быть ограничен константой (например, `for _ in 0..200`, что покрывает пакеты до `1600` байт), чтобы верификатор eBPF гарантированно доказал конечность цикла.
* **Обработка «хвоста» пакета (`len % 8 != 0`):** Если после основного цикла по 8 байт остаётся от 1 до 7 байт до `data_end`, генерируется ещё одно слово `let tail_mask = rng.next_u64().to_le_bytes();` и выполняется побайтовый XOR оставшихся `0..7` байт с проверкой `ptr + 1 <= data_end`.

---

## 5. Логика работы программ eBPF (`anet-ebpf`)

В существующем крейте `anet-ebpf` (где уже находится `anet_shaper`) добавляются две программы: `astpl_xdp_ingress` (`#[xdp]`) и `astpl_tc_egress` (`#[classifier]`).

### 5.1. Ingress: Программа `XDP` (на физическом интерфейсе `eth0`)

1. Получает `XdpContext`. Читает `data = ctx.data()` и `data_end = ctx.data_end()`.
2. Проверяет наличие `Ethernet Header (14) + Outer IPv4 Header (20) + Outer UDP Header (8) + ASTP-L Seq (4) = 46 байт` (`data + 46 <= data_end`).
3. Проверяет:
   * `EthHdr.ether_type == 0x0800_u16.to_be()` (IPv4);
   * `Ipv4Hdr.proto == 17` (UDP) и `Ipv4Hdr.ihl() == 5` (без IP-опций, 20 байт);
   * `UdpHdr.dst_port == ASTPL_PORT.load()`.
   Если любая проверка не прошла — возвращает `XDP_PASS`.
4. Читает 4 байта `Seq` сразу после UDP-заголовка (`offset 42..46`):
   * Если `Seq == 0`, возвращает `XDP_PASS` (пакет идёт в Userspace `anet-server` для Handshake / Rekey).
5. Формирует ключ `OuterEndpoint { src_ip: ip.src_addr, src_port: udp.src_port, _pad: 0 }` и ищет сессию через `ASTPL_INGRESS_MAP.get_ptr_mut(&key)`:
   * Если записи нет — возвращает `XDP_DROP` (защита от DDoS и неавторизованных пакетов на уровне драйвера сетевой карты).
6. Инициализирует `Xoroshiro128Plus::new(session.crypto_seed, u32::from_be(seq))` и расшифровывает payload (`data + 46 .. data_end`) прямо в буфере пакета (по 8 байт + хвост `1..7` байт).
7. Проверяет, что расшифрованный внутренний пакет (`data + 46`) содержит минимум 20 байт (`data + 66 <= data_end`), является валидным IPv4 (`version == 4`) и его `inner_ip.src_addr == session.assigned_ip` (защита от IP-спуфинга внутри туннеля). Обновляет `session.rx_bytes` и `session.last_seen_ns`.
8. **Декапсуляция на уровне XDP с сохранением L2-заголовка:**
   * Копирует 14 байт оригинального `Ethernet Header` (`data .. data + 14`) на 32 байта вправо (`data + 32 .. data + 46`), прямо перед началом расшифрованного внутреннего IPv4-пакета.
   * Вызывает `unsafe { aya_ebpf::helpers::bpf_xdp_adjust_head(ctx.ctx, 32) }` (сдвигает начало пакета на `20 (Outer IP) + 8 (UDP) + 4 (Seq) = 32` байта вправо).
   * Возвращает **`XDP_PASS`**.
   * **Результат:** Ядро Linux получает готовый стандартный Ethernet-кадр с расшифрованным внутренним IPv4-пакетом клиента и мгновенно маршрутизирует его через стандартный IP Forwarding / NAT в интернет без участия `tun0` и Userspace.

### 5.2. Egress: Программа `TC Classifier` (на виртуальном интерфейсе `tun0`)

Когда ответный пакет из интернета маршрутизируется ядром в подсеть VPN (`10.0.0.0/24`), он попадает в `tun0` (сначала проходит через `anet_shaper`, а затем в `astpl_tc_egress`):

1. Получает `TcContext`. Проверяет минимальную длину IPv4-пакета (`ctx.data() + 20 <= ctx.data_end()`).
2. Читает `Inner Dst IP` (байты `16..20` заголовка IPv4).
3. Ищет `Inner Dst IP` в `ASTPL_EGRESS_MAP.get_ptr_mut(&inner_dst_ip)`:
   * Если записи нет — возвращает `TC_ACT_OK` (пакет идёт обычным путём для классических клиентов Anet).
4. **Линеаризация буфера `sk_buff` (КРИТИЧНО для TC):**
   * Вызывает **`ctx.pull_data(0)`** (`bpf_skb_pull_data`), чтобы подтянуть все нелинейные страницы (`paged frags`) пакета в линейную область `ctx.data()..ctx.data_end()`.
   * Заново перечитывает `ctx.data()` и `ctx.data_end()`.
5. Инкрементирует `routing.tx_seq` (если в результате переполнения получилось `0`, ставит `1`), обновляет `routing.tx_bytes` и `routing.last_seen_ns`.
6. Инициализирует `Xoroshiro128Plus::new(routing.crypto_seed, routing.tx_seq)` и шифрует весь внутренний IPv4-пакет (`ctx.data() .. ctx.data_end()`) на месте (по 8 байт + хвост `1..7` байт).
7. **Расширение заголовка (`adjust_room`):**
   * Вызывает метод `TcContext`:
     ```rust
     let flags = (BPF_F_ADJ_ROOM_FIXED_GSO
         | BPF_F_ADJ_ROOM_ENCAP_L3_IPV4
         | BPF_F_ADJ_ROOM_ENCAP_L4_UDP) as u64;
     ctx.adjust_room(32, BPF_ADJ_ROOM_NET, flags)?;
     ```
   * Это раздвигает начало пакета ровно на **32 байта** (`Outer IPv4 (20) + Outer UDP (8) + ASTP-L Seq (4)`).
8. Заново проверяет `ctx.data() + 32 <= ctx.data_end()` и записывает в новые 32 байта:
   * **Outer IPv4 Header (20 байт):** `version_ihl = 0x45`, `tos = 0`, `tot_len = (ctx.len() as u16).to_be()`, `id = 0`, `frag_off = 0x4000u16.to_be()` (DF), `ttl = 64`, `proto = 17` (UDP), `src_addr = SERVER_IP.load()`, `dst_addr = routing.dst_ip`, и вычисляет IPv4 Header Checksum (компактной inline-функцией свертки 10 слов `u16`).
   * **Outer UDP Header (8 байт):** `src_port = ASTPL_PORT.load()`, `dst_port = routing.dst_port`, `len = ((ctx.len() - 20) as u16).to_be()`, `check = 0` (для IPv4 UDP checksum `0` валиден по RFC 768 и не требует пересчёта по всему payload).
   * **ASTP-L Seq (4 байта):** `routing.tx_seq.to_be()`.
9. **Отправка в физический интерфейс через подсистему соседей (ARP/Neighbour):**
   * Вызывает `unsafe { aya_ebpf::helpers::bpf_redirect_neigh(ETH_IFINDEX.load(), core::ptr::null_mut(), 0, 0) as i32 }`.
   * Хелпер `bpf_redirect_neigh` (доступен в Linux 5.10+) самостоятельно определяет L2 MAC-адреса (`src_mac` / `dst_mac` шлюза по таблице маршрутизации и ARP) и отправляет пакет напрямую в `eth0`, полностью минуя чтение из файлового дескриптора `tun0` в Userspace.

---

## 6. Логика работы Userspace (`anet-server`)

1. **Инициализация и сосуществование с `Shaper`:**
   * При старте `anet-server` загружает единый eBPF-объект `anet-ebpf` через `EbpfLoader::new()` с установкой `ASTPL_PORT`, `SERVER_IP`, `ETH_IFINDEX`.
   * Прикрепляет `astpl_xdp_ingress` к физическому интерфейсу (например, `eth0`) в режиме `XdpFlags::default()` (с fallback на `XdpFlags::SKB_MODE`, если драйвер VPS не поддерживает Native XDP).
   * На `tun0` добавляет `clsact` (`aya::programs::tc::qdisc_add_clsact`) и прикрепляет `anet_shaper` (с `priority: 10`) и `astpl_tc_egress` (с `priority: 20` через `TcAttachOptions::Netlink(NlOptions { priority: 20, ..Default::default() })`).
   * Для `tun0` рекомендуется отключить `GSO`/`TSO`/`GRO` через `ethtool -K` или `ioctl`, чтобы пакеты шифровались в пределах MTU без сегментации.
2. **Обработка Handshake (`Seq == 0`):**
   * Сервер слушает UDP-сокет на порту `ASTPL_PORT`. Поскольку `XDP` забирает все валидные пакеты с `Seq > 0`, в Userspace попадают только пакеты с `Seq == 0`.
   * Выполняется существующий криптографический Handshake Anet (`AuthHandler`), клиенту выделяется IP из пула (`10.0.0.x`), и из общего секрета выводится `crypto_seed: u64`.
   * Сервер записывает сессию в `ASTPL_INGRESS_MAP` и `ASTPL_EGRESS_MAP` и отправляет клиенту подтверждение хендшейка с `Seq = 0`.
3. **Фоновая синхронизация с `ClientRegistry` и Rekeying:**
   * Поскольку пакеты данных не проходят через Userspace, фоновая задача `anet-server` раз в `5–10` секунд читает `rx_bytes`, `tx_bytes` и `last_seen_ns` из BPF-карт и обновляет `ClientInfo` в `ClientRegistry` (чтобы `cleanup_inactive_clients` не удалял активные eBPF-сессии по таймауту, а в статистике отображался реальный трафик).
   * При удалении неактивного клиента его ключи удаляются из `ASTPL_INGRESS_MAP` и `ASTPL_EGRESS_MAP`.
   * Раз в `N` минут (или по объёму трафика) инициируется управляющий пакет с `Seq = 0` для смены `crypto_seed` (Rekeying) и атомарного обновления карт.

---

## 7. Логика работы Клиента (`anet-client` / `anet-client-core`)

Клиент может работать на любой ОС (Windows, macOS, Android, iOS, Linux) полностью в Userspace без зависимости от eBPF:

1. Выполняет Handshake с сервером, отправляя пакеты с префиксом `0x00000000` (`Seq = 0`).
2. Получает от сервера настройки `TUN` и `crypto_seed: u64`.
3. **Отправка (TX):**
   * Читает IPv4-пакет из локального `TUN`.
   * Увеличивает локальный `tx_seq: u32` (при переполнении в `0` ставит `1`).
   * Инициализирует `Xoroshiro128Plus::new(crypto_seed, tx_seq)` (с 2 раундами прогрева) и шифрует буфер (по 8 байт + хвост `1..7` байт).
   * Дописывает в начало 4 байта `tx_seq.to_be_bytes()` и отправляет в UDP-сокет.
4. **Приём (RX):**
   * Читает датаграмму из UDP-сокета.
   * Читает первые 4 байта (`seq`). Если `seq == 0` — передаёт пакет обработчику Control Plane (Rekey / Keepalive).
   * Если `seq > 0` — инициализирует `Xoroshiro128Plus::new(crypto_seed, seq)`, расшифровывает остаток буфера и пишет чистый IPv4-пакет в локальный `TUN`.

---

## 8. Требования к реализации и окружению сборки

1. **Версии крейтов в workspace:**
   * Userspace (`anet-server`): `aya = "0.14.0"`, `aya-log = "0.3.0"`.
   * Kernelspace (`anet-ebpf`): `aya-ebpf = "0.2.1"`, `aya-log-ebpf = "0.2.0"`, Rust `edition = "2024"`.
   * Общие типы (`anet-ebpf-common`): `#![no_std]`, `aya = { version = "0.14.0", optional = true }`.
2. **Строгие правила для BPF-верификатора (`anet-ebpf`):**
   * В Rust 2024 использовать `#[unsafe(no_mangle)]` и явные блоки `unsafe { ... }` внутри `unsafe fn`.
   * Перед любым чтением или записью по указателю пакета (`data + offset`) выполнять явную проверку `if ptr + size > data_end { return ...; }`.
   * После вызовов `ctx.pull_data(...)`, `ctx.adjust_room(...)` или `bpf_xdp_adjust_head(...)` все старые указатели на пакет считаются недействительными — обязательно заново получать `ctx.data()` и `ctx.data_end()`.
   * Все циклы шифрования должны иметь жёсткую верхнюю границу итераций (`for _ in 0..MAX_BLOCKS`), а вспомогательные функции помечаться `#[inline(always)]`.
   * Не использовать динамические аллокации (`alloc`, `Vec`, `String`) и паникующие индексации срезов (`slice[i]`) в коде `anet-ebpf`.
