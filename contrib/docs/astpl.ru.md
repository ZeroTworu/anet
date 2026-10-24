# Техническое задание: Реализация протокола ASTP-L (Anet Stream Transport Protocol - Lite) с поддержкой eBPF Offload

## 1. Общее описание и архитектура

**ASTP-L** — это гибридный транспортный протокол для VPN Anet, разделяющий жизненный цикл соединения на две фазы на **едином UDP-порту**:

1. **Control Plane (Userspace):** Аутентификация, установка сессии (4-фазный стелс-хендшейк ASTP с поддержкой UDP-фрагментации `DatagramReassembler`), обмен ключами (X25519 + HKDF-SHA256 + ChaCha20-Poly1305), выделение IP-адреса и фоновая синхронизация статистики. Выполняется стандартным Rust-сервером (`anet-server`) и клиентом (`anet-client` / `anet-client-core`).
2. **Data Plane (Kernelspace — eBPF):** Сверхбыстрая маршрутизация, демультиплексирование по `nonce_prefix` за $O(1)$, бесшовный NAT Rebinding, инкапсуляция, декапсуляция и потоковое шифрование полезной нагрузки (IPv4-пакетов) непосредственно в ядре Linux на стороне сервера, минуя копирование памяти в Userspace (`Zero-Copy`).

**Ключевые архитектурные возможности (унифицированные с QUIC-транспортом):**
* **Единый UDP-порт для Handshake и Data Plane:** Сервер слушает один UDP-сокет (`astpl_bind_to`, например `0.0.0.0:8444`). XDP-программа в ядре за $O(1)$ отличает трафик активных сессий по 4-байтному `nonce_prefix` от пакетов первичного рукопожатия ASTP (Phase I / Phase III), прозрачно пропуская хендшейки в Userspace через `XDP_PASS`.
* **Поддержка UDP-фрагментации хендшейка (`DatagramReassembler`):** Первые пакеты рукопожатия (до появления сессионного ключа в BPF-карте) могут дробиться клиентом на $N$ независимых UDP-фрагментов со случайными точками разреза и наносекундным джиттером (`[stealth] frag_enabled = true`). Поскольку их префиксы не зарегистрированы в `ASTPL_INGRESS_MAP`, XDP пропускает все фрагменты (`XDP_PASS`) в Userspace-сокет, где штатный `DatagramReassembler` собирает их даже при перестановке датаграмм в сети.
* **Бесшовная миграция адреса клиента в ядре (Kernel NAT Rebinding):** При смене внешнего IP/порта клиента (переход Wi-Fi ↔ LTE или протухание NAT-таблицы) XDP-программа находит сессию по `nonce_prefix`, верифицирует инварианты расшифрованного IPv4-заголовка и **напрямую из ядра** обновляет внешний адрес клиента в `ASTPL_EGRESS_MAP` без пробуждения Userspace.

---

## 2. Спецификация протокола и структуры пакета

Протокол работает поверх **UDP** (IPv4). Порт сервера и IPv4-адрес сервера задаются в конфигурационном файле (`server.toml`) и пробрасываются в eBPF на этапе загрузки программ.

### 2.1. Формат пакета Data Plane (внешний)

После успешного хендшейка обе стороны выводят из `shared_key` через HKDF-SHA256:
* `nonce_prefix: [u8; 4]` (`u32`) — уникальный 4-байтный идентификатор маршрутизации сессии (аналогично QUIC-транспорту).
* `crypto_seed: u64` — 64-битный секретный ключ инициализации генератора `Xoroshiro128+`.

Все пакеты данных имеют следующую структуру (начиная с L2 на физическом интерфейсе):

```text
+-----------------------------------------------------------------------+
| Ethernet Header (14 байт)                                             |
+-----------------------------------------------------------------------+
| Outer IPv4 Header (20 байт, без IP Options, IHL = 5)                  |
+-----------------------------------------------------------------------+
| Outer UDP Header (8 байт)                                             |
+-----------------------------------------------------------------------+
| ASTP-L Header (8 байт):                                               |
|   - Nonce Prefix (4 байта, u32, Big-Endian) — ID сессии из HKDF       |
|   - Sequence Number (4 байта, u32, Big-Endian) — счётчик пакета       |
+-----------------------------------------------------------------------+
| Encrypted Payload: Внутренний IPv4 пакет (от 20 до MTU байт)          |
| Зашифрован потоковым шифром Xoroshiro128+ (XOR)                       |
+-----------------------------------------------------------------------+
```

* Суммарный размер инкапсуляции поверх внутреннего IPv4-пакета (Overhead): **`20 (Outer IPv4) + 8 (Outer UDP) + 8 (ASTP-L Header) = 36 байт`**.
* **Демультиплексирование Control Plane vs Data Plane:**
  * Пакеты Handshake (Phase I / Phase III), в том числе нарезанные через `fragment_datagram`, не содержат зарегистрированного `nonce_prefix` в `ASTPL_INGRESS_MAP`. XDP-программа при промахе в `ASTPL_INGRESS_MAP` мгновенно возвращает `XDP_PASS`, доставляя пакет в Userspace (`anet-server`) на том же UDP-порту.
  * Если в рамках установленной сессии требуется передать управляющий пакет в Userspace, используется зарезервированное значение `Seq == 0` (`XDP_PASS`). Пакеты данных всегда имеют `Seq >= 1`.

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

Используется `XDP`-программой на физическом интерфейсе (`eth0`) для $O(1)$ идентификации сессии по `nonce_prefix` (независимо от смены IP/порта клиента при NAT Rebinding), расшифровки входящего пакета и обновления его статистики.

* **Key (`u32`, 4 байта):** `nonce_prefix` (первые 4 байта UDP payload в Big-Endian).
* **Value (`IngressSessionData`, 40 байт):**
  ```rust
  #[repr(C)]
  #[derive(Clone, Copy)]
  pub struct IngressSessionData {
      pub crypto_seed: u64,   // 64-битный мастер-ключ сессии (RX/TX seed)
      pub rx_bytes: u64,      // Счётчик принятых байт (для синхронизации с ClientRegistry)
      pub last_seen_ns: u64,  // Таймстемп bpf_ktime_get_ns() последнего пакета
      pub assigned_ip: u32,   // Внутренний VPN IP клиента (Big-Endian, для anti-spoofing и поиска в EGRESS_MAP)
      pub last_seq: u32,      // Последний принятый Seq
      pub client_ip: u32,     // Текущий внешний IPv4 клиента (Big-Endian, отслеживание NAT Rebinding)
      pub client_port: u16,   // Текущий внешний UDP-порт клиента (Big-Endian, отслеживание NAT Rebinding)
      pub _pad: u16,          // Явное выравнивание до 40 байт (всегда 0)
  }
  ```

### 3.3. Таблица №2: `ASTPL_EGRESS_MAP` (`BPF_MAP_TYPE_HASH`)

Используется `TC Egress`-программой на виртуальном интерфейсе (`tun0`), когда ответный пакет из интернета возвращается к клиенту, а также **обновляется напрямую из `XDP`** при обнаружении миграции адреса клиента (NAT Rebinding).

* **Key (`u32`, 4 байта):** Внутренний IPv4-адрес назначения (`Inner Dst IP` — VPN IP клиента, Big-Endian, равен `assigned_ip`).
* **Value (`EgressRoutingData`, 40 байт):**
  ```rust
  #[repr(C)]
  #[derive(Clone, Copy)]
  pub struct EgressRoutingData {
      pub crypto_seed: u64,   // 64-битный мастер-ключ сессии
      pub tx_bytes: u64,      // Счётчик отправленных байт (для синхронизации с ClientRegistry)
      pub last_seen_ns: u64,  // Таймстемп bpf_ktime_get_ns()
      pub dst_ip: u32,        // Текущий внешний IPv4 клиента в интернете (Big-Endian, обновляется при роуминге)
      pub nonce_prefix: u32,  // 4-байтный идентификатор сессии для заголовка ASTP-L (Big-Endian)
      pub tx_seq: u32,        // Счётчик исходящих пакетов (инкрементируется в eBPF, >= 1)
      pub dst_port: u16,      // Текущий внешний UDP-порт клиента (Big-Endian, обновляется при роуминге)
      pub _pad: u16,          // Явное выравнивание до 40 байт (всегда 0)
  }
  ```

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

### 5.0. Универсальная обёртка доступа к пакету (`ContextWrapper`) и `network-types`

Чтобы не дублировать арифметику указателей и проверки границ для верификатора между `XdpContext` и `TcContext`, а также использовать готовые `#[repr(C)]` заголовки (`EthHdr`, `EtherType`, `Ipv4Hdr`, `IpProto`, `UdpHdr`) из крейта `network-types = "0.0.7"`, в `anet-ebpf` вводится `ContextWrapper`:

```rust
use core::mem;
use aya_ebpf::programs::{TcContext, XdpContext};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    udp::UdpHdr,
};

pub enum ContextWrapper<'a> {
    Xdp(&'a XdpContext),
    Tc(&'a TcContext),
}

impl<'a> ContextWrapper<'a> {
    #[inline(always)]
    pub fn data(&self) -> usize {
        match self {
            Self::Xdp(ctx) => ctx.data(),
            Self::Tc(ctx) => ctx.data(),
        }
    }

    #[inline(always)]
    pub fn data_end(&self) -> usize {
        match self {
            Self::Xdp(ctx) => ctx.data_end(),
            Self::Tc(ctx) => ctx.data_end(),
        }
    }

    /// Безопасное получение константного указателя со строгой проверкой границ для BPF-верификатора
    #[inline(always)]
    pub fn ptr_at<T>(&self, offset: usize) -> Result<*const T, ()> {
        let start = self.data();
        let end = self.data_end();
        let len = mem::size_of::<T>();

        if start + offset + len > end {
            return Err(());
        }
        Ok((start + offset) as *const T)
    }

    /// Безопасное получение мутабельного указателя со строгой проверкой границ для BPF-верификатора
    #[inline(always)]
    pub fn ptr_at_mut<T>(&self, offset: usize) -> Result<*mut T, ()> {
        let start = self.data();
        let end = self.data_end();
        let len = mem::size_of::<T>();

        if start + offset + len > end {
            return Err(());
        }
        Ok((start + offset) as *mut T)
    }

    /// Невыровненное чтение (важно после 14-байтного EthHdr, где смещение L3/L4 кратно 2, но не 4 или 8)
    #[inline(always)]
    pub fn read_unaligned<T: Copy>(&self, offset: usize) -> Result<T, ()> {
        let ptr = self.ptr_at::<T>(offset)?;
        Ok(unsafe { core::ptr::read_unaligned(ptr) })
    }

    /// Невыровненная запись (для u32/u64 полей и блоков шифрования)
    #[inline(always)]
    pub fn write_unaligned<T: Copy>(&self, offset: usize, val: T) -> Result<(), ()> {
        let ptr = self.ptr_at_mut::<T>(offset)?;
        unsafe { core::ptr::write_unaligned(ptr, val) };
        Ok(())
    }
}
```

### 5.1. Ingress: Программа `XDP` (на физическом интерфейсе `eth0`)

1. Получает `XdpContext` и оборачивает его в `let w = ContextWrapper::Xdp(&ctx);`.
2. Проверяет наличие `EthHdr::LEN (14) + Ipv4Hdr::LEN (20) + UdpHdr::LEN (8) + ASTP-L Header (8) = 50 байт`.
3. Через `w.ptr_at::<EthHdr>(0)`, `w.ptr_at::<Ipv4Hdr>(14)` и `w.ptr_at::<UdpHdr>(34)` проверяет:
   * `eth.ether_type == EtherType::Ipv4` (`0x0800_u16.to_be()`);
   * `ipv4.proto == IpProto::Udp` (`17`) и `ipv4.ihl() == 5` (без IP-опций, 20 байт);
   * `udp.dest == ASTPL_PORT.load()`.
   Если любая проверка не прошла — возвращает `XDP_PASS`.
4. **Демультиплексирование по `nonce_prefix` за $O(1)$:**
   * Читает `nonce_prefix = w.read_unaligned::<u32>(42)?` и `seq = w.read_unaligned::<u32>(46)?`.
   * Ищет сессию через `ASTPL_INGRESS_MAP.get_ptr_mut(&nonce_prefix)`.
   * **Если записи нет или `seq == 0`:** возвращает **`XDP_PASS`**. Благодаря этому пакеты первичного рукопожатия ASTP (Phase I / Phase III), включая UDP-фрагменты для `DatagramReassembler`, прозрачно проходят в Userspace UDP-сокет `anet-server` на этом же порту.
5. **Дешифрование и верификация инвариантов внутреннего IPv4-заголовка:**
   * Инициализирует `Xoroshiro128Plus::new(session.crypto_seed, u32::from_be(seq))` и расшифровывает payload (`data + 50 .. data_end`) прямо в буфере пакета (по 8 байт через `read_unaligned`/`write_unaligned` + хвост `1..7` байт).
   * Проверяет внутренний IPv4-заголовок (`w.ptr_at::<Ipv4Hdr>(50)`):
     1. `(inner_ip.version_ihl >> 4) == 4` (валидный IPv4).
     2. `u16::from_be(inner_ip.tot_len) as usize == (ctx.data_end() - ctx.data()) - 50` (длина внутреннего IPv4-пакета строго равна длине UDP-payload минус 8 байт заголовка ASTP-L).
     3. `inner_ip.src_addr == session.assigned_ip` (anti-spoofing проверка: источник внутри туннеля строго соответствует выданному клиенту VPN IP).
   * *Защита от коллизий и подделок:* Если проверка инвариантов не прошла (например, 1 на $2^{32}$ случайная коллизия префикса фрагмента хендшейка с активным `nonce_prefix` или попытка спуфинга), XDP повторным прогоном `Xoroshiro128Plus::new(session.crypto_seed, u32::from_be(seq))` возвращает исходные байты на место и отдаёт `XDP_PASS` (или `XDP_DROP`, если источник уже известен как сессионный).
6. **Бесшовная миграция адреса клиента (Kernel NAT Rebinding):**
   * После успешной верификации внутреннего IPv4-заголовка проверяет, изменился ли внешний адрес или порт клиента:
     ```rust
     if outer_src_ip != session.client_ip || outer_src_port != session.client_port {
         session.client_ip = outer_src_ip;
         session.client_port = outer_src_port;
         if let Some(egress_ptr) = ASTPL_EGRESS_MAP.get_ptr_mut(&session.assigned_ip) {
             unsafe {
                 (*egress_ptr).dst_ip = outer_src_ip;
                 (*egress_ptr).dst_port = outer_src_port;
             }
         }
     }
     ```
   * Обновляет `session.rx_bytes`, `session.last_seq` и `session.last_seen_ns`.
7. **Декапсуляция на уровне XDP с сохранением L2-заголовка:**
   * Читает 14 байт оригинального `EthHdr` (`let eth_hdr = w.read_unaligned::<EthHdr>(0)?;`) и записывает их на 36 байт вправо (`w.write_unaligned::<EthHdr>(36, eth_hdr)?;`), прямо перед началом расшифрованного внутреннего IPv4-пакета.
   * Вызывает `unsafe { aya_ebpf::helpers::bpf_xdp_adjust_head(ctx.ctx, 36) }` (сдвигает начало пакета на `20 (Outer IP) + 8 (UDP) + 8 (ASTP-L Header) = 36` байт вправо).
   * Возвращает **`XDP_PASS`**.
   * **Результат:** Ядро Linux получает готовый стандартный Ethernet-кадр с расшифрованным внутренним IPv4-пакетом клиента и мгновенно маршрутизирует его через стандартный IP Forwarding / NAT в интернет без участия `tun0` и Userspace.

### 5.2. Egress: Программа `TC Classifier` (на виртуальном интерфейсе `tun0`)

Когда ответный пакет из интернета маршрутизируется ядром в подсеть VPN (`10.0.0.0/24`), он попадает в `tun0` (сначала проходит через `anet_shaper`, а затем в `astpl_tc_egress`):

1. Получает `TcContext` и оборачивает его в `ContextWrapper::Tc(&ctx)`. Проверяет минимальную длину IPv4-пакета (`w.ptr_at::<Ipv4Hdr>(0)`).
2. Читает `Inner Dst IP` (`inner_ip.dst_addr`).
3. Ищет `Inner Dst IP` в `ASTPL_EGRESS_MAP.get_ptr_mut(&inner_dst_ip)`:
   * Если записи нет — возвращает `TC_ACT_OK` (пакет идёт обычным путём для классических QUIC/SSH/VNC клиентов Anet).
4. **Линеаризация буфера `sk_buff` (КРИТИЧНО для TC):**
   * Для одиночных пакетов (до 1450 байт) вызывает **`bpf_skb_pull_data(skb_len)`**, подтягивая все нелинейные страницы (`paged frags`) пакета в линейную область `ctx.data()..ctx.data_end()`.
   * GSO-суперпакеты (> 1450 байт) и локальный трафик сервера пропускаются через `TC_ACT_OK` в `validate_xmit_skb` на TUN для сегментации.
5. **Финализация контрольной суммы L4 (`CHECKSUM_PARTIAL`) в ядре Linux 6.x:**
   * Гипервизор KVM (`virtio_net`) при транзитном Download оставляет в TCP/UDP поле `check` только seed псевдозаголовка.
   * Программа `astpl_tc_egress` вычисляет сумму L4 по RFC 1071 прямо в ядре через `finalize_l4_checksum` и записывает честную контрольную сумму **до** шифрования.
6. Инкрементирует `routing.tx_seq` (если в результате переполнения получилось `0`, ставит `1`), обновляет `routing.tx_bytes` и `routing.last_seen_ns`.
7. Инициализирует `Xoroshiro128Plus::new(routing.crypto_seed, routing.tx_seq)` и шифрует весь внутренний IPv4-пакет (`ctx.data() .. ctx.data_end()`) на месте (по 8 байт + хвост `1..7` байт).
8. **Расширение заголовка (`bpf_skb_change_head` на 50 байт):**
   * Вызывает `bpf_skb_change_head(ctx, 50, 0)`:
     `EthHdr (14) + Outer IPv4 (20) + Outer UDP (8) + ASTP-L Header (8)`.
   * В ядре Linux 6.x `bpf_skb_change_head` обнуляет 50 байт и оставляет `skb->mac_header < skb->network_header`, что идеально подходит для `__bpf_redirect_neigh`.
9. Заново проверяет границы через `ContextWrapper::Tc(&ctx)` и записывает в новые 50 байт:
   * **EtherType (2 байта, offset 12):** `0x0800` (IPv4).
   * **Outer IPv4 Header (`Ipv4Hdr`, 20 байт, offset 14):** `version_ihl = 0x45`, `tos = 0`, `tot_len = (total_ip_len as u16).to_be()`, `id = (tx_seq as u16).to_be()`, `frag_off = 0`, `ttl = 64`, `proto = IPPROTO_UDP`, `src_addr = SERVER_IP`, `dst_addr = routing.dst_ip`, и вычисляет IPv4 Header Checksum.
   * **Outer UDP Header (`UdpHdr`, 8 байт, offset 34):** `source = ASTPL_PORT`, `dest = routing.dst_port`, `len = (udp_total_len as u16).to_be()`, `check = 0` (RFC 768).
   * **ASTP-L Nonce Prefix (4 байта, offset 42):** `routing.nonce_prefix` (в Big-Endian).
   * **ASTP-L Seq (4 байта, offset 46):** `routing.tx_seq.to_be()`.
10. **Отправка в физический интерфейс через подсистему соседей (ARP/Neighbour):**
   * Вызывает `unsafe { aya_ebpf::helpers::bpf_redirect_neigh(ETH_IFINDEX.load(), core::ptr::null_mut(), 0, 0) as i32 }`.
   * Хелпер `bpf_redirect_neigh` самостоятельно определяет L2 MAC-адреса и отправляет зашифрованный пакет напрямую в `eth0`, полностью минуя чтение из `tun0` в Userspace.

---

## 6. Логика работы Userspace (`anet-server`)

1. **Подготовка окружения (Linux 6.x):**
   * Снятие лимита `RLIMIT_MEMLOCK` для BPF-карт.
   * Pre-flight очистка старого XDP на физическом интерфейсе (`ip link set dev <eth> xdp off`).
   * При старте `anet-server` загружает единый eBPF-объект `anet-ebpf`, инициализирует `ASTPL_CONFIG` (порт, server IP, ifindex внешнего интерфейса).
   * Прикрепляет `astpl_xdp_ingress` к физическому интерфейсу (`ens3` / `eth0`) в режиме `XdpMode::Driver` (Native XDP).
   * Прикрепляет `astpl_tc_egress` к `tun0` в цепочку `clsact egress`.
2. **Обработка Handshake и `DatagramReassembler` на едином UDP-сокете:**
   * Сервер слушает обычный `tokio::net::UdpSocket` на порту `ASTPL_PORT`. Поскольку `XDP` забирает все пакеты активных сессий по `nonce_prefix`, в Userspace попадают только пакеты с неизвестным префиксом (Phase I / Phase III хендшейка и их UDP-фрагменты) либо управляющие пакеты с `Seq == 0`.
   * Если первый байт пакета имеет бит фрагментации (`(byte & 0x80) != 0`), пакет передаётся в `DatagramReassembler::push_fragment(remote_addr, data)` (полная совместимость с `[stealth] frag_enabled = true`).
   * Выполняется стандартный 4-фазный криптографический Handshake Anet (`AuthHandler`), клиенту выделяется IP из пула (`10.0.0.x`), и из `shared_key` через HKDF-SHA256 выводятся:
     * `nonce_prefix: u32` (4 байта идентификатора сессии, проверяется отсутствие коллизии в `ASTPL_INGRESS_MAP`);
     * `crypto_seed: u64` (8 байт ключа для `Xoroshiro128+`).
   * Сервер записывает сессию в `ASTPL_INGRESS_MAP` (по ключу `nonce_prefix`) и в `ASTPL_EGRESS_MAP` (по ключу `assigned_ip`) ДО или в момент отправки `AuthResponse` (Phase IV).
3. **Фоновая синхронизация с `ClientRegistry` и NAT Rebinding:**
   * Фоновая задача `anet-server` раз в `5–10` секунд читает `rx_bytes`, `tx_bytes`, `last_seen_ns`, а также актуальные `client_ip` / `client_port` из BPF-карт и синхронизирует их с `ClientInfo` в `ClientRegistry` (чтобы `cleanup_inactive_clients` не удалял активные eBPF-сессии по таймауту, а в статистике отображался реальный трафик и актуальный endpoint после NAT Rebinding).
   * При удалении неактивного клиента его записи удаляются из `ASTPL_INGRESS_MAP` (по `nonce_prefix`) и `ASTPL_EGRESS_MAP` (по `assigned_ip`).

---

## 7. Логика работы Клиента (`anet-client` / `anet-client-core`)

Клиент может работать на любой ОС (Windows, macOS, Android, iOS, Linux) полностью в Userspace без зависимости от eBPF:

1. Выполняет стандартный 4-фазный Handshake ASTP с сервером на порту `ASTPL_PORT` (при включённом `frag_enabled = true` нарезая датаграммы Phase I и Phase III через `fragment_datagram` со случайным джиттером).
2. Получает от сервера `AuthResponse` (настройки `TUN`) и выводит из `shared_key` через HKDF-SHA256 `nonce_prefix: [u8; 4]` и `crypto_seed: u64`.
3. **Отправка (TX):**
   * Читает IPv4-пакет из локального `TUN`.
   * Увеличивает локальный `tx_seq: u32` (при переполнении в `0` ставит `1`).
   * Инициализирует `Xoroshiro128Plus::new(crypto_seed, tx_seq)` (с 2 раундами прогрева) и шифрует буфер (по 8 байт + хвост `1..7` байт).
   * Формирует 8-байтный заголовок `[nonce_prefix (4B)][tx_seq.to_be_bytes() (4B)]`, дописывает зашифрованный пакет и отправляет в UDP-сокет.
4. **Приём (RX):**
   * Читает датаграмму из UDP-сокета (не менее `8 + 20 = 28` байт).
   * Сверяет первые 4 байта с `nonce_prefix` своей сессии и читает следующие 4 байта (`seq = u32::from_be_bytes(...)`).
   * Если `seq == 0` — передаёт пакет обработчику Control Plane (Rekey / Keepalive).
   * Если `seq > 0` — инициализирует `Xoroshiro128Plus::new(crypto_seed, seq)`, расшифровывает остаток буфера (`data[8..]`) и пишет чистый IPv4-пакет в локальный `TUN`.

---

## 8. Требования к реализации и окружению сборки

1. **Версии крейтов в workspace:**
   * Userspace (`anet-server`): `aya = "0.14.0"`, `aya-log = "0.3.0"`, `libc = "0.2"`.
   * Kernelspace (`anet-ebpf`): `aya-ebpf = "0.2.1"`, `aya-log-ebpf = "0.2.0"`, `network-types = "0.0.7"`, Rust `edition = "2024"`.
   * Общие типы (`anet-ebpf-common`): `#![no_std]`, `aya = { version = "0.14.0", optional = true }`.
2. **Строгие правила для BPF-верификатора (`anet-ebpf`):**
   * В Rust 2024 использовать `#[unsafe(no_mangle)]` и явные блоки `unsafe { ... }` внутри `unsafe fn`.
   * Перед любым чтением или записью по указателю пакета (`data + offset`) выполнять явную проверку `if start + offset + len > end { return Err(()); }` через `ContextWrapper::ptr_at` / `ptr_at_mut`.
   * Для чтения/записи многобайтовых полей после 14-байтного `EthHdr` и 8-байтных блоков шифрования использовать `read_unaligned` / `write_unaligned` во избежание невыровненного доступа.
   * После вызовов `ctx.pull_data(...)`, `ctx.adjust_room(...)` или `bpf_xdp_adjust_head(...)` все старые указатели на пакет считаются недействительными — обязательно заново обращаться к `ContextWrapper` для чтения `ctx.data()` и `ctx.data_end()`.
   * Все циклы шифрования должны иметь жёсткую верхнюю границу итераций (`for _ in 0..MAX_BLOCKS`), а вспомогательные функции помечаться `#[inline(always)]`.
   * Не использовать динамические аллокации (`alloc`, `Vec`, `String`) и паникующие индексации срезов (`slice[i]`) в коде `anet-ebpf`.

