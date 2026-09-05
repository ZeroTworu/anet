#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::{xdp_action, TC_ACT_OK},
    helpers::{bpf_ktime_get_ns, bpf_skb_set_tstamp},
    macros::{classifier, map, xdp},
    maps::HashMap,
    programs::{TcContext, XdpContext},
    EbpfContext,
};
use aya_log_ebpf::debug;

use anet_ebpf_common::{EdtState, RateRule, TokenBucketState};

mod ip;
use ip::{parse_dst_ipv4, parse_src_ipv4};

/// `BPF_SKB_TSTAMP_DELIVERY_MONO` из `enum bpf_skb_tstamp_type` ядра
/// (include/uapi/linux/bpf.h). В сгенерированных биндингах aya-ebpf 0.1.1
/// (`aya_ebpf::bindings`) этот enum отсутствует, поэтому значение
/// захардкожено — это стабильный UAPI ядра, он не меняется между релизами.
const BPF_SKB_TSTAMP_DELIVERY_MONO: u32 = 1;

/// Правила ограничения скорости. Ключ — IPv4 клиента внутри туннельной сети
/// (`assigned_ip`) в сетевом (big-endian) порядке байт. Заполняется/чистится
/// из `anet-server::shaper::Shaper` по мере жизни клиентских сессий.
#[map(name = "RATE_RULES")]
static RATE_RULES: HashMap<u32, RateRule> = HashMap::with_max_entries(4096, 0);

/// EDT-состояние для egress (download клиента: интернет -> клиент).
#[map(name = "EDT_STATE")]
static EDT_STATE: HashMap<u32, EdtState> = HashMap::with_max_entries(4096, 0);

/// Token-Bucket состояние для ingress (upload клиента: клиент -> интернет).
#[map(name = "TB_STATE")]
static TB_STATE: HashMap<u32, TokenBucketState> = HashMap::with_max_entries(4096, 0);

/// EDT egress classifier. Вешается на `clsact egress` TUN-интерфейса сервера
/// (см. `anet-server::shaper::Shaper::attach`). TUN-egress — это пакеты,
/// которые ядро отдаёт обратно клиенту, т.е. download с его точки зрения.
///
/// Реализация без потерь: считаем момент, когда пакет МОЖЕТ уйти (Earliest
/// Departure Time), пишем его в `skb->tstamp` — фактическую задержку и
/// порядок отправки берёт на себя qdisc `fq`, который ОБЯЗАН стоять как root
/// qdisc интерфейса, иначе `tstamp` тихо игнорируется и пакет уйдёт сразу.
#[classifier]
pub fn tc_egress(ctx: TcContext) -> i32 {
    match try_tc_egress(&ctx) {
        Ok(action) => action,
        Err(()) => TC_ACT_OK,
    }
}

fn try_tc_egress(ctx: &TcContext) -> Result<i32, ()> {
    let Some(dst_ip) = parse_dst_ipv4(ctx) else {
        return Ok(TC_ACT_OK);
    };

    // Лимит не настроен для этого клиента — пропускаем, не трогая state map
    // (частый путь: большинство клиентов вообще без speed_limit).
    let Some(rule) = (unsafe { RATE_RULES.get(&dst_ip) }) else {
        return Ok(TC_ACT_OK);
    };

    if rule.rate_bytes_per_sec == 0 {
        return Ok(TC_ACT_OK);
    }

    let packet_len = ctx.len() as u64;
    let now = unsafe { bpf_ktime_get_ns() };

    let scheduled_from = match unsafe { EDT_STATE.get(&dst_ip) } {
        Some(state) => state.next_departure_ns.max(now),
        None => now,
    };

    // 10^9 * packet_len (максимум ~65535) = ~6.5 * 10^13, что с запасом
    // укладывается в u64 (предел u64: 1.84 * 10^19). 128-битная арифметика не требуется.
    let cost_ns = (1_000_000_000u64 * packet_len) / rule.rate_bytes_per_sec;
    let mut next_departure = scheduled_from.saturating_add(cost_ns);

    // Не даём очереди "убегать" в будущее дальше чем на burst — иначе клиент,
    // долго простаивавший (накопивший виртуальный кредит), потом продавит
    // канал одним залпом. burst_bytes / rate = максимальная глубина пейсинга.
    // Ограничиваем burst 1 ГБ для гарантии отсутствия переполнения u64 при умножении.
    let safe_burst = rule.burst_bytes.max(1).min(1_000_000_000);
    let max_horizon_ns = (1_000_000_000u64 * safe_burst) / rule.rate_bytes_per_sec;
    let horizon = now.saturating_add(max_horizon_ns.max(cost_ns));
    if next_departure > horizon {
        next_departure = horizon;
    }

    let _ = EDT_STATE.insert(&dst_ip, &EdtState { next_departure_ns: next_departure }, 0);

    // ВНИМАНИЕ: bpf_skb_set_tstamp — helper, появившийся в Linux 5.18
    // (BPF_FUNC_skb_set_tstamp).
    unsafe {
        let _ = bpf_skb_set_tstamp(
            ctx.as_ptr() as *mut _,
            next_departure,
            BPF_SKB_TSTAMP_DELIVERY_MONO,
        );
    }

    debug!(ctx, "tc_egress: dst={:i}, next_departure_ns={}", dst_ip, next_departure);
    Ok(TC_ACT_OK)
}

/// Token-Bucket ingress. Вешается в SKB(generic)-режиме — TUN не
/// поддерживает native/driver XDP. TUN-ingress — это пакеты, которые сам
/// `anet-server` записывает в устройство после расшифровки клиентского
/// трафика (путь клиент -> сервер -> интернет), т.е. upload с точки зрения
/// клиента. Лишнее дропается: TCP отправителя сам снизит окно перегрузки.
#[xdp]
pub fn xdp_ingress(ctx: XdpContext) -> u32 {
    match try_xdp_ingress(&ctx) {
        Ok(action) => action,
        Err(()) => xdp_action::XDP_PASS,
    }
}

fn try_xdp_ingress(ctx: &XdpContext) -> Result<u32, ()> {
    let Some(src_ip) = parse_src_ipv4(ctx) else {
        return Ok(xdp_action::XDP_PASS);
    };

    let Some(rule) = (unsafe { RATE_RULES.get(&src_ip) }) else {
        return Ok(xdp_action::XDP_PASS);
    };

    if rule.rate_bytes_per_sec == 0 {
        return Ok(xdp_action::XDP_PASS);
    }

    let packet_len = (ctx.data_end() - ctx.data()) as i64;
    let now = unsafe { bpf_ktime_get_ns() };

    let mut state = match unsafe { TB_STATE.get(&src_ip) } {
        Some(state) => *state,
        None => TokenBucketState {
            tokens: rule.burst_bytes as i64,
            last_update_ns: now,
        },
    };

    // Ограничиваем elapsed_ns 1 секундой (1_000_000_000 нс).
    // Это полностью защищает умножение (rate * elapsed_ns) от переполнения u64
    // даже на скоростях 100 Гбит/с и исключает вызовы встроенных функций 128-битной математики.
    let elapsed_ns = now.saturating_sub(state.last_update_ns).min(1_000_000_000);
    let refill = ((rule.rate_bytes_per_sec * elapsed_ns) / 1_000_000_000) as i64;

    state.tokens = state.tokens.saturating_add(refill).min(rule.burst_bytes as i64);
    state.last_update_ns = now;

    let action = if state.tokens >= packet_len {
        state.tokens -= packet_len;
        xdp_action::XDP_PASS
    } else {
        xdp_action::XDP_DROP
    };

    let _ = TB_STATE.insert(&src_ip, &state, 0);
    debug!(ctx, "xdp_ingress: src={:i}, action={}, tokens={}", src_ip, action, state.tokens);

    Ok(action)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
