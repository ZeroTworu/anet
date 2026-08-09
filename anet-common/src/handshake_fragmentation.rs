//! Фрагментация самого первого пакета рукопожатия — до появления сессионного
//! ключа, поэтому вне обычного padding/jitter-конвейера (`jitter.rs`,
//! `bridge_crypto_stream_with_jitter`), который требует уже готовый `Cipher`.
//!
//! Цель — не дать DPI опознать фиксированную по размеру/структуре сигнатуру
//! первого пакета, разбив его на несколько частей со случайными точками
//! разреза и джиттером между ними (аналог `--native-frag` в GoodbyeDPI, но
//! применённый проактивно к своему же исходящему хендшейку).
//!
//! Два независимых бэкенда:
//!
//! - [`write_fragmented`] — для любого потокового транспорта
//!   (`AsyncWrite + Unpin`: TCP/SSH/VNC, и в будущем WS(S)). Получателю не
//!   требуется НИКАКИХ изменений — поток сам доставляет байты по порядку
//!   независимо от границ TCP-сегментов, это встроенное свойство байтовых
//!   потоков. Новый транспорт получает фрагментацию бесплатно, просто реализуя
//!   `VpnStream` (`transport_trait.rs`).
//!
//! - [`send_fragmented_datagrams`] + [`DatagramReassembler`] — для UDP/QUIC-
//!   конверта, где датаграммы независимы, порядок и доставка не гарантированы.
//!   Здесь нужен явный 2-байтный заголовок фрагмента и восстановление на приёме.

use crate::config::StealthConfig;
use log::debug;
use rand::rngs::OsRng;
use rand::Rng;
use std::collections::BTreeMap;
use std::io;
use std::time::Duration;
use tokio::io::{AsyncWrite, AsyncWriteExt};

/// Настройки фрагментации хендшейка.
#[derive(Debug, Clone)]
pub struct FragmentConfig {
    pub enabled: bool,
    pub min_chunks: u8,
    pub max_chunks: u8,
    pub min_delay_ns: u64,
    pub max_delay_ns: u64,
}

impl Default for FragmentConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            min_chunks: 2,
            max_chunks: 2,
            min_delay_ns: 0,
            max_delay_ns: 0,
        }
    }
}

impl FragmentConfig {
    pub fn from_stealth(cfg: &StealthConfig) -> Self {
        let min_chunks = cfg.frag_min_chunks.max(2);
        let max_chunks = cfg.frag_max_chunks.max(min_chunks);
        Self {
            enabled: cfg.frag_enabled,
            min_chunks,
            max_chunks,
            min_delay_ns: cfg.min_jitter_ns,
            max_delay_ns: cfg.max_jitter_ns,
        }
    }
}

/// Выбирает случайные, неповторяющиеся точки разреза строго внутри `[1, len)`.
/// Точки НЕ выравниваются на фиксированную границу — иначе сама точка разреза
/// становится новой сигнатурой. Возвращает меньше точек, если `len` слишком
/// мал для запрошенного числа кусков (деградирует, а не паникует).
fn random_split_points(len: usize, n_chunks: u8) -> Vec<usize> {
    let n_chunks = n_chunks.max(1) as usize;
    if len < 2 || n_chunks <= 1 {
        return vec![];
    }

    let n_cuts = (n_chunks - 1).min(len.saturating_sub(1));
    if n_cuts == 0 {
        return vec![];
    }

    let mut rng = OsRng;
    let mut points: Vec<usize> = Vec::with_capacity(n_cuts);
    while points.len() < n_cuts {
        let p = rng.gen_range(1..len);
        if !points.contains(&p) {
            points.push(p);
        }
    }
    points.sort_unstable();
    points
}

fn pick_chunk_count(cfg: &FragmentConfig) -> u8 {
    let lo = cfg.min_chunks.max(2);
    let hi = cfg.max_chunks.max(lo);
    if hi > lo {
        OsRng.gen_range(lo..=hi)
    } else {
        lo
    }
}

async fn jittered_delay(cfg: &FragmentConfig) {
    if cfg.max_delay_ns == 0 && cfg.min_delay_ns == 0 {
        return;
    }
    let lo = cfg.min_delay_ns.min(cfg.max_delay_ns);
    let hi = cfg.max_delay_ns.max(cfg.min_delay_ns);
    let ns = if hi > lo { OsRng.gen_range(lo..=hi) } else { lo };
    if ns > 0 {
        tokio::time::sleep(Duration::from_nanos(ns)).await;
    }
}

// ============================================================================
// СТРИМОВЫЕ ТРАНСПОРТЫ (TCP/SSH/VNC/etc)
// ============================================================================

/// Пишет `data` в поток несколькими отдельными `write_all + flush` вызовами
/// вместо одного, со случайными точками разреза и джиттером между частями.
///
/// Получателю не требуется никаких изменений на уровне протокола — поток
/// гарантирует доставку байт по порядку независимо от того, сколькими
/// TCP-сегментами это было разбито на передаче.
///
/// ВАЖНО: для реального эффекта на TCP-сокете должен быть выставлен
/// `TCP_NODELAY` (отключён Nagle) — иначе ОС может успеть склеить несколько
/// быстрых `write()` обратно в один сегмент до отправки. Для `TcpStream`
/// вызовите `.set_nodelay(true)?` при установлении соединения, до вызова
/// этой функции.
pub async fn write_fragmented<S>(stream: &mut S, data: &[u8], cfg: &FragmentConfig) -> io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    if !cfg.enabled || data.len() < 2 {
        debug!(
            "handshake_fragmentation: DISABLED or too short — sending {} bytes as a single write",
            data.len()
        );
        stream.write_all(data).await?;
        return stream.flush().await;
    }

    let n_chunks = pick_chunk_count(cfg);
    let mut boundaries = random_split_points(data.len(), n_chunks);

    if boundaries.is_empty() {
        debug!(
            "handshake_fragmentation: no valid split points for {} bytes — sending as a single write",
            data.len()
        );
        stream.write_all(data).await?;
        return stream.flush().await;
    }
    boundaries.push(data.len());

    debug!(
        "handshake_fragmentation: STREAM splitting {} bytes into {} chunk(s) at boundaries {:?}",
        data.len(),
        boundaries.len(),
        boundaries
    );

    let mut start = 0usize;
    for (i, &end) in boundaries.iter().enumerate() {
        let t0 = std::time::Instant::now();
        stream.write_all(&data[start..end]).await?;
        stream.flush().await?;
        debug!(
            "handshake_fragmentation: STREAM chunk {}/{} = {} bytes written+flushed in {:?}",
            i + 1,
            boundaries.len(),
            end - start,
            t0.elapsed()
        );
        start = end;

        if i + 1 < boundaries.len() {
            jittered_delay(cfg).await;
        }
    }

    Ok(())
}

// ============================================================================
// UDP / QUIC-КОНВЕРТ
// ============================================================================

/// Заголовок фрагмента датаграммы: `[index: u8][total: u8]` + полезная
/// нагрузка. 2 байта оверхеда на фрагмент — приемлемо для одноразового
/// хендшейка, который в остальном не имеет собственного framing на этом
/// уровне (в отличие от `stream_framing.rs`).
const FRAG_HEADER_LEN: usize = 2;

fn wrap_single(data: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(FRAG_HEADER_LEN + data.len());
    buf.push(0);
    buf.push(1);
    buf.extend_from_slice(data);
    buf
}

/// Разбивает `data` на фрагменты-датаграммы, каждая со своим заголовком.
/// При выключенной фрагментации (или коротком `data`) возвращает один
/// элемент с `total == 1` — получатель обрабатывает оба случая одинаково.
fn split_datagram_fragments(data: &[u8], cfg: &FragmentConfig) -> Vec<Vec<u8>> {
    if !cfg.enabled || data.len() < 2 {
        return vec![wrap_single(data)];
    }

    let n_chunks = pick_chunk_count(cfg);
    let mut cuts = random_split_points(data.len(), n_chunks);
    if cuts.is_empty() {
        return vec![wrap_single(data)];
    }
    cuts.push(data.len());

    let total = cuts.len() as u8;
    let mut out = Vec::with_capacity(cuts.len());
    let mut start = 0usize;
    for (i, &end) in cuts.iter().enumerate() {
        let mut frag = Vec::with_capacity(FRAG_HEADER_LEN + (end - start));
        frag.push(i as u8);
        frag.push(total);
        frag.extend_from_slice(&data[start..end]);
        out.push(frag);
        start = end;
    }
    out
}

/// Отправляет `data` как одну или несколько отдельных UDP-датаграмм.
///
/// `send_fn` — фактическая отправка одной уже готовой (с заголовком фрагмента)
/// датаграммы. Сигнатура намеренно абстрактна (не привязана к конкретному
/// типу сокета), чтобы подходить и для `tokio::net::UdpSocket::send_to`,
/// и для кастомной обёртки поверх `quinn`-совместимого сокета.
pub async fn send_fragmented_datagrams<F, Fut>(
    data: &[u8],
    cfg: &FragmentConfig,
    mut send_fn: F,
) -> io::Result<()>
where
    F: FnMut(Vec<u8>) -> Fut,
    Fut: std::future::Future<Output = io::Result<()>>,
{
    let fragments = split_datagram_fragments(data, cfg);

    for (i, frag) in fragments.iter().enumerate() {
        send_fn(frag.clone()).await?;
        if i + 1 < fragments.len() {
            jittered_delay(cfg).await;
        }
    }

    Ok(())
}

/// Восстанавливает фрагментированную (или обычную, `total == 1`) датаграмму
/// хендшейка на стороне получателя.
///
/// Один экземпляр — на один ожидаемый хендшейк/источник (например, держите
/// `DatagramReassembler` в `HashMap<SocketAddr, DatagramReassembler>`, пока
/// для этого адреса ещё не установлена полноценная сессия). После того как
/// `feed()` вернул `Some(..)`, состояние уже сброшено — экземпляр готов для
/// следующего хендшейка того же источника, пересоздавать не нужно.
#[derive(Debug, Default)]
pub struct DatagramReassembler {
    total: Option<u8>,
    parts: BTreeMap<u8, Vec<u8>>,
}

impl DatagramReassembler {
    pub fn new() -> Self {
        Self::default()
    }

    /// Скармливает очередную полученную датаграмму. Возвращает `Some(data)`,
    /// когда собраны все фрагменты (в т.ч. сразу для нефрагментированного
    /// случая `total == 1`). Датаграммы короче заголовка или с некорректным
    /// `index`/`total` молча игнорируются (не относящийся к хендшейку мусор).
    pub fn feed(&mut self, datagram: &[u8]) -> Option<Vec<u8>> {
        if datagram.len() < FRAG_HEADER_LEN {
            return None;
        }
        let index = datagram[0];
        let total = datagram[1];
        if total == 0 || index >= total {
            return None;
        }

        // Датаграмма из другого набора (total изменился) — считаем это новым
        // хендшейком и сбрасываем ранее накопленные части.
        if self.total.is_some_and(|t| t != total) {
            self.parts.clear();
        }
        self.total = Some(total);
        self.parts.insert(index, datagram[FRAG_HEADER_LEN..].to_vec());

        if self.parts.len() as u8 == total {
            let mut out = Vec::new();
            for i in 0..total {
                out.extend_from_slice(self.parts.get(&i)?);
            }
            self.parts.clear();
            self.total = None;
            Some(out)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frag_cfg(min: u8, max: u8) -> FragmentConfig {
        FragmentConfig {
            enabled: true,
            min_chunks: min,
            max_chunks: max,
            min_delay_ns: 0,
            max_delay_ns: 0,
        }
    }

    #[test]
    fn split_points_are_within_bounds_and_sorted() {
        let points = random_split_points(100, 3);
        assert!(points.len() <= 2);
        for w in points.windows(2) {
            assert!(w[0] < w[1]);
        }
        for &p in &points {
            assert!(p > 0 && p < 100);
        }
    }

    #[test]
    fn split_points_handle_tiny_input() {
        assert!(random_split_points(1, 4).is_empty());
        assert!(random_split_points(0, 4).is_empty());
    }

    #[tokio::test]
    async fn write_fragmented_reassembles_correctly_over_stream() {
        let cfg = frag_cfg(3, 3);
        let data = b"hello world this is a handshake payload of some length";

        let (mut client, mut server) = tokio::io::duplex(4096);

        let data_owned = data.to_vec();
        let writer = tokio::spawn(async move {
            write_fragmented(&mut client, &data_owned, &cfg).await.unwrap();
        });

        let mut buf = vec![0u8; data.len()];
        tokio::io::AsyncReadExt::read_exact(&mut server, &mut buf)
            .await
            .unwrap();
        writer.await.unwrap();

        assert_eq!(&buf, data);
    }

    #[tokio::test]
    async fn write_fragmented_disabled_is_a_single_write() {
        let cfg = FragmentConfig::default(); // enabled = false
        let data = b"unfragmented payload";

        let (mut client, mut server) = tokio::io::duplex(4096);
        let data_owned = data.to_vec();
        let writer = tokio::spawn(async move {
            write_fragmented(&mut client, &data_owned, &cfg).await.unwrap();
        });

        let mut buf = vec![0u8; data.len()];
        tokio::io::AsyncReadExt::read_exact(&mut server, &mut buf)
            .await
            .unwrap();
        writer.await.unwrap();

        assert_eq!(&buf, data);
    }

    #[test]
    fn datagram_fragments_reassemble_out_of_order() {
        let cfg = frag_cfg(3, 3);
        let data = b"another handshake payload, split across several datagrams";

        let fragments = split_datagram_fragments(data, &cfg);
        assert!(fragments.len() >= 2);

        // получатель может увидеть их в перемешанном порядке
        let mut shuffled = fragments.clone();
        shuffled.reverse();

        let mut reassembler = DatagramReassembler::new();
        let mut result = None;
        for frag in &shuffled {
            result = reassembler.feed(frag);
        }

        assert_eq!(result.unwrap(), data);
    }

    #[test]
    fn single_fragment_case_is_transparent() {
        let cfg = FragmentConfig::default(); // enabled = false
        let fragments = split_datagram_fragments(b"short", &cfg);
        assert_eq!(fragments.len(), 1);

        let mut reassembler = DatagramReassembler::new();
        let result = reassembler.feed(&fragments[0]);
        assert_eq!(result.unwrap(), b"short".to_vec());
    }

    #[test]
    fn garbage_datagram_is_ignored() {
        let mut reassembler = DatagramReassembler::new();
        assert!(reassembler.feed(&[]).is_none());
        assert!(reassembler.feed(&[0]).is_none()); // короче заголовка
        assert!(reassembler.feed(&[5, 2, 1, 2, 3]).is_none()); // index >= total
    }
}
