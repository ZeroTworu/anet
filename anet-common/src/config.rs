use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct StealthConfig {
    /// Минимальная задержка джиттера (наносекунды)
    pub min_jitter_ns: u64,
    /// Максимальная задержка джиттера (наносекунды)
    pub max_jitter_ns: u64,
    /// Шаг выравнивания паддинга (байты)
    pub padding_step: u16,

    /// Фрагментировать самый первый пакет рукопожатия (до появления
    /// сессионного ключа, поэтому вне обычного padding/jitter-конвейера).
    pub frag_enabled: bool,
    /// Минимальное число частей, на которое дробится хендшейк.
    pub frag_min_chunks: u8,
    /// Максимальное число частей, на которое дробится хендшейк.
    pub frag_max_chunks: u8,
}

impl Default for StealthConfig {
    fn default() -> Self {
        Self {
            min_jitter_ns: 0,
            max_jitter_ns: 0,
            padding_step: 0,
            frag_enabled: false,
            frag_min_chunks: 2,
            frag_max_chunks: 3,
        }
    }
}
