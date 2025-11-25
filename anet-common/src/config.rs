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
}

impl Default for StealthConfig {
    fn default() -> Self {
        Self {
            min_jitter_ns: 0,
            max_jitter_ns: 0,
            padding_step: 0,
        }
    }
}
