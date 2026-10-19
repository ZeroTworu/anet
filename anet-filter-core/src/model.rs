//! Базовые структуры данных и формат .abc (ANet Binary Cache) с поддержкой Zero-Copy (rkyv).

use bytecheck::CheckBytes;
use rkyv::{check_archived_root, Archive, Deserialize, Serialize};
use std::fmt;

use crate::radix::IpRoutingTable;
use crate::trie::DomainTrie;

/// Магическая сигнатура заголовка .abc файла: 'ABC1' (Little-Endian: 0x31434241)
pub const MAGIC_ABC1: u32 = 0x31434241;

/// Текущая версия схемы формата .abc
pub const CURRENT_SCHEMA_VERSION: u32 = 1;

/// Служебный канареечный домен Mozilla Firefox для отключения DoH
pub const MOZILLA_CANARY_DOMAIN: &str = "use-application-dns.net";

/// Известные публичные DoH-резолверы, блокируемые по умолчанию для отката браузеров на системный DNS (п. 5.2 ТЗ)
pub const DEFAULT_DOH_DOMAINS: &[&str] = &[
    "cloudflare-dns.com",
    "dns.google",
    "dns.quad9.net",
    "doh.opendns.com",
];

/// Служебные домены проверки доступности интернета ОС (Captive Portal), которые никогда не блокируются AdBlock (п. 5.3 ТЗ)
pub const CAPTIVE_PORTAL_DOMAINS: &[&str] = &[
    "connectivitycheck.gstatic.com",
    "msftconnecttest.com",
    "captive.apple.com",
    "detectportal.firefox.com",
];

/// Действие маршрутизатора для домена или IP-адреса/сети
#[derive(
    Archive,
    Deserialize,
    Serialize,
    CheckBytes,
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    serde::Serialize,
    serde::Deserialize,
)]
#[archive(check_bytes)]
#[repr(u8)]
pub enum RuleAction {
    /// Трафик направляется через защищенный VPN-туннель
    Proxy = 0,
    /// Трафик идет напрямую в обход VPN через системный сетевой интерфейс
    Direct = 1,
    /// Трафик блокируется (генерация 0.0.0.0 / :: на уровне DNS или сброс пакета)
    Block = 2,
}

impl RuleAction {
    pub fn is_block(&self) -> bool {
        matches!(self, RuleAction::Block)
    }

    pub fn is_direct(&self) -> bool {
        matches!(self, RuleAction::Direct)
    }

    pub fn is_proxy(&self) -> bool {
        matches!(self, RuleAction::Proxy)
    }

    pub fn from_str_loose(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "proxy" | "tunnel" | "vpn" => Some(RuleAction::Proxy),
            "direct" | "bypass" => Some(RuleAction::Direct),
            "block" | "drop" | "reject" => Some(RuleAction::Block),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            RuleAction::Proxy => "proxy",
            RuleAction::Direct => "direct",
            RuleAction::Block => "block",
        }
    }
}

impl fmt::Display for RuleAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Корневой контейнер скомпилированных правил маршрутизации (.abc)
#[derive(Archive, Deserialize, Serialize, CheckBytes, Debug, PartialEq)]
#[archive(check_bytes)]
pub struct CompiledRoutingCache {
    /// Сигнатура 'ABC1' (0x31434241)
    pub magic: u32,
    /// Версия структуры схемы (начиная с 1)
    pub schema_version: u32,
    /// Метка времени компиляции (Unix Epoch в секундах)
    pub created_at: u64,
    /// Действие по умолчанию (если правило не найдено ни в Trie, ни в LPM)
    pub default_action: RuleAction,
    /// Префиксное инвертированное дерево доменов (Domain Trie)
    pub domain_trie: DomainTrie,
    /// Дерево поиска максимального префикса сетей (Radix Tree LPM)
    pub ip_table: IpRoutingTable,
}

impl CompiledRoutingCache {
    /// Создает новый контейнер скомпилированных правил
    pub fn new(
        default_action: RuleAction,
        domain_trie: DomainTrie,
        ip_table: IpRoutingTable,
    ) -> Self {
        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            magic: MAGIC_ABC1,
            schema_version: CURRENT_SCHEMA_VERSION,
            created_at,
            default_action,
            domain_trie,
            ip_table,
        }
    }

    /// Сериализует контейнер правил в байтовый массив формата .abc
    pub fn to_bytes(&self) -> Result<Vec<u8>, anyhow::Error> {
        let aligned = rkyv::to_bytes::<_, 4096>(self)
            .map_err(|e| anyhow::anyhow!("Failed to serialize CompiledRoutingCache: {e}"))?;
        Ok(aligned.to_vec())
    }

    /// Выполняет быструю Zero-Copy валидацию и возвращает ссылку на корень архива
    pub fn from_bytes(bytes: &[u8]) -> Result<&ArchivedCompiledRoutingCache, anyhow::Error> {
        if bytes.len() < std::mem::size_of::<ArchivedCompiledRoutingCache>() {
            anyhow::bail!("Buffer is too small for a valid .abc cache ({} bytes)", bytes.len());
        }

        let archived = check_archived_root::<CompiledRoutingCache>(bytes)
            .map_err(|e| anyhow::anyhow!("Validation error in .abc cache: {e}"))?;

        if archived.magic != MAGIC_ABC1 {
            anyhow::bail!(
                "Invalid .abc cache magic: expected 0x{:08X}, got 0x{:08X}",
                MAGIC_ABC1,
                archived.magic
            );
        }

        if archived.schema_version != CURRENT_SCHEMA_VERSION {
            anyhow::bail!(
                "Unsupported .abc schema version: expected {}, got {}",
                CURRENT_SCHEMA_VERSION,
                archived.schema_version
            );
        }

        Ok(archived)
    }
}
