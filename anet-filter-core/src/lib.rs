#![allow(unsafe_op_in_unsafe_fn)]

//! # anet-filter-core
//!
//! Ядро системы Smart DNS, Geo-Routing и AdBlock для ANet VPN.
//! Предоставляет структуры данных и Zero-Copy формат `.abc` (ANet Binary Cache).

pub mod builder;
pub mod checksum;
pub mod model;
pub mod overrides;
pub mod radix;
pub mod trie;

pub use builder::RoutingCacheCompiler;
pub use checksum::{
    compute_ipv4_checksum, compute_udp_v4_checksum, compute_udp_v6_checksum,
    verify_ipv4_checksum,
};
pub use model::{
    CompiledRoutingCache, RuleAction, CAPTIVE_PORTAL_DOMAINS, CURRENT_SCHEMA_VERSION,
    DEFAULT_DOH_DOMAINS, MAGIC_ABC1, MOZILLA_CANARY_DOMAIN,
};
pub use overrides::{LocalOverrides, LocalOverridesConfig};
pub use radix::{IpRoutingTable, IpRoutingTableBuilder};
pub use trie::{DomainTrie, DomainTrieBuilder};

