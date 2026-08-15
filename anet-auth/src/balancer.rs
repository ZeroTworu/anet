//! Алгоритмы выбора entry point для пула VPN-нод.
//!
//! Resolver панели сортирует узлы перед генерацией `client.toml`: первый узел
//! становится предпочтительным, остальные остаются в списке failover.

use sha2::{Digest, Sha256};
use uuid::Uuid;

#[derive(Debug, Clone, Copy)]
pub struct BalanceCandidate {
    /// Идентификатор зарегистрированной ноды.
    pub server_id: Uuid,
    /// Вес ноды в weighted-пуле; чем он выше, тем чаще нода выбирается первой.
    pub weight: u32,
    /// Число активных подключений из последнего heartbeat.
    pub active_connections: u64,
}

/// Упорядочивает кандидатов согласно выбранной стратегией пула.
pub fn order_candidates(
    strategy: &str,
    user_id: Uuid,
    pool_id: Uuid,
    candidates: &mut [BalanceCandidate],
) {
    match strategy {
        // Least-connections использует актуальную нагрузку и стабильный hash
        // только для детерминированного разрешения одинаковых значений.
        "least_connections" => candidates.sort_by_key(|candidate| {
            (
                candidate.active_connections,
                stable_hash(user_id, pool_id, candidate.server_id),
            )
        }),
        // Weighted rendezvous сохраняет привязку пользователя к entry point,
        // но распределяет разных пользователей с учётом весов нод.
        _ => candidates.sort_by(|left, right| {
            weighted_score(user_id, pool_id, *left)
                .total_cmp(&weighted_score(user_id, pool_id, *right))
        }),
    }
}

fn stable_hash(user_id: Uuid, pool_id: Uuid, server_id: Uuid) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(user_id.as_bytes());
    hasher.update(pool_id.as_bytes());
    hasher.update(server_id.as_bytes());
    let digest = hasher.finalize();
    u64::from_be_bytes(digest[..8].try_into().expect("SHA-256 prefix"))
}

fn weighted_score(user_id: Uuid, pool_id: Uuid, candidate: BalanceCandidate) -> f64 {
    let hash = stable_hash(user_id, pool_id, candidate.server_id);
    let uniform = (hash as f64 + 1.0) / (u64::MAX as f64 + 2.0);
    -uniform.ln() / candidate.weight.max(1) as f64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn least_connections_puts_less_loaded_node_first() {
        let user = Uuid::new_v4();
        let pool = Uuid::new_v4();
        let light = Uuid::new_v4();
        let heavy = Uuid::new_v4();
        let mut candidates = vec![
            BalanceCandidate {
                server_id: heavy,
                weight: 1,
                active_connections: 20,
            },
            BalanceCandidate {
                server_id: light,
                weight: 1,
                active_connections: 2,
            },
        ];
        order_candidates("least_connections", user, pool, &mut candidates);
        assert_eq!(candidates[0].server_id, light);
    }

    #[test]
    fn weighted_rendezvous_favours_larger_weight() {
        let pool = Uuid::new_v4();
        let light = Uuid::new_v4();
        let heavy = Uuid::new_v4();
        let mut light_wins = 0;
        let mut heavy_wins = 0;
        for _ in 0..1_000 {
            let mut candidates = vec![
                BalanceCandidate {
                    server_id: light,
                    weight: 1,
                    active_connections: 0,
                },
                BalanceCandidate {
                    server_id: heavy,
                    weight: 5,
                    active_connections: 0,
                },
            ];
            order_candidates("weighted", Uuid::new_v4(), pool, &mut candidates);
            if candidates[0].server_id == heavy {
                heavy_wins += 1
            } else {
                light_wins += 1
            }
        }
        assert!(
            heavy_wins > light_wins * 3,
            "heavy={heavy_wins}, light={light_wins}"
        );
    }
}
