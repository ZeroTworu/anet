use anyhow::Error;
use sea_orm::{ActiveValue::Set, DatabaseConnection, QuerySelect, TransactionTrait, sqlx::types::chrono};
use std::net::Ipv4Addr;
use crate::entities::clients;
use sea_orm::{EntityTrait};

#[derive(Clone)]
pub struct IpPool {
    pub network: Ipv4Addr,
    pub netmask: Ipv4Addr,
    pub gateway: Ipv4Addr,
    pub server: Ipv4Addr,
    pub mtu: u16,
    db: DatabaseConnection,
}

impl IpPool {
    pub fn new(
        network: Ipv4Addr,
        netmask: Ipv4Addr,
        gateway: Ipv4Addr,
        server: Ipv4Addr,
        mtu: u16,
        db: DatabaseConnection,
    ) -> Self {
        Self {
            network,
            netmask,
            gateway,
            server,
            mtu,
            db,
        }
    }

    pub async fn allocate(
        &self,
        fingerprint: String,
    ) -> Result<Ipv4Addr, Error> {
    
        let txn = self.db.begin().await?;
    
        // 1. уже есть IP
        if let Some(ip) = self.get_ip(&txn, fingerprint.clone()).await? {
            txn.commit().await?;
            return Ok(ip);
        }
    
        // 2. ищем свободный
        let ip = self.assign_ip(&txn).await?;
    
        // 3. сохраняем
        self.set_ip(&txn, fingerprint, ip).await?;
    
        txn.commit().await?;
    
        Ok(ip)
    }

    async fn get_ip(
        &self,
        txn: &sea_orm::DatabaseTransaction,
        fingerprint: String,
    ) -> Result<Option<Ipv4Addr>, Error> {

        let model = clients::Entity::find_by_id(fingerprint)
            .one(txn)
            .await?;

        Ok(model.map(|m| Ipv4Addr::from(m.ip as u32)))
    }

    async fn assign_ip(
        &self,
        txn: &sea_orm::DatabaseTransaction,
    ) -> Result<Ipv4Addr, Error> {

        let used: Vec<i64> = clients::Entity::find()
            .select_only()
            .column(clients::Column::Ip)
            .into_tuple()
            .all(txn)
            .await?;

        let used: std::collections::HashSet<u32> =
            used.into_iter().map(|v| v as u32).collect();

        let net = u32::from(self.network);
        let mask = u32::from(self.netmask);

        for host in 1..=254u32 {
            let candidate = net | host;

            if (candidate & mask) != (net & mask) {
                break;
            }

            let ip = Ipv4Addr::from(candidate);

            if ip == self.gateway || ip == self.server {
                continue;
            }

            if used.contains(&candidate) {
                continue;
            }

            return Ok(ip);
        }

        Err(anyhow::anyhow!("no free IPs in pool"))
    }

    async fn set_ip(
        &self,
        txn: &sea_orm::DatabaseTransaction,
        fingerprint: String,
        ip: Ipv4Addr,
    ) -> Result<(), Error> {
    
        clients::Entity::insert(clients::ActiveModel {
            fingerprint: Set(fingerprint),
            ip: Set(u32::from(ip) as i64),
            created_at: Set(chrono::Utc::now().naive_utc()),
            updated_at: Set(chrono::Utc::now().naive_utc()),
        })
        .exec(txn)
        .await?;
    
        Ok(())
    }
}
