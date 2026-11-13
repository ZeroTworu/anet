use log::{info, warn};
use std::env;
use std::sync::OnceLock;

#[derive(Debug, Clone)]
pub struct BillingRuntimeConfig {
    pub app_env: String,
    pub cabinet: CabinetConfig,
    pub billing: BillingConfig,
}

#[derive(Debug, Clone)]
pub struct CabinetConfig {
    pub web: CabinetWebConfig,
    pub telegram: CabinetTelegramConfig,
}

#[derive(Debug, Clone)]
pub struct CabinetWebConfig {
    pub public_domain: String,
    pub verification_token_ttl_mins: u64,
    pub min_password_length: usize,
}

#[derive(Debug, Clone)]
pub struct CabinetTelegramConfig {
    pub bot_token: String,
    pub web_app_data_key: String,
}

#[derive(Debug, Clone)]
pub struct BillingConfig {
    pub freekassa: FreeKassaConfig,
}

#[derive(Debug, Clone)]
pub struct FreeKassaConfig {
    pub shop_id: String,
    pub secret1: String,
    pub secret2: String,
    pub api_key: String,
    pub sync_interval_secs: u64,
    pub pending_threshold_mins: i64,
    pub pay_url: String,
    pub api_url: String,
}

static CONFIG: OnceLock<BillingRuntimeConfig> = OnceLock::new();

fn env_non_empty(keys: &[&str]) -> Option<String> {
    for key in keys {
        if let Ok(val) = env::var(key) {
            let trimmed = val.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }
    None
}

fn env_parse_u64(key: &str, default: u64) -> u64 {
    env::var(key)
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(default)
}

fn env_parse_i64(key: &str, default: i64) -> i64 {
    env::var(key)
        .ok()
        .and_then(|v| v.trim().parse::<i64>().ok())
        .unwrap_or(default)
}

fn env_parse_usize(key: &str, default: usize) -> usize {
    env::var(key)
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .unwrap_or(default)
}

fn load_from_env() -> BillingRuntimeConfig {
    let app_env = env_non_empty(&["APP_ENV"])
        .unwrap_or_else(|| "production".to_string())
        .to_lowercase();

    let public_domain = env_non_empty(&["PUBLIC_DOMAIN", "ANET_PUBLIC_URL"])
        .unwrap_or_else(|| "https://service.example.com".to_string());

    let bot_token = env_non_empty(&["TELEGRAM_BOT_TOKEN"]).unwrap_or_default();
    let web_app_data_key = env_non_empty(&["TELEGRAM_WEB_APP_DATA_KEY"])
        .unwrap_or_else(|| "WebAppData".to_string());

    let shop_id = env_non_empty(&["FK_SHOP_ID"]).unwrap_or_default();
    let secret1 = env_non_empty(&["FK_SECRET1"]).unwrap_or_default();
    let secret2 = env_non_empty(&["FK_SECRET2"]).unwrap_or_default();
    let api_key = env_non_empty(&["FK_API_KEY"]).unwrap_or_default();
    let pay_url = env_non_empty(&["FK_PAY_URL"])
        .unwrap_or_else(|| "https://pay.freekassa.ru/".to_string());
    let api_url = env_non_empty(&["FK_API_URL"])
        .unwrap_or_else(|| "https://api.fk.life/v1".to_string());

    let cfg = BillingRuntimeConfig {
        app_env,
        cabinet: CabinetConfig {
            web: CabinetWebConfig {
                public_domain,
                verification_token_ttl_mins: env_parse_u64("VERIFICATION_TOKEN_TTL_MINS", 15),
                min_password_length: env_parse_usize("MIN_PASSWORD_LENGTH", 5),
            },
            telegram: CabinetTelegramConfig {
                bot_token,
                web_app_data_key,
            },
        },
        billing: BillingConfig {
            freekassa: FreeKassaConfig {
                shop_id,
                secret1,
                secret2,
                api_key,
                sync_interval_secs: env_parse_u64("FK_SYNC_INTERVAL_SECS", 900),
                pending_threshold_mins: env_parse_i64("FK_PENDING_THRESHOLD_MINS", 15),
                pay_url,
                api_url,
            },
        },
    };

    if env_non_empty(&["JWT_SECRET"]).is_none() {
        warn!("[Config] JWT_SECRET is not set in .env / EnvironmentFile; using fallback secret (set JWT_SECRET in production!)");
    }
    if cfg.billing.freekassa.shop_id.is_empty() || cfg.billing.freekassa.secret2.is_empty() {
        warn!("[Config] FK_SHOP_ID or FK_SECRET2 is not configured; FreeKassa webhooks will return 500 until set");
    } else {
        info!(
            "[Config] Loaded billing & cabinet env config: public_domain='{}', fk_shop_id='{}', fk_api_key_set={}, tg_bot_set={}",
            cfg.cabinet.web.public_domain,
            cfg.billing.freekassa.shop_id,
            !cfg.billing.freekassa.api_key.is_empty(),
            !cfg.cabinet.telegram.bot_token.is_empty(),
        );
    }

    cfg
}

pub fn init_config() -> &'static BillingRuntimeConfig {
    CONFIG.get_or_init(load_from_env)
}

pub fn get() -> &'static BillingRuntimeConfig {
    CONFIG.get_or_init(load_from_env)
}

pub fn jwt_secret() -> String {
    env_non_empty(&["JWT_SECRET"]).unwrap_or_else(|| "secret_na_chushpana".to_string())
}
