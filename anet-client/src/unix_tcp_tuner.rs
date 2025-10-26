use std::process::Command;
use std::fs;
use log::{info, warn};

pub struct UnixTcpTuner;

impl UnixTcpTuner {
    pub fn set_congestion_control(algorithm: &str) -> Result<(), String> {
        let valid_algorithms = ["cubic", "reno", "bbr", "vegas", "westwood"];
        if !valid_algorithms.contains(&algorithm.to_lowercase().as_str()) {
            return Err(format!("Unsupported algorithm: {}. Use: cubic, reno, bbr, vegas, westwood", algorithm));
        }

        // Проверяем доступность алгоритма в системе
        if !Self::is_algorithm_available(algorithm)? {
            return Err(format!("Algorithm {} is not available on this system", algorithm));
        }

        // Пробуем установить через sysctl
        if Self::try_sysctl(algorithm).is_ok() {
            info!("Successfully set TCP congestion control to {} via sysctl", algorithm);
            return Ok(());
        }

        // Пробуем записать напрямую в /proc
        if Self::try_proc(algorithm).is_ok() {
            info!("Successfully set TCP congestion control to {} via /proc", algorithm);
            return Ok(());
        }

        Err("Failed to set TCP congestion control using all methods".to_string())
    }

    fn is_algorithm_available(algorithm: &str) -> Result<bool, String> {
        let available_path = "/proc/sys/net/ipv4/tcp_available_congestion_control";

        let available_algorithms = fs::read_to_string(available_path)
            .map_err(|e| format!("Failed to read {}: {}", available_path, e))?;

        Ok(available_algorithms.split_whitespace().any(|a| a == algorithm))
    }

    fn try_sysctl(algorithm: &str) -> Result<(), String> {
        let output = Command::new("sysctl")
            .args(&[
                "-w",
                &format!("net.ipv4.tcp_congestion_control={}", algorithm)
            ])
            .output()
            .map_err(|e| format!("sysctl failed: {}", e))?;

        if output.status.success() {
            Ok(())
        } else {
            Err(String::from_utf8_lossy(&output.stderr).to_string())
        }
    }

    fn try_proc(algorithm: &str) -> Result<(), String> {
        let proc_path = "/proc/sys/net/ipv4/tcp_congestion_control";

        fs::write(proc_path, algorithm)
            .map_err(|e| format!("Failed to write to {}: {}", proc_path, e))
    }

    pub fn get_current_algorithm() -> Result<String, String> {
        let proc_path = "/proc/sys/net/ipv4/tcp_congestion_control";

        fs::read_to_string(proc_path)
            .map(|s| s.trim().to_string())
            .map_err(|e| format!("Failed to read {}: {}", proc_path, e))
    }

    pub fn get_available_algorithms() -> Result<Vec<String>, String> {
        let available_path = "/proc/sys/net/ipv4/tcp_available_congestion_control";

        let content = fs::read_to_string(available_path)
            .map_err(|e| format!("Failed to read {}: {}", available_path, e))?;

        Ok(content.split_whitespace().map(|s| s.to_string()).collect())
    }

    pub fn enable_bbr_if_available() -> Result<(), String> {
        let available = Self::get_available_algorithms()?;

        if available.contains(&"bbr".to_string()) {
            info!("BBR is available, enabling...");
            Self::set_congestion_control("bbr")
        } else {
            warn!("BBR is not available on this system. Available algorithms: {:?}", available);

            // Пробуем cubic как fallback
            if available.contains(&"cubic".to_string()) {
                info!("Falling back to cubic");
                Self::set_congestion_control("cubic")
            } else if !available.is_empty() {
                info!("Falling back to first available: {}", available[0]);
                Self::set_congestion_control(&available[0])
            } else {
                Err("No TCP congestion control algorithms available".to_string())
            }
        }
    }
    
}
