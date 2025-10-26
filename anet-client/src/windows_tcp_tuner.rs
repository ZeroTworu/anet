use std::process::Command;
use log::info;

pub struct WindowsTcpTuner;

impl WindowsTcpTuner {
    pub fn set_congestion_control(algorithm: &str) -> Result<(), String> {
        let valid_algorithms = ["cubic", "ctcp", "dctcp"];
        if !valid_algorithms.contains(&algorithm.to_lowercase().as_str()) {
            return Err(format!("Unsupported algorithm: {}. Use: cubic, ctcp, dctcp", algorithm));
        }

        // Попробуем разные методы
        if Self::try_powershell(algorithm).is_ok() {
            info!("Successfully set TCP congestion control to {} via PowerShell", algorithm);
            return Ok(());
        }

        if Self::try_netsh(algorithm).is_ok() {
            info!("Successfully set TCP congestion control to {} via netsh", algorithm);
            return Ok(());
        }

        if Self::try_registry(algorithm).is_ok() {
            info!("Successfully set TCP congestion control to {} via registry", algorithm);
            return Ok(());
        }

        Err("Failed to set TCP congestion control using all methods".to_string())
    }

    fn try_powershell(algorithm: &str) -> Result<(), String> {
        let ps_algorithm = match algorithm.to_lowercase().as_str() {
            "cubic" => "Cubic",
            "ctcp" => "Ctcp",
            "dctcp" => "Dctcp",
            _ => return Err("Unsupported algorithm".to_string())
        };

        let output = Command::new("powershell")
            .args(&[
                "-Command",
                &format!("Set-NetTCPSetting -SettingName InternetCustom -CongestionProvider {}; Write-Output 'Success'", ps_algorithm)
            ])
            .output()
            .map_err(|e| format!("PowerShell failed: {}", e))?;

        if output.status.success() {
            Ok(())
        } else {
            Err(String::from_utf8_lossy(&output.stderr).to_string())
        }
    }

    fn try_netsh(algorithm: &str) -> Result<(), String> {
        let netsh_algorithm = match algorithm.to_lowercase().as_str() {
            "cubic" => "cubic",
            "ctcp" => "ctcp",
            "dctcp" => "dctcp",
            _ => return Err("Unsupported algorithm".to_string())
        };

        let output = Command::new("netsh")
            .args(&[
                "int", "tcp", "set", "global",
                &format!("congestionprovider={}", netsh_algorithm)
            ])
            .output()
            .map_err(|e| format!("netsh failed: {}", e))?;

        if output.status.success() {
            Ok(())
        } else {
            Err(String::from_utf8_lossy(&output.stderr).to_string())
        }
    }

    fn try_registry(algorithm: &str) -> Result<(), String> {
        let reg_algorithm = match algorithm.to_lowercase().as_str() {
            "cubic" => "Cubic",
            "ctcp" => "CTCP",
            "dctcp" => "DCTCP",
            _ => return Err("Unsupported algorithm".to_string())
        };

        let output = Command::new("reg")
            .args(&[
                "add",
                "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters",
                "/v", "TcpCongestionControl",
                "/t", "REG_SZ",
                "/d", reg_algorithm,
                "/f"
            ])
            .output()
            .map_err(|e| format!("reg failed: {}", e))?;

        if output.status.success() {
            Ok(())
        } else {
            Err(String::from_utf8_lossy(&output.stderr).to_string())
        }
    }

    pub fn get_current_algorithm() -> Result<String, String> {
        // Сначала пробуем PowerShell
        let output = Command::new("powershell")
            .args(&["-Command", "Get-NetTCPSetting | Select-Object -First 1 | Select-Object -ExpandProperty CongestionProvider"])
            .output()
            .map_err(|e| format!("PowerShell failed: {}", e))?;

        if output.status.success() {
            let result = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !result.is_empty() {
                return Ok(result);
            }
        }

        // Пробуем через реестр
        let output = Command::new("reg")
            .args(&[
                "query",
                "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters",
                "/v", "TcpCongestionControl"
            ])
            .output()
            .map_err(|e| format!("reg failed: {}", e))?;

        if output.status.success() {
            let output_str = String::from_utf8_lossy(&output.stdout);
            if let Some(line) = output_str.lines().find(|l| l.contains("TcpCongestionControl")) {
                if let Some(value) = line.split_whitespace().last() {
                    return Ok(value.to_string());
                }
            }
        }

        Err("Could not determine current TCP congestion control algorithm".to_string())
    }
}
