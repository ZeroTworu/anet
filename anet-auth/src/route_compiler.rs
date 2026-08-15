//! Компиляция декларативной route map в поля клиентского TOML.
//!
//! Администратор задаёт default action и исключения, а этот модуль проверяет
//! правила, нормализует CIDR и раскладывает их в сетевые и per-app фильтры.

use ipnet::IpNet;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteRuleSpec {
    /// Тип совпадения: `cidr` или `application`.
    pub match_type: String,
    /// CIDR-сеть либо имя исполняемого файла.
    pub match_value: String,
    /// Действие, противоположное default action карты.
    pub action: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledRouteConfig {
    pub route_for: Vec<String>,
    pub exclude_route_for: Vec<String>,
    pub per_app: Vec<String>,
    pub per_app_mode: String,
}

pub fn compile_route_map(
    default_action: &str,
    rules: &[RouteRuleSpec],
) -> Result<CompiledRouteConfig, String> {
    // Все правила являются исключениями из default action. Поэтому карта
    // остаётся однозначной даже когда CIDR и application правила смешаны.
    if default_action != "tunnel" && default_action != "direct" {
        return Err("default_action must be tunnel or direct".to_string());
    }
    let expected_action = if default_action == "tunnel" {
        "direct"
    } else {
        "tunnel"
    };
    let mut cidrs = Vec::new();
    let mut applications = Vec::new();
    for rule in rules {
        if rule.action != expected_action {
            return Err(format!(
                "rule action must be {expected_action} for this default action"
            ));
        }
        match rule.match_type.as_str() {
            "cidr" => {
                let network: IpNet = rule
                    .match_value
                    .parse()
                    .map_err(|_| format!("invalid CIDR: {}", rule.match_value))?;
                cidrs.push(network.trunc().to_string());
            }
            "application" => {
                let value = rule.match_value.trim();
                if value.is_empty() || value.contains('/') || value.contains('\\') {
                    return Err(format!("invalid application name: {}", rule.match_value));
                }
                applications.push(value.to_string());
            }
            other => return Err(format!("unsupported match type: {other}")),
        }
    }

    let mut compiled = CompiledRouteConfig {
        route_for: Vec::new(),
        exclude_route_for: Vec::new(),
        per_app: Vec::new(),
        per_app_mode: "all".to_string(),
    };
    if default_action == "direct" {
        compiled.route_for = cidrs;
    } else {
        compiled.exclude_route_for = cidrs;
    }
    if !applications.is_empty() {
        compiled.per_app = applications;
        compiled.per_app_mode = if default_action == "direct" {
            "include"
        } else {
            "exclude"
        }
        .to_string();
    }
    Ok(compiled)
}

pub fn toml_string_array(values: &[String]) -> String {
    toml::Value::Array(values.iter().cloned().map(toml::Value::String).collect()).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direct_by_default_compiles_tunnel_cidrs() {
        let compiled = compile_route_map(
            "direct",
            &[RouteRuleSpec {
                match_type: "cidr".into(),
                match_value: "10.0.0.7/24".into(),
                action: "tunnel".into(),
            }],
        )
        .unwrap();
        assert_eq!(compiled.route_for, vec!["10.0.0.0/24"]);
        assert!(compiled.exclude_route_for.is_empty());
    }

    #[test]
    fn tunnel_by_default_compiles_excluded_apps() {
        let compiled = compile_route_map(
            "tunnel",
            &[RouteRuleSpec {
                match_type: "application".into(),
                match_value: "steam.exe".into(),
                action: "direct".into(),
            }],
        )
        .unwrap();
        assert_eq!(compiled.per_app_mode, "exclude");
        assert_eq!(compiled.per_app, vec!["steam.exe"]);
    }

    #[test]
    fn mixed_rule_kinds_compile_into_both_client_filters() {
        let compiled = compile_route_map(
            "tunnel",
            &[
                RouteRuleSpec {
                    match_type: "cidr".into(),
                    match_value: "10.0.0.0/8".into(),
                    action: "direct".into(),
                },
                RouteRuleSpec {
                    match_type: "application".into(),
                    match_value: "steam.exe".into(),
                    action: "direct".into(),
                },
            ],
        )
        .unwrap();
        assert_eq!(compiled.exclude_route_for, vec!["10.0.0.0/8"]);
        assert_eq!(compiled.per_app, vec!["steam.exe"]);
        assert_eq!(compiled.per_app_mode, "exclude");
    }

    #[test]
    fn generated_client_template_is_valid_toml() {
        let compiled = compile_route_map(
            "direct",
            &[RouteRuleSpec {
                match_type: "cidr".into(),
                match_value: "10.0.0.0/8".into(),
                action: "tunnel".into(),
            }],
        )
        .unwrap();
        let rendered = include_str!("../../contrib/client_template.toml")
            .replace("{{PRIVATE_KEY}}", "private")
            .replace("{{SERVER_PUB_KEY}}", "public")
            .replace("{{ROUTE_FOR}}", &toml_string_array(&compiled.route_for))
            .replace(
                "{{EXCLUDE_ROUTE_FOR}}",
                &toml_string_array(&compiled.exclude_route_for),
            )
            .replace("{{PER_APP}}", &toml_string_array(&compiled.per_app))
            .replace("{{PER_APP_MODE}}", &compiled.per_app_mode);
        toml::from_str::<toml::Value>(&rendered).unwrap();
    }
}
