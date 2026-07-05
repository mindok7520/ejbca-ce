use crate::{
    AppState,
    error::{AppError, AppResult},
    storage::{EjbcaFeatureFilter, EjbcaFeatureRecord},
};

#[derive(Debug, Clone)]
pub struct AccessRuleContext<'a> {
    pub actor: &'a str,
    pub action: &'a str,
    pub protocol: &'a str,
    pub ca_id: Option<&'a str>,
    pub certificate_profile_id: Option<&'a str>,
    pub end_entity_profile_id: Option<&'a str>,
}

pub async fn enforce_access_rules(
    state: &AppState,
    context: &AccessRuleContext<'_>,
) -> AppResult<()> {
    if actor_is_root_admin(context.actor) {
        return Ok(());
    }

    let features = state
        .db
        .list_ejbca_features(
            &EjbcaFeatureFilter {
                feature_type: Some("access_rule".to_string()),
                status: None,
            },
            200,
        )
        .await?;

    let mut concrete_policy_seen = false;
    let mut require_allow_match = false;
    let mut allow_match = false;

    for feature in features {
        if !matches!(feature.status.as_str(), "active" | "configured") {
            continue;
        }
        let config = parse_config(&feature);
        let rules = rules_from_config(&config);
        if rules.is_empty() {
            continue;
        }
        concrete_policy_seen = true;
        require_allow_match |= config_requires_allow(&config);
        for rule in rules {
            if !rule_matches(&rule, context) {
                continue;
            }
            match rule_effect(&rule) {
                RuleEffect::Deny => {
                    return Err(AppError::Forbidden(format!(
                        "access rule '{}'이 '{}' 작업을 차단했습니다",
                        feature.name, context.action
                    )));
                }
                RuleEffect::Allow => allow_match = true,
            }
        }
    }

    if concrete_policy_seen && require_allow_match && !allow_match {
        Err(AppError::Forbidden(format!(
            "access rule scope에 '{}' 작업 권한이 없습니다: actor={}, protocol={}, ca={}",
            context.action,
            context.actor,
            context.protocol,
            context.ca_id.unwrap_or("-")
        )))
    } else {
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuleEffect {
    Allow,
    Deny,
}

fn parse_config(feature: &EjbcaFeatureRecord) -> serde_json::Value {
    serde_json::from_str(&feature.config_json).unwrap_or(serde_json::Value::Null)
}

fn rules_from_config(config: &serde_json::Value) -> Vec<serde_json::Value> {
    if let Some(rules) = config.get("rules").and_then(serde_json::Value::as_array) {
        return rules
            .iter()
            .filter(|rule| rule.is_object())
            .cloned()
            .collect();
    }
    if is_rule_like(config) {
        vec![config.clone()]
    } else {
        Vec::new()
    }
}

fn is_rule_like(config: &serde_json::Value) -> bool {
    [
        "effect",
        "actions",
        "permissions",
        "actors",
        "roles",
        "ca_ids",
        "certificate_profile_ids",
        "end_entity_profile_ids",
        "protocols",
    ]
    .iter()
    .any(|key| config.get(*key).is_some())
}

fn config_requires_allow(config: &serde_json::Value) -> bool {
    config_bool(config, "require_match")
        || config_bool(config, "allowlist")
        || config
            .get("mode")
            .or_else(|| config.get("default"))
            .and_then(serde_json::Value::as_str)
            .map(|value| {
                let value = value.trim().to_ascii_lowercase();
                matches!(value.as_str(), "allowlist" | "deny" | "default_deny")
            })
            .unwrap_or(false)
}

fn rule_effect(rule: &serde_json::Value) -> RuleEffect {
    rule.get("effect")
        .or_else(|| rule.get("decision"))
        .and_then(serde_json::Value::as_str)
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| matches!(value.as_str(), "deny" | "block" | "forbid"))
        .map(|_| RuleEffect::Deny)
        .unwrap_or(RuleEffect::Allow)
}

fn rule_matches(rule: &serde_json::Value, context: &AccessRuleContext<'_>) -> bool {
    value_matches_any(
        values_for(rule, &["actions", "action", "permissions", "permission"]),
        context.action,
    ) && actor_matches(rule, context.actor)
        && optional_value_matches_any(values_for(rule, &["ca_ids", "ca_id", "cas"]), context.ca_id)
        && optional_value_matches_any(
            values_for(
                rule,
                &[
                    "certificate_profile_ids",
                    "certificate_profile_id",
                    "profiles",
                ],
            ),
            context.certificate_profile_id,
        )
        && optional_value_matches_any(
            values_for(rule, &["end_entity_profile_ids", "end_entity_profile_id"]),
            context.end_entity_profile_id,
        )
        && value_matches_any(
            values_for(rule, &["protocols", "protocol", "sources", "source"]),
            context.protocol,
        )
}

fn actor_matches(rule: &serde_json::Value, actor: &str) -> bool {
    let values = values_for(
        rule,
        &[
            "actors",
            "actor",
            "roles",
            "role",
            "role_names",
            "role_name",
        ],
    );
    if values.is_empty() {
        return true;
    }
    let normalized_actor = actor.trim().to_ascii_lowercase();
    let role_suffix = normalized_actor
        .rsplit_once(':')
        .map(|(_, value)| value)
        .unwrap_or(normalized_actor.as_str());
    values.iter().any(|value| {
        let value = value.trim().to_ascii_lowercase();
        value == "*"
            || value == normalized_actor
            || value == role_suffix
            || (value == "admin" && actor_is_root_admin(actor))
    })
}

fn value_matches_any(values: Vec<String>, actual: &str) -> bool {
    if values.is_empty() {
        return true;
    }
    let actual = actual.trim().to_ascii_lowercase();
    values.iter().any(|value| {
        let value = value.trim().to_ascii_lowercase();
        value == "*" || value == actual
    })
}

fn optional_value_matches_any(values: Vec<String>, actual: Option<&str>) -> bool {
    if values.is_empty() {
        return true;
    }
    let Some(actual) = actual else {
        return values.iter().any(|value| value.trim() == "*");
    };
    value_matches_any(values, actual)
}

fn values_for(config: &serde_json::Value, keys: &[&str]) -> Vec<String> {
    for key in keys {
        let Some(value) = config.get(*key) else {
            continue;
        };
        if let Some(value) = value.as_str() {
            return split_csv_values(value);
        }
        if let Some(values) = value.as_array() {
            return values
                .iter()
                .filter_map(serde_json::Value::as_str)
                .flat_map(split_csv_values)
                .collect();
        }
    }
    Vec::new()
}

fn split_csv_values(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
        .collect()
}

fn config_bool(config: &serde_json::Value, key: &str) -> bool {
    config
        .get(key)
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
}

fn actor_is_root_admin(actor: &str) -> bool {
    actor == "admin" || actor.starts_with("cert-role-admin:")
}
