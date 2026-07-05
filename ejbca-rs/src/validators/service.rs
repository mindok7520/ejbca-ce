use std::time::Duration as StdDuration;

use futures_util::TryStreamExt;

use crate::{
    AppState,
    error::{AppError, AppResult},
    storage::ValidatorRecord,
    util::now_unix,
    validators::{
        CreateValidatorRequest, UpdateValidatorRequest, ValidationContext, ValidatorConfig,
        ValidatorResponse, WebhookValidationRequest, WebhookValidationResponse,
    },
};
use uuid::Uuid;

pub async fn create_validator(
    state: &AppState,
    request: CreateValidatorRequest,
    actor: &str,
) -> AppResult<ValidatorResponse> {
    if request.name.trim().is_empty() {
        return Err(AppError::BadRequest(
            "validator 이름은 비어 있을 수 없습니다".to_string(),
        ));
    }
    let config = parse_config(&request.kind, request.config.clone())?;
    let now = now_unix();
    let record = ValidatorRecord {
        id: Uuid::new_v4().to_string(),
        name: request.name.trim().to_string(),
        kind: request.kind,
        config_json: serde_json::to_string(&config)
            .map_err(|err| AppError::Internal(err.to_string()))?,
        enabled: request.enabled.unwrap_or(true),
        created_at: now,
        updated_at: now,
    };
    state.db.insert_validator(&record).await?;
    state
        .db
        .audit(
            actor,
            "validator.create",
            &record.id,
            "success",
            &serde_json::json!({"name": record.name, "kind": record.kind}).to_string(),
        )
        .await?;
    Ok(record_to_response(record))
}

pub async fn list_validators(state: &AppState) -> AppResult<Vec<ValidatorResponse>> {
    Ok(state
        .db
        .list_validators(false)
        .await?
        .into_iter()
        .map(record_to_response)
        .collect())
}

pub async fn update_validator(
    state: &AppState,
    id: &str,
    request: UpdateValidatorRequest,
    actor: &str,
) -> AppResult<ValidatorResponse> {
    let mut record = state
        .db
        .get_validator(id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("validator를 찾을 수 없습니다: {id}")))?;
    if let Some(name) = request.name {
        let name = name.trim();
        if name.is_empty() {
            return Err(AppError::BadRequest(
                "validator 이름은 비어 있을 수 없습니다".to_string(),
            ));
        }
        record.name = name.to_string();
    }
    if let Some(kind) = request.kind {
        record.kind = kind;
    }
    let config_value = match request.config {
        Some(config) => config,
        None => serde_json::from_str(&record.config_json)
            .map_err(|err| AppError::Internal(format!("validator 설정 파싱 실패: {err}")))?,
    };
    let config = parse_config(&record.kind, config_value)?;
    record.config_json =
        serde_json::to_string(&config).map_err(|err| AppError::Internal(err.to_string()))?;
    if let Some(enabled) = request.enabled {
        record.enabled = enabled;
    }
    record.updated_at = now_unix();
    let updated = state.db.update_validator(&record).await?;
    if updated == 0 {
        return Err(AppError::NotFound(format!(
            "validator를 찾을 수 없습니다: {id}"
        )));
    }
    state
        .db
        .audit(
            actor,
            "validator.update",
            id,
            "success",
            &serde_json::json!({"name": record.name, "kind": record.kind, "enabled": record.enabled}).to_string(),
        )
        .await?;
    Ok(record_to_response(record))
}

pub async fn delete_validator(state: &AppState, id: &str, actor: &str) -> AppResult<()> {
    let deleted = state.db.delete_validator(id).await?;
    if deleted == 0 {
        return Err(AppError::NotFound(format!(
            "validator를 찾을 수 없습니다: {id}"
        )));
    }
    state
        .db
        .audit(actor, "validator.delete", id, "success", "{}")
        .await?;
    Ok(())
}

pub async fn validate_pre_issue(state: &AppState, context: &ValidationContext) -> AppResult<()> {
    let validators = state.db.list_validators(true).await?;
    for validator in validators {
        let config: ValidatorConfig = serde_json::from_str(&validator.config_json)
            .map_err(|err| AppError::Internal(format!("validator 설정 파싱 실패: {err}")))?;
        apply_validator(state, &validator.name, config, context).await?;
    }
    Ok(())
}

fn parse_config(kind: &str, config: serde_json::Value) -> AppResult<ValidatorConfig> {
    match kind {
        "deny_subject_keywords" => {
            let keywords = config
                .get("keywords")
                .and_then(|v| v.as_array())
                .ok_or_else(|| AppError::BadRequest("keywords 배열이 필요합니다".to_string()))?
                .iter()
                .filter_map(|v| v.as_str().map(ToString::to_string))
                .collect();
            Ok(ValidatorConfig::DenySubjectKeywords { keywords })
        }
        "dns_allowlist" => {
            let domains = domains_from_config(&config)?;
            Ok(ValidatorConfig::DnsAllowlist { domains })
        }
        "dns_denylist" => {
            let domains = domains_from_config(&config)?;
            Ok(ValidatorConfig::DnsDenylist { domains })
        }
        "external_webhook" => {
            #[derive(serde::Deserialize)]
            struct External {
                url: String,
                token: Option<String>,
                timeout_ms: Option<u64>,
            }
            let external: External = serde_json::from_value(config).map_err(|err| {
                AppError::BadRequest(format!("webhook 설정이 잘못되었습니다: {err}"))
            })?;
            Ok(ValidatorConfig::ExternalWebhook {
                url: external.url,
                token: external.token,
                timeout_ms: external.timeout_ms,
            })
        }
        _ => Err(AppError::BadRequest(format!(
            "지원하지 않는 validator kind입니다: {kind}"
        ))),
    }
}

fn domains_from_config(config: &serde_json::Value) -> AppResult<Vec<String>> {
    Ok(config
        .get("domains")
        .and_then(|v| v.as_array())
        .ok_or_else(|| AppError::BadRequest("domains 배열이 필요합니다".to_string()))?
        .iter()
        .filter_map(|v| v.as_str().map(|s| s.trim().to_ascii_lowercase()))
        .filter(|s| !s.is_empty())
        .collect())
}

async fn apply_validator(
    state: &AppState,
    name: &str,
    config: ValidatorConfig,
    context: &ValidationContext,
) -> AppResult<()> {
    match config {
        ValidatorConfig::DenySubjectKeywords { keywords } => {
            let subject = context.subject_dn.to_ascii_lowercase();
            for keyword in keywords {
                if subject.contains(&keyword.to_ascii_lowercase()) {
                    return Err(AppError::Forbidden(format!(
                        "validator '{name}' 실패: subject DN에 금지 키워드가 포함되어 있습니다"
                    )));
                }
            }
            Ok(())
        }
        ValidatorConfig::DnsAllowlist { domains } => {
            for dns in &context.dns_names {
                if !domain_matches_any(dns, &domains) {
                    return Err(AppError::Forbidden(format!(
                        "validator '{name}' 실패: DNS 이름이 allowlist에 없습니다: {dns}"
                    )));
                }
            }
            Ok(())
        }
        ValidatorConfig::DnsDenylist { domains } => {
            for dns in &context.dns_names {
                if domain_matches_any(dns, &domains) {
                    return Err(AppError::Forbidden(format!(
                        "validator '{name}' 실패: DNS 이름이 denylist에 포함됩니다: {dns}"
                    )));
                }
            }
            Ok(())
        }
        ValidatorConfig::ExternalWebhook {
            url,
            token,
            timeout_ms,
        } => {
            let timeout_ms = effective_webhook_timeout_ms(
                state.settings.validator_webhook_default_timeout_ms,
                state.settings.validator_webhook_max_timeout_ms,
                timeout_ms,
            );
            let max_response_bytes = state.settings.validator_webhook_max_response_bytes.max(1);
            let mut request = state
                .http
                .post(url)
                .timeout(StdDuration::from_millis(timeout_ms))
                .json(&WebhookValidationRequest {
                    phase: "pre_issue",
                    context,
                });
            if let Some(token) = token {
                request = request.bearer_auth(token);
            }
            let response = request.send().await.map_err(|err| {
                AppError::Forbidden(format!("validator '{name}' 실패: webhook 호출 실패: {err}"))
            })?;
            if !response.status().is_success() {
                return Err(AppError::Forbidden(format!(
                    "validator '{name}' 실패: webhook HTTP 상태 {}",
                    response.status()
                )));
            }
            let body = read_webhook_response(name, response, max_response_bytes).await?;
            let body: WebhookValidationResponse = serde_json::from_slice(&body).map_err(|err| {
                AppError::Forbidden(format!(
                    "validator '{name}' 실패: webhook 응답 JSON 파싱 실패: {err}"
                ))
            })?;
            if body.allowed {
                Ok(())
            } else {
                Err(AppError::Forbidden(format!(
                    "validator '{name}' 실패: {}",
                    body.message
                        .unwrap_or_else(|| "webhook rejected".to_string())
                )))
            }
        }
    }
}

fn effective_webhook_timeout_ms(
    default_timeout_ms: u64,
    max_timeout_ms: u64,
    requested: Option<u64>,
) -> u64 {
    let max_timeout_ms = max_timeout_ms.max(1);
    requested
        .unwrap_or(default_timeout_ms)
        .clamp(1, max_timeout_ms)
}

async fn read_webhook_response(
    name: &str,
    response: reqwest::Response,
    max_response_bytes: usize,
) -> AppResult<Vec<u8>> {
    if let Some(length) = response.content_length()
        && length > max_response_bytes as u64
    {
        return Err(AppError::Forbidden(format!(
            "validator '{name}' 실패: webhook 응답이 너무 큽니다: {length} bytes"
        )));
    }

    let mut body = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.try_next().await.map_err(|err| {
        AppError::Forbidden(format!(
            "validator '{name}' 실패: webhook 응답 읽기 실패: {err}"
        ))
    })? {
        if body.len().saturating_add(chunk.len()) > max_response_bytes {
            return Err(AppError::Forbidden(format!(
                "validator '{name}' 실패: webhook 응답이 너무 큽니다: limit={max_response_bytes} bytes"
            )));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn domain_matches_any(domain: &str, rules: &[String]) -> bool {
    let domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    rules.iter().any(|rule| {
        let rule = rule.trim().trim_end_matches('.').to_ascii_lowercase();
        domain == rule || domain.ends_with(&format!(".{rule}"))
    })
}

fn record_to_response(record: ValidatorRecord) -> ValidatorResponse {
    let config = serde_json::from_str(&record.config_json).unwrap_or(serde_json::Value::Null);
    ValidatorResponse {
        id: record.id,
        name: record.name,
        kind: record.kind,
        config,
        enabled: record.enabled,
        created_at: record.created_at,
        updated_at: record.updated_at,
    }
}

#[cfg(test)]
mod tests {
    use std::{path::PathBuf, sync::Arc};

    use tokio::sync::Semaphore;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };
    use uuid::Uuid;

    use super::*;
    use crate::{config::Settings, storage::Db};

    async fn test_state() -> (AppState, PathBuf) {
        let data_dir =
            std::env::temp_dir().join(format!("ejbca-rs-validator-test-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&data_dir).unwrap();
        let settings = Arc::new(Settings {
            config_file: None,
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            data_dir: data_dir.to_string_lossy().to_string(),
            database_url: None,
            admin_token: Some("test-admin-token".to_string()),
            public_base_url: "http://127.0.0.1:0".to_string(),
            ca_key_provider: "database".to_string(),
            ca_key_dir: None,
            max_request_bytes: 100_000,
            max_list_limit: 1000,
            cors_allowed_origins: String::new(),
            adminweb_client_cert_required: false,
            adminweb_client_cert_header: "x-admin-client-cert-pem".to_string(),
            adminweb_client_cert_proxy_secret: None,
            adminweb_client_cert_allowed_fingerprints: String::new(),
            adminweb_client_cert_allowed_subjects: String::new(),
            database_max_connections: 4,
            database_busy_timeout_seconds: 30,
            max_concurrent_issuance: 4,
            validator_webhook_default_timeout_ms: 3000,
            validator_webhook_max_timeout_ms: 30_000,
            validator_webhook_max_response_bytes: 8192,
            json_logs: false,
            log_level: "error".to_string(),
            log_output: "stdout".to_string(),
            log_dir: None,
            log_retention_days: 14,
            log_retention_files: 30,
            metrics_enabled: true,
            metrics_public: false,
            metrics_device_limit: 100,
            metrics_event_retention_days: 90,
            audit_event_retention_days: 365,
            maintenance_enabled: false,
            maintenance_interval_seconds: 3600,
            maintenance_backup: false,
            maintenance_purge_expired_certificates: false,
            maintenance_purge_expired_crls: false,
            maintenance_purge_audit_events: false,
            maintenance_optimize: false,
            maintenance_older_than_days: 30,
            maintenance_batch_size: 100,
            maintenance_generate_crls: false,
            maintenance_crl_validity_days: 7,
            maintenance_crl_partition_count: 1,
            command: None,
        });
        let db = Db::connect(
            &settings.database_url(),
            settings.database_max_connections,
            settings.database_busy_timeout_seconds,
        )
        .await
        .unwrap();
        db.migrate().await.unwrap();
        let state = AppState {
            db,
            settings: settings.clone(),
            http: reqwest::Client::new(),
            issue_limiter: Arc::new(Semaphore::new(4)),
        };
        (state, data_dir)
    }

    #[test]
    fn domain_match_supports_subdomains() {
        assert!(domain_matches_any(
            "api.example.com",
            &["example.com".into()]
        ));
        assert!(domain_matches_any("example.com", &["example.com".into()]));
        assert!(!domain_matches_any(
            "badexample.com",
            &["example.com".into()]
        ));
    }

    #[test]
    fn webhook_timeout_uses_default_and_global_max() {
        assert_eq!(effective_webhook_timeout_ms(3000, 30_000, None), 3000);
        assert_eq!(effective_webhook_timeout_ms(3000, 30_000, Some(500)), 500);
        assert_eq!(
            effective_webhook_timeout_ms(3000, 30_000, Some(60_000)),
            30_000
        );
        assert_eq!(effective_webhook_timeout_ms(0, 0, Some(0)), 1);
    }

    #[tokio::test]
    async fn webhook_response_content_length_limit_rejects_large_body() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0_u8; 512];
            let _ = socket.read(&mut request).await.unwrap();
            socket
                .write_all(
                    b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 100\r\n\r\n{}",
                )
                .await
                .unwrap();
        });

        let response = reqwest::get(format!("http://{addr}/")).await.unwrap();
        let error = read_webhook_response("large", response, 16)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("webhook 응답이 너무 큽니다"));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn updates_validator_config_and_enabled_state() {
        let (state, data_dir) = test_state().await;
        let validator = create_validator(
            &state,
            CreateValidatorRequest {
                name: "allow-a".to_string(),
                kind: "dns_allowlist".to_string(),
                config: serde_json::json!({"domains":["example.com"]}),
                enabled: Some(true),
            },
            "admin",
        )
        .await
        .unwrap();

        let updated = update_validator(
            &state,
            &validator.id,
            UpdateValidatorRequest {
                name: Some("allow-b".to_string()),
                kind: None,
                config: Some(serde_json::json!({"domains":["example.org"]})),
                enabled: Some(false),
            },
            "admin",
        )
        .await
        .unwrap();

        assert_eq!(updated.name, "allow-b");
        assert_eq!(updated.kind, "dns_allowlist");
        assert_eq!(
            updated.config,
            serde_json::json!({"type":"dns_allowlist","domains":["example.org"]})
        );
        assert!(!updated.enabled);

        std::fs::remove_dir_all(data_dir).ok();
    }
}
