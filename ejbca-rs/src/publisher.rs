use std::{path::PathBuf, time::Duration};

use serde::Serialize;
use tokio::{fs::OpenOptions, io::AsyncWriteExt};

use crate::{
    AppState,
    error::{AppError, AppResult},
    storage::{CertificateRecord, EjbcaFeatureFilter, EjbcaFeatureRecord},
    util::now_unix,
};

#[derive(Debug, Serialize)]
struct CertificatePublisherEvent {
    event_type: String,
    certificate_id: String,
    ca_id: String,
    serial_hex: String,
    subject_dn: String,
    dns_names: Vec<String>,
    status: String,
    revocation_reason: Option<String>,
    revoked_at: Option<i64>,
    not_before: i64,
    not_after: i64,
    fingerprint_sha256: String,
    cert_pem: String,
    actor: String,
    occurred_at: i64,
}

pub async fn dispatch_certificate_event(
    state: &AppState,
    event_type: &str,
    record: &CertificateRecord,
    actor: &str,
) -> AppResult<()> {
    let event_type = normalize_event_type(event_type)?;
    let publishers = state
        .db
        .list_ejbca_features(
            &EjbcaFeatureFilter {
                feature_type: Some("publisher".to_string()),
                status: None,
            },
            200,
        )
        .await?;
    if publishers.is_empty() {
        return Ok(());
    }

    let payload = publisher_event(&event_type, record, actor);
    let mut required_failures = Vec::new();
    for publisher in publishers {
        if !matches!(publisher.status.as_str(), "active" | "configured") {
            continue;
        }
        let config = parse_config(&publisher);
        if !handles_event(&config, &event_type) {
            continue;
        }
        if !is_concrete_publisher(&config) {
            continue;
        }
        let required = config_bool(&config, "required")
            || config_bool(&config, "fail_closed")
            || config_bool(&config, "block_on_failure");
        let result = dispatch_one(state, &publisher, &config, &payload).await;
        audit_dispatch(state, actor, &publisher, &event_type, &result).await;
        if required {
            if let Err(err) = result {
                required_failures.push(format!("{}: {err}", publisher.name));
            }
        }
    }

    if required_failures.is_empty() {
        Ok(())
    } else {
        Err(AppError::Internal(format!(
            "필수 publisher dispatch 실패: {}",
            required_failures.join("; ")
        )))
    }
}

async fn dispatch_one(
    state: &AppState,
    publisher: &EjbcaFeatureRecord,
    config: &serde_json::Value,
    payload: &CertificatePublisherEvent,
) -> Result<String, String> {
    let publisher_type = publisher_type(config);
    match publisher_type.as_deref() {
        Some("webhook") => dispatch_webhook(state, config, payload).await,
        Some("file") => dispatch_file(config, payload).await,
        Some(other) => Err(format!("지원하지 않는 publisher type입니다: {other}")),
        None => Err(format!(
            "publisher '{}'에는 type/url/path/directory 설정이 필요합니다",
            publisher.name
        )),
    }
}

async fn dispatch_webhook(
    state: &AppState,
    config: &serde_json::Value,
    payload: &CertificatePublisherEvent,
) -> Result<String, String> {
    let url = config
        .get("url")
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "webhook publisher에는 url이 필요합니다".to_string())?;
    let timeout_ms = config
        .get("timeout_ms")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(3000)
        .clamp(100, 30_000);
    let mut request = state
        .http
        .post(url)
        .timeout(Duration::from_millis(timeout_ms))
        .json(payload);
    if let Some(token) = config
        .get("token")
        .or_else(|| config.get("bearer_token"))
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        request = request.bearer_auth(token);
    }
    if let (Some(name), Some(value)) = (
        config
            .get("header_name")
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty()),
        config
            .get("header_value")
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty()),
    ) {
        request = request.header(name, value);
    }
    let response = request.send().await.map_err(|err| err.to_string())?;
    let status = response.status();
    if status.is_success() {
        Ok(format!("webhook {status}"))
    } else {
        let body = response.text().await.unwrap_or_default();
        Err(format!(
            "webhook 응답 실패: {status}: {}",
            truncate_detail(&body, 256)
        ))
    }
}

async fn dispatch_file(
    config: &serde_json::Value,
    payload: &CertificatePublisherEvent,
) -> Result<String, String> {
    let path = publisher_file_path(config)?;
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|err| format!("publisher directory 생성 실패: {err}"))?;
    }
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .await
        .map_err(|err| format!("publisher file 열기 실패: {err}"))?;
    let mut line = serde_json::to_vec(payload).map_err(|err| err.to_string())?;
    line.push(b'\n');
    file.write_all(&line)
        .await
        .map_err(|err| format!("publisher file 쓰기 실패: {err}"))?;
    Ok(format!("file {}", path.display()))
}

async fn audit_dispatch(
    state: &AppState,
    actor: &str,
    publisher: &EjbcaFeatureRecord,
    event_type: &str,
    result: &Result<String, String>,
) {
    let (status, detail) = match result {
        Ok(message) => (
            "success",
            serde_json::json!({"event_type": event_type, "message": message}),
        ),
        Err(error) => (
            "failure",
            serde_json::json!({"event_type": event_type, "error": error}),
        ),
    };
    if let Err(err) = state
        .db
        .audit(
            actor,
            "publisher.dispatch",
            &publisher.id,
            status,
            &detail.to_string(),
        )
        .await
    {
        tracing::warn!("publisher dispatch 감사 로그 저장 실패: {err}");
    }
}

fn publisher_event(
    event_type: &str,
    record: &CertificateRecord,
    actor: &str,
) -> CertificatePublisherEvent {
    CertificatePublisherEvent {
        event_type: event_type.to_string(),
        certificate_id: record.id.clone(),
        ca_id: record.ca_id.clone(),
        serial_hex: record.serial_hex.clone(),
        subject_dn: record.subject_dn.clone(),
        dns_names: serde_json::from_str(&record.san_json).unwrap_or_default(),
        status: record.status.clone(),
        revocation_reason: record.revocation_reason.clone(),
        revoked_at: record.revoked_at,
        not_before: record.not_before,
        not_after: record.not_after,
        fingerprint_sha256: record.fingerprint_sha256.clone(),
        cert_pem: record.cert_pem.clone(),
        actor: actor.to_string(),
        occurred_at: now_unix(),
    }
}

fn parse_config(publisher: &EjbcaFeatureRecord) -> serde_json::Value {
    serde_json::from_str(&publisher.config_json).unwrap_or(serde_json::Value::Null)
}

fn is_concrete_publisher(config: &serde_json::Value) -> bool {
    publisher_type(config).is_some()
}

fn publisher_type(config: &serde_json::Value) -> Option<String> {
    config
        .get("type")
        .or_else(|| config.get("publisher_type"))
        .and_then(serde_json::Value::as_str)
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| !value.is_empty())
        .or_else(|| {
            config
                .get("url")
                .and_then(serde_json::Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(|_| "webhook".to_string())
        })
        .or_else(|| {
            if config.get("path").is_some() || config.get("directory").is_some() {
                Some("file".to_string())
            } else {
                None
            }
        })
}

fn handles_event(config: &serde_json::Value, event_type: &str) -> bool {
    config
        .get("events")
        .or_else(|| config.get("event_types"))
        .and_then(serde_json::Value::as_array)
        .map(|events| {
            events
                .iter()
                .filter_map(serde_json::Value::as_str)
                .map(|value| value.trim().to_ascii_lowercase())
                .any(|value| value == "*" || value == event_type)
        })
        .unwrap_or(true)
}

fn publisher_file_path(config: &serde_json::Value) -> Result<PathBuf, String> {
    if let Some(path) = config
        .get("path")
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        return Ok(PathBuf::from(path));
    }
    if let Some(directory) = config
        .get("directory")
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        return Ok(PathBuf::from(directory).join("publisher-events.ndjson"));
    }
    Err("file publisher에는 path 또는 directory가 필요합니다".to_string())
}

fn config_bool(config: &serde_json::Value, key: &str) -> bool {
    config
        .get(key)
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
}

fn normalize_event_type(value: &str) -> AppResult<String> {
    let value = value.trim().to_ascii_lowercase();
    match value.as_str() {
        "issue" | "revoke" => Ok(value),
        _ => Err(AppError::BadRequest(format!(
            "지원하지 않는 publisher event type입니다: {value}"
        ))),
    }
}

fn truncate_detail(value: &str, max_len: usize) -> String {
    if value.len() <= max_len {
        value.to_string()
    } else {
        format!("{}...", &value[..max_len])
    }
}
