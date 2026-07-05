use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    AppState,
    error::{AppError, AppResult},
    storage::ClusterNodeRecord,
    util::now_unix,
};

#[derive(Debug, Deserialize)]
pub struct ClusterHeartbeatRequest {
    pub node_id: String,
    pub role: Option<String>,
    pub status: Option<String>,
    #[serde(default)]
    pub metadata: serde_json::Value,
}

#[derive(Debug, Serialize)]
pub struct ClusterNodeResponse {
    pub id: String,
    pub node_id: String,
    pub role: String,
    pub status: String,
    pub heartbeat_at: i64,
    pub metadata: serde_json::Value,
    pub created_at: i64,
    pub updated_at: i64,
}

pub async fn heartbeat(
    state: &AppState,
    request: ClusterHeartbeatRequest,
    actor: &str,
) -> AppResult<ClusterNodeResponse> {
    let node_id = normalize_required("node_id", &request.node_id)?;
    let role = request
        .role
        .as_deref()
        .map(|value| normalize_required("role", value))
        .transpose()?
        .unwrap_or_else(|| "ra-ca".to_string());
    let status = request
        .status
        .as_deref()
        .map(normalize_status)
        .transpose()?
        .unwrap_or_else(|| "up".to_string());
    if !request.metadata.is_null() && !request.metadata.is_object() {
        return Err(AppError::BadRequest(
            "cluster metadata는 JSON object여야 합니다".to_string(),
        ));
    }
    let now = now_unix();
    let record = ClusterNodeRecord {
        id: Uuid::new_v4().to_string(),
        node_id,
        role,
        status,
        heartbeat_at: now,
        metadata_json: if request.metadata.is_null() {
            "{}".to_string()
        } else {
            serde_json::to_string(&request.metadata)
                .map_err(|err| AppError::Internal(err.to_string()))?
        },
        created_at: now,
        updated_at: now,
    };
    state.db.upsert_cluster_node(&record).await?;
    let stored = state
        .db
        .get_cluster_node_by_node_id(&record.node_id)
        .await?
        .unwrap_or_else(|| record.clone());
    state
        .db
        .audit(
            actor,
            "cluster.heartbeat",
            &record.node_id,
            "success",
            &serde_json::json!({
                "role": record.role,
                "status": record.status,
                "heartbeat_at": record.heartbeat_at
            })
            .to_string(),
        )
        .await?;
    Ok(stored.into())
}

pub async fn list_nodes(state: &AppState, limit: i64) -> AppResult<Vec<ClusterNodeResponse>> {
    Ok(state
        .db
        .list_cluster_nodes(limit)
        .await?
        .into_iter()
        .map(Into::into)
        .collect())
}

fn normalize_required(field: &str, value: &str) -> AppResult<String> {
    let value = value.trim();
    if value.is_empty() {
        return Err(AppError::BadRequest(format!(
            "{field}는 비어 있을 수 없습니다"
        )));
    }
    if value.len() > 128 {
        return Err(AppError::BadRequest(format!("{field}가 너무 깁니다")));
    }
    Ok(value.to_string())
}

fn normalize_status(value: &str) -> AppResult<String> {
    match value.trim().to_ascii_lowercase().as_str() {
        "up" | "active" | "online" => Ok("up".to_string()),
        "draining" | "maintenance" => Ok("draining".to_string()),
        "down" | "offline" | "disabled" => Ok("down".to_string()),
        other => Err(AppError::BadRequest(format!(
            "cluster node status는 up, draining, down 중 하나여야 합니다: {other}"
        ))),
    }
}

impl From<ClusterNodeRecord> for ClusterNodeResponse {
    fn from(value: ClusterNodeRecord) -> Self {
        Self {
            id: value.id,
            node_id: value.node_id,
            role: value.role,
            status: value.status,
            heartbeat_at: value.heartbeat_at,
            metadata: serde_json::from_str(&value.metadata_json).unwrap_or_default(),
            created_at: value.created_at,
            updated_at: value.updated_at,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{path::PathBuf, sync::Arc};

    use tokio::sync::Semaphore;
    use uuid::Uuid;

    use super::*;
    use crate::{config::Settings, storage::Db};

    async fn test_state() -> (AppState, PathBuf) {
        let data_dir =
            std::env::temp_dir().join(format!("ejbca-rs-cluster-test-{}", Uuid::new_v4()));
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

    #[tokio::test]
    async fn upserts_cluster_heartbeat_by_node_id() {
        let (state, data_dir) = test_state().await;
        heartbeat(
            &state,
            ClusterHeartbeatRequest {
                node_id: "node-a".to_string(),
                role: Some("ra".to_string()),
                status: Some("up".to_string()),
                metadata: serde_json::json!({"zone":"az-a"}),
            },
            "test",
        )
        .await
        .unwrap();
        heartbeat(
            &state,
            ClusterHeartbeatRequest {
                node_id: "node-a".to_string(),
                role: Some("va".to_string()),
                status: Some("maintenance".to_string()),
                metadata: serde_json::json!({"zone":"az-b"}),
            },
            "test",
        )
        .await
        .unwrap();

        let nodes = list_nodes(&state, 10).await.unwrap();
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].node_id, "node-a");
        assert_eq!(nodes[0].role, "va");
        assert_eq!(nodes[0].status, "draining");
        assert_eq!(nodes[0].metadata["zone"], "az-b");

        std::fs::remove_dir_all(data_dir).ok();
    }
}
