use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    AppState,
    error::{AppError, AppResult},
    storage::{EjbcaFeatureFilter, EjbcaFeatureRecord},
    util::now_unix,
};

const FEATURE_TYPES: &[&str] = &[
    "product_scope",
    "ca_lifecycle",
    "crypto_token",
    "key_binding",
    "enrollment_protocol",
    "cmp_auth_module",
    "cmp_flow",
    "end_entity_lifecycle",
    "access_rule",
    "approval",
    "publisher",
    "db_protection",
    "cluster_node",
    "adminweb_extension",
];

#[derive(Debug, Clone, Deserialize)]
pub struct CreateEjbcaFeatureRequest {
    pub feature_type: String,
    pub name: String,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub config: serde_json::Value,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UpdateEjbcaFeatureRequest {
    #[serde(default)]
    pub feature_type: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub config: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize)]
pub struct EjbcaFeatureResponse {
    pub id: String,
    pub feature_type: String,
    pub name: String,
    pub status: String,
    pub config: serde_json::Value,
    pub created_at: i64,
    pub updated_at: i64,
}

pub async fn ensure_default_features(state: &AppState) -> AppResult<()> {
    if state.db.ejbca_feature_count().await? > 0 {
        return Ok(());
    }
    for (feature_type, name, status, config) in default_features() {
        create_feature(
            state,
            CreateEjbcaFeatureRequest {
                feature_type: feature_type.to_string(),
                name: name.to_string(),
                status: Some(status.to_string()),
                config,
            },
            "system",
        )
        .await?;
    }
    Ok(())
}

pub async fn list_features(
    state: &AppState,
    feature_type: Option<String>,
    status: Option<String>,
    limit: i64,
) -> AppResult<Vec<EjbcaFeatureResponse>> {
    let filter = EjbcaFeatureFilter {
        feature_type: normalize_optional_feature_type(feature_type)?,
        status: normalize_optional_status(status)?,
    };
    Ok(state
        .db
        .list_ejbca_features(&filter, limit)
        .await?
        .into_iter()
        .map(Into::into)
        .collect())
}

pub async fn create_feature(
    state: &AppState,
    request: CreateEjbcaFeatureRequest,
    actor: &str,
) -> AppResult<EjbcaFeatureResponse> {
    let now = now_unix();
    let record = EjbcaFeatureRecord {
        id: Uuid::new_v4().to_string(),
        feature_type: normalize_feature_type(&request.feature_type)?,
        name: normalize_name(&request.name)?,
        status: normalize_status(request.status.as_deref().unwrap_or("active"))?,
        config_json: serialize_config(request.config)?,
        created_at: now,
        updated_at: now,
    };
    state.db.insert_ejbca_feature(&record).await?;
    state
        .db
        .audit(actor, "ejbca_feature.create", &record.id, "success", "{}")
        .await?;
    Ok(record.into())
}

pub async fn update_feature(
    state: &AppState,
    id: &str,
    request: UpdateEjbcaFeatureRequest,
    actor: &str,
) -> AppResult<EjbcaFeatureResponse> {
    let mut record =
        state.db.get_ejbca_feature(id).await?.ok_or_else(|| {
            AppError::NotFound(format!("EJBCA 기능 객체를 찾을 수 없습니다: {id}"))
        })?;
    if let Some(feature_type) = request.feature_type {
        record.feature_type = normalize_feature_type(&feature_type)?;
    }
    if let Some(name) = request.name {
        record.name = normalize_name(&name)?;
    }
    if let Some(status) = request.status {
        record.status = normalize_status(&status)?;
    }
    if let Some(config) = request.config {
        record.config_json = serialize_config(config)?;
    }
    record.updated_at = now_unix();
    let changed = state.db.update_ejbca_feature(&record).await?;
    if changed == 0 {
        return Err(AppError::NotFound(format!(
            "EJBCA 기능 객체를 찾을 수 없습니다: {id}"
        )));
    }
    state
        .db
        .audit(actor, "ejbca_feature.update", id, "success", "{}")
        .await?;
    Ok(record.into())
}

pub async fn delete_feature(state: &AppState, id: &str, actor: &str) -> AppResult<()> {
    let changed = state.db.delete_ejbca_feature(id).await?;
    if changed == 0 {
        return Err(AppError::NotFound(format!(
            "EJBCA 기능 객체를 찾을 수 없습니다: {id}"
        )));
    }
    state
        .db
        .audit(actor, "ejbca_feature.delete", id, "success", "{}")
        .await
}

fn default_features() -> Vec<(&'static str, &'static str, &'static str, serde_json::Value)> {
    vec![
        (
            "product_scope",
            "enterprise-pki-surface",
            "active",
            serde_json::json!({
                "mode": "lightweight",
                "capabilities": ["ca_lifecycle", "crypto_token", "enrollment_protocol", "approval", "publisher", "cluster_node"],
            }),
        ),
        (
            "ca_lifecycle",
            "renewal-rollover-expiration-publishing",
            "active",
            serde_json::json!({
                "supports": ["renewal", "rollover", "expiration_monitor", "publisher_hooks"],
                "default_renewal_window_days": 90,
            }),
        ),
        (
            "crypto_token",
            "software-file-command-pkcs11-token",
            "active",
            serde_json::json!({
                "providers": ["database", "file", "encrypted", "command", "pkcs11-command-bridge"],
                "key_binding_required": false,
            }),
        ),
        (
            "key_binding",
            "default-ca-key-binding",
            "active",
            serde_json::json!({
                "binding_type": "ca_signing",
                "crypto_token": "software-file-command-pkcs11-token",
            }),
        ),
        (
            "enrollment_protocol",
            "est",
            "configured",
            serde_json::json!({"endpoint": "/.well-known/est", "mode": "lightweight-csr-proxy"}),
        ),
        (
            "enrollment_protocol",
            "scep",
            "configured",
            serde_json::json!({"endpoint": "/scep", "mode": "lightweight-csr-proxy"}),
        ),
        (
            "enrollment_protocol",
            "acme",
            "configured",
            serde_json::json!({"endpoint": "/acme", "mode": "lightweight-order-registry"}),
        ),
        (
            "cmp_auth_module",
            "end-entity-certificate",
            "configured",
            serde_json::json!({"module": "EndEntityCertificate", "trusted_issuer_mode": "role_or_vendor_ca"}),
        ),
        (
            "cmp_auth_module",
            "vendor-certificate-mode",
            "configured",
            serde_json::json!({
                "module": "VendorCertificate",
                "vendor_ca_source": "tls_proxy_trust_store",
                "example_rule": {
                    "aliases": ["vendor-a-ra"],
                    "client_cert_header": "x-cmp-client-cert-pem",
                    "proxy_secret_header": "x-cmp-proxy-secret",
                    "allowed_issuer_dns": ["CN=Vendor A Root CA,O=VendorA,C=KR"]
                }
            }),
        ),
        (
            "cmp_flow",
            "client-mode-certconf-kur",
            "configured",
            serde_json::json!({
                "flows": ["client_mode", "certConf", "implicitConfirm", "kur"],
                "mode": "lightweight-state-machine"
            }),
        ),
        (
            "end_entity_lifecycle",
            "ejbca-status-password-workflow",
            "configured",
            serde_json::json!({
                "statuses": ["NEW", "FAILED", "INITIALIZED", "INPROCESS", "GENERATED", "REVOKED", "HISTORICAL"],
                "password_policy": "hashed_secret",
                "approval_required": false
            }),
        ),
        (
            "access_rule",
            "ca-profile-protocol-rule-tree",
            "configured",
            serde_json::json!({
                "scopes": ["ca", "certificate_profile", "end_entity_profile", "protocol", "role"],
                "fallback": "role_permissions"
            }),
        ),
        (
            "approval",
            "multi-step-approval",
            "configured",
            serde_json::json!({
                "steps": 1,
                "actions": ["issue", "revoke", "ca_update", "profile_update"],
                "expiry_seconds": 86400
            }),
        ),
        (
            "publisher",
            "ldap-ad-va-webhook-file",
            "configured",
            serde_json::json!({
                "types": ["ldap", "active_directory", "va", "webhook", "file"],
                "dispatch": "post_issue_and_revoke"
            }),
        ),
        (
            "db_protection",
            "signed-table-protection",
            "active",
            serde_json::json!({
                "protected_tables": ["audit_events", "certificates", "end_entities", "approvals"],
                "algorithm": "sha256-chain"
            }),
        ),
        (
            "cluster_node",
            "single-node-ha-registry",
            "active",
            serde_json::json!({
                "node_id": "local",
                "role": "ca-ra",
                "heartbeat_seconds": 30
            }),
        ),
        (
            "adminweb_extension",
            "ejbca-parity-console",
            "active",
            serde_json::json!({
                "sections": ["ca_lifecycle", "crypto_tokens", "enrollment", "approvals", "publishers", "cluster"],
                "frontend": "feature_catalog"
            }),
        ),
    ]
}

fn normalize_optional_feature_type(value: Option<String>) -> AppResult<Option<String>> {
    value
        .map(|value| normalize_feature_type(&value))
        .transpose()
}

fn normalize_optional_status(value: Option<String>) -> AppResult<Option<String>> {
    value.map(|value| normalize_status(&value)).transpose()
}

fn normalize_feature_type(value: &str) -> AppResult<String> {
    let normalized = value.trim().to_ascii_lowercase().replace('-', "_");
    if FEATURE_TYPES.contains(&normalized.as_str()) {
        Ok(normalized)
    } else {
        Err(AppError::BadRequest(format!(
            "지원하지 않는 EJBCA 기능 타입입니다: {value}. 지원 타입: {}",
            FEATURE_TYPES.join(", ")
        )))
    }
}

fn normalize_name(value: &str) -> AppResult<String> {
    let name = value.trim();
    if name.is_empty() {
        return Err(AppError::BadRequest(
            "EJBCA 기능 이름은 비워둘 수 없습니다".to_string(),
        ));
    }
    Ok(name.to_string())
}

fn normalize_status(value: &str) -> AppResult<String> {
    let status = value.trim().to_ascii_lowercase();
    match status.as_str() {
        "active" | "configured" | "disabled" | "pending" | "approved" | "rejected" | "failed" => {
            Ok(status)
        }
        _ => Err(AppError::BadRequest(format!(
            "지원하지 않는 EJBCA 기능 상태입니다: {value}"
        ))),
    }
}

fn serialize_config(value: serde_json::Value) -> AppResult<String> {
    serde_json::to_string(&value).map_err(|err| AppError::BadRequest(err.to_string()))
}

impl From<EjbcaFeatureRecord> for EjbcaFeatureResponse {
    fn from(value: EjbcaFeatureRecord) -> Self {
        Self {
            id: value.id,
            feature_type: value.feature_type,
            name: value.name,
            status: value.status,
            config: serde_json::from_str(&value.config_json).unwrap_or(serde_json::Value::Null),
            created_at: value.created_at,
            updated_at: value.updated_at,
        }
    }
}
