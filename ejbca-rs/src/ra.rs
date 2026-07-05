use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::{RngCore, rngs::OsRng};
use ring::pbkdf2;
use serde::{Deserialize, Serialize};
use std::num::NonZeroU32;
use subtle::ConstantTimeEq;
use uuid::Uuid;

use crate::{
    AppState,
    certs::{IssueCertificateRequest, IssueCsrRequest},
    error::{AppError, AppResult},
    storage::{
        ApprovalRequestFilter, ApprovalRequestRecord, EjbcaFeatureFilter, EndEntityFilter,
        EndEntityRecord,
    },
    util::now_unix,
};

const END_ENTITY_PASSWORD_HASH_PREFIX: &str = "pbkdf2-sha256";
const END_ENTITY_PASSWORD_HASH_ITERATIONS: u32 = 210_000;
const END_ENTITY_PASSWORD_HASH_SALT_BYTES: usize = 16;
const END_ENTITY_PASSWORD_HASH_BYTES: usize = 32;

#[derive(Debug, Clone, Deserialize)]
pub struct CreateEndEntityRequest {
    pub username: String,
    pub subject_dn: String,
    #[serde(default)]
    pub dns_names: Vec<String>,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub ca_id: Option<String>,
    #[serde(default)]
    pub certificate_profile_id: Option<String>,
    #[serde(default)]
    pub end_entity_profile_id: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub token_type: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UpdateEndEntityRequest {
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub subject_dn: Option<String>,
    #[serde(default)]
    pub dns_names: Option<Vec<String>>,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub ca_id: Option<String>,
    #[serde(default)]
    pub certificate_profile_id: Option<String>,
    #[serde(default)]
    pub end_entity_profile_id: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub token_type: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CreateApprovalRequest {
    pub action: String,
    pub target_id: String,
    #[serde(default)]
    pub request: serde_json::Value,
    #[serde(default)]
    pub expires_at: Option<i64>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DecideApprovalRequest {
    pub status: String,
    #[serde(default)]
    pub decision: serde_json::Value,
}

#[derive(Debug, Clone, Serialize)]
pub struct EndEntityResponse {
    pub id: String,
    pub username: String,
    pub subject_dn: String,
    pub dns_names: Vec<String>,
    pub email: Option<String>,
    pub ca_id: Option<String>,
    pub certificate_profile_id: Option<String>,
    pub end_entity_profile_id: Option<String>,
    pub status: String,
    pub password_configured: bool,
    pub token_type: String,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ApprovalRequestResponse {
    pub id: String,
    pub action: String,
    pub target_id: String,
    pub status: String,
    pub requester: String,
    pub approver: Option<String>,
    pub request: serde_json::Value,
    pub decision: Option<serde_json::Value>,
    pub created_at: i64,
    pub updated_at: i64,
    pub expires_at: Option<i64>,
}

pub async fn list_end_entities(
    state: &AppState,
    username: Option<String>,
    status: Option<String>,
    ca_id: Option<String>,
    limit: i64,
) -> AppResult<Vec<EndEntityResponse>> {
    let filter = EndEntityFilter {
        username_contains: clean_filter(username),
        status: normalize_optional_end_entity_status(status)?,
        ca_id: clean_filter(ca_id),
    };
    Ok(state
        .db
        .list_end_entities(&filter, limit)
        .await?
        .into_iter()
        .map(Into::into)
        .collect())
}

pub async fn create_end_entity(
    state: &AppState,
    request: CreateEndEntityRequest,
    actor: &str,
) -> AppResult<EndEntityResponse> {
    let now = now_unix();
    let record = EndEntityRecord {
        id: Uuid::new_v4().to_string(),
        username: normalize_name(&request.username, "end entity username")?,
        subject_dn: normalize_required(&request.subject_dn, "subject DN")?,
        san_json: serialize_dns_names(request.dns_names)?,
        email: clean_filter(request.email),
        ca_id: clean_filter(request.ca_id),
        certificate_profile_id: clean_filter(request.certificate_profile_id),
        end_entity_profile_id: clean_filter(request.end_entity_profile_id),
        status: normalize_end_entity_status(request.status.as_deref().unwrap_or("NEW"))?,
        password_hash: hash_optional_password(request.password)?,
        token_type: normalize_token_type(request.token_type.as_deref().unwrap_or("USERGENERATED"))?,
        created_at: now,
        updated_at: now,
    };
    state.db.insert_end_entity(&record).await?;
    state
        .db
        .audit(actor, "end_entity.create", &record.id, "success", "{}")
        .await?;
    Ok(record.into())
}

pub async fn update_end_entity(
    state: &AppState,
    id: &str,
    request: UpdateEndEntityRequest,
    actor: &str,
) -> AppResult<EndEntityResponse> {
    let mut record = state
        .db
        .get_end_entity(id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("end entity를 찾을 수 없습니다: {id}")))?;
    if let Some(username) = request.username {
        record.username = normalize_name(&username, "end entity username")?;
    }
    if let Some(subject_dn) = request.subject_dn {
        record.subject_dn = normalize_required(&subject_dn, "subject DN")?;
    }
    if let Some(dns_names) = request.dns_names {
        record.san_json = serialize_dns_names(dns_names)?;
    }
    if request.email.is_some() {
        record.email = clean_filter(request.email);
    }
    if request.ca_id.is_some() {
        record.ca_id = clean_filter(request.ca_id);
    }
    if request.certificate_profile_id.is_some() {
        record.certificate_profile_id = clean_filter(request.certificate_profile_id);
    }
    if request.end_entity_profile_id.is_some() {
        record.end_entity_profile_id = clean_filter(request.end_entity_profile_id);
    }
    if let Some(status) = request.status {
        record.status = normalize_end_entity_status(&status)?;
    }
    if request.password.is_some() {
        record.password_hash = hash_optional_password(request.password)?;
    }
    if let Some(token_type) = request.token_type {
        record.token_type = normalize_token_type(&token_type)?;
    }
    record.updated_at = now_unix();
    let changed = state.db.update_end_entity(&record).await?;
    if changed == 0 {
        return Err(AppError::NotFound(format!(
            "end entity를 찾을 수 없습니다: {id}"
        )));
    }
    state
        .db
        .audit(actor, "end_entity.update", id, "success", "{}")
        .await?;
    Ok(record.into())
}

pub async fn delete_end_entity(state: &AppState, id: &str, actor: &str) -> AppResult<()> {
    let changed = state.db.delete_end_entity(id).await?;
    if changed == 0 {
        return Err(AppError::NotFound(format!(
            "end entity를 찾을 수 없습니다: {id}"
        )));
    }
    state
        .db
        .audit(actor, "end_entity.delete", id, "success", "{}")
        .await
}

pub async fn list_approval_requests(
    state: &AppState,
    action: Option<String>,
    target_id: Option<String>,
    status: Option<String>,
    limit: i64,
) -> AppResult<Vec<ApprovalRequestResponse>> {
    let filter = ApprovalRequestFilter {
        action: normalize_optional_action(action)?,
        target_id: clean_filter(target_id),
        status: normalize_optional_approval_status(status)?,
    };
    Ok(state
        .db
        .list_approval_requests(&filter, limit)
        .await?
        .into_iter()
        .map(Into::into)
        .collect())
}

pub async fn create_approval_request(
    state: &AppState,
    request: CreateApprovalRequest,
    actor: &str,
) -> AppResult<ApprovalRequestResponse> {
    let now = now_unix();
    let record = ApprovalRequestRecord {
        id: Uuid::new_v4().to_string(),
        action: normalize_action(&request.action)?,
        target_id: normalize_required(&request.target_id, "approval target")?,
        status: "pending".to_string(),
        requester: actor.to_string(),
        approver: None,
        request_json: serialize_json(request.request)?,
        decision_json: None,
        created_at: now,
        updated_at: now,
        expires_at: request.expires_at,
    };
    state.db.insert_approval_request(&record).await?;
    state
        .db
        .audit(actor, "approval.create", &record.id, "success", "{}")
        .await?;
    Ok(record.into())
}

pub async fn decide_approval_request(
    state: &AppState,
    id: &str,
    request: DecideApprovalRequest,
    actor: &str,
) -> AppResult<ApprovalRequestResponse> {
    let mut record =
        state.db.get_approval_request(id).await?.ok_or_else(|| {
            AppError::NotFound(format!("approval request를 찾을 수 없습니다: {id}"))
        })?;
    record.status = normalize_decision_status(&request.status)?;
    record.approver = Some(actor.to_string());
    record.decision_json = Some(serialize_json(request.decision)?);
    record.updated_at = now_unix();
    let changed = state.db.update_approval_request(&record).await?;
    if changed == 0 {
        return Err(AppError::NotFound(format!(
            "approval request를 찾을 수 없습니다: {id}"
        )));
    }
    state
        .db
        .audit(actor, "approval.decide", id, "success", "{}")
        .await?;
    Ok(record.into())
}

pub async fn hydrate_issue_certificate_request(
    state: &AppState,
    mut request: IssueCertificateRequest,
) -> AppResult<IssueCertificateRequest> {
    if let Some(end_entity_id) = request.end_entity_id.as_deref() {
        let entity = active_end_entity(state, end_entity_id).await?;
        request.ca_id = request.ca_id.or(entity.ca_id);
        request.certificate_profile_id = request
            .certificate_profile_id
            .or(entity.certificate_profile_id);
        request.end_entity_profile_id = request
            .end_entity_profile_id
            .or(entity.end_entity_profile_id);
        request.subject_dn = entity.subject_dn;
        request.dns_names = dns_names_from_json(&entity.san_json);
    }
    Ok(request)
}

pub async fn hydrate_issue_csr_request(
    state: &AppState,
    mut request: IssueCsrRequest,
) -> AppResult<IssueCsrRequest> {
    if let Some(end_entity_id) = request.end_entity_id.as_deref() {
        let entity = active_end_entity(state, end_entity_id).await?;
        request.ca_id = request.ca_id.or(entity.ca_id);
        request.certificate_profile_id = request
            .certificate_profile_id
            .or(entity.certificate_profile_id);
        request.end_entity_profile_id = request
            .end_entity_profile_id
            .or(entity.end_entity_profile_id);
    }
    Ok(request)
}

pub async fn ensure_end_entity_matches_request(
    state: &AppState,
    end_entity_id: Option<&str>,
    subject_dn: &str,
    dns_names: &[String],
) -> AppResult<()> {
    let Some(end_entity_id) = end_entity_id else {
        return Ok(());
    };
    let entity = active_end_entity(state, end_entity_id).await?;
    if entity.subject_dn != subject_dn {
        return Err(AppError::Forbidden(format!(
            "CSR subject DN이 end entity와 일치하지 않습니다: {end_entity_id}"
        )));
    }
    let expected_dns = dns_names_from_json(&entity.san_json);
    if expected_dns != dns_names {
        return Err(AppError::Forbidden(format!(
            "CSR DNS SAN이 end entity와 일치하지 않습니다: {end_entity_id}"
        )));
    }
    Ok(())
}

pub async fn mark_end_entity_generated(
    state: &AppState,
    end_entity_id: Option<&str>,
) -> AppResult<()> {
    if let Some(end_entity_id) = end_entity_id {
        state
            .db
            .update_end_entity_status(end_entity_id, "GENERATED", now_unix())
            .await?;
    }
    Ok(())
}

pub async fn ensure_approval_permits(
    state: &AppState,
    action: &str,
    target_id: &str,
    approval_id: Option<&str>,
) -> AppResult<()> {
    let action = normalize_action(action)?;
    if let Some(approval_id) = approval_id {
        let approval = state
            .db
            .get_approval_request(approval_id)
            .await?
            .ok_or_else(|| {
                AppError::Forbidden(format!("approval을 찾을 수 없습니다: {approval_id}"))
            })?;
        if approval.action != action {
            return Err(AppError::Forbidden(format!(
                "approval action이 요청과 일치하지 않습니다: expected={action}, actual={}",
                approval.action
            )));
        }
        if approval.target_id != target_id {
            return Err(AppError::Forbidden(format!(
                "approval target이 요청과 일치하지 않습니다: expected={target_id}, actual={}",
                approval.target_id
            )));
        }
        if approval.status != "approved" {
            return Err(AppError::Forbidden(format!(
                "approval 상태가 approved가 아닙니다: {}",
                approval.status
            )));
        }
        if let Some(expires_at) = approval.expires_at
            && expires_at < now_unix()
        {
            return Err(AppError::Forbidden("approval이 만료되었습니다".to_string()));
        }
        return Ok(());
    }
    if approval_required_for_action(state, &action).await? {
        return Err(AppError::Forbidden(format!(
            "{action} 작업에는 승인된 approval_id가 필요합니다"
        )));
    }
    Ok(())
}

async fn active_end_entity(state: &AppState, id: &str) -> AppResult<EndEntityRecord> {
    let entity = state
        .db
        .get_end_entity(id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("end entity를 찾을 수 없습니다: {id}")))?;
    if matches!(entity.status.as_str(), "REVOKED" | "HISTORICAL" | "FAILED") {
        return Err(AppError::Forbidden(format!(
            "end entity 상태가 발급 가능 상태가 아닙니다: {}",
            entity.status
        )));
    }
    Ok(entity)
}

async fn approval_required_for_action(state: &AppState, action: &str) -> AppResult<bool> {
    for feature_type in ["approval", "end_entity_lifecycle"] {
        let features = state
            .db
            .list_ejbca_features(
                &EjbcaFeatureFilter {
                    feature_type: Some(feature_type.to_string()),
                    status: None,
                },
                100,
            )
            .await?;
        for feature in features {
            if !matches!(feature.status.as_str(), "active" | "configured") {
                continue;
            }
            let config: serde_json::Value =
                serde_json::from_str(&feature.config_json).unwrap_or(serde_json::Value::Null);
            let explicitly_required = config
                .get("approval_required")
                .or_else(|| config.get("require_approval"))
                .or_else(|| config.get("required"))
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false);
            if !explicitly_required {
                continue;
            }
            let action_matches = config
                .get("actions")
                .and_then(serde_json::Value::as_array)
                .map(|actions| actions.iter().any(|value| value.as_str() == Some(action)))
                .unwrap_or(true);
            if action_matches {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn hash_optional_password(password: Option<String>) -> AppResult<Option<String>> {
    let Some(password) = password else {
        return Ok(None);
    };
    let password = password.trim();
    if password.is_empty() {
        return Ok(None);
    }
    let iterations = NonZeroU32::new(END_ENTITY_PASSWORD_HASH_ITERATIONS)
        .expect("PBKDF2 iterations must be non-zero");
    let mut salt = [0u8; END_ENTITY_PASSWORD_HASH_SALT_BYTES];
    OsRng.fill_bytes(&mut salt);
    let mut hash = [0u8; END_ENTITY_PASSWORD_HASH_BYTES];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        iterations,
        &salt,
        password.as_bytes(),
        &mut hash,
    );
    Ok(Some(format!(
        "{}${}${}${}",
        END_ENTITY_PASSWORD_HASH_PREFIX,
        END_ENTITY_PASSWORD_HASH_ITERATIONS,
        URL_SAFE_NO_PAD.encode(salt),
        URL_SAFE_NO_PAD.encode(hash)
    )))
}

#[allow(dead_code)]
fn verify_password(password: &str, stored: &str) -> bool {
    let parts = stored.split('$').collect::<Vec<_>>();
    if parts.len() != 4 || parts[0] != END_ENTITY_PASSWORD_HASH_PREFIX {
        return false;
    }
    let Ok(iterations) = parts[1].parse::<u32>() else {
        return false;
    };
    let Some(iterations) = NonZeroU32::new(iterations) else {
        return false;
    };
    let Ok(salt) = URL_SAFE_NO_PAD.decode(parts[2]) else {
        return false;
    };
    let Ok(expected) = URL_SAFE_NO_PAD.decode(parts[3]) else {
        return false;
    };
    let mut actual = vec![0u8; expected.len()];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        iterations,
        &salt,
        password.as_bytes(),
        &mut actual,
    );
    actual.ct_eq(&expected).into()
}

fn normalize_optional_end_entity_status(value: Option<String>) -> AppResult<Option<String>> {
    value
        .map(|value| normalize_end_entity_status(&value))
        .transpose()
}

fn normalize_end_entity_status(value: &str) -> AppResult<String> {
    let normalized = value.trim().to_ascii_uppercase();
    match normalized.as_str() {
        "NEW" | "FAILED" | "INITIALIZED" | "INPROCESS" | "GENERATED" | "REVOKED" | "HISTORICAL" => {
            Ok(normalized)
        }
        _ => Err(AppError::BadRequest(format!(
            "지원하지 않는 end entity 상태입니다: {value}"
        ))),
    }
}

fn normalize_optional_approval_status(value: Option<String>) -> AppResult<Option<String>> {
    value
        .map(|value| normalize_approval_status(&value))
        .transpose()
}

fn normalize_approval_status(value: &str) -> AppResult<String> {
    let normalized = value.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "pending" | "approved" | "rejected" | "expired" | "cancelled" => Ok(normalized),
        _ => Err(AppError::BadRequest(format!(
            "지원하지 않는 approval 상태입니다: {value}"
        ))),
    }
}

fn normalize_decision_status(value: &str) -> AppResult<String> {
    let normalized = normalize_approval_status(value)?;
    match normalized.as_str() {
        "approved" | "rejected" | "cancelled" => Ok(normalized),
        _ => Err(AppError::BadRequest(
            "approval 결정 상태는 approved, rejected, cancelled 중 하나여야 합니다".to_string(),
        )),
    }
}

fn normalize_optional_action(value: Option<String>) -> AppResult<Option<String>> {
    value.map(|value| normalize_action(&value)).transpose()
}

fn normalize_action(value: &str) -> AppResult<String> {
    let normalized = value.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return Err(AppError::BadRequest(
            "approval action은 비워둘 수 없습니다".to_string(),
        ));
    }
    Ok(normalized)
}

fn normalize_token_type(value: &str) -> AppResult<String> {
    let normalized = value.trim().to_ascii_uppercase();
    if normalized.is_empty() {
        return Err(AppError::BadRequest(
            "token type은 비워둘 수 없습니다".to_string(),
        ));
    }
    Ok(normalized)
}

fn normalize_name(value: &str, label: &str) -> AppResult<String> {
    normalize_required(value, label)
}

fn normalize_required(value: &str, label: &str) -> AppResult<String> {
    let value = value.trim();
    if value.is_empty() {
        return Err(AppError::BadRequest(format!(
            "{label}은 비워둘 수 없습니다"
        )));
    }
    Ok(value.to_string())
}

fn clean_filter(value: Option<String>) -> Option<String> {
    value
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn serialize_dns_names(dns_names: Vec<String>) -> AppResult<String> {
    serde_json::to_string(
        &dns_names
            .into_iter()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .collect::<Vec<_>>(),
    )
    .map_err(|err| AppError::BadRequest(err.to_string()))
}

fn dns_names_from_json(value: &str) -> Vec<String> {
    serde_json::from_str(value).unwrap_or_default()
}

fn serialize_json(value: serde_json::Value) -> AppResult<String> {
    serde_json::to_string(&value).map_err(|err| AppError::BadRequest(err.to_string()))
}

impl From<EndEntityRecord> for EndEntityResponse {
    fn from(value: EndEntityRecord) -> Self {
        Self {
            id: value.id,
            username: value.username,
            subject_dn: value.subject_dn,
            dns_names: dns_names_from_json(&value.san_json),
            email: value.email,
            ca_id: value.ca_id,
            certificate_profile_id: value.certificate_profile_id,
            end_entity_profile_id: value.end_entity_profile_id,
            status: value.status,
            password_configured: value.password_hash.is_some(),
            token_type: value.token_type,
            created_at: value.created_at,
            updated_at: value.updated_at,
        }
    }
}

impl From<ApprovalRequestRecord> for ApprovalRequestResponse {
    fn from(value: ApprovalRequestRecord) -> Self {
        Self {
            id: value.id,
            action: value.action,
            target_id: value.target_id,
            status: value.status,
            requester: value.requester,
            approver: value.approver,
            request: serde_json::from_str(&value.request_json).unwrap_or(serde_json::Value::Null),
            decision: value
                .decision_json
                .as_deref()
                .and_then(|json| serde_json::from_str(json).ok()),
            created_at: value.created_at,
            updated_at: value.updated_at,
            expires_at: value.expires_at,
        }
    }
}
