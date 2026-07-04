use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::{RngCore, rngs::OsRng};
use regex::Regex;
use ring::pbkdf2;
use sha2::{Digest, Sha256};
use std::num::NonZeroU32;
use subtle::ConstantTimeEq;
use uuid::Uuid;

use crate::{
    AppState,
    error::{AppError, AppResult},
    profiles::{
        AccessRoleResponse, CertificateProfileResponse, CmpAliasResponse, CreateAccessRoleRequest,
        CreateCertificateProfileRequest, CreateCmpAliasRequest, CreateEndEntityProfileRequest,
        EndEntityProfileResponse, UpdateAccessRoleRequest, UpdateCertificateProfileRequest,
        UpdateCmpAliasRequest, UpdateEndEntityProfileRequest,
    },
    storage::{AccessRoleRecord, CertificateProfileRecord, CmpAliasRecord, EndEntityProfileRecord},
    util::now_unix,
};

const PERSISTED_SECRET_HASH_PREFIX: &str = "pbkdf2-sha256";
const PERSISTED_SECRET_HASH_ITERATIONS: u32 = 210_000;
const PERSISTED_SECRET_HASH_SALT_BYTES: usize = 16;
const PERSISTED_SECRET_HASH_BYTES: usize = 32;

pub async fn ensure_default_profiles(state: &AppState) -> AppResult<()> {
    if state.db.certificate_profile_count().await? == 0 {
        let profile = create_certificate_profile(
            state,
            CreateCertificateProfileRequest {
                name: "tls-server-client-default".to_string(),
                validity_days: Some(397),
                key_usages: default_key_usages(),
                extended_key_usages: default_extended_key_usages(),
                allow_server_generated_key: Some(true),
                require_san: Some(false),
            },
            "system",
        )
        .await?;
        state
            .db
            .audit(
                "system",
                "certificate_profile.default",
                &profile.id,
                "success",
                "{}",
            )
            .await?;
    }

    if state.db.end_entity_profile_count().await? == 0 {
        let default_profile_id = state
            .db
            .list_certificate_profiles()
            .await?
            .into_iter()
            .next()
            .map(|profile| profile.id);
        let profile = create_end_entity_profile(
            state,
            CreateEndEntityProfileRequest {
                name: "default-end-entity".to_string(),
                subject_regex: Some(r"^CN=[^,]+(,.*)?$".to_string()),
                allowed_dns_domains: Vec::new(),
                default_certificate_profile_id: default_profile_id,
            },
            "system",
        )
        .await?;
        state
            .db
            .audit(
                "system",
                "end_entity_profile.default",
                &profile.id,
                "success",
                "{}",
            )
            .await?;
    }

    if state.db.cmp_alias_count().await? == 0 {
        let ca_id = state
            .db
            .list_cas()
            .await?
            .into_iter()
            .next()
            .map(|ca| ca.id);
        let certificate_profile_id = state
            .db
            .list_certificate_profiles()
            .await?
            .into_iter()
            .next()
            .map(|profile| profile.id);
        let end_entity_profile_id = state
            .db
            .list_end_entity_profiles()
            .await?
            .into_iter()
            .next()
            .map(|profile| profile.id);
        let alias = create_cmp_alias(
            state,
            CreateCmpAliasRequest {
                alias: "default".to_string(),
                ca_id,
                certificate_profile_id,
                end_entity_profile_id,
                enabled: Some(true),
                hmac_secret: None,
            },
            "system",
        )
        .await?;
        state
            .db
            .audit("system", "cmp_alias.default", &alias.id, "success", "{}")
            .await?;
    }
    Ok(())
}

pub async fn create_certificate_profile(
    state: &AppState,
    request: CreateCertificateProfileRequest,
    actor: &str,
) -> AppResult<CertificateProfileResponse> {
    let name = normalized_name(&request.name, "certificate profile 이름")?;
    let key_usages = if request.key_usages.is_empty() {
        default_key_usages()
    } else {
        normalize_list(request.key_usages)
    };
    let extended_key_usages = if request.extended_key_usages.is_empty() {
        default_extended_key_usages()
    } else {
        normalize_list(request.extended_key_usages)
    };
    let now = now_unix();
    let record = CertificateProfileRecord {
        id: Uuid::new_v4().to_string(),
        name,
        validity_days: request.validity_days.unwrap_or(397).clamp(1, 825),
        key_usages_json: serde_json::to_string(&key_usages)
            .map_err(|err| AppError::Internal(err.to_string()))?,
        extended_key_usages_json: serde_json::to_string(&extended_key_usages)
            .map_err(|err| AppError::Internal(err.to_string()))?,
        allow_server_generated_key: request.allow_server_generated_key.unwrap_or(true),
        require_san: request.require_san.unwrap_or(false),
        created_at: now,
        updated_at: now,
    };
    state.db.insert_certificate_profile(&record).await?;
    audit_create(state, actor, "certificate_profile.create", &record.id).await?;
    Ok(record.into())
}

pub async fn list_certificate_profiles(
    state: &AppState,
) -> AppResult<Vec<CertificateProfileResponse>> {
    Ok(state
        .db
        .list_certificate_profiles()
        .await?
        .into_iter()
        .map(Into::into)
        .collect())
}

pub async fn delete_certificate_profile(state: &AppState, id: &str, actor: &str) -> AppResult<()> {
    delete_one(
        state.db.delete_certificate_profile(id).await?,
        "certificate profile",
        id,
    )?;
    audit_delete(state, actor, "certificate_profile.delete", id).await
}

pub async fn update_certificate_profile(
    state: &AppState,
    id: &str,
    request: UpdateCertificateProfileRequest,
    actor: &str,
) -> AppResult<CertificateProfileResponse> {
    let mut record = state.db.get_certificate_profile(id).await?.ok_or_else(|| {
        AppError::NotFound(format!("certificate profile을 찾을 수 없습니다: {id}"))
    })?;
    if let Some(name) = request.name {
        record.name = normalized_name(&name, "certificate profile 이름")?;
    }
    if let Some(validity_days) = request.validity_days {
        record.validity_days = validity_days.clamp(1, 825);
    }
    if let Some(key_usages) = request.key_usages {
        let key_usages = if key_usages.is_empty() {
            default_key_usages()
        } else {
            normalize_list(key_usages)
        };
        record.key_usages_json = serde_json::to_string(&key_usages)
            .map_err(|err| AppError::Internal(err.to_string()))?;
    }
    if let Some(extended_key_usages) = request.extended_key_usages {
        let extended_key_usages = if extended_key_usages.is_empty() {
            default_extended_key_usages()
        } else {
            normalize_list(extended_key_usages)
        };
        record.extended_key_usages_json = serde_json::to_string(&extended_key_usages)
            .map_err(|err| AppError::Internal(err.to_string()))?;
    }
    if let Some(value) = request.allow_server_generated_key {
        record.allow_server_generated_key = value;
    }
    if let Some(value) = request.require_san {
        record.require_san = value;
    }
    record.updated_at = now_unix();
    update_one(
        state.db.update_certificate_profile(&record).await?,
        "certificate profile",
        id,
    )?;
    audit_update(state, actor, "certificate_profile.update", id).await?;
    Ok(record.into())
}

pub async fn create_end_entity_profile(
    state: &AppState,
    request: CreateEndEntityProfileRequest,
    actor: &str,
) -> AppResult<EndEntityProfileResponse> {
    let name = normalized_name(&request.name, "end entity profile 이름")?;
    if let Some(pattern) = request
        .subject_regex
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    {
        Regex::new(pattern).map_err(|err| {
            AppError::BadRequest(format!("subject_regex가 올바르지 않습니다: {err}"))
        })?;
    }
    if let Some(profile_id) = request.default_certificate_profile_id.as_deref() {
        state
            .db
            .get_certificate_profile(profile_id)
            .await?
            .ok_or_else(|| {
                AppError::NotFound(format!(
                    "certificate profile을 찾을 수 없습니다: {profile_id}"
                ))
            })?;
    }
    let now = now_unix();
    let allowed_dns_domains = normalize_list(request.allowed_dns_domains);
    let record = EndEntityProfileRecord {
        id: Uuid::new_v4().to_string(),
        name,
        subject_regex: request
            .subject_regex
            .filter(|value| !value.trim().is_empty()),
        allowed_dns_domains_json: serde_json::to_string(&allowed_dns_domains)
            .map_err(|err| AppError::Internal(err.to_string()))?,
        default_certificate_profile_id: request.default_certificate_profile_id,
        created_at: now,
        updated_at: now,
    };
    state.db.insert_end_entity_profile(&record).await?;
    audit_create(state, actor, "end_entity_profile.create", &record.id).await?;
    Ok(record.into())
}

pub async fn list_end_entity_profiles(
    state: &AppState,
) -> AppResult<Vec<EndEntityProfileResponse>> {
    Ok(state
        .db
        .list_end_entity_profiles()
        .await?
        .into_iter()
        .map(Into::into)
        .collect())
}

pub async fn delete_end_entity_profile(state: &AppState, id: &str, actor: &str) -> AppResult<()> {
    delete_one(
        state.db.delete_end_entity_profile(id).await?,
        "end entity profile",
        id,
    )?;
    audit_delete(state, actor, "end_entity_profile.delete", id).await
}

pub async fn update_end_entity_profile(
    state: &AppState,
    id: &str,
    request: UpdateEndEntityProfileRequest,
    actor: &str,
) -> AppResult<EndEntityProfileResponse> {
    let mut record = state.db.get_end_entity_profile(id).await?.ok_or_else(|| {
        AppError::NotFound(format!("end entity profile을 찾을 수 없습니다: {id}"))
    })?;
    if let Some(name) = request.name {
        record.name = normalized_name(&name, "end entity profile 이름")?;
    }
    if let Some(subject_regex) = request.subject_regex {
        record.subject_regex = normalize_optional_regex(subject_regex)?;
    }
    if let Some(allowed_dns_domains) = request.allowed_dns_domains {
        record.allowed_dns_domains_json =
            serde_json::to_string(&normalize_list(allowed_dns_domains))
                .map_err(|err| AppError::Internal(err.to_string()))?;
    }
    if let Some(profile_id) = request.default_certificate_profile_id {
        record.default_certificate_profile_id =
            normalize_optional_certificate_profile_id(state, profile_id).await?;
    }
    record.updated_at = now_unix();
    update_one(
        state.db.update_end_entity_profile(&record).await?,
        "end entity profile",
        id,
    )?;
    audit_update(state, actor, "end_entity_profile.update", id).await?;
    Ok(record.into())
}

pub async fn create_cmp_alias(
    state: &AppState,
    request: CreateCmpAliasRequest,
    actor: &str,
) -> AppResult<CmpAliasResponse> {
    let alias = normalized_alias(&request.alias)?;
    if let Some(ca_id) = request.ca_id.as_deref() {
        state
            .db
            .get_ca(ca_id)
            .await?
            .ok_or_else(|| AppError::NotFound(format!("CA를 찾을 수 없습니다: {ca_id}")))?;
    }
    if let Some(profile_id) = request.certificate_profile_id.as_deref() {
        state
            .db
            .get_certificate_profile(profile_id)
            .await?
            .ok_or_else(|| {
                AppError::NotFound(format!(
                    "certificate profile을 찾을 수 없습니다: {profile_id}"
                ))
            })?;
    }
    if let Some(profile_id) = request.end_entity_profile_id.as_deref() {
        state
            .db
            .get_end_entity_profile(profile_id)
            .await?
            .ok_or_else(|| {
                AppError::NotFound(format!(
                    "end entity profile을 찾을 수 없습니다: {profile_id}"
                ))
            })?;
    }
    let now = now_unix();
    let record = CmpAliasRecord {
        id: Uuid::new_v4().to_string(),
        alias,
        ca_id: request.ca_id,
        certificate_profile_id: request.certificate_profile_id,
        end_entity_profile_id: request.end_entity_profile_id,
        enabled: request.enabled.unwrap_or(true),
        hmac_secret_sha256: request
            .hmac_secret
            .as_deref()
            .filter(|secret| !secret.is_empty())
            .map(hash_persisted_secret),
        created_at: now,
        updated_at: now,
    };
    state.db.insert_cmp_alias(&record).await?;
    audit_create(state, actor, "cmp_alias.create", &record.id).await?;
    Ok(record.into())
}

pub async fn list_cmp_aliases(state: &AppState) -> AppResult<Vec<CmpAliasResponse>> {
    Ok(state
        .db
        .list_cmp_aliases()
        .await?
        .into_iter()
        .map(Into::into)
        .collect())
}

pub async fn delete_cmp_alias(state: &AppState, id: &str, actor: &str) -> AppResult<()> {
    delete_one(state.db.delete_cmp_alias(id).await?, "CMP alias", id)?;
    audit_delete(state, actor, "cmp_alias.delete", id).await
}

pub async fn update_cmp_alias(
    state: &AppState,
    id: &str,
    request: UpdateCmpAliasRequest,
    actor: &str,
) -> AppResult<CmpAliasResponse> {
    let mut record = state
        .db
        .get_cmp_alias(id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("CMP alias를 찾을 수 없습니다: {id}")))?;
    if let Some(alias) = request.alias {
        record.alias = normalized_alias(&alias)?;
    }
    if let Some(ca_id) = request.ca_id {
        record.ca_id = normalize_optional_ca_id(state, ca_id).await?;
    }
    if let Some(profile_id) = request.certificate_profile_id {
        record.certificate_profile_id =
            normalize_optional_certificate_profile_id(state, profile_id).await?;
    }
    if let Some(profile_id) = request.end_entity_profile_id {
        record.end_entity_profile_id =
            normalize_optional_end_entity_profile_id(state, profile_id).await?;
    }
    if let Some(enabled) = request.enabled {
        record.enabled = enabled;
    }
    if request.clear_hmac_secret.unwrap_or(false) {
        record.hmac_secret_sha256 = None;
    } else if let Some(secret) = request.hmac_secret.filter(|secret| !secret.is_empty()) {
        record.hmac_secret_sha256 = Some(hash_persisted_secret(&secret));
    }
    record.updated_at = now_unix();
    update_one(state.db.update_cmp_alias(&record).await?, "CMP alias", id)?;
    audit_update(state, actor, "cmp_alias.update", id).await?;
    Ok(record.into())
}

pub async fn create_access_role(
    state: &AppState,
    request: CreateAccessRoleRequest,
    actor: &str,
) -> AppResult<AccessRoleResponse> {
    let name = normalized_name(&request.name, "access role 이름")?;
    let permissions = if request.permissions.is_empty() {
        vec!["admin".to_string()]
    } else {
        normalize_list(request.permissions)
    };
    ensure_role_can_grant(actor, &permissions)?;
    let now = now_unix();
    let api_token_hash = if let Some(token) = request
        .api_token
        .as_deref()
        .filter(|token| !token.is_empty())
    {
        ensure_access_token_unique(state, token, None).await?;
        Some(hash_access_token(token))
    } else {
        None
    };
    let certificate_member = normalize_certificate_member(
        request.certificate_issuer_dn,
        request.certificate_match_key,
        request.certificate_match_value,
    )?;
    let record = AccessRoleRecord {
        id: Uuid::new_v4().to_string(),
        name,
        permissions_json: serde_json::to_string(&permissions)
            .map_err(|err| AppError::Internal(err.to_string()))?,
        api_token_sha256: api_token_hash,
        certificate_issuer_dn: certificate_member.issuer_dn,
        certificate_match_key: certificate_member.match_key,
        certificate_match_value: certificate_member.match_value,
        created_at: now,
        updated_at: now,
    };
    state.db.insert_access_role(&record).await?;
    audit_create(state, actor, "access_role.create", &record.id).await?;
    Ok(record.into())
}

pub async fn list_access_roles(state: &AppState) -> AppResult<Vec<AccessRoleResponse>> {
    Ok(state
        .db
        .list_access_roles()
        .await?
        .into_iter()
        .map(Into::into)
        .collect())
}

pub async fn delete_access_role(state: &AppState, id: &str, actor: &str) -> AppResult<()> {
    delete_one(state.db.delete_access_role(id).await?, "access role", id)?;
    audit_delete(state, actor, "access_role.delete", id).await
}

pub async fn update_access_role(
    state: &AppState,
    id: &str,
    request: UpdateAccessRoleRequest,
    actor: &str,
) -> AppResult<AccessRoleResponse> {
    let mut record = state
        .db
        .get_access_role(id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("access role을 찾을 수 없습니다: {id}")))?;
    if let Some(name) = request.name {
        record.name = normalized_name(&name, "access role 이름")?;
    }
    if let Some(permissions) = request.permissions {
        let permissions = if permissions.is_empty() {
            permissions_from_json(&record.permissions_json)
        } else {
            normalize_list(permissions)
        };
        ensure_role_can_grant(actor, &permissions)?;
        record.permissions_json = serde_json::to_string(&permissions)
            .map_err(|err| AppError::Internal(err.to_string()))?;
    }
    if request.clear_api_token.unwrap_or(false) {
        record.api_token_sha256 = None;
    } else if let Some(token) = request.api_token.filter(|token| !token.is_empty()) {
        ensure_access_token_unique(state, &token, Some(id)).await?;
        record.api_token_sha256 = Some(hash_access_token(&token));
    }
    if request.clear_certificate_member.unwrap_or(false) {
        record.certificate_issuer_dn = None;
        record.certificate_match_key = None;
        record.certificate_match_value = None;
    } else if request.certificate_issuer_dn.is_some()
        || request.certificate_match_key.is_some()
        || request.certificate_match_value.is_some()
    {
        let certificate_member = normalize_certificate_member(
            request.certificate_issuer_dn,
            request.certificate_match_key,
            request.certificate_match_value,
        )?;
        record.certificate_issuer_dn = certificate_member.issuer_dn;
        record.certificate_match_key = certificate_member.match_key;
        record.certificate_match_value = certificate_member.match_value;
    }
    record.updated_at = now_unix();
    update_one(
        state.db.update_access_role(&record).await?,
        "access role",
        id,
    )?;
    audit_update(state, actor, "access_role.update", id).await?;
    Ok(record.into())
}

pub fn legacy_token_hash(token: &str) -> String {
    legacy_secret_hash(token)
}

pub fn verify_access_token(token: &str, stored: &str) -> bool {
    verify_persisted_secret(token, stored)
}

pub fn legacy_secret_hash(secret: &str) -> String {
    sha256_hex(secret)
}

pub fn verify_persisted_secret(secret: &str, stored: &str) -> bool {
    if let Some(parts) = parse_persisted_secret_hash(stored) {
        let (iterations, salt, expected) = parts;
        let Some(iterations) = NonZeroU32::new(iterations) else {
            return false;
        };
        let mut derived = [0_u8; PERSISTED_SECRET_HASH_BYTES];
        pbkdf2::derive(
            pbkdf2::PBKDF2_HMAC_SHA256,
            iterations,
            &salt,
            secret.as_bytes(),
            &mut derived,
        );
        return derived.as_slice().ct_eq(expected.as_slice()).into();
    }
    legacy_secret_hash(secret)
        .as_bytes()
        .ct_eq(stored.as_bytes())
        .into()
}

pub fn permissions_from_json(json: &str) -> Vec<String> {
    serde_json::from_str(json).unwrap_or_default()
}

async fn ensure_access_token_unique(
    state: &AppState,
    token: &str,
    except_id: Option<&str>,
) -> AppResult<()> {
    let legacy_hash = legacy_token_hash(token);
    for role in state.db.list_access_roles().await? {
        if except_id == Some(role.id.as_str()) {
            continue;
        }
        let Some(stored) = role.api_token_sha256.as_deref() else {
            continue;
        };
        if stored == legacy_hash || verify_access_token(token, stored) {
            return Err(AppError::BadRequest(
                "이미 사용 중인 access role API token입니다".to_string(),
            ));
        }
    }
    Ok(())
}

fn normalized_name(value: &str, label: &str) -> AppResult<String> {
    let value = value.trim();
    if value.is_empty() {
        return Err(AppError::BadRequest(format!(
            "{label}은 비어 있을 수 없습니다"
        )));
    }
    if value.len() > 128 {
        return Err(AppError::BadRequest(format!(
            "{label}은 128자 이하여야 합니다"
        )));
    }
    Ok(value.to_string())
}

struct CertificateMemberConfig {
    issuer_dn: Option<String>,
    match_key: Option<String>,
    match_value: Option<String>,
}

fn normalize_certificate_member(
    issuer_dn: Option<String>,
    match_key: Option<String>,
    match_value: Option<String>,
) -> AppResult<CertificateMemberConfig> {
    let issuer_dn = clean_optional(issuer_dn);
    let match_key = clean_optional(match_key);
    let match_value = clean_optional(match_value);
    if issuer_dn.is_none() && match_key.is_none() && match_value.is_none() {
        return Ok(CertificateMemberConfig {
            issuer_dn: None,
            match_key: None,
            match_value: None,
        });
    }

    let issuer_dn = issuer_dn.ok_or_else(|| {
        AppError::BadRequest("certificate role member에는 issuer DN이 필요합니다".to_string())
    })?;
    let match_key = normalize_certificate_match_key(match_key.as_deref().unwrap_or("serial_hex"))?;
    let match_value = if match_key == "any" {
        None
    } else {
        let value = match_value.ok_or_else(|| {
            AppError::BadRequest("certificate role member에는 match value가 필요합니다".to_string())
        })?;
        Some(if match_key == "serial_hex" {
            normalize_hex_identifier(&value)
        } else {
            value
        })
    };

    Ok(CertificateMemberConfig {
        issuer_dn: Some(issuer_dn),
        match_key: Some(match_key),
        match_value,
    })
}

fn clean_optional(value: Option<String>) -> Option<String> {
    value
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

pub fn normalize_certificate_match_key(value: &str) -> AppResult<String> {
    match value.trim().to_ascii_lowercase().replace('-', "_").as_str() {
        "serial" | "serial_number" | "serial_hex" => Ok("serial_hex".to_string()),
        "subject" | "subject_dn" | "full_dn" | "fulldn" => Ok("subject_dn".to_string()),
        "cn" | "common_name" | "commonname" => Ok("common_name".to_string()),
        "any" => Ok("any".to_string()),
        other => Err(AppError::BadRequest(format!(
            "지원하지 않는 certificate match key입니다: {other}"
        ))),
    }
}

pub fn normalize_hex_identifier(value: &str) -> String {
    let normalized = value
        .chars()
        .filter(|ch| ch.is_ascii_hexdigit())
        .collect::<String>()
        .trim_start_matches('0')
        .to_ascii_lowercase();
    if normalized.is_empty() {
        "0".to_string()
    } else {
        normalized
    }
}

fn normalized_alias(value: &str) -> AppResult<String> {
    let value = value.trim();
    if value.is_empty() {
        return Err(AppError::BadRequest(
            "CMP alias는 비어 있을 수 없습니다".to_string(),
        ));
    }
    if value.len() > 32
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(AppError::BadRequest(
            "CMP alias는 영문/숫자/-/_ 조합의 32자 이하 값이어야 합니다".to_string(),
        ));
    }
    Ok(value.to_string())
}

fn normalize_list(values: Vec<String>) -> Vec<String> {
    values
        .into_iter()
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| !value.is_empty())
        .collect()
}

fn ensure_role_can_grant(actor: &str, permissions: &[String]) -> AppResult<()> {
    if actor != "admin"
        && !actor.starts_with("cert-role-admin:")
        && permissions
            .iter()
            .any(|permission| matches!(permission.as_str(), "admin" | "*"))
    {
        return Err(AppError::Forbidden(
            "admin 권한이 없는 role로 admin 또는 * 권한을 부여할 수 없습니다".to_string(),
        ));
    }
    Ok(())
}

fn normalize_optional_regex(value: String) -> AppResult<Option<String>> {
    let value = value.trim().to_string();
    if value.is_empty() {
        return Ok(None);
    }
    Regex::new(&value)
        .map_err(|err| AppError::BadRequest(format!("subject_regex가 올바르지 않습니다: {err}")))?;
    Ok(Some(value))
}

async fn normalize_optional_ca_id(state: &AppState, value: String) -> AppResult<Option<String>> {
    let value = value.trim().to_string();
    if value.is_empty() {
        return Ok(None);
    }
    state
        .db
        .get_ca(&value)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("CA를 찾을 수 없습니다: {value}")))?;
    Ok(Some(value))
}

async fn normalize_optional_certificate_profile_id(
    state: &AppState,
    value: String,
) -> AppResult<Option<String>> {
    let value = value.trim().to_string();
    if value.is_empty() {
        return Ok(None);
    }
    state
        .db
        .get_certificate_profile(&value)
        .await?
        .ok_or_else(|| {
            AppError::NotFound(format!("certificate profile을 찾을 수 없습니다: {value}"))
        })?;
    Ok(Some(value))
}

async fn normalize_optional_end_entity_profile_id(
    state: &AppState,
    value: String,
) -> AppResult<Option<String>> {
    let value = value.trim().to_string();
    if value.is_empty() {
        return Ok(None);
    }
    state
        .db
        .get_end_entity_profile(&value)
        .await?
        .ok_or_else(|| {
            AppError::NotFound(format!("end entity profile을 찾을 수 없습니다: {value}"))
        })?;
    Ok(Some(value))
}

fn default_key_usages() -> Vec<String> {
    vec![
        "digital_signature".to_string(),
        "key_encipherment".to_string(),
    ]
}

fn default_extended_key_usages() -> Vec<String> {
    vec!["server_auth".to_string(), "client_auth".to_string()]
}

fn sha256_hex(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    hex::encode(digest)
}

fn hash_access_token(token: &str) -> String {
    hash_persisted_secret(token)
}

fn hash_persisted_secret(secret: &str) -> String {
    let mut salt = [0_u8; PERSISTED_SECRET_HASH_SALT_BYTES];
    OsRng.fill_bytes(&mut salt);
    let mut derived = [0_u8; PERSISTED_SECRET_HASH_BYTES];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        NonZeroU32::new(PERSISTED_SECRET_HASH_ITERATIONS)
            .expect("persisted secret PBKDF2 반복 횟수는 0이 아닙니다"),
        &salt,
        secret.as_bytes(),
        &mut derived,
    );
    format!(
        "{}${}${}${}",
        PERSISTED_SECRET_HASH_PREFIX,
        PERSISTED_SECRET_HASH_ITERATIONS,
        URL_SAFE_NO_PAD.encode(salt),
        URL_SAFE_NO_PAD.encode(derived)
    )
}

fn parse_persisted_secret_hash(stored: &str) -> Option<(u32, Vec<u8>, Vec<u8>)> {
    let mut parts = stored.split('$');
    let prefix = parts.next()?;
    if prefix != PERSISTED_SECRET_HASH_PREFIX {
        return None;
    }
    let iterations = parts.next()?.parse::<u32>().ok()?;
    let salt = URL_SAFE_NO_PAD.decode(parts.next()?).ok()?;
    let expected = URL_SAFE_NO_PAD.decode(parts.next()?).ok()?;
    if parts.next().is_some()
        || salt.len() != PERSISTED_SECRET_HASH_SALT_BYTES
        || expected.len() != PERSISTED_SECRET_HASH_BYTES
    {
        return None;
    }
    Some((iterations, salt, expected))
}

fn delete_one(rows: u64, label: &str, id: &str) -> AppResult<()> {
    if rows == 0 {
        Err(AppError::NotFound(format!(
            "{label}을 찾을 수 없습니다: {id}"
        )))
    } else {
        Ok(())
    }
}

fn update_one(rows: u64, label: &str, id: &str) -> AppResult<()> {
    if rows == 0 {
        Err(AppError::NotFound(format!(
            "{label}을 찾을 수 없습니다: {id}"
        )))
    } else {
        Ok(())
    }
}

async fn audit_create(state: &AppState, actor: &str, action: &str, id: &str) -> AppResult<()> {
    state.db.audit(actor, action, id, "success", "{}").await
}

async fn audit_update(state: &AppState, actor: &str, action: &str, id: &str) -> AppResult<()> {
    state.db.audit(actor, action, id, "success", "{}").await
}

async fn audit_delete(state: &AppState, actor: &str, action: &str, id: &str) -> AppResult<()> {
    state.db.audit(actor, action, id, "success", "{}").await
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
            std::env::temp_dir().join(format!("ejbca-rs-profiles-test-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&data_dir).unwrap();
        let settings = Arc::new(Settings {
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
    async fn updates_profiles_aliases_and_roles() {
        let (state, data_dir) = test_state().await;
        let cert_profile = create_certificate_profile(
            &state,
            CreateCertificateProfileRequest {
                name: "profile-a".to_string(),
                validity_days: Some(100),
                key_usages: Vec::new(),
                extended_key_usages: Vec::new(),
                allow_server_generated_key: Some(true),
                require_san: Some(false),
            },
            "admin",
        )
        .await
        .unwrap();
        let cert_profile = update_certificate_profile(
            &state,
            &cert_profile.id,
            UpdateCertificateProfileRequest {
                name: Some("profile-b".to_string()),
                validity_days: Some(30),
                key_usages: Some(vec!["Digital_Signature".to_string()]),
                extended_key_usages: None,
                allow_server_generated_key: Some(false),
                require_san: Some(true),
            },
            "admin",
        )
        .await
        .unwrap();
        assert_eq!(cert_profile.name, "profile-b");
        assert_eq!(cert_profile.validity_days, 30);
        assert_eq!(cert_profile.key_usages, vec!["digital_signature"]);
        assert!(!cert_profile.allow_server_generated_key);
        assert!(cert_profile.require_san);

        let ee_profile = create_end_entity_profile(
            &state,
            CreateEndEntityProfileRequest {
                name: "ee-a".to_string(),
                subject_regex: Some("^CN=.*$".to_string()),
                allowed_dns_domains: vec!["example.com".to_string()],
                default_certificate_profile_id: Some(cert_profile.id.clone()),
            },
            "admin",
        )
        .await
        .unwrap();
        let ee_profile = update_end_entity_profile(
            &state,
            &ee_profile.id,
            UpdateEndEntityProfileRequest {
                name: Some("ee-b".to_string()),
                subject_regex: Some(String::new()),
                allowed_dns_domains: Some(vec!["Example.ORG".to_string()]),
                default_certificate_profile_id: Some(String::new()),
            },
            "admin",
        )
        .await
        .unwrap();
        assert_eq!(ee_profile.name, "ee-b");
        assert!(ee_profile.subject_regex.is_none());
        assert_eq!(ee_profile.allowed_dns_domains, vec!["example.org"]);
        assert!(ee_profile.default_certificate_profile_id.is_none());

        let alias = create_cmp_alias(
            &state,
            CreateCmpAliasRequest {
                alias: "cmpa".to_string(),
                ca_id: None,
                certificate_profile_id: None,
                end_entity_profile_id: None,
                enabled: Some(true),
                hmac_secret: Some("secret".to_string()),
            },
            "admin",
        )
        .await
        .unwrap();
        let alias = update_cmp_alias(
            &state,
            &alias.id,
            UpdateCmpAliasRequest {
                alias: Some("cmpb".to_string()),
                ca_id: None,
                certificate_profile_id: Some(cert_profile.id.clone()),
                end_entity_profile_id: Some(ee_profile.id.clone()),
                enabled: Some(false),
                hmac_secret: None,
                clear_hmac_secret: Some(true),
            },
            "admin",
        )
        .await
        .unwrap();
        assert_eq!(alias.alias, "cmpb");
        assert!(!alias.enabled);
        assert_eq!(alias.certificate_profile_id, Some(cert_profile.id.clone()));
        assert_eq!(alias.end_entity_profile_id, Some(ee_profile.id.clone()));
        assert!(!alias.hmac_secret_configured);

        let role = create_access_role(
            &state,
            CreateAccessRoleRequest {
                name: "operator-a".to_string(),
                permissions: vec!["read".to_string()],
                api_token: Some("token-a".to_string()),
                certificate_issuer_dn: None,
                certificate_match_key: None,
                certificate_match_value: None,
            },
            "admin",
        )
        .await
        .unwrap();
        let role = update_access_role(
            &state,
            &role.id,
            UpdateAccessRoleRequest {
                name: Some("operator-b".to_string()),
                permissions: Some(vec!["read".to_string(), "issue".to_string()]),
                api_token: None,
                clear_api_token: Some(true),
                certificate_issuer_dn: None,
                certificate_match_key: None,
                certificate_match_value: None,
                clear_certificate_member: None,
            },
            "admin",
        )
        .await
        .unwrap();
        assert_eq!(role.name, "operator-b");
        assert_eq!(role.permissions, vec!["read", "issue"]);
        assert!(!role.api_token_configured);

        std::fs::remove_dir_all(data_dir).ok();
    }

    #[tokio::test]
    async fn access_role_tokens_use_kdf_hash_and_reject_duplicates() {
        let (state, data_dir) = test_state().await;
        let role = create_access_role(
            &state,
            CreateAccessRoleRequest {
                name: "issuer-a".to_string(),
                permissions: vec!["read".to_string()],
                api_token: Some("shared-token".to_string()),
                certificate_issuer_dn: None,
                certificate_match_key: None,
                certificate_match_value: None,
            },
            "admin",
        )
        .await
        .unwrap();
        let stored = state
            .db
            .get_access_role(&role.id)
            .await
            .unwrap()
            .unwrap()
            .api_token_sha256
            .unwrap();
        assert!(stored.starts_with(PERSISTED_SECRET_HASH_PREFIX));
        assert_ne!(stored, legacy_token_hash("shared-token"));
        assert!(verify_access_token("shared-token", &stored));
        assert!(!verify_access_token("wrong-token", &stored));
        assert!(verify_access_token(
            "legacy-token",
            &legacy_token_hash("legacy-token")
        ));

        let duplicate = create_access_role(
            &state,
            CreateAccessRoleRequest {
                name: "issuer-b".to_string(),
                permissions: vec!["read".to_string()],
                api_token: Some("shared-token".to_string()),
                certificate_issuer_dn: None,
                certificate_match_key: None,
                certificate_match_value: None,
            },
            "admin",
        )
        .await
        .unwrap_err();
        assert!(duplicate.to_string().contains("이미 사용 중"));

        std::fs::remove_dir_all(data_dir).ok();
    }

    #[tokio::test]
    async fn cmp_alias_hmac_secrets_use_kdf_hash_and_accept_legacy() {
        let (state, data_dir) = test_state().await;
        let alias = create_cmp_alias(
            &state,
            CreateCmpAliasRequest {
                alias: "securecmp".to_string(),
                ca_id: None,
                certificate_profile_id: None,
                end_entity_profile_id: None,
                enabled: Some(true),
                hmac_secret: Some("cmp-secret".to_string()),
            },
            "admin",
        )
        .await
        .unwrap();
        let stored = state
            .db
            .get_cmp_alias(&alias.id)
            .await
            .unwrap()
            .unwrap()
            .hmac_secret_sha256
            .unwrap();
        assert!(stored.starts_with(PERSISTED_SECRET_HASH_PREFIX));
        assert_ne!(stored, legacy_secret_hash("cmp-secret"));
        assert!(verify_persisted_secret("cmp-secret", &stored));
        assert!(!verify_persisted_secret("wrong-secret", &stored));
        assert!(verify_persisted_secret(
            "legacy-cmp-secret",
            &legacy_secret_hash("legacy-cmp-secret")
        ));

        update_cmp_alias(
            &state,
            &alias.id,
            UpdateCmpAliasRequest {
                alias: None,
                ca_id: None,
                certificate_profile_id: None,
                end_entity_profile_id: None,
                enabled: None,
                hmac_secret: Some("new-cmp-secret".to_string()),
                clear_hmac_secret: None,
            },
            "admin",
        )
        .await
        .unwrap();
        let updated = state
            .db
            .get_cmp_alias(&alias.id)
            .await
            .unwrap()
            .unwrap()
            .hmac_secret_sha256
            .unwrap();
        assert!(updated.starts_with(PERSISTED_SECRET_HASH_PREFIX));
        assert_ne!(stored, updated);
        assert!(verify_persisted_secret("new-cmp-secret", &updated));
        assert!(!verify_persisted_secret("cmp-secret", &updated));

        std::fs::remove_dir_all(data_dir).ok();
    }
}

impl From<CertificateProfileRecord> for CertificateProfileResponse {
    fn from(value: CertificateProfileRecord) -> Self {
        Self {
            id: value.id,
            name: value.name,
            validity_days: value.validity_days,
            key_usages: serde_json::from_str(&value.key_usages_json).unwrap_or_default(),
            extended_key_usages: serde_json::from_str(&value.extended_key_usages_json)
                .unwrap_or_default(),
            allow_server_generated_key: value.allow_server_generated_key,
            require_san: value.require_san,
            created_at: value.created_at,
            updated_at: value.updated_at,
        }
    }
}

impl From<EndEntityProfileRecord> for EndEntityProfileResponse {
    fn from(value: EndEntityProfileRecord) -> Self {
        Self {
            id: value.id,
            name: value.name,
            subject_regex: value.subject_regex,
            allowed_dns_domains: serde_json::from_str(&value.allowed_dns_domains_json)
                .unwrap_or_default(),
            default_certificate_profile_id: value.default_certificate_profile_id,
            created_at: value.created_at,
            updated_at: value.updated_at,
        }
    }
}

impl From<CmpAliasRecord> for CmpAliasResponse {
    fn from(value: CmpAliasRecord) -> Self {
        Self {
            id: value.id,
            alias: value.alias,
            ca_id: value.ca_id,
            certificate_profile_id: value.certificate_profile_id,
            end_entity_profile_id: value.end_entity_profile_id,
            enabled: value.enabled,
            hmac_secret_configured: value.hmac_secret_sha256.is_some(),
            created_at: value.created_at,
            updated_at: value.updated_at,
        }
    }
}

impl From<AccessRoleRecord> for AccessRoleResponse {
    fn from(value: AccessRoleRecord) -> Self {
        Self {
            id: value.id,
            name: value.name,
            permissions: permissions_from_json(&value.permissions_json),
            api_token_configured: value.api_token_sha256.is_some(),
            certificate_member_configured: value.certificate_match_key.is_some(),
            certificate_issuer_dn: value.certificate_issuer_dn,
            certificate_match_key: value.certificate_match_key,
            certificate_match_value: value.certificate_match_value,
            created_at: value.created_at,
            updated_at: value.updated_at,
        }
    }
}
