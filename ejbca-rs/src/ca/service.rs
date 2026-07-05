use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair, KeyUsagePurpose};
use time::{Duration, OffsetDateTime};
use tracing::info;
use uuid::Uuid;
use x509_parser::prelude::{FromDer, X509Certificate};

use crate::{
    AppState,
    ca::{
        CaResponse, CreateCaRequest, ImportCaRequest, RenewCaRequest, RolloverCaRequest,
        UpdateCaRequest,
    },
    error::{AppError, AppResult},
    key_provider::{self, CaSigningKey},
    storage::CaRecord,
    util::{now, parse_distinguished_name},
};

pub async fn ensure_default_ca(state: &AppState) -> AppResult<()> {
    if state.db.ca_count().await? == 0 {
        let request = CreateCaRequest {
            name: "ejbca-rs-default-ca".to_string(),
            subject_dn: "CN=ejbca-rs Default Root CA,O=ejbca-rs".to_string(),
            validity_days: Some(3650),
        };
        let ca = create_ca(state, request, "system").await?;
        info!("기본 CA를 생성했습니다: {} ({})", ca.name, ca.id);
    }
    Ok(())
}

pub async fn create_ca(
    state: &AppState,
    request: CreateCaRequest,
    actor: &str,
) -> AppResult<CaResponse> {
    if request.name.trim().is_empty() {
        return Err(AppError::BadRequest(
            "CA 이름은 비어 있을 수 없습니다".to_string(),
        ));
    }
    let is_default = state.db.ca_count().await? == 0;
    let (params, not_after) = ca_certificate_params(&request.subject_dn, request.validity_days)?;
    let key_pair = KeyPair::generate()?;
    let cert = params.self_signed(&key_pair)?;
    let ca_id = Uuid::new_v4().to_string();
    let key_ref = key_provider::persist_new_ca_key(&state.settings, &ca_id, &key_pair).await?;
    let record = CaRecord {
        id: ca_id,
        name: request.name.trim().to_string(),
        subject_dn: request.subject_dn,
        cert_pem: cert.pem(),
        key_pem: key_ref,
        cert_der: cert.der().as_ref().to_vec(),
        status: "active".to_string(),
        is_default,
        created_at: now().unix_timestamp(),
        not_after: not_after.unix_timestamp(),
    };
    state.db.insert_ca(&record).await?;
    state
        .db
        .audit(
            actor,
            "ca.create",
            &record.id,
            "success",
            &serde_json::json!({"name": record.name}).to_string(),
        )
        .await?;
    Ok(record.into())
}

pub async fn import_ca(
    state: &AppState,
    request: ImportCaRequest,
    actor: &str,
) -> AppResult<CaResponse> {
    if request.name.trim().is_empty() {
        return Err(AppError::BadRequest(
            "CA 이름은 비어 있을 수 없습니다".to_string(),
        ));
    }
    key_provider::validate_key_ref(&request.key_ref)?;
    let is_default = state.db.ca_count().await? == 0;
    let cert_pem = request.cert_pem.trim().to_string();
    let cert_der = pem::parse(&cert_pem)
        .map_err(|err| AppError::BadRequest(format!("CA 인증서 PEM 파싱 실패: {err}")))?
        .contents()
        .to_vec();
    let (_, parsed) = X509Certificate::from_der(&cert_der)
        .map_err(|err| AppError::BadRequest(format!("CA 인증서 DER 파싱 실패: {err}")))?;
    let subject_dn = parsed.subject().to_string();
    let not_after = parsed.validity().not_after.to_datetime().unix_timestamp();
    let record = CaRecord {
        id: Uuid::new_v4().to_string(),
        name: request.name.trim().to_string(),
        subject_dn,
        cert_pem,
        key_pem: request.key_ref,
        cert_der,
        status: "active".to_string(),
        is_default,
        created_at: now().unix_timestamp(),
        not_after,
    };
    // import 시점에 provider와 공개키 파싱을 검증한다. 실제 서명 가능성은 발급/CRL/OCSP 때 검증된다.
    let _ = key_provider::load_ca_signing_key(&record).await?;
    state.db.insert_ca(&record).await?;
    state
        .db
        .audit(
            actor,
            "ca.import",
            &record.id,
            "success",
            &serde_json::json!({
                "name": &record.name,
                "key_provider": key_provider::provider_label(&record.key_pem)
            })
            .to_string(),
        )
        .await?;
    Ok(record.into())
}

pub async fn renew_ca(
    state: &AppState,
    id: &str,
    request: RenewCaRequest,
    actor: &str,
) -> AppResult<CaResponse> {
    let mut record = state
        .db
        .get_ca(id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("CA를 찾을 수 없습니다: {id}")))?;
    ensure_active_lifecycle_ca(&record)?;

    let (params, not_after) = ca_certificate_params(&record.subject_dn, request.validity_days)?;
    let public_key = key_provider::load_ca_signing_key(&record).await?;
    let issuer_key = key_provider::load_ca_signing_key(&record).await?;
    let issuer = Issuer::from_ca_cert_pem(&record.cert_pem, issuer_key)?;
    let cert = params.signed_by(&public_key, &issuer)?;
    record.cert_pem = cert.pem();
    record.cert_der = cert.der().as_ref().to_vec();
    record.not_after = not_after.unix_timestamp();

    let updated = state.db.update_ca(&record).await?;
    if updated == 0 {
        return Err(AppError::NotFound(format!("CA를 찾을 수 없습니다: {id}")));
    }
    state
        .db
        .audit(
            actor,
            "ca.renew",
            id,
            "success",
            &serde_json::json!({
                "name": record.name,
                "subject_dn": record.subject_dn,
                "not_after": record.not_after,
            })
            .to_string(),
        )
        .await?;
    Ok(record.into())
}

pub async fn rollover_ca(
    state: &AppState,
    id: &str,
    request: RolloverCaRequest,
    actor: &str,
) -> AppResult<CaResponse> {
    let mut old_record = state
        .db
        .get_ca(id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("CA를 찾을 수 없습니다: {id}")))?;
    ensure_active_lifecycle_ca(&old_record)?;

    let disable_old = request.disable_old.unwrap_or(false);
    let make_default = request
        .make_default
        .unwrap_or(old_record.is_default || disable_old);
    if disable_old && old_record.is_default && !make_default {
        return Err(AppError::BadRequest(
            "기본 CA를 비활성화하려면 새 rollover CA를 기본 CA로 지정해야 합니다".to_string(),
        ));
    }

    let subject_dn = request
        .subject_dn
        .unwrap_or_else(|| old_record.subject_dn.clone());
    let name = request
        .name
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| format!("{}-rollover-{}", old_record.name, now().unix_timestamp()));
    let (params, not_after) = ca_certificate_params(&subject_dn, request.validity_days)?;
    let key_pair = KeyPair::generate()?;
    let cert = params.self_signed(&key_pair)?;
    let ca_id = Uuid::new_v4().to_string();
    let key_ref = key_provider::persist_new_ca_key(&state.settings, &ca_id, &key_pair).await?;
    let mut new_record = CaRecord {
        id: ca_id,
        name,
        subject_dn,
        cert_pem: cert.pem(),
        key_pem: key_ref,
        cert_der: cert.der().as_ref().to_vec(),
        status: "active".to_string(),
        is_default: false,
        created_at: now().unix_timestamp(),
        not_after: not_after.unix_timestamp(),
    };
    state.db.insert_ca(&new_record).await?;
    if make_default {
        new_record.is_default = true;
        state.db.update_ca(&new_record).await?;
    }
    if disable_old {
        old_record.status = "disabled".to_string();
        if make_default {
            old_record.is_default = false;
        }
        state.db.update_ca(&old_record).await?;
    }
    state
        .db
        .audit(
            actor,
            "ca.rollover",
            &old_record.id,
            "success",
            &serde_json::json!({
                "old_ca_id": old_record.id,
                "new_ca_id": new_record.id,
                "new_name": new_record.name,
                "make_default": new_record.is_default,
                "disable_old": disable_old,
            })
            .to_string(),
        )
        .await?;
    Ok(new_record.into())
}

pub async fn list_cas(state: &AppState) -> AppResult<Vec<CaResponse>> {
    Ok(state
        .db
        .list_cas()
        .await?
        .into_iter()
        .map(Into::into)
        .collect())
}

pub async fn update_ca(
    state: &AppState,
    id: &str,
    request: UpdateCaRequest,
    actor: &str,
) -> AppResult<CaResponse> {
    let mut record = state
        .db
        .get_ca(id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("CA를 찾을 수 없습니다: {id}")))?;

    if let Some(name) = request.name {
        let name = name.trim();
        if name.is_empty() {
            return Err(AppError::BadRequest(
                "CA 이름은 비어 있을 수 없습니다".to_string(),
            ));
        }
        record.name = name.to_string();
    }
    if let Some(status) = request.status {
        record.status = normalize_ca_status(&status)?;
    }
    if request.make_default.unwrap_or(false) {
        record.is_default = true;
    }
    if record.is_default && record.status != "active" {
        return Err(AppError::BadRequest(
            "비활성 CA는 기본 CA로 지정할 수 없습니다".to_string(),
        ));
    }
    let updated = state.db.update_ca(&record).await?;
    if updated == 0 {
        return Err(AppError::NotFound(format!("CA를 찾을 수 없습니다: {id}")));
    }
    state
        .db
        .audit(
            actor,
            "ca.update",
            id,
            "success",
            &serde_json::json!({
                "name": record.name,
                "status": record.status,
                "is_default": record.is_default,
            })
            .to_string(),
        )
        .await?;
    Ok(record.into())
}

pub async fn load_issuer(ca: &CaRecord) -> AppResult<Issuer<'static, CaSigningKey>> {
    let signing_key = key_provider::load_ca_signing_key(ca).await?;
    Ok(Issuer::from_ca_cert_pem(&ca.cert_pem, signing_key)?)
}

fn normalize_ca_status(value: &str) -> AppResult<String> {
    match value.trim().to_ascii_lowercase().as_str() {
        "active" | "enabled" => Ok("active".to_string()),
        "disabled" | "inactive" => Ok("disabled".to_string()),
        _ => Err(AppError::BadRequest(
            "CA status는 active 또는 disabled여야 합니다".to_string(),
        )),
    }
}

fn ensure_active_lifecycle_ca(ca: &CaRecord) -> AppResult<()> {
    if ca.status == "active" {
        Ok(())
    } else {
        Err(AppError::BadRequest(format!(
            "비활성 CA에는 lifecycle 작업을 실행할 수 없습니다: {}",
            ca.id
        )))
    }
}

fn ca_certificate_params(
    subject_dn: &str,
    validity_days: Option<i64>,
) -> AppResult<(CertificateParams, OffsetDateTime)> {
    let validity_days = validity_days.unwrap_or(3650).clamp(1, 20 * 365);
    let not_before = now() - Duration::days(1);
    let not_after = now() + Duration::days(validity_days);
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    params.distinguished_name = parse_distinguished_name(subject_dn)?;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];
    params.not_before = not_before;
    params.not_after = not_after;
    Ok((params, not_after))
}

impl From<CaRecord> for CaResponse {
    fn from(value: CaRecord) -> Self {
        Self {
            id: value.id,
            name: value.name,
            subject_dn: value.subject_dn,
            cert_pem: value.cert_pem,
            key_provider: key_provider::provider_label(&value.key_pem).to_string(),
            status: value.status,
            is_default: value.is_default,
            created_at: value.created_at,
            not_after: value.not_after,
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
        let data_dir = std::env::temp_dir().join(format!("ejbca-rs-ca-test-{}", Uuid::new_v4()));
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
    async fn updates_ca_status_and_default_selection() {
        let (state, data_dir) = test_state().await;
        let first = create_ca(
            &state,
            CreateCaRequest {
                name: "first-ca".to_string(),
                subject_dn: "CN=first-ca,O=Test".to_string(),
                validity_days: Some(365),
            },
            "admin",
        )
        .await
        .unwrap();
        assert_eq!(first.status, "active");
        assert!(first.is_default);

        let second = create_ca(
            &state,
            CreateCaRequest {
                name: "second-ca".to_string(),
                subject_dn: "CN=second-ca,O=Test".to_string(),
                validity_days: Some(365),
            },
            "admin",
        )
        .await
        .unwrap();
        assert!(!second.is_default);

        let promoted = update_ca(
            &state,
            &second.id,
            UpdateCaRequest {
                name: Some("second-ca-renamed".to_string()),
                status: None,
                make_default: Some(true),
            },
            "admin",
        )
        .await
        .unwrap();
        assert_eq!(promoted.name, "second-ca-renamed");
        assert!(promoted.is_default);

        let disabled_first = update_ca(
            &state,
            &first.id,
            UpdateCaRequest {
                name: None,
                status: Some("disabled".to_string()),
                make_default: None,
            },
            "admin",
        )
        .await
        .unwrap();
        assert_eq!(disabled_first.status, "disabled");

        let error = update_ca(
            &state,
            &second.id,
            UpdateCaRequest {
                name: None,
                status: Some("disabled".to_string()),
                make_default: None,
            },
            "admin",
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("비활성 CA는 기본 CA"));

        let listed = list_cas(&state).await.unwrap();
        assert_eq!(listed[0].id, second.id);
        assert!(listed[0].is_default);

        std::fs::remove_dir_all(data_dir).ok();
    }

    #[tokio::test]
    async fn renews_and_rolls_over_ca_lifecycle() {
        let (state, data_dir) = test_state().await;
        let ca = create_ca(
            &state,
            CreateCaRequest {
                name: "lifecycle-ca".to_string(),
                subject_dn: "CN=lifecycle-ca,O=Test".to_string(),
                validity_days: Some(365),
            },
            "admin",
        )
        .await
        .unwrap();
        let before = state.db.get_ca(&ca.id).await.unwrap().unwrap();

        let renewed = renew_ca(
            &state,
            &ca.id,
            RenewCaRequest {
                validity_days: Some(730),
            },
            "admin",
        )
        .await
        .unwrap();
        let after = state.db.get_ca(&ca.id).await.unwrap().unwrap();
        assert_eq!(renewed.id, ca.id);
        assert_eq!(after.key_pem, before.key_pem);
        assert_ne!(after.cert_pem, before.cert_pem);

        let rollover = rollover_ca(
            &state,
            &ca.id,
            RolloverCaRequest {
                name: Some("lifecycle-ca-rollover".to_string()),
                subject_dn: None,
                validity_days: Some(3650),
                make_default: Some(true),
                disable_old: Some(true),
            },
            "admin",
        )
        .await
        .unwrap();
        assert_ne!(rollover.id, ca.id);
        assert!(rollover.is_default);

        let old = state.db.get_ca(&ca.id).await.unwrap().unwrap();
        assert_eq!(old.status, "disabled");
        assert!(!old.is_default);

        std::fs::remove_dir_all(data_dir).ok();
    }
}
