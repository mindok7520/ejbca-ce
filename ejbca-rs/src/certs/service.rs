use openssl::{pkcs12::Pkcs12, pkey::PKey, stack::Stack, x509::X509};
use rcgen::{
    CertificateParams, CertificateSigningRequestParams, CrlDistributionPoint,
    ExtendedKeyUsagePurpose, KeyPair, KeyUsagePurpose, SanType, SubjectPublicKeyInfo,
};
use regex::Regex;
use time::Duration;
use tokio::sync::OwnedSemaphorePermit;
use uuid::Uuid;

use crate::{
    AppState,
    ca::service::load_issuer,
    certs::{
        CertificateResponse, CertificateSummaryResponse, IssueCertificateRequest, IssueCsrRequest,
        IssuePkcs12Request, IssuePublicKeyRequest, Pkcs12IssueResponse,
    },
    error::{AppError, AppResult},
    storage::{
        CaRecord, CertificateFilter, CertificateProfileRecord, CertificateRecord,
        EndEntityProfileRecord, NewCertificateEvent,
    },
    util::{
        days_from_now, fingerprint_sha256, format_distinguished_name, new_serial, now,
        parse_distinguished_name,
    },
    validators::{ValidationContext, service::validate_pre_issue},
};

pub async fn issue_generated(
    state: &AppState,
    request: IssueCertificateRequest,
    actor: &str,
) -> AppResult<CertificateResponse> {
    let request = crate::ra::hydrate_issue_certificate_request(state, request).await?;
    let started = std::time::Instant::now();
    let device_id = device_id_from_parts(&request.subject_dn, &request.dns_names);
    let request_ca_id = request.ca_id.clone();
    let request_subject = request.subject_dn.clone();
    record_issue_event(
        state,
        "request",
        request_ca_id.clone(),
        None,
        None,
        device_id.clone(),
        Some(request_subject.clone()),
        "admin_api",
        None,
        None,
    )
    .await;

    let result = match acquire_issue_permit(state) {
        Ok(_permit) => issue_generated_inner(state, request, actor).await,
        Err(err) => Err(err),
    };
    record_issue_result(
        state,
        &result,
        request_ca_id,
        device_id,
        Some(request_subject),
        started,
        "admin_api",
    )
    .await;
    result
}

pub async fn issue_pkcs12(
    state: &AppState,
    request: IssuePkcs12Request,
    actor: &str,
) -> AppResult<Pkcs12IssueResponse> {
    let password = request.pkcs12_password.trim();
    if password.is_empty() {
        return Err(AppError::BadRequest(
            "PKCS#12 password는 비어 있을 수 없습니다".to_string(),
        ));
    }
    let friendly_name = request
        .friendly_name
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("ejbca-rs admin");
    let issued = issue_generated(state, IssueCertificateRequest::from(&request), actor).await?;
    let private_key_pem = issued
        .private_key_pem
        .as_deref()
        .ok_or_else(|| AppError::Internal("서버 생성 private key가 응답에 없습니다".to_string()))?;
    let ca =
        state.db.get_ca(&issued.ca_id).await?.ok_or_else(|| {
            AppError::NotFound(format!("CA를 찾을 수 없습니다: {}", issued.ca_id))
        })?;
    let der = build_pkcs12_der(
        &issued.cert_pem,
        private_key_pem,
        Some(&ca.cert_pem),
        password,
        friendly_name,
    )?;
    Ok(Pkcs12IssueResponse {
        filename: format!("{}.p12", safe_filename_component(friendly_name)),
        certificate_id: issued.id,
        serial_hex: issued.serial_hex,
        der,
    })
}

async fn issue_generated_inner(
    state: &AppState,
    request: IssueCertificateRequest,
    actor: &str,
) -> AppResult<CertificateResponse> {
    let approval_target = request
        .end_entity_id
        .as_deref()
        .unwrap_or(&request.subject_dn)
        .to_string();
    crate::ra::ensure_approval_permits(
        state,
        "issue",
        &approval_target,
        request.approval_id.as_deref(),
    )
    .await?;
    let end_entity_id = request.end_entity_id.clone();
    let ca = resolve_ca(state, request.ca_id.as_deref()).await?;
    let issuer = load_issuer(&ca).await?;
    let policy = resolve_issuance_policy(
        state,
        request.certificate_profile_id.as_deref(),
        request.end_entity_profile_id.as_deref(),
    )
    .await?;
    enforce_issue_access_rules(state, actor, "admin_api", &ca, &policy).await?;
    validate_issuance_policy(
        &policy,
        &request.subject_dn,
        &request.dns_names,
        IssuanceMode::ServerGeneratedKey,
    )?;
    let validity_days = policy_validity_days(&policy, request.validity_days);
    let not_before = now() - Duration::minutes(5);
    let not_after = days_from_now(validity_days);
    let (serial, serial_hex) = new_serial();

    let mut params = CertificateParams::new(request.dns_names.clone())?;
    params.distinguished_name = parse_distinguished_name(&request.subject_dn)?;
    params.serial_number = Some(serial);
    params.not_before = not_before;
    params.not_after = not_after;
    params.use_authority_key_identifier_extension = true;
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    params.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ServerAuth,
        ExtendedKeyUsagePurpose::ClientAuth,
    ];
    params.crl_distribution_points = vec![CrlDistributionPoint {
        uris: vec![format!(
            "{}/crl/{}/latest",
            state.settings.public_base_url.trim_end_matches('/'),
            ca.id
        )],
    }];

    validate_pre_issue(
        state,
        &ValidationContext {
            ca_id: ca.id.clone(),
            subject_dn: request.subject_dn.clone(),
            dns_names: request.dns_names.clone(),
            csr_pem: None,
        },
    )
    .await?;

    let key_pair = KeyPair::generate()?;
    let cert = params.signed_by(&key_pair, &issuer)?;
    let private_key_pem = key_pair.serialize_pem();
    let record = build_record(
        &ca,
        &policy,
        serial_hex,
        request.subject_dn,
        request.dns_names,
        cert.pem(),
        cert.der().as_ref().to_vec(),
        None,
        not_before.unix_timestamp(),
        not_after.unix_timestamp(),
    )?;
    store_issued_certificate(state, actor, &record).await?;
    crate::ra::mark_end_entity_generated(state, end_entity_id.as_deref()).await?;
    crate::publisher::dispatch_certificate_event(state, "issue", &record, actor).await?;
    Ok(to_response(record, Some(private_key_pem)))
}

pub async fn issue_from_csr(
    state: &AppState,
    request: IssueCsrRequest,
    actor: &str,
) -> AppResult<CertificateResponse> {
    issue_from_csr_with_source(state, request, actor, "admin_api").await
}

pub async fn issue_from_csr_with_source(
    state: &AppState,
    request: IssueCsrRequest,
    actor: &str,
    source: &str,
) -> AppResult<CertificateResponse> {
    let request = crate::ra::hydrate_issue_csr_request(state, request).await?;
    let started = std::time::Instant::now();
    let request_ca_id = request.ca_id.clone();
    record_issue_event(
        state,
        "request",
        request_ca_id.clone(),
        None,
        None,
        None,
        None,
        source,
        None,
        None,
    )
    .await;

    let result = match acquire_issue_permit(state) {
        Ok(_permit) => issue_from_csr_inner(state, request, actor, source).await,
        Err(err) => Err(err),
    };
    record_issue_result(state, &result, request_ca_id, None, None, started, source).await;
    result
}

pub async fn issue_from_public_key_with_source(
    state: &AppState,
    request: IssuePublicKeyRequest,
    actor: &str,
    source: &str,
) -> AppResult<CertificateResponse> {
    let started = std::time::Instant::now();
    let device_id = device_id_from_parts(&request.subject_dn, &request.dns_names);
    let request_ca_id = request.ca_id.clone();
    let request_subject = request.subject_dn.clone();
    record_issue_event(
        state,
        "request",
        request_ca_id.clone(),
        None,
        None,
        device_id.clone(),
        Some(request_subject.clone()),
        source,
        None,
        None,
    )
    .await;

    let result = match acquire_issue_permit(state) {
        Ok(_permit) => issue_from_public_key_inner(state, request, actor, source).await,
        Err(err) => Err(err),
    };
    record_issue_result(
        state,
        &result,
        request_ca_id,
        device_id,
        Some(request_subject),
        started,
        source,
    )
    .await;
    result
}

fn acquire_issue_permit(state: &AppState) -> AppResult<OwnedSemaphorePermit> {
    state
        .issue_limiter
        .clone()
        .try_acquire_owned()
        .map_err(|_| {
            AppError::TooManyRequests(format!(
                "동시 인증서 발급 요청이 너무 많습니다: limit={}",
                state.settings.max_concurrent_issuance.max(1)
            ))
        })
}

async fn issue_from_csr_inner(
    state: &AppState,
    request: IssueCsrRequest,
    actor: &str,
    source: &str,
) -> AppResult<CertificateResponse> {
    let ca = resolve_ca(state, request.ca_id.as_deref()).await?;
    let issuer = load_issuer(&ca).await?;
    let policy = resolve_issuance_policy(
        state,
        request.certificate_profile_id.as_deref(),
        request.end_entity_profile_id.as_deref(),
    )
    .await?;
    enforce_issue_access_rules(state, actor, source, &ca, &policy).await?;
    let validity_days = policy_validity_days(&policy, request.validity_days);
    let not_before = now() - Duration::minutes(5);
    let not_after = days_from_now(validity_days);
    let (serial, serial_hex) = new_serial();

    let mut csr = CertificateSigningRequestParams::from_pem(&request.csr_pem)
        .map_err(|err| AppError::BadRequest(format!("CSR 파싱/검증에 실패했습니다: {err}")))?;
    let subject_dn = format_distinguished_name(&csr.params.distinguished_name);
    let dns_names = san_to_dns_names(&csr.params.subject_alt_names);
    crate::ra::ensure_end_entity_matches_request(
        state,
        request.end_entity_id.as_deref(),
        &subject_dn,
        &dns_names,
    )
    .await?;
    let approval_target = request
        .end_entity_id
        .as_deref()
        .unwrap_or(&subject_dn)
        .to_string();
    crate::ra::ensure_approval_permits(
        state,
        "issue",
        &approval_target,
        request.approval_id.as_deref(),
    )
    .await?;
    let end_entity_id = request.end_entity_id.clone();
    validate_issuance_policy(&policy, &subject_dn, &dns_names, IssuanceMode::Csr)?;

    validate_pre_issue(
        state,
        &ValidationContext {
            ca_id: ca.id.clone(),
            subject_dn: subject_dn.clone(),
            dns_names: dns_names.clone(),
            csr_pem: Some(request.csr_pem.clone()),
        },
    )
    .await?;

    csr.params.serial_number = Some(serial);
    csr.params.not_before = not_before;
    csr.params.not_after = not_after;
    csr.params.use_authority_key_identifier_extension = true;
    if csr.params.key_usages.is_empty() {
        csr.params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
    }
    if csr.params.extended_key_usages.is_empty() {
        csr.params.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth,
        ];
    }
    csr.params.crl_distribution_points = vec![CrlDistributionPoint {
        uris: vec![format!(
            "{}/crl/{}/latest",
            state.settings.public_base_url.trim_end_matches('/'),
            ca.id
        )],
    }];

    let cert = csr.signed_by(&issuer)?;
    let record = build_record(
        &ca,
        &policy,
        serial_hex,
        subject_dn,
        dns_names,
        cert.pem(),
        cert.der().as_ref().to_vec(),
        Some(request.csr_pem),
        not_before.unix_timestamp(),
        not_after.unix_timestamp(),
    )?;
    store_issued_certificate(state, actor, &record).await?;
    crate::ra::mark_end_entity_generated(state, end_entity_id.as_deref()).await?;
    crate::publisher::dispatch_certificate_event(state, "issue", &record, actor).await?;
    Ok(to_response(record, None))
}

async fn issue_from_public_key_inner(
    state: &AppState,
    request: IssuePublicKeyRequest,
    actor: &str,
    source: &str,
) -> AppResult<CertificateResponse> {
    let ca = resolve_ca(state, request.ca_id.as_deref()).await?;
    let issuer = load_issuer(&ca).await?;
    let policy = resolve_issuance_policy(
        state,
        request.certificate_profile_id.as_deref(),
        request.end_entity_profile_id.as_deref(),
    )
    .await?;
    enforce_issue_access_rules(state, actor, source, &ca, &policy).await?;
    validate_issuance_policy(
        &policy,
        &request.subject_dn,
        &request.dns_names,
        IssuanceMode::ClientProvidedKey,
    )?;
    let public_key = SubjectPublicKeyInfo::from_der(&request.subject_public_key_info_der)
        .map_err(|err| AppError::BadRequest(format!("SubjectPublicKeyInfo 파싱 실패: {err}")))?;
    let validity_days = policy_validity_days(&policy, request.validity_days);
    let not_before = now() - Duration::minutes(5);
    let not_after = days_from_now(validity_days);
    let (serial, serial_hex) = new_serial();

    let mut params = CertificateParams::new(request.dns_names.clone())?;
    params.distinguished_name = parse_distinguished_name(&request.subject_dn)?;
    params.serial_number = Some(serial);
    params.not_before = not_before;
    params.not_after = not_after;
    params.use_authority_key_identifier_extension = true;
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    params.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ServerAuth,
        ExtendedKeyUsagePurpose::ClientAuth,
    ];
    params.crl_distribution_points = vec![CrlDistributionPoint {
        uris: vec![format!(
            "{}/crl/{}/latest",
            state.settings.public_base_url.trim_end_matches('/'),
            ca.id
        )],
    }];

    validate_pre_issue(
        state,
        &ValidationContext {
            ca_id: ca.id.clone(),
            subject_dn: request.subject_dn.clone(),
            dns_names: request.dns_names.clone(),
            csr_pem: None,
        },
    )
    .await?;

    let cert = params.signed_by(&public_key, &issuer)?;
    let record = build_record(
        &ca,
        &policy,
        serial_hex,
        request.subject_dn,
        request.dns_names,
        cert.pem(),
        cert.der().as_ref().to_vec(),
        None,
        not_before.unix_timestamp(),
        not_after.unix_timestamp(),
    )?;
    store_issued_certificate(state, actor, &record).await?;
    crate::publisher::dispatch_certificate_event(state, "issue", &record, actor).await?;
    Ok(to_response(record, None))
}

pub async fn list_certificates(
    state: &AppState,
    filter: CertificateFilter,
    limit: i64,
) -> AppResult<Vec<CertificateSummaryResponse>> {
    Ok(state
        .db
        .list_certificates(&filter, limit.clamp(1, 500))
        .await?
        .into_iter()
        .map(to_summary_response)
        .collect())
}

pub async fn get_certificate(state: &AppState, cert_id: &str) -> AppResult<CertificateResponse> {
    let record = state
        .db
        .get_certificate(cert_id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("인증서를 찾을 수 없습니다: {cert_id}")))?;
    Ok(to_response(record, None))
}

pub async fn certificate_pem(state: &AppState, cert_id: &str) -> AppResult<String> {
    let record = state
        .db
        .get_certificate(cert_id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("인증서를 찾을 수 없습니다: {cert_id}")))?;
    Ok(record.cert_pem)
}

pub async fn certificate_der(state: &AppState, cert_id: &str) -> AppResult<Vec<u8>> {
    let record = state
        .db
        .get_certificate(cert_id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("인증서를 찾을 수 없습니다: {cert_id}")))?;
    Ok(record.cert_der)
}

pub fn build_pkcs12_der(
    cert_pem: &str,
    private_key_pem: &str,
    ca_cert_pem: Option<&str>,
    password: &str,
    friendly_name: &str,
) -> AppResult<Vec<u8>> {
    let cert = X509::from_pem(cert_pem.as_bytes())
        .map_err(|err| AppError::Internal(format!("PKCS#12 인증서 파싱 실패: {err}")))?;
    let key = PKey::private_key_from_pem(private_key_pem.as_bytes())
        .map_err(|err| AppError::Internal(format!("PKCS#12 private key 파싱 실패: {err}")))?;
    let mut builder = Pkcs12::builder();
    builder.name(friendly_name).cert(&cert).pkey(&key);
    if let Some(ca_cert_pem) = ca_cert_pem {
        let ca_cert = X509::from_pem(ca_cert_pem.as_bytes())
            .map_err(|err| AppError::Internal(format!("PKCS#12 CA 인증서 파싱 실패: {err}")))?;
        let mut chain = Stack::new()
            .map_err(|err| AppError::Internal(format!("PKCS#12 chain 생성 실패: {err}")))?;
        chain
            .push(ca_cert)
            .map_err(|err| AppError::Internal(format!("PKCS#12 CA chain 추가 실패: {err}")))?;
        builder.ca(chain);
    }
    builder
        .build2(password)
        .and_then(|pkcs12| pkcs12.to_der())
        .map_err(|err| AppError::Internal(format!("PKCS#12 생성 실패: {err}")))
}

fn safe_filename_component(value: &str) -> String {
    let safe = value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.') {
                ch
            } else {
                '-'
            }
        })
        .collect::<String>()
        .trim_matches('-')
        .to_string();
    if safe.is_empty() {
        "browser-certificate".to_string()
    } else {
        safe
    }
}

pub async fn revoke_certificate(
    state: &AppState,
    cert_id: &str,
    reason: Option<String>,
    approval_id: Option<String>,
    actor: &str,
) -> AppResult<CertificateResponse> {
    revoke_certificate_with_source(state, cert_id, reason, approval_id, actor, "admin_api").await
}

async fn revoke_certificate_with_source(
    state: &AppState,
    cert_id: &str,
    reason: Option<String>,
    approval_id: Option<String>,
    actor: &str,
    source: &str,
) -> AppResult<CertificateResponse> {
    crate::ra::ensure_approval_permits(state, "revoke", cert_id, approval_id.as_deref()).await?;
    let existing = state
        .db
        .get_certificate(cert_id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("인증서를 찾을 수 없습니다: {cert_id}")))?;
    enforce_revoke_access_rules(state, actor, source, &existing).await?;
    let reason = reason.unwrap_or_else(|| "unspecified".to_string());
    let details_json = serde_json::json!({"reason": reason}).to_string();
    let changed = state
        .db
        .revoke_certificate_with_audit(cert_id, &reason, actor, &details_json)
        .await?;
    if changed == 0 {
        return Err(AppError::NotFound(format!(
            "폐기할 활성 인증서를 찾지 못했습니다: {cert_id}"
        )));
    }
    let record = state
        .db
        .get_certificate(cert_id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("인증서를 찾을 수 없습니다: {cert_id}")))?;
    record_revoke_event(state, &record, actor).await;
    crate::publisher::dispatch_certificate_event(state, "revoke", &record, actor).await?;
    Ok(to_response(record, None))
}

pub async fn revoke_certificate_by_serial(
    state: &AppState,
    ca_id: &str,
    serial_hex: &str,
    reason: &str,
    actor: &str,
) -> AppResult<CertificateResponse> {
    let cert = state
        .db
        .get_certificate_by_serial(ca_id, serial_hex)
        .await?
        .ok_or_else(|| {
            AppError::NotFound(format!(
                "CA에서 serial에 해당하는 인증서를 찾을 수 없습니다: ca_id={ca_id}, serial={serial_hex}"
            ))
        })?;
    revoke_certificate_with_source(
        state,
        &cert.id,
        Some(reason.to_string()),
        None,
        actor,
        "cmp",
    )
    .await
}

async fn resolve_ca(state: &AppState, ca_id: Option<&str>) -> AppResult<CaRecord> {
    if let Some(ca_id) = ca_id {
        let ca = state
            .db
            .get_ca(ca_id)
            .await?
            .ok_or_else(|| AppError::NotFound(format!("CA를 찾을 수 없습니다: {ca_id}")))?;
        if ca.status != "active" {
            return Err(AppError::BadRequest(format!(
                "비활성 CA로는 인증서를 발급할 수 없습니다: {ca_id}"
            )));
        }
        return Ok(ca);
    }
    let cas = state.db.list_cas().await?;
    cas.iter()
        .find(|ca| ca.is_default && ca.status == "active")
        .cloned()
        .or_else(|| cas.into_iter().find(|ca| ca.status == "active"))
        .ok_or_else(|| AppError::NotFound("사용 가능한 CA가 없습니다".to_string()))
}

#[derive(Debug, Clone, Copy)]
enum IssuanceMode {
    ServerGeneratedKey,
    Csr,
    ClientProvidedKey,
}

#[derive(Debug, Clone)]
struct IssuancePolicy {
    certificate_profile: Option<CertificateProfileRecord>,
    end_entity_profile: Option<EndEntityProfileRecord>,
}

async fn resolve_issuance_policy(
    state: &AppState,
    certificate_profile_id: Option<&str>,
    end_entity_profile_id: Option<&str>,
) -> AppResult<IssuancePolicy> {
    let end_entity_profile = match end_entity_profile_id {
        Some(id) => Some(state.db.get_end_entity_profile(id).await?.ok_or_else(|| {
            AppError::NotFound(format!("end entity profile을 찾을 수 없습니다: {id}"))
        })?),
        None => state
            .db
            .list_end_entity_profiles()
            .await?
            .into_iter()
            .next(),
    };

    let effective_certificate_profile_id =
        certificate_profile_id.map(ToOwned::to_owned).or_else(|| {
            end_entity_profile
                .as_ref()
                .and_then(|profile| profile.default_certificate_profile_id.clone())
        });
    let certificate_profile = match effective_certificate_profile_id {
        Some(id) => Some(
            state
                .db
                .get_certificate_profile(&id)
                .await?
                .ok_or_else(|| {
                    AppError::NotFound(format!("certificate profile을 찾을 수 없습니다: {id}"))
                })?,
        ),
        None => state
            .db
            .list_certificate_profiles()
            .await?
            .into_iter()
            .next(),
    };

    Ok(IssuancePolicy {
        certificate_profile,
        end_entity_profile,
    })
}

fn policy_validity_days(policy: &IssuancePolicy, requested_days: Option<i64>) -> i64 {
    let profile_max = policy
        .certificate_profile
        .as_ref()
        .map(|profile| profile.validity_days)
        .unwrap_or(825)
        .clamp(1, 825);
    requested_days.unwrap_or(profile_max).clamp(1, profile_max)
}

async fn enforce_issue_access_rules(
    state: &AppState,
    actor: &str,
    protocol: &str,
    ca: &CaRecord,
    policy: &IssuancePolicy,
) -> AppResult<()> {
    crate::access_rules::enforce_access_rules(
        state,
        &crate::access_rules::AccessRuleContext {
            actor,
            action: "issue",
            protocol,
            ca_id: Some(ca.id.as_str()),
            certificate_profile_id: policy
                .certificate_profile
                .as_ref()
                .map(|profile| profile.id.as_str()),
            end_entity_profile_id: policy
                .end_entity_profile
                .as_ref()
                .map(|profile| profile.id.as_str()),
        },
    )
    .await
}

async fn enforce_revoke_access_rules(
    state: &AppState,
    actor: &str,
    protocol: &str,
    record: &CertificateRecord,
) -> AppResult<()> {
    crate::access_rules::enforce_access_rules(
        state,
        &crate::access_rules::AccessRuleContext {
            actor,
            action: "revoke",
            protocol,
            ca_id: Some(record.ca_id.as_str()),
            certificate_profile_id: record.certificate_profile_id.as_deref(),
            end_entity_profile_id: record.end_entity_profile_id.as_deref(),
        },
    )
    .await
}

fn validate_issuance_policy(
    policy: &IssuancePolicy,
    subject_dn: &str,
    dns_names: &[String],
    mode: IssuanceMode,
) -> AppResult<()> {
    if let Some(profile) = &policy.certificate_profile {
        if matches!(mode, IssuanceMode::ServerGeneratedKey) && !profile.allow_server_generated_key {
            return Err(AppError::Forbidden(format!(
                "certificate profile이 서버 키 생성을 허용하지 않습니다: {}",
                profile.name
            )));
        }
        if profile.require_san && dns_names.is_empty() {
            return Err(AppError::BadRequest(format!(
                "certificate profile이 SAN을 필수로 요구합니다: {}",
                profile.name
            )));
        }
    }

    if let Some(profile) = &policy.end_entity_profile {
        if let Some(pattern) = profile.subject_regex.as_deref() {
            let regex = Regex::new(pattern).map_err(|err| {
                AppError::Internal(format!(
                    "end entity profile subject regex가 올바르지 않습니다: {err}"
                ))
            })?;
            if !regex.is_match(subject_dn) {
                return Err(AppError::Forbidden(format!(
                    "subject DN이 end entity profile 규칙과 일치하지 않습니다: {}",
                    profile.name
                )));
            }
        }

        let allowed_domains: Vec<String> =
            serde_json::from_str(&profile.allowed_dns_domains_json).unwrap_or_default();
        if !allowed_domains.is_empty()
            && !dns_names
                .iter()
                .all(|dns| dns_allowed_by_domains(dns, &allowed_domains))
        {
            return Err(AppError::Forbidden(format!(
                "DNS SAN이 end entity profile 허용 도메인 밖에 있습니다: {}",
                profile.name
            )));
        }
    }
    Ok(())
}

fn dns_allowed_by_domains(dns: &str, domains: &[String]) -> bool {
    let dns = dns.trim_end_matches('.').to_ascii_lowercase();
    domains.iter().any(|domain| {
        let domain = domain.trim().trim_start_matches('.').to_ascii_lowercase();
        dns == domain || dns.ends_with(&format!(".{domain}"))
    })
}

fn build_record(
    ca: &CaRecord,
    policy: &IssuancePolicy,
    serial_hex: String,
    subject_dn: String,
    dns_names: Vec<String>,
    cert_pem: String,
    cert_der: Vec<u8>,
    csr_pem: Option<String>,
    not_before: i64,
    not_after: i64,
) -> AppResult<CertificateRecord> {
    Ok(CertificateRecord {
        id: Uuid::new_v4().to_string(),
        ca_id: ca.id.clone(),
        certificate_profile_id: policy
            .certificate_profile
            .as_ref()
            .map(|profile| profile.id.clone()),
        end_entity_profile_id: policy
            .end_entity_profile
            .as_ref()
            .map(|profile| profile.id.clone()),
        serial_hex,
        subject_dn,
        san_json: serde_json::to_string(&dns_names)
            .map_err(|err| AppError::Internal(err.to_string()))?,
        cert_pem,
        fingerprint_sha256: fingerprint_sha256(&cert_der),
        cert_der,
        csr_pem,
        status: "active".to_string(),
        revocation_reason: None,
        revoked_at: None,
        not_before,
        not_after,
        created_at: now().unix_timestamp(),
    })
}

fn to_response(record: CertificateRecord, private_key_pem: Option<String>) -> CertificateResponse {
    let dns_names = serde_json::from_str(&record.san_json).unwrap_or_default();
    CertificateResponse {
        id: record.id,
        ca_id: record.ca_id,
        certificate_profile_id: record.certificate_profile_id,
        end_entity_profile_id: record.end_entity_profile_id,
        serial_hex: record.serial_hex,
        subject_dn: record.subject_dn,
        dns_names,
        cert_pem: record.cert_pem,
        private_key_pem,
        status: record.status,
        revocation_reason: record.revocation_reason,
        revoked_at: record.revoked_at,
        not_before: record.not_before,
        not_after: record.not_after,
        fingerprint_sha256: record.fingerprint_sha256,
        created_at: record.created_at,
    }
}

fn to_summary_response(record: CertificateRecord) -> CertificateSummaryResponse {
    let dns_names = serde_json::from_str(&record.san_json).unwrap_or_default();
    CertificateSummaryResponse {
        id: record.id,
        ca_id: record.ca_id,
        certificate_profile_id: record.certificate_profile_id,
        end_entity_profile_id: record.end_entity_profile_id,
        serial_hex: record.serial_hex,
        subject_dn: record.subject_dn,
        dns_names,
        status: record.status,
        revocation_reason: record.revocation_reason,
        revoked_at: record.revoked_at,
        not_before: record.not_before,
        not_after: record.not_after,
        fingerprint_sha256: record.fingerprint_sha256,
        created_at: record.created_at,
    }
}

fn san_to_dns_names(sans: &[SanType]) -> Vec<String> {
    sans.iter()
        .filter_map(|san| match san {
            SanType::DnsName(value) => Some(value.to_string()),
            _ => None,
        })
        .collect()
}

async fn record_issue_result(
    state: &AppState,
    result: &AppResult<CertificateResponse>,
    fallback_ca_id: Option<String>,
    fallback_device_id: Option<String>,
    fallback_subject_dn: Option<String>,
    started: std::time::Instant,
    source: &str,
) {
    match result {
        Ok(response) => {
            record_issue_event(
                state,
                "success",
                Some(response.ca_id.clone()),
                Some(response.id.clone()),
                Some(response.serial_hex.clone()),
                device_id_from_parts(&response.subject_dn, &response.dns_names)
                    .or(fallback_device_id),
                Some(response.subject_dn.clone()),
                source,
                None,
                Some(started.elapsed().as_millis().min(i64::MAX as u128) as i64),
            )
            .await;
        }
        Err(err) => {
            record_issue_event(
                state,
                "failure",
                fallback_ca_id,
                None,
                None,
                fallback_device_id,
                fallback_subject_dn,
                source,
                Some(error_code(err)),
                Some(started.elapsed().as_millis().min(i64::MAX as u128) as i64),
            )
            .await;
        }
    }
}

async fn record_issue_event(
    state: &AppState,
    status: &str,
    ca_id: Option<String>,
    certificate_id: Option<String>,
    serial_hex: Option<String>,
    device_id: Option<String>,
    subject_dn: Option<String>,
    source: &str,
    error_code: Option<String>,
    latency_ms: Option<i64>,
) {
    let event = NewCertificateEvent {
        event_type: "issue".to_string(),
        status: status.to_string(),
        ca_id,
        certificate_id,
        serial_hex,
        device_id,
        subject_dn,
        source: source.to_string(),
        error_code,
        latency_ms,
    };
    if let Err(err) = state.db.record_certificate_event(event).await {
        tracing::warn!("발급 metrics 이벤트 저장 실패: {err}");
    }
}

async fn record_revoke_event(state: &AppState, record: &CertificateRecord, source: &str) {
    let dns_names: Vec<String> = serde_json::from_str(&record.san_json).unwrap_or_default();
    let event = NewCertificateEvent {
        event_type: "revoke".to_string(),
        status: "success".to_string(),
        ca_id: Some(record.ca_id.clone()),
        certificate_id: Some(record.id.clone()),
        serial_hex: Some(record.serial_hex.clone()),
        device_id: device_id_from_parts(&record.subject_dn, &dns_names),
        subject_dn: Some(record.subject_dn.clone()),
        source: source.to_string(),
        error_code: None,
        latency_ms: None,
    };
    if let Err(err) = state.db.record_certificate_event(event).await {
        tracing::warn!("폐기 metrics 이벤트 저장 실패: {err}");
    }
}

fn device_id_from_parts(subject_dn: &str, dns_names: &[String]) -> Option<String> {
    dns_names
        .first()
        .cloned()
        .or_else(|| subject_dn_cn(subject_dn))
}

fn subject_dn_cn(subject_dn: &str) -> Option<String> {
    subject_dn.split(',').find_map(|part| {
        let (key, value) = part.split_once('=')?;
        if key.trim().eq_ignore_ascii_case("CN") {
            Some(value.trim().to_string()).filter(|value| !value.is_empty())
        } else {
            None
        }
    })
}

fn error_code(err: &AppError) -> String {
    match err {
        AppError::BadRequest(_) => "bad_request",
        AppError::Unauthorized(_) => "unauthorized",
        AppError::Forbidden(_) => "forbidden",
        AppError::NotFound(_) => "not_found",
        AppError::Conflict(_) => "conflict",
        AppError::TooManyRequests(_) => "too_many_requests",
        AppError::Sqlx(_) => "database",
        AppError::Rcgen(_) => "crypto",
        AppError::Reqwest(_) => "http_client",
        AppError::Internal(_) => "internal",
    }
    .to_string()
}

async fn store_issued_certificate(
    state: &AppState,
    actor: &str,
    record: &CertificateRecord,
) -> AppResult<()> {
    state
        .db
        .insert_certificate_with_audit(
            record,
            actor,
            "certificate.issue",
            &record.id,
            "success",
            &serde_json::json!({
                "ca_id": record.ca_id,
                "serial": record.serial_hex,
                "subject_dn": record.subject_dn
            })
            .to_string(),
        )
        .await
}

#[cfg(test)]
mod tests {
    use std::{collections::HashSet, path::PathBuf, sync::Arc};

    use tokio::sync::Semaphore;

    use super::*;
    use crate::{
        ca,
        config::Settings,
        profiles,
        storage::{Db, EjbcaFeatureRecord},
    };

    async fn test_state(max_concurrent_issuance: usize) -> (AppState, PathBuf) {
        let data_dir = std::env::temp_dir().join(format!("ejbca-rs-cert-test-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&data_dir).expect("테스트 data dir 생성 실패");
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
            database_max_connections: 16,
            database_busy_timeout_seconds: 30,
            max_concurrent_issuance,
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
            issue_limiter: Arc::new(Semaphore::new(max_concurrent_issuance.max(1))),
        };
        ca::service::ensure_default_ca(&state).await.unwrap();
        profiles::service::ensure_default_profiles(&state)
            .await
            .unwrap();
        (state, data_dir)
    }

    fn generated_request(index: usize) -> IssueCertificateRequest {
        IssueCertificateRequest {
            end_entity_id: None,
            approval_id: None,
            ca_id: None,
            certificate_profile_id: None,
            end_entity_profile_id: None,
            subject_dn: format!("CN=device-{index:03},O=Load Test"),
            dns_names: vec![format!("device-{index:03}.example.com")],
            validity_days: Some(30),
        }
    }

    #[tokio::test]
    async fn issue_pkcs12_returns_browser_importable_bundle() {
        let (state, data_dir) = test_state(4).await;
        let response = issue_pkcs12(
            &state,
            IssuePkcs12Request {
                end_entity_id: None,
                approval_id: None,
                ca_id: None,
                certificate_profile_id: None,
                end_entity_profile_id: None,
                subject_dn: "CN=browser-admin,O=Load Test".to_string(),
                dns_names: vec!["browser-admin.example.com".to_string()],
                validity_days: Some(30),
                pkcs12_password: "changeit".to_string(),
                friendly_name: Some("browser-admin".to_string()),
            },
            "pkcs12-test",
        )
        .await
        .unwrap();

        assert!(response.filename.ends_with(".p12"));
        assert!(!response.der.is_empty());
        let parsed = Pkcs12::from_der(&response.der)
            .unwrap()
            .parse2("changeit")
            .unwrap();
        assert!(parsed.cert.is_some());
        assert!(parsed.pkey.is_some());

        std::fs::remove_dir_all(data_dir).ok();
    }

    #[tokio::test]
    async fn file_publisher_receives_issue_and_revoke_events() {
        let (state, data_dir) = test_state(4).await;
        let publisher_path = data_dir.join("publisher-events.ndjson");
        let now = crate::util::now_unix();
        state
            .db
            .insert_ejbca_feature(&EjbcaFeatureRecord {
                id: "file-publisher".to_string(),
                feature_type: "publisher".to_string(),
                name: "file-publisher".to_string(),
                status: "active".to_string(),
                config_json: serde_json::json!({
                    "type": "file",
                    "path": publisher_path,
                    "events": ["issue", "revoke"]
                })
                .to_string(),
                created_at: now,
                updated_at: now,
            })
            .await
            .unwrap();

        let issued = issue_generated(&state, generated_request(1), "publisher-test")
            .await
            .unwrap();
        revoke_certificate(
            &state,
            &issued.id,
            Some("key_compromise".to_string()),
            None,
            "publisher-test",
        )
        .await
        .unwrap();

        let published = tokio::fs::read_to_string(&publisher_path).await.unwrap();
        assert!(published.contains(r#""event_type":"issue""#));
        assert!(published.contains(r#""event_type":"revoke""#));
        assert!(published.contains(&issued.serial_hex));

        std::fs::remove_dir_all(data_dir).ok();
    }

    #[tokio::test]
    async fn access_rule_scopes_limit_issue_by_actor_ca_profile_and_protocol() {
        let (state, data_dir) = test_state(4).await;
        let ca = state.db.list_cas().await.unwrap().remove(0);
        let certificate_profile = state
            .db
            .list_certificate_profiles()
            .await
            .unwrap()
            .remove(0);
        let end_entity_profile = state.db.list_end_entity_profiles().await.unwrap().remove(0);
        let now = crate::util::now_unix();
        state
            .db
            .insert_ejbca_feature(&EjbcaFeatureRecord {
                id: "access-rule-issue-scope".to_string(),
                feature_type: "access_rule".to_string(),
                name: "issue-scope".to_string(),
                status: "active".to_string(),
                config_json: serde_json::json!({
                    "mode": "allowlist",
                    "rules": [{
                        "effect": "allow",
                        "actors": ["role:issuer"],
                        "actions": ["issue", "revoke"],
                        "protocols": ["admin_api"],
                        "ca_ids": [ca.id],
                        "certificate_profile_ids": [certificate_profile.id],
                        "end_entity_profile_ids": [end_entity_profile.id]
                    }]
                })
                .to_string(),
                created_at: now,
                updated_at: now,
            })
            .await
            .unwrap();

        let mut allowed = generated_request(1);
        allowed.ca_id = Some(ca.id.clone());
        allowed.certificate_profile_id = Some(certificate_profile.id.clone());
        allowed.end_entity_profile_id = Some(end_entity_profile.id.clone());
        let issued = issue_generated(&state, allowed, "role:issuer")
            .await
            .unwrap();
        assert_eq!(
            issued.certificate_profile_id.as_deref(),
            Some(certificate_profile.id.as_str())
        );
        assert_eq!(
            issued.end_entity_profile_id.as_deref(),
            Some(end_entity_profile.id.as_str())
        );
        revoke_certificate(
            &state,
            &issued.id,
            Some("superseded".to_string()),
            None,
            "role:issuer",
        )
        .await
        .unwrap();

        let mut denied = generated_request(2);
        denied.ca_id = Some(ca.id);
        denied.certificate_profile_id = Some(certificate_profile.id);
        denied.end_entity_profile_id = Some(end_entity_profile.id);
        let result = issue_generated(&state, denied, "role:other").await;
        assert!(matches!(result, Err(AppError::Forbidden(_))));

        std::fs::remove_dir_all(data_dir).ok();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_generated_issuance_keeps_metrics_and_audit_chain_valid() {
        let (state, data_dir) = test_state(32).await;
        let issue_count = 24usize;
        let mut tasks = Vec::with_capacity(issue_count);

        for index in 0..issue_count {
            let state = state.clone();
            tasks.push(tokio::spawn(async move {
                issue_generated(&state, generated_request(index), "load-test").await
            }));
        }

        let mut serials = HashSet::with_capacity(issue_count);
        for task in tasks {
            let response = task.await.unwrap().unwrap();
            assert!(serials.insert(response.serial_hex));
            assert!(response.private_key_pem.is_some());
        }

        let certificates = state
            .db
            .list_certificates(&CertificateFilter::default(), issue_count as i64 + 10)
            .await
            .unwrap();
        assert_eq!(certificates.len(), issue_count);

        let summary = state.db.summary().await.unwrap();
        assert_eq!(summary.issue_success_count, issue_count as i64);
        assert_eq!(summary.issue_failure_count, 0);

        let chain = state.db.verify_audit_chain().await.unwrap();
        assert!(chain.valid, "{chain:?}");
        assert_eq!(chain.legacy_events, 0);
        assert!(chain.checked_events >= issue_count as u64);

        std::fs::remove_dir_all(data_dir).ok();
    }

    #[tokio::test]
    async fn issuance_limiter_rejects_without_queueing_and_records_failure_metric() {
        let (state, data_dir) = test_state(1).await;
        let _held_permit = state.issue_limiter.clone().try_acquire_owned().unwrap();

        let result = issue_generated(&state, generated_request(1), "load-test").await;
        assert!(matches!(result, Err(AppError::TooManyRequests(_))));

        let certificates = state
            .db
            .list_certificates(&CertificateFilter::default(), 10)
            .await
            .unwrap();
        assert!(certificates.is_empty());

        let summary = state.db.summary().await.unwrap();
        assert_eq!(summary.issue_success_count, 0);
        assert_eq!(summary.issue_failure_count, 1);

        let chain = state.db.verify_audit_chain().await.unwrap();
        assert!(chain.valid, "{chain:?}");

        std::fs::remove_dir_all(data_dir).ok();
    }

    #[tokio::test]
    async fn audit_failure_rolls_back_issued_certificate() {
        let (state, data_dir) = test_state(4).await;
        sqlx::query(
            r#"
            CREATE TRIGGER fail_issue_audit
            BEFORE INSERT ON audit_events
            WHEN NEW.action = 'certificate.issue'
            BEGIN
                SELECT RAISE(ABORT, 'forced audit failure');
            END
            "#,
        )
        .execute(state.db.pool())
        .await
        .unwrap();

        let result = issue_generated(&state, generated_request(1), "atomicity-test").await;
        assert!(matches!(result, Err(AppError::Sqlx(_))));

        let certificates = state
            .db
            .list_certificates(&CertificateFilter::default(), 10)
            .await
            .unwrap();
        assert!(certificates.is_empty());

        let summary = state.db.summary().await.unwrap();
        assert_eq!(summary.issue_success_count, 0);
        assert_eq!(summary.issue_failure_count, 1);

        let chain = state.db.verify_audit_chain().await.unwrap();
        assert!(chain.valid, "{chain:?}");

        std::fs::remove_dir_all(data_dir).ok();
    }

    #[tokio::test]
    async fn audit_failure_rolls_back_revocation_status_change() {
        let (state, data_dir) = test_state(4).await;
        let issued = issue_generated(&state, generated_request(1), "atomicity-test")
            .await
            .unwrap();
        sqlx::query(
            r#"
            CREATE TRIGGER fail_revoke_audit
            BEFORE INSERT ON audit_events
            WHEN NEW.action = 'certificate.revoke'
            BEGIN
                SELECT RAISE(ABORT, 'forced audit failure');
            END
            "#,
        )
        .execute(state.db.pool())
        .await
        .unwrap();

        let result = revoke_certificate(
            &state,
            &issued.id,
            Some("key_compromise".to_string()),
            None,
            "atomicity-test",
        )
        .await;
        assert!(matches!(result, Err(AppError::Sqlx(_))));

        let certificate = state.db.get_certificate(&issued.id).await.unwrap().unwrap();
        assert_eq!(certificate.status, "active");
        assert!(certificate.revoked_at.is_none());
        assert!(certificate.revocation_reason.is_none());

        let chain = state.db.verify_audit_chain().await.unwrap();
        assert!(chain.valid, "{chain:?}");

        std::fs::remove_dir_all(data_dir).ok();
    }
}
