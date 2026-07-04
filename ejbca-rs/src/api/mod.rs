use axum::{
    Json, Router,
    body::Bytes,
    extract::{DefaultBodyLimit, Path, Query, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post, put},
};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE, URL_SAFE_NO_PAD},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use time::{Duration, OffsetDateTime, UtcOffset, macros::format_description};
use tower_http::{
    cors::{AllowOrigin, CorsLayer},
    services::ServeDir,
};
use x509_parser::prelude::{FromDer, X509Certificate};

use crate::config::Settings;
use crate::{
    AppState,
    ca::{CreateCaRequest, ImportCaRequest, UpdateCaRequest, service as ca_service},
    certs::{
        IssueCertificateRequest, IssueCsrRequest, IssuePkcs12Request, RevokeCertificateRequest,
        service as cert_service,
    },
    cmp::service as cmp_service,
    crl::{GenerateCrlRequest, service as crl_service},
    error::{AppError, AppResult},
    maintenance::{
        MaintenanceRequest, UpdateMaintenanceConfigRequest, service as maintenance_service,
    },
    metrics,
    ocsp::{BinaryOcspResponse, service as ocsp_service},
    profiles::{
        CreateAccessRoleRequest, CreateCertificateProfileRequest, CreateCmpAliasRequest,
        CreateEndEntityProfileRequest, UpdateAccessRoleRequest, UpdateCertificateProfileRequest,
        UpdateCmpAliasRequest, UpdateEndEntityProfileRequest, service as profile_service,
    },
    storage::{AccessRoleRecord, AuditEventFilter, CertificateFilter},
    validators::{CreateValidatorRequest, UpdateValidatorRequest, service as validator_service},
};

#[derive(Debug, Deserialize)]
struct ListQuery {
    limit: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct CertificateListQuery {
    limit: Option<i64>,
    ca_id: Option<String>,
    status: Option<String>,
    serial_hex: Option<String>,
    subject: Option<String>,
    expires_before: Option<i64>,
    expires_after: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct CertificateDownloadQuery {
    format: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AuditQuery {
    limit: Option<i64>,
    actor: Option<String>,
    action: Option<String>,
    target: Option<String>,
    status: Option<String>,
    since: Option<i64>,
    until: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct LatestCrlQuery {
    partition: Option<i64>,
    delta: Option<bool>,
}

pub fn router(state: AppState) -> Router {
    let body_limit = state.settings.max_request_bytes;
    let cors = cors_layer(&state.settings.cors_allowed_origins);
    let app = Router::new()
        .route("/health", get(health))
        .route("/api/v1/adminweb/session", get(adminweb_session))
        .route("/metrics", get(prometheus_metrics))
        .route("/api/v1/summary", get(summary))
        .route("/api/v1/cas", get(list_cas).post(create_ca))
        .route("/api/v1/cas/{id}", put(update_ca))
        .route("/api/v1/cas/import", post(import_ca))
        .route(
            "/api/v1/certificate-profiles",
            get(list_certificate_profiles).post(create_certificate_profile),
        )
        .route(
            "/api/v1/certificate-profiles/{id}",
            put(update_certificate_profile).delete(delete_certificate_profile),
        )
        .route(
            "/api/v1/end-entity-profiles",
            get(list_end_entity_profiles).post(create_end_entity_profile),
        )
        .route(
            "/api/v1/end-entity-profiles/{id}",
            put(update_end_entity_profile).delete(delete_end_entity_profile),
        )
        .route(
            "/api/v1/cmp-aliases",
            get(list_cmp_aliases).post(create_cmp_alias),
        )
        .route(
            "/api/v1/cmp-aliases/{id}",
            put(update_cmp_alias).delete(delete_cmp_alias),
        )
        .route(
            "/api/v1/access-roles",
            get(list_access_roles).post(create_access_role),
        )
        .route(
            "/api/v1/access-roles/{id}",
            put(update_access_role).delete(delete_access_role),
        )
        .route("/api/v1/certificates", get(list_certificates))
        .route("/api/v1/certificates/issue", post(issue_generated))
        .route("/api/v1/certificates/issue-pkcs12", post(issue_pkcs12))
        .route("/api/v1/certificates/issue-csr", post(issue_csr))
        .route("/api/v1/certificates/{id}", get(get_certificate))
        .route(
            "/api/v1/certificates/{id}/download",
            get(download_certificate),
        )
        .route("/api/v1/certificates/{id}/revoke", post(revoke_certificate))
        .route("/api/v1/crls", get(list_crls))
        .route("/api/v1/crls/generate", post(generate_crl))
        .route("/api/v1/crls/{id}/download", get(download_crl_by_id))
        .route(
            "/api/v1/validators",
            get(list_validators).post(create_validator),
        )
        .route(
            "/api/v1/validators/{id}",
            put(update_validator).delete(delete_validator),
        )
        .route(
            "/api/v1/maintenance/config",
            get(maintenance_config).put(update_maintenance_config),
        )
        .route("/api/v1/maintenance/run", post(run_maintenance))
        .route("/api/v1/audit-events", get(list_audit_events))
        .route("/api/v1/audit-events/verify", get(verify_audit_events))
        .route("/api/v1/ocsp/status/{ca_id}/{serial_hex}", get(ocsp_status))
        .route("/ocsp", get(ocsp_binary_empty).post(ocsp_binary_post))
        .route("/ocsp/{encoded}", get(ocsp_binary_get))
        .route("/cmp/{alias}", post(cmp))
        .route("/crl/{ca_id}/latest", get(download_latest_crl))
        .fallback_service(ServeDir::new("web/dist"))
        .layer(DefaultBodyLimit::max(body_limit));
    let app = if let Some(cors) = cors {
        app.layer(cors)
    } else {
        app
    };
    app.with_state(state)
}

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({"status": "ok"}))
}

#[derive(Debug, Serialize)]
struct AdminWebSessionResponse {
    required: bool,
    authenticated: bool,
    mode: &'static str,
    role_name: Option<String>,
    subject_dn: Option<String>,
    issuer_dn: Option<String>,
    serial_hex: Option<String>,
    fingerprint_sha256: Option<String>,
    detail: String,
}

#[derive(Debug, Clone)]
struct ParsedClientCertificate {
    subject_dn: String,
    issuer_dn: String,
    serial_hex: String,
    fingerprint_sha256: String,
}

async fn adminweb_session(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Json<AdminWebSessionResponse> {
    let mut session = evaluate_adminweb_certificate(&state, &headers);
    if session.authenticated {
        if let (Some(subject_dn), Some(issuer_dn), Some(serial_hex), Some(fingerprint_sha256)) = (
            session.subject_dn.clone(),
            session.issuer_dn.clone(),
            session.serial_hex.clone(),
            session.fingerprint_sha256.clone(),
        ) {
            let parsed = ParsedClientCertificate {
                subject_dn,
                issuer_dn,
                serial_hex,
                fingerprint_sha256,
            };
            match authorize_client_certificate_role(&state, &parsed, None).await {
                Ok(CertificateRoleAuthorization::Authorized(role)) => {
                    session.role_name = Some(role.name.clone());
                    session.detail = format!(
                        "AdminWeb client certificate가 access role '{}'로 확인되었습니다",
                        role.name
                    );
                }
                Ok(CertificateRoleAuthorization::NoMatchingRole) if session.required => {
                    session.authenticated = false;
                    session.detail =
                        "AdminWeb client certificate에 매칭되는 access role이 없습니다".to_string();
                }
                Ok(CertificateRoleAuthorization::NoMatchingRole) => {}
                Ok(CertificateRoleAuthorization::Forbidden(_)) => {}
                Err(err) => {
                    session.authenticated = false;
                    session.detail = err.to_string();
                }
            }
        }
    }
    Json(session)
}

async fn prometheus_metrics(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Response> {
    let (metrics_enabled, metrics_public, device_limit) =
        maintenance_service::metrics_config(&state).await?;
    if !metrics_enabled {
        return Err(AppError::NotFound(
            "metrics가 비활성화되어 있습니다".to_string(),
        ));
    }
    if !metrics_public {
        require_permission(&state, &headers, "read").await?;
    }
    let body = metrics::prometheus_text(&state, device_limit).await?;
    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        body,
    )
        .into_response())
}

async fn summary(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Json<serde_json::Value>> {
    require_permission(&state, &headers, "read").await?;
    Ok(Json(
        serde_json::to_value(state.db.summary().await?).unwrap(),
    ))
}

async fn list_cas(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Json<serde_json::Value>> {
    require_permission(&state, &headers, "read").await?;
    Ok(Json(
        serde_json::to_value(ca_service::list_cas(&state).await?).unwrap(),
    ))
}

async fn create_ca(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CreateCaRequest>,
) -> AppResult<Json<serde_json::Value>> {
    let actor = require_permission(&state, &headers, "ca").await?;
    Ok(Json(
        serde_json::to_value(ca_service::create_ca(&state, request, &actor).await?).unwrap(),
    ))
}

async fn update_ca(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(request): Json<UpdateCaRequest>,
) -> AppResult<Json<serde_json::Value>> {
    let actor = require_permission(&state, &headers, "ca").await?;
    Ok(Json(
        serde_json::to_value(ca_service::update_ca(&state, &id, request, &actor).await?).unwrap(),
    ))
}

async fn import_ca(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<ImportCaRequest>,
) -> AppResult<Json<serde_json::Value>> {
    let actor = require_permission(&state, &headers, "ca").await?;
    Ok(Json(
        serde_json::to_value(ca_service::import_ca(&state, request, &actor).await?).unwrap(),
    ))
}

async fn list_certificate_profiles(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Json<serde_json::Value>> {
    require_permission(&state, &headers, "read").await?;
    Ok(Json(
        serde_json::to_value(profile_service::list_certificate_profiles(&state).await?).unwrap(),
    ))
}

async fn create_certificate_profile(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CreateCertificateProfileRequest>,
) -> AppResult<Json<serde_json::Value>> {
    let actor = require_permission(&state, &headers, "profile").await?;
    Ok(Json(
        serde_json::to_value(
            profile_service::create_certificate_profile(&state, request, &actor).await?,
        )
        .unwrap(),
    ))
}

async fn update_certificate_profile(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(request): Json<UpdateCertificateProfileRequest>,
) -> AppResult<Json<serde_json::Value>> {
    let actor = require_permission(&state, &headers, "profile").await?;
    Ok(Json(
        serde_json::to_value(
            profile_service::update_certificate_profile(&state, &id, request, &actor).await?,
        )
        .unwrap(),
    ))
}

async fn delete_certificate_profile(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> AppResult<StatusCode> {
    let actor = require_permission(&state, &headers, "profile").await?;
    profile_service::delete_certificate_profile(&state, &id, &actor).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn list_end_entity_profiles(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Json<serde_json::Value>> {
    require_permission(&state, &headers, "read").await?;
    Ok(Json(
        serde_json::to_value(profile_service::list_end_entity_profiles(&state).await?).unwrap(),
    ))
}

async fn create_end_entity_profile(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CreateEndEntityProfileRequest>,
) -> AppResult<Json<serde_json::Value>> {
    let actor = require_permission(&state, &headers, "profile").await?;
    Ok(Json(
        serde_json::to_value(
            profile_service::create_end_entity_profile(&state, request, &actor).await?,
        )
        .unwrap(),
    ))
}

async fn update_end_entity_profile(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(request): Json<UpdateEndEntityProfileRequest>,
) -> AppResult<Json<serde_json::Value>> {
    let actor = require_permission(&state, &headers, "profile").await?;
    Ok(Json(
        serde_json::to_value(
            profile_service::update_end_entity_profile(&state, &id, request, &actor).await?,
        )
        .unwrap(),
    ))
}

async fn delete_end_entity_profile(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> AppResult<StatusCode> {
    let actor = require_permission(&state, &headers, "profile").await?;
    profile_service::delete_end_entity_profile(&state, &id, &actor).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn list_cmp_aliases(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Json<serde_json::Value>> {
    require_permission(&state, &headers, "read").await?;
    Ok(Json(
        serde_json::to_value(profile_service::list_cmp_aliases(&state).await?).unwrap(),
    ))
}

async fn create_cmp_alias(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CreateCmpAliasRequest>,
) -> AppResult<Json<serde_json::Value>> {
    let actor = require_permission(&state, &headers, "cmp").await?;
    Ok(Json(
        serde_json::to_value(profile_service::create_cmp_alias(&state, request, &actor).await?)
            .unwrap(),
    ))
}

async fn update_cmp_alias(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(request): Json<UpdateCmpAliasRequest>,
) -> AppResult<Json<serde_json::Value>> {
    let actor = require_permission(&state, &headers, "cmp").await?;
    Ok(Json(
        serde_json::to_value(
            profile_service::update_cmp_alias(&state, &id, request, &actor).await?,
        )
        .unwrap(),
    ))
}

async fn delete_cmp_alias(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> AppResult<StatusCode> {
    let actor = require_permission(&state, &headers, "cmp").await?;
    profile_service::delete_cmp_alias(&state, &id, &actor).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn list_access_roles(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Json<serde_json::Value>> {
    require_permission(&state, &headers, "role").await?;
    Ok(Json(
        serde_json::to_value(profile_service::list_access_roles(&state).await?).unwrap(),
    ))
}

async fn create_access_role(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CreateAccessRoleRequest>,
) -> AppResult<Json<serde_json::Value>> {
    let actor = require_permission(&state, &headers, "role").await?;
    Ok(Json(
        serde_json::to_value(profile_service::create_access_role(&state, request, &actor).await?)
            .unwrap(),
    ))
}

async fn update_access_role(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(request): Json<UpdateAccessRoleRequest>,
) -> AppResult<Json<serde_json::Value>> {
    let actor = require_permission(&state, &headers, "role").await?;
    Ok(Json(
        serde_json::to_value(
            profile_service::update_access_role(&state, &id, request, &actor).await?,
        )
        .unwrap(),
    ))
}

async fn delete_access_role(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> AppResult<StatusCode> {
    let actor = require_permission(&state, &headers, "role").await?;
    profile_service::delete_access_role(&state, &id, &actor).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn issue_generated(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<IssueCertificateRequest>,
) -> AppResult<Response> {
    let actor = require_permission(&state, &headers, "issue").await?;
    Ok(no_store_json_response(
        serde_json::to_value(cert_service::issue_generated(&state, request, &actor).await?)
            .unwrap(),
    ))
}

async fn issue_pkcs12(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<IssuePkcs12Request>,
) -> AppResult<Response> {
    let actor = require_permission(&state, &headers, "issue").await?;
    let response = cert_service::issue_pkcs12(&state, request, &actor).await?;
    Ok(pkcs12_response(response.filename, response.der))
}

async fn issue_csr(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<IssueCsrRequest>,
) -> AppResult<Json<serde_json::Value>> {
    let actor = require_permission(&state, &headers, "issue").await?;
    Ok(Json(
        serde_json::to_value(cert_service::issue_from_csr(&state, request, &actor).await?).unwrap(),
    ))
}

async fn list_certificates(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<CertificateListQuery>,
) -> AppResult<Json<serde_json::Value>> {
    require_permission(&state, &headers, "read").await?;
    let limit = bounded_list_limit(query.limit, state.settings.max_list_limit);
    let filter = CertificateFilter {
        ca_id: clean_filter(query.ca_id),
        status: clean_filter(query.status).map(|value| value.to_ascii_lowercase()),
        serial_hex: clean_filter(query.serial_hex).map(|value| value.to_ascii_lowercase()),
        subject_contains: clean_filter(query.subject),
        expires_before: query.expires_before,
        expires_after: query.expires_after,
    };
    Ok(Json(
        serde_json::to_value(cert_service::list_certificates(&state, filter, limit).await?)
            .unwrap(),
    ))
}

async fn get_certificate(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> AppResult<Json<serde_json::Value>> {
    require_permission(&state, &headers, "read").await?;
    Ok(Json(
        serde_json::to_value(cert_service::get_certificate(&state, &id).await?).unwrap(),
    ))
}

async fn download_certificate(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(query): Query<CertificateDownloadQuery>,
) -> AppResult<Response> {
    require_permission(&state, &headers, "read").await?;
    let format = query
        .format
        .as_deref()
        .unwrap_or("pem")
        .trim()
        .to_ascii_lowercase();
    match format.as_str() {
        "pem" => Ok(certificate_response(
            "application/pem-certificate-chain",
            format!("{id}.pem"),
            cert_service::certificate_pem(&state, &id)
                .await?
                .into_bytes(),
        )),
        "der" => Ok(certificate_response(
            "application/pkix-cert",
            format!("{id}.cer"),
            cert_service::certificate_der(&state, &id).await?,
        )),
        _ => Err(AppError::BadRequest(
            "format은 pem 또는 der이어야 합니다".to_string(),
        )),
    }
}

async fn revoke_certificate(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(request): Json<RevokeCertificateRequest>,
) -> AppResult<Json<serde_json::Value>> {
    let actor = require_permission(&state, &headers, "revoke").await?;
    Ok(Json(
        serde_json::to_value(
            cert_service::revoke_certificate(&state, &id, request.reason, &actor).await?,
        )
        .unwrap(),
    ))
}

async fn generate_crl(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<GenerateCrlRequest>,
) -> AppResult<Json<serde_json::Value>> {
    let actor = require_permission(&state, &headers, "crl").await?;
    Ok(Json(
        serde_json::to_value(crl_service::generate_crl(&state, request, &actor).await?).unwrap(),
    ))
}

async fn list_crls(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ListQuery>,
) -> AppResult<Json<serde_json::Value>> {
    require_permission(&state, &headers, "read").await?;
    let limit = bounded_list_limit(query.limit, state.settings.max_list_limit);
    Ok(Json(
        serde_json::to_value(crl_service::list_crls(&state, limit).await?).unwrap(),
    ))
}

async fn download_crl_by_id(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> AppResult<Response> {
    require_permission(&state, &headers, "read").await?;
    let record = state
        .db
        .get_crl(&id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("CRL을 찾을 수 없습니다: {id}")))?;
    Ok(crl_response(record.der, format!("{}.crl", record.id)))
}

async fn download_latest_crl(
    State(state): State<AppState>,
    Path(ca_id): Path<String>,
    Query(query): Query<LatestCrlQuery>,
) -> AppResult<Response> {
    let partition_index = query.partition.unwrap_or(-1);
    let is_delta = query.delta.unwrap_or(false);
    let der = crl_service::latest_crl_der_for_scope(&state, &ca_id, partition_index, is_delta)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("CA의 CRL을 찾을 수 없습니다: {ca_id}")))?;
    let suffix = if is_delta {
        format!("delta-p{partition_index}")
    } else {
        format!("base-p{partition_index}")
    };
    Ok(crl_response(der, format!("{ca_id}-{suffix}.crl")))
}

async fn list_validators(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Json<serde_json::Value>> {
    require_permission(&state, &headers, "validator").await?;
    Ok(Json(
        serde_json::to_value(validator_service::list_validators(&state).await?).unwrap(),
    ))
}

async fn create_validator(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CreateValidatorRequest>,
) -> AppResult<Json<serde_json::Value>> {
    let actor = require_permission(&state, &headers, "validator").await?;
    Ok(Json(
        serde_json::to_value(validator_service::create_validator(&state, request, &actor).await?)
            .unwrap(),
    ))
}

async fn update_validator(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(request): Json<UpdateValidatorRequest>,
) -> AppResult<Json<serde_json::Value>> {
    let actor = require_permission(&state, &headers, "validator").await?;
    Ok(Json(
        serde_json::to_value(
            validator_service::update_validator(&state, &id, request, &actor).await?,
        )
        .unwrap(),
    ))
}

async fn delete_validator(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> AppResult<StatusCode> {
    let actor = require_permission(&state, &headers, "validator").await?;
    validator_service::delete_validator(&state, &id, &actor).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn run_maintenance(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<MaintenanceRequest>,
) -> AppResult<Json<serde_json::Value>> {
    let actor = require_permission(&state, &headers, "maintenance").await?;
    Ok(Json(
        serde_json::to_value(maintenance_service::run_maintenance(&state, request, &actor).await?)
            .unwrap(),
    ))
}

async fn maintenance_config(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Json<serde_json::Value>> {
    require_permission(&state, &headers, "maintenance").await?;
    Ok(Json(
        serde_json::to_value(maintenance_service::config_response(&state).await?).unwrap(),
    ))
}

async fn update_maintenance_config(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<UpdateMaintenanceConfigRequest>,
) -> AppResult<Json<serde_json::Value>> {
    let actor = require_permission(&state, &headers, "maintenance").await?;
    Ok(Json(
        serde_json::to_value(maintenance_service::update_config(&state, request, &actor).await?)
            .unwrap(),
    ))
}

async fn list_audit_events(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AuditQuery>,
) -> AppResult<Json<serde_json::Value>> {
    require_permission(&state, &headers, "audit").await?;
    let limit = bounded_list_limit(query.limit, state.settings.max_list_limit);
    let filter = AuditEventFilter {
        actor: clean_filter(query.actor),
        action: clean_filter(query.action),
        target: clean_filter(query.target),
        status: clean_filter(query.status),
        since: query.since,
        until: query.until,
    };
    Ok(Json(
        serde_json::to_value(state.db.list_audit_events(&filter, limit).await?).unwrap(),
    ))
}

async fn verify_audit_events(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Json<serde_json::Value>> {
    require_permission(&state, &headers, "audit").await?;
    Ok(Json(
        serde_json::to_value(state.db.verify_audit_chain().await?).unwrap(),
    ))
}

async fn ocsp_status(
    State(state): State<AppState>,
    Path((ca_id, serial_hex)): Path<(String, String)>,
) -> AppResult<Json<serde_json::Value>> {
    Ok(Json(
        serde_json::to_value(ocsp_service::status_json(&state, &ca_id, &serial_hex).await?)
            .unwrap(),
    ))
}

async fn ocsp_binary_post(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !content_type_matches(&headers, "application/ocsp-request") {
        return ocsp_der_response_with_status(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            ocsp_service::malformed_response(),
        );
    }
    ocsp_der_response(ocsp_service::binary_response(&state, &body).await)
}

async fn ocsp_binary_get(State(state): State<AppState>, Path(encoded): Path<String>) -> Response {
    match decode_ocsp_get_request(&encoded) {
        Ok(body) => ocsp_der_response(ocsp_service::binary_response(&state, &body).await),
        Err(_) => ocsp_der_response(ocsp_service::malformed_response()),
    }
}

async fn ocsp_binary_empty() -> Response {
    ocsp_der_response(ocsp_service::malformed_response())
}

async fn cmp(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(alias): Path<String>,
    body: Bytes,
) -> AppResult<Response> {
    if !content_type_matches(&headers, "application/pkixcmp") {
        return Err(AppError::BadRequest(
            "CMP 요청 content-type은 application/pkixcmp여야 합니다".to_string(),
        ));
    }
    let status = cmp_service::accept_cmp_envelope(&state, &alias, &body).await?;
    if accept_matches(&headers, "application/pkixcmp")
        && let Some(der) = status.pkixcmp_der.clone()
    {
        return Ok((
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/pkixcmp")],
            der,
        )
            .into_response());
    }
    Ok((
        StatusCode::ACCEPTED,
        [(header::CONTENT_TYPE, "application/json")],
        Json(status),
    )
        .into_response())
}

fn crl_response(der: Vec<u8>, filename: String) -> Response {
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/pkix-crl".to_string()),
            (
                header::HeaderName::from_static("x-content-type-options"),
                "nosniff".to_string(),
            ),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{}\"", filename.replace('"', "")),
            ),
        ],
        der,
    )
        .into_response()
}

fn certificate_response(content_type: &str, filename: String, body: Vec<u8>) -> Response {
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, content_type.to_string()),
            (
                header::HeaderName::from_static("x-content-type-options"),
                "nosniff".to_string(),
            ),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{}\"", filename.replace('"', "")),
            ),
        ],
        body,
    )
        .into_response()
}

fn pkcs12_response(filename: String, body: Vec<u8>) -> Response {
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/x-pkcs12".to_string()),
            (header::CACHE_CONTROL, "no-store".to_string()),
            (header::PRAGMA, "no-cache".to_string()),
            (
                header::HeaderName::from_static("x-content-type-options"),
                "nosniff".to_string(),
            ),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{}\"", filename.replace('"', "")),
            ),
        ],
        body,
    )
        .into_response()
}

fn cors_layer(allowed_origins: &str) -> Option<CorsLayer> {
    let origins: Vec<HeaderValue> = allowed_origins
        .split(',')
        .map(str::trim)
        .filter(|origin| !origin.is_empty())
        .filter_map(|origin| {
            if origin == "*" {
                tracing::warn!("CORS wildcard '*'는 관리자 토큰 보호 API에서 허용하지 않습니다");
                return None;
            }
            HeaderValue::from_str(origin)
                .inspect_err(|err| tracing::warn!("CORS origin 파싱 실패: {origin}: {err}"))
                .ok()
        })
        .collect();
    if origins.is_empty() {
        return None;
    }
    Some(
        CorsLayer::new()
            .allow_origin(AllowOrigin::list(origins))
            .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE])
            .allow_headers([
                header::ACCEPT,
                header::CONTENT_TYPE,
                header::AUTHORIZATION,
                header::HeaderName::from_static("x-admin-token"),
                header::HeaderName::from_static("x-admin-client-cert-pem"),
                header::HeaderName::from_static("x-adminweb-proxy-secret"),
            ])
            .expose_headers([header::CONTENT_DISPOSITION]),
    )
}

fn ocsp_der_response(response: BinaryOcspResponse) -> Response {
    ocsp_der_response_with_status(StatusCode::OK, response)
}

fn ocsp_der_response_with_status(status: StatusCode, response: BinaryOcspResponse) -> Response {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/ocsp-response"),
    );
    headers.insert(
        header::HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    if let Some(cache_seconds) = response.cache_seconds {
        let now = OffsetDateTime::now_utc();
        let expires = now + Duration::seconds(cache_seconds.min(i64::MAX as u64) as i64);
        let cache_control = format!("public, max-age={cache_seconds}, no-transform");
        headers.insert(
            header::CACHE_CONTROL,
            HeaderValue::from_str(&cache_control)
                .unwrap_or_else(|_| HeaderValue::from_static("public, max-age=300, no-transform")),
        );
        headers.insert(
            header::LAST_MODIFIED,
            HeaderValue::from_str(&http_date(now))
                .unwrap_or_else(|_| HeaderValue::from_static("Thu, 01 Jan 1970 00:00:00 GMT")),
        );
        headers.insert(
            header::EXPIRES,
            HeaderValue::from_str(&http_date(expires))
                .unwrap_or_else(|_| HeaderValue::from_static("Thu, 01 Jan 1970 00:00:00 GMT")),
        );
    } else {
        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    }
    (status, headers, response.der).into_response()
}

fn no_store_json_response(value: serde_json::Value) -> Response {
    let mut headers = HeaderMap::new();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    headers.insert(
        header::HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    (headers, Json(value)).into_response()
}

fn http_date(value: OffsetDateTime) -> String {
    let format = format_description!(
        "[weekday repr:short], [day padding:zero] [month repr:short] [year] [hour padding:zero]:[minute padding:zero]:[second padding:zero] GMT"
    );
    value
        .to_offset(UtcOffset::UTC)
        .format(&format)
        .unwrap_or_else(|_| "Thu, 01 Jan 1970 00:00:00 GMT".to_string())
}

fn content_type_matches(headers: &HeaderMap, expected: &str) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(|value| {
            value
                .split(';')
                .next()
                .unwrap_or_default()
                .trim()
                .eq_ignore_ascii_case(expected)
        })
        .unwrap_or(false)
}

fn accept_matches(headers: &HeaderMap, expected: &str) -> bool {
    headers
        .get(header::ACCEPT)
        .and_then(|value| value.to_str().ok())
        .map(|value| {
            value.split(',').any(|part| {
                part.split(';')
                    .next()
                    .unwrap_or_default()
                    .trim()
                    .eq_ignore_ascii_case(expected)
            })
        })
        .unwrap_or(false)
}

fn decode_ocsp_get_request(encoded: &str) -> Result<Vec<u8>, base64::DecodeError> {
    STANDARD
        .decode(encoded)
        .or_else(|_| URL_SAFE.decode(encoded))
        .or_else(|_| URL_SAFE_NO_PAD.decode(encoded))
        .or_else(|_| {
            let mut padded = encoded.to_string();
            while padded.len() % 4 != 0 {
                padded.push('=');
            }
            URL_SAFE.decode(padded)
        })
}

async fn require_permission(
    state: &AppState,
    headers: &HeaderMap,
    required: &str,
) -> AppResult<String> {
    if let Some(supplied) = supplied_auth_token(headers) {
        let expected = state.settings.admin_token();
        if supplied.as_bytes().ct_eq(expected.as_bytes()).into() {
            return Ok("admin".to_string());
        }

        let token_hash = profile_service::legacy_token_hash(supplied);
        if let Some(role) = state.db.find_access_role_by_token_hash(&token_hash).await? {
            let permissions = profile_service::permissions_from_json(&role.permissions_json);
            if permission_allows(&permissions, required) {
                return Ok(format!("role:{}", role.name));
            }
            return Err(AppError::Forbidden(format!(
                "access role '{}'에 '{}' 권한이 없습니다",
                role.name, required
            )));
        }
        for role in state.db.list_access_roles().await? {
            let Some(stored) = role.api_token_sha256.as_deref() else {
                continue;
            };
            if !profile_service::verify_access_token(supplied, stored) {
                continue;
            }
            let permissions = profile_service::permissions_from_json(&role.permissions_json);
            if permission_allows(&permissions, required) {
                return Ok(format!("role:{}", role.name));
            }
            return Err(AppError::Forbidden(format!(
                "access role '{}'에 '{}' 권한이 없습니다",
                role.name, required
            )));
        }
    }

    if let Some(certificate) = verified_adminweb_client_certificate(&state.settings, headers)? {
        return match authorize_client_certificate_role(state, &certificate, Some(required)).await? {
            CertificateRoleAuthorization::Authorized(role) => Ok(certificate_role_actor(&role)),
            CertificateRoleAuthorization::Forbidden(role_names) => {
                let names = role_names.join(",");
                Err(AppError::Forbidden(format!(
                    "client certificate access role '{}'에 '{}' 권한이 없습니다",
                    names, required
                )))
            }
            CertificateRoleAuthorization::NoMatchingRole => Err(AppError::Unauthorized(
                "client certificate에 매칭되는 access role이 없습니다".to_string(),
            )),
        };
    }

    if supplied_auth_token(headers).is_some() {
        return Err(AppError::Unauthorized(
            "관리자 토큰이 올바르지 않습니다".to_string(),
        ));
    }

    Err(AppError::Unauthorized(
        "x-admin-token, Authorization: Bearer 또는 AdminWeb client certificate access role이 필요합니다"
            .to_string(),
    ))
}

fn certificate_role_actor(role: &AccessRoleRecord) -> String {
    let permissions = profile_service::permissions_from_json(&role.permissions_json);
    if permission_allows(&permissions, "admin") {
        format!("cert-role-admin:{}", role.name)
    } else {
        format!("cert-role:{}", role.name)
    }
}

enum CertificateRoleAuthorization {
    Authorized(AccessRoleRecord),
    Forbidden(Vec<String>),
    NoMatchingRole,
}

async fn authorize_client_certificate_role(
    state: &AppState,
    certificate: &ParsedClientCertificate,
    required: Option<&str>,
) -> AppResult<CertificateRoleAuthorization> {
    let roles = state
        .db
        .list_access_roles_by_certificate_issuer(&certificate.issuer_dn)
        .await?;
    let mut forbidden_roles = Vec::new();
    for role in roles {
        if !certificate_matches_role_member(certificate, &role) {
            continue;
        }
        if let Some(required) = required {
            let permissions = profile_service::permissions_from_json(&role.permissions_json);
            if !permission_allows(&permissions, required) {
                forbidden_roles.push(role.name.clone());
                continue;
            }
        }
        return Ok(CertificateRoleAuthorization::Authorized(role));
    }
    if forbidden_roles.is_empty() {
        Ok(CertificateRoleAuthorization::NoMatchingRole)
    } else {
        Ok(CertificateRoleAuthorization::Forbidden(forbidden_roles))
    }
}

fn certificate_matches_role_member(
    certificate: &ParsedClientCertificate,
    role: &AccessRoleRecord,
) -> bool {
    if role.certificate_issuer_dn.as_deref() != Some(certificate.issuer_dn.as_str()) {
        return false;
    }
    let Some(match_key) = role.certificate_match_key.as_deref() else {
        return false;
    };
    match match_key {
        "any" => true,
        "serial_hex" => role
            .certificate_match_value
            .as_deref()
            .map(|value| profile_service::normalize_hex_identifier(value))
            .is_some_and(|value| value == certificate.serial_hex),
        "subject_dn" => {
            role.certificate_match_value.as_deref() == Some(certificate.subject_dn.as_str())
        }
        "common_name" => role
            .certificate_match_value
            .as_deref()
            .is_some_and(|value| {
                certificate_common_names(&certificate.subject_dn)
                    .iter()
                    .any(|cn| cn == value)
            }),
        _ => false,
    }
}

fn certificate_common_names(subject_dn: &str) -> Vec<String> {
    subject_dn
        .split(',')
        .filter_map(|part| {
            let part = part.trim();
            part.strip_prefix("CN=")
                .or_else(|| part.strip_prefix("cn="))
                .map(|value| value.trim().to_string())
        })
        .collect()
}

fn verified_adminweb_client_certificate(
    settings: &Settings,
    headers: &HeaderMap,
) -> AppResult<Option<ParsedClientCertificate>> {
    let session = evaluate_adminweb_certificate_for_settings(settings, headers);
    if session.authenticated {
        if let (Some(subject_dn), Some(issuer_dn), Some(serial_hex), Some(fingerprint_sha256)) = (
            session.subject_dn,
            session.issuer_dn,
            session.serial_hex,
            session.fingerprint_sha256,
        ) {
            return Ok(Some(ParsedClientCertificate {
                subject_dn,
                issuer_dn,
                serial_hex,
                fingerprint_sha256,
            }));
        }
        return Ok(None);
    }
    if settings.adminweb_client_cert_required {
        return Err(AppError::Forbidden(format!(
            "AdminWeb client certificate 인증 실패: {}",
            session.detail
        )));
    }
    Ok(None)
}

fn supplied_auth_token(headers: &HeaderMap) -> Option<&str> {
    if let Some(token) = headers
        .get("x-admin-token")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        return Some(token);
    }

    let authorization = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())?
        .trim();
    if authorization.len() > "Bearer ".len()
        && authorization[.."Bearer ".len()].eq_ignore_ascii_case("Bearer ")
    {
        let token = authorization["Bearer ".len()..].trim();
        if !token.is_empty() {
            return Some(token);
        }
    }
    None
}

fn permission_allows(permissions: &[String], required: &str) -> bool {
    let required = required.to_ascii_lowercase();
    permissions.iter().any(|permission| {
        let permission = permission.trim().to_ascii_lowercase();
        permission == "*" || permission == "admin" || permission == required
    })
}

fn bounded_list_limit(requested: Option<i64>, max_limit: i64) -> i64 {
    let max_limit = max_limit.max(1);
    requested.unwrap_or(100).clamp(1, max_limit)
}

fn clean_filter(value: Option<String>) -> Option<String> {
    value
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn evaluate_adminweb_certificate(state: &AppState, headers: &HeaderMap) -> AdminWebSessionResponse {
    evaluate_adminweb_certificate_for_settings(&state.settings, headers)
}

fn evaluate_adminweb_certificate_for_settings(
    settings: &Settings,
    headers: &HeaderMap,
) -> AdminWebSessionResponse {
    let required = settings.adminweb_client_cert_required;
    let mode = "proxy-client-cert";

    if let Some(expected_secret) = settings
        .adminweb_client_cert_proxy_secret
        .as_deref()
        .filter(|value| !value.is_empty())
    {
        let supplied = headers
            .get("x-adminweb-proxy-secret")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        if supplied
            .as_bytes()
            .ct_eq(expected_secret.as_bytes())
            .unwrap_u8()
            != 1
        {
            return AdminWebSessionResponse {
                required,
                authenticated: false,
                mode,
                role_name: None,
                subject_dn: None,
                issuer_dn: None,
                serial_hex: None,
                fingerprint_sha256: None,
                detail: "AdminWeb client certificate proxy secret이 일치하지 않습니다".to_string(),
            };
        }
    }

    let header_name = settings.adminweb_client_cert_header.trim();
    let cert_header = headers
        .get(header_name)
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.trim().is_empty());

    let Some(cert_header) = cert_header else {
        return AdminWebSessionResponse {
            required,
            authenticated: !required,
            mode,
            role_name: None,
            subject_dn: None,
            issuer_dn: None,
            serial_hex: None,
            fingerprint_sha256: None,
            detail: if required {
                format!("AdminWeb client certificate 헤더가 필요합니다: {header_name}")
            } else {
                "AdminWeb client certificate 검증이 비활성화되어 있습니다".to_string()
            },
        };
    };

    let parsed = match parse_adminweb_client_certificate(cert_header) {
        Ok(parsed) => parsed,
        Err(detail) => {
            return AdminWebSessionResponse {
                required,
                authenticated: false,
                mode,
                role_name: None,
                subject_dn: None,
                issuer_dn: None,
                serial_hex: None,
                fingerprint_sha256: None,
                detail,
            };
        }
    };

    let allowed_fingerprints =
        split_config_values(&settings.adminweb_client_cert_allowed_fingerprints)
            .into_iter()
            .map(|value| value.replace(':', "").to_ascii_lowercase())
            .collect::<Vec<_>>();
    let allowed_subjects = split_config_values(&settings.adminweb_client_cert_allowed_subjects);
    let fingerprint_allowed = allowed_fingerprints.is_empty()
        || allowed_fingerprints
            .iter()
            .any(|value| value == &parsed.fingerprint_sha256);
    let subject_allowed = allowed_subjects.is_empty()
        || allowed_subjects
            .iter()
            .any(|value| value == &parsed.subject_dn);
    let authenticated = fingerprint_allowed && subject_allowed;
    let detail = if authenticated {
        if required {
            "AdminWeb client certificate가 확인되었습니다"
        } else {
            "AdminWeb client certificate가 확인되었지만 필수 모드는 아닙니다"
        }
    } else if !fingerprint_allowed {
        "AdminWeb client certificate fingerprint가 허용 목록과 일치하지 않습니다"
    } else {
        "AdminWeb client certificate subject가 허용 목록과 일치하지 않습니다"
    };

    AdminWebSessionResponse {
        required,
        authenticated,
        mode,
        role_name: None,
        subject_dn: Some(parsed.subject_dn),
        issuer_dn: Some(parsed.issuer_dn),
        serial_hex: Some(parsed.serial_hex),
        fingerprint_sha256: Some(parsed.fingerprint_sha256),
        detail: detail.to_string(),
    }
}

fn parse_adminweb_client_certificate(value: &str) -> Result<ParsedClientCertificate, String> {
    let decoded = decode_client_certificate_header(value)?;
    let pem = pem::parse(decoded.as_bytes())
        .map_err(|err| format!("AdminWeb client certificate PEM 파싱 실패: {err}"))?;
    let cert_der = pem.contents();
    let (_, cert) = X509Certificate::from_der(cert_der)
        .map_err(|err| format!("AdminWeb client certificate DER 파싱 실패: {err}"))?;
    let fingerprint_sha256 = hex::encode(Sha256::digest(cert_der));
    Ok(ParsedClientCertificate {
        subject_dn: cert.subject().to_string(),
        issuer_dn: cert.issuer().to_string(),
        serial_hex: profile_service::normalize_hex_identifier(&hex::encode(
            cert.tbs_certificate.raw_serial(),
        )),
        fingerprint_sha256,
    })
}

fn decode_client_certificate_header(value: &str) -> Result<String, String> {
    let mut value = value.trim();
    if let Some(cert_start) = value.find("Cert=\"") {
        value = &value[cert_start + "Cert=\"".len()..];
        if let Some(cert_end) = value.find('"') {
            value = &value[..cert_end];
        }
    }
    let unescaped = percent_decode(value)?.replace("\\n", "\n");
    Ok(unescaped)
}

fn percent_decode(value: &str) -> Result<String, String> {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len() {
                return Err("AdminWeb client certificate percent encoding이 잘렸습니다".to_string());
            }
            let hex = std::str::from_utf8(&bytes[index + 1..index + 3]).map_err(|_| {
                "AdminWeb client certificate percent encoding이 올바르지 않습니다".to_string()
            })?;
            let byte = u8::from_str_radix(hex, 16).map_err(|_| {
                "AdminWeb client certificate percent encoding이 올바르지 않습니다".to_string()
            })?;
            out.push(byte);
            index += 3;
        } else {
            out.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(out)
        .map_err(|_| "AdminWeb client certificate 헤더가 UTF-8이 아닙니다".to_string())
}

fn split_config_values(value: &str) -> Vec<String> {
    value
        .split(|ch| matches!(ch, ',' | '\n' | ';'))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use clap::Parser;
    use rcgen::{CertificateParams, DnType, KeyPair};
    use std::{convert::Infallible, path::PathBuf, sync::Arc};
    use tokio::sync::Semaphore;
    use tower::{ServiceBuilder, ServiceExt, service_fn};
    use uuid::Uuid;

    async fn test_state() -> (AppState, PathBuf) {
        let data_dir = std::env::temp_dir().join(format!("ejbca-rs-api-test-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&data_dir).unwrap();
        let mut settings = Settings::parse_from(["ejbca-rs"]);
        settings.data_dir = data_dir.to_string_lossy().to_string();
        settings.database_url = None;
        settings.admin_token = Some("test-admin-token".to_string());
        settings.database_max_connections = 4;
        settings.adminweb_client_cert_required = true;
        let settings = Arc::new(settings);
        let db = crate::storage::Db::connect(
            &settings.database_url(),
            settings.database_max_connections,
            settings.database_busy_timeout_seconds,
        )
        .await
        .unwrap();
        db.migrate().await.unwrap();
        let state = AppState {
            db,
            settings,
            http: reqwest::Client::new(),
            issue_limiter: Arc::new(Semaphore::new(4)),
        };
        (state, data_dir)
    }

    #[test]
    fn ocsp_success_response_sets_short_cache_headers() {
        let response = ocsp_der_response(BinaryOcspResponse {
            der: vec![0x30, 0x03, 0x0a, 0x01, 0x00],
            cache_seconds: Some(300),
        });

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/ocsp-response"
        );
        assert_eq!(
            response
                .headers()
                .get(header::HeaderName::from_static("x-content-type-options"))
                .unwrap(),
            "nosniff"
        );
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "public, max-age=300, no-transform"
        );
        assert!(response.headers().contains_key(header::LAST_MODIFIED));
        assert!(response.headers().contains_key(header::EXPIRES));
    }

    #[test]
    fn ocsp_error_response_disables_http_caching() {
        let response = ocsp_der_response(BinaryOcspResponse {
            der: ocsp_service::malformed_der_response(),
            cache_seconds: None,
        });

        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
        assert_eq!(
            response
                .headers()
                .get(header::HeaderName::from_static("x-content-type-options"))
                .unwrap(),
            "nosniff"
        );
        assert_eq!(response.headers().get(header::PRAGMA).unwrap(), "no-cache");
        assert!(!response.headers().contains_key(header::EXPIRES));
    }

    #[test]
    fn private_key_json_response_disables_caching() {
        let response = no_store_json_response(serde_json::json!({
            "private_key_pem": "-----BEGIN PRIVATE KEY-----"
        }));

        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
        assert_eq!(response.headers().get(header::PRAGMA).unwrap(), "no-cache");
        assert_eq!(
            response
                .headers()
                .get(header::HeaderName::from_static("x-content-type-options"))
                .unwrap(),
            "nosniff"
        );
    }

    #[test]
    fn adminweb_session_accepts_allowed_client_certificate_header() {
        let key_pair = KeyPair::generate().unwrap();
        let cert = CertificateParams::new(vec!["admin.example.com".to_string()])
            .unwrap()
            .self_signed(&key_pair)
            .unwrap();
        let cert_pem = cert.pem();
        let parsed = parse_adminweb_client_certificate(&cert_pem).unwrap();
        let mut settings = Settings::parse_from(["ejbca-rs"]);
        settings.adminweb_client_cert_required = true;
        settings.adminweb_client_cert_proxy_secret = Some("proxy-secret".to_string());
        settings.adminweb_client_cert_allowed_fingerprints =
            parsed.fingerprint_sha256.to_ascii_uppercase();

        let mut headers = HeaderMap::new();
        headers.insert(
            "x-admin-client-cert-pem",
            HeaderValue::from_str(&cert_pem.replace('\n', "%0A")).unwrap(),
        );
        headers.insert(
            "x-adminweb-proxy-secret",
            HeaderValue::from_static("proxy-secret"),
        );

        let session = evaluate_adminweb_certificate_for_settings(&settings, &headers);
        assert!(session.required);
        assert!(session.authenticated);
        assert_eq!(session.fingerprint_sha256, Some(parsed.fingerprint_sha256));
        assert_eq!(session.subject_dn, Some(parsed.subject_dn));
    }

    #[test]
    fn adminweb_session_rejects_missing_certificate_when_required() {
        let mut settings = Settings::parse_from(["ejbca-rs"]);
        settings.adminweb_client_cert_required = true;

        let session = evaluate_adminweb_certificate_for_settings(&settings, &HeaderMap::new());

        assert!(session.required);
        assert!(!session.authenticated);
        assert!(session.detail.contains("client certificate"));
    }

    #[tokio::test]
    async fn client_certificate_role_authorizes_api_without_admin_token() {
        let (state, data_dir) = test_state().await;
        let key_pair = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(vec!["admin.example.com".to_string()]).unwrap();
        params
            .distinguished_name
            .push(DnType::CommonName, "admin.example.com");
        let cert = params.self_signed(&key_pair).unwrap();
        let cert_pem = cert.pem();
        let parsed = parse_adminweb_client_certificate(&cert_pem).unwrap();
        profile_service::create_access_role(
            &state,
            CreateAccessRoleRequest {
                name: "certificate-admin".to_string(),
                permissions: vec!["read".to_string()],
                api_token: None,
                certificate_issuer_dn: Some(parsed.issuer_dn.clone()),
                certificate_match_key: Some("serial_hex".to_string()),
                certificate_match_value: Some(parsed.serial_hex.clone()),
            },
            "admin",
        )
        .await
        .unwrap();

        let mut headers = HeaderMap::new();
        headers.insert(
            "x-admin-client-cert-pem",
            HeaderValue::from_str(&cert_pem.replace('\n', "%0A")).unwrap(),
        );

        let actor = require_permission(&state, &headers, "read").await.unwrap();
        assert_eq!(actor, "cert-role:certificate-admin");
        let denied = require_permission(&state, &headers, "issue")
            .await
            .unwrap_err();
        assert!(denied.to_string().contains("권한이 없습니다"));

        std::fs::remove_dir_all(data_dir).ok();
    }

    #[test]
    fn download_responses_disable_mime_sniffing() {
        let cert = certificate_response("application/pkix-cert", "cert.cer".to_string(), vec![1]);
        let crl = crl_response(vec![1], "ca.crl".to_string());
        for response in [cert, crl] {
            assert_eq!(
                response
                    .headers()
                    .get(header::HeaderName::from_static("x-content-type-options"))
                    .unwrap(),
                "nosniff"
            );
        }
    }

    #[test]
    fn supplied_auth_token_accepts_admin_header_and_bearer() {
        let mut headers = HeaderMap::new();
        headers.insert("x-admin-token", HeaderValue::from_static("admin-token"));
        assert_eq!(supplied_auth_token(&headers), Some("admin-token"));

        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer role-token"),
        );
        assert_eq!(supplied_auth_token(&headers), Some("role-token"));

        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, HeaderValue::from_static("Basic abc"));
        assert_eq!(supplied_auth_token(&headers), None);
    }

    #[tokio::test]
    async fn cors_preflight_allows_adminweb_put_and_auth_headers() {
        let cors = cors_layer("http://127.0.0.1:5173").unwrap();
        let service = ServiceBuilder::new()
            .layer(cors)
            .service(service_fn(|_| async {
                Ok::<_, Infallible>(Response::new(Body::empty()))
            }));
        let request = axum::http::Request::builder()
            .method(Method::OPTIONS)
            .uri("/api/v1/cas/test-ca")
            .header(header::ORIGIN, "http://127.0.0.1:5173")
            .header(header::ACCESS_CONTROL_REQUEST_METHOD, "PUT")
            .header(
                header::ACCESS_CONTROL_REQUEST_HEADERS,
                "authorization,x-admin-token,content-type",
            )
            .body(Body::empty())
            .unwrap();

        let response = service.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .unwrap(),
            "http://127.0.0.1:5173"
        );
        let methods = response
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_METHODS)
            .unwrap()
            .to_str()
            .unwrap()
            .to_ascii_uppercase();
        assert!(methods.contains("PUT"));
        let headers = response
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_HEADERS)
            .unwrap()
            .to_str()
            .unwrap()
            .to_ascii_lowercase();
        assert!(headers.contains("authorization"));
        assert!(headers.contains("x-admin-token"));
        assert!(headers.contains("content-type"));
    }
}
