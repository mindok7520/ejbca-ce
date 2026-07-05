use serde::Serialize;

use crate::{
    AppState,
    certs::{IssueCsrRequest, service as cert_service},
    error::{AppError, AppResult},
    storage::CmpAliasRecord,
};

#[derive(Debug, Serialize)]
pub struct EnrollmentIssueResponse {
    pub protocol: String,
    pub alias: String,
    pub certificate_id: String,
    pub serial_hex: String,
    pub cert_pem: String,
}

pub async fn issue_csr_via_alias(
    state: &AppState,
    protocol: &str,
    alias: &str,
    body: &[u8],
) -> AppResult<EnrollmentIssueResponse> {
    if body.is_empty() {
        return Err(AppError::BadRequest(format!(
            "{protocol} enrollment CSR 본문이 비어 있습니다"
        )));
    }
    if body.len() > state.settings.max_request_bytes {
        return Err(AppError::BadRequest(format!(
            "{protocol} enrollment 요청이 너무 큽니다: {} > {}",
            body.len(),
            state.settings.max_request_bytes
        )));
    }
    let alias_config = state
        .db
        .get_cmp_alias_by_alias(alias)
        .await?
        .ok_or_else(|| {
            AppError::NotFound(format!("enrollment alias를 찾을 수 없습니다: {alias}"))
        })?;
    if !alias_config.enabled {
        return Err(AppError::Forbidden(format!(
            "enrollment alias가 비활성 상태입니다: {alias}"
        )));
    }
    let csr_pem = csr_body_to_pem(body)?;
    issue_with_alias_config(state, protocol, alias, &alias_config, csr_pem).await
}

async fn issue_with_alias_config(
    state: &AppState,
    protocol: &str,
    alias: &str,
    alias_config: &CmpAliasRecord,
    csr_pem: String,
) -> AppResult<EnrollmentIssueResponse> {
    let issued = cert_service::issue_from_csr_with_source(
        state,
        IssueCsrRequest {
            end_entity_id: None,
            approval_id: None,
            ca_id: alias_config.ca_id.clone(),
            certificate_profile_id: alias_config.certificate_profile_id.clone(),
            end_entity_profile_id: alias_config.end_entity_profile_id.clone(),
            csr_pem,
            validity_days: None,
        },
        &format!("{protocol}-client"),
        protocol,
    )
    .await?;
    Ok(EnrollmentIssueResponse {
        protocol: protocol.to_string(),
        alias: alias.to_string(),
        certificate_id: issued.id,
        serial_hex: issued.serial_hex,
        cert_pem: issued.cert_pem,
    })
}

fn csr_body_to_pem(body: &[u8]) -> AppResult<String> {
    if body.starts_with(b"-----BEGIN CERTIFICATE REQUEST-----") {
        return String::from_utf8(body.to_vec())
            .map_err(|_| AppError::BadRequest("CSR PEM이 UTF-8이 아닙니다".to_string()));
    }
    let csr = crate::asn1::parse_single(body)
        .map_err(|err| AppError::BadRequest(format!("CSR DER 파싱 실패: {err}")))?;
    if !crate::asn1::is_universal_sequence(&csr) {
        return Err(AppError::BadRequest(
            "CSR DER는 SEQUENCE여야 합니다".to_string(),
        ));
    }
    Ok(pem::encode(&pem::Pem::new(
        "CERTIFICATE REQUEST",
        csr.full.to_vec(),
    )))
}
