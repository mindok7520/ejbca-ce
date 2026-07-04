use rcgen::SigningKey;
use sha1::Sha1;
use sha2::{Digest, Sha256};
use time::{Duration, OffsetDateTime, macros::format_description};
use tracing::error;
use x509_parser::prelude::{FromDer, X509Certificate};

use crate::{
    AppState,
    asn1::{
        DerElement, DerTagClass, decode_oid_content, der_bit_string, der_context_constructed,
        der_context_primitive, der_enum, der_explicit_context, der_generalized_time,
        der_octet_string, der_oid, der_sequence, is_universal_sequence, parse_children,
        parse_single,
    },
    error::AppResult,
    key_provider,
    ocsp::{BinaryOcspResponse, OcspResponseStatus, OcspStatusResponse},
    storage::{CaRecord, CertificateRecord},
    util::now_unix,
};

pub const OCSP_RESPONSE_CACHE_SECONDS: u64 = 300;

pub async fn status_json(
    state: &AppState,
    ca_id: &str,
    serial_hex: &str,
) -> AppResult<OcspStatusResponse> {
    let cert = state
        .db
        .get_certificate_by_serial(ca_id, serial_hex)
        .await?;
    let (status, revocation_reason, revoked_at) = match cert {
        Some(cert) if cert.status == "revoked" => (
            "revoked".to_string(),
            cert.revocation_reason,
            cert.revoked_at,
        ),
        Some(cert) if cert.not_after < now_unix() => ("expired".to_string(), None, None),
        Some(_) => ("good".to_string(), None, None),
        None => ("unknown".to_string(), None, None),
    };
    Ok(OcspStatusResponse {
        ca_id: ca_id.to_string(),
        serial_hex: serial_hex.to_string(),
        status,
        revocation_reason,
        revoked_at,
        this_update: now_unix(),
    })
}

pub async fn binary_response(state: &AppState, body: &[u8]) -> BinaryOcspResponse {
    if body.is_empty() || body.len() > state.settings.max_request_bytes {
        return uncached_response(ocsp_response_status_der(
            OcspResponseStatus::MalformedRequest,
        ));
    }

    let requests = match parse_ocsp_requests(body) {
        Ok(requests) => requests,
        Err(_) => {
            return uncached_response(ocsp_response_status_der(
                OcspResponseStatus::MalformedRequest,
            ));
        }
    };

    match build_basic_ocsp_response(state, requests).await {
        Ok(response) => cached_response(response),
        Err(OcspBuildError::Unauthorized) => {
            uncached_response(ocsp_response_status_der(OcspResponseStatus::Unauthorized))
        }
        Err(OcspBuildError::Internal(message)) => {
            error!("OCSP 응답 생성 실패: {message}");
            uncached_response(ocsp_response_status_der(OcspResponseStatus::InternalError))
        }
    }
}

fn parse_ocsp_requests(body: &[u8]) -> Result<Vec<ParsedOcspRequest>, String> {
    let root = parse_single(body).map_err(|err| err.to_string())?;
    require_sequence(&root, "OCSPRequest")?;
    let request_children = parse_children(root.content).map_err(|err| err.to_string())?;
    let tbs_request = request_children
        .first()
        .ok_or_else(|| "OCSPRequest.tbsRequest가 없습니다".to_string())?;
    require_sequence(tbs_request, "TBSRequest")?;

    let tbs_children = parse_children(tbs_request.content).map_err(|err| err.to_string())?;
    let mut index = 0usize;
    for optional_tag in [0u64, 1u64] {
        if tbs_children.get(index).is_some_and(|element| {
            element.tag.class == DerTagClass::ContextSpecific && element.tag.number == optional_tag
        }) {
            index += 1;
        }
    }
    let request_list = tbs_children
        .get(index)
        .ok_or_else(|| "TBSRequest.requestList가 없습니다".to_string())?;
    require_sequence(request_list, "requestList")?;

    let requests = parse_children(request_list.content).map_err(|err| err.to_string())?;
    if requests.is_empty() {
        return Err("requestList가 비어 있습니다".to_string());
    }
    requests.iter().map(parse_single_ocsp_request).collect()
}

fn parse_single_ocsp_request(request: &DerElement<'_>) -> Result<ParsedOcspRequest, String> {
    require_sequence(request, "Request")?;
    let request_children = parse_children(request.content).map_err(|err| err.to_string())?;
    let cert_id = request_children
        .first()
        .ok_or_else(|| "Request.reqCert가 없습니다".to_string())?;
    require_sequence(cert_id, "CertID")?;

    let cert_id_children = parse_children(cert_id.content).map_err(|err| err.to_string())?;
    let hash_alg = parse_hash_algorithm(
        cert_id_children
            .first()
            .ok_or_else(|| "CertID.hashAlgorithm이 없습니다".to_string())?,
    )?;
    let issuer_name_hash = read_octet_string(
        cert_id_children
            .get(1)
            .ok_or_else(|| "CertID.issuerNameHash가 없습니다".to_string())?,
        "issuerNameHash",
    )?;
    let issuer_key_hash = read_octet_string(
        cert_id_children
            .get(2)
            .ok_or_else(|| "CertID.issuerKeyHash가 없습니다".to_string())?,
        "issuerKeyHash",
    )?;
    let serial_hex = read_integer_hex(
        cert_id_children
            .get(3)
            .ok_or_else(|| "CertID.serialNumber가 없습니다".to_string())?,
    )?;

    Ok(ParsedOcspRequest {
        cert_id_der: cert_id.full.to_vec(),
        hash_alg,
        issuer_name_hash,
        issuer_key_hash,
        serial_hex,
    })
}

async fn build_basic_ocsp_response(
    state: &AppState,
    requests: Vec<ParsedOcspRequest>,
) -> Result<Vec<u8>, OcspBuildError> {
    let mut resolved = Vec::with_capacity(requests.len());
    for request in requests {
        resolved.push(resolve_ocsp_request(state, request).await?);
    }
    let signing_ca = resolved
        .first()
        .ok_or_else(|| OcspBuildError::Internal("OCSP 요청이 비어 있습니다".to_string()))?
        .ca
        .clone();
    if resolved.iter().any(|item| item.ca.id != signing_ca.id) {
        return Err(OcspBuildError::Unauthorized);
    }

    let ca_cert = parse_ca_cert(&signing_ca)?;
    let produced_at = OffsetDateTime::now_utc();
    let next_update = produced_at + Duration::minutes(5);

    let mut single_responses = Vec::new();
    for item in &resolved {
        single_responses.extend(single_response_der(item, produced_at, next_update));
    }

    let response_data = der_sequence(join([
        der_explicit_context(1, ca_cert.subject_der),
        der_generalized_time(&generalized_time(produced_at)),
        der_sequence(single_responses),
    ]));

    let signing_key = key_provider::load_ca_signing_key(&signing_ca)
        .await
        .map_err(|err| OcspBuildError::Internal(format!("CA 키를 읽을 수 없습니다: {err}")))?;
    let signature = signing_key
        .sign(&response_data)
        .map_err(|err| OcspBuildError::Internal(format!("OCSP 응답 서명 실패: {err}")))?;

    let basic_response = der_sequence(join([
        response_data,
        ecdsa_sha256_algorithm_identifier(),
        der_bit_string(signature),
        der_explicit_context(0, der_sequence(signing_ca.cert_der.clone())),
    ]));
    let response_bytes = der_sequence(join([
        der_oid(&[1, 3, 6, 1, 5, 5, 7, 48, 1, 1]),
        der_octet_string(basic_response),
    ]));
    Ok(der_sequence(join([
        der_enum(OcspResponseStatus::Successful as u8),
        der_explicit_context(0, response_bytes),
    ])))
}

async fn resolve_ocsp_request(
    state: &AppState,
    request: ParsedOcspRequest,
) -> Result<ResolvedOcspRequest, OcspBuildError> {
    let ca = matching_ca(state, &request).await?;
    let certificates = state
        .db
        .list_certificates_by_serial(&request.serial_hex)
        .await
        .map_err(|err| OcspBuildError::Internal(err.to_string()))?;
    let cert = certificates
        .into_iter()
        .find(|certificate| certificate.ca_id == ca.id);
    Ok(ResolvedOcspRequest { request, ca, cert })
}

async fn matching_ca(
    state: &AppState,
    request: &ParsedOcspRequest,
) -> Result<CaRecord, OcspBuildError> {
    for ca in state
        .db
        .list_cas()
        .await
        .map_err(|err| OcspBuildError::Internal(err.to_string()))?
    {
        let parsed = parse_ca_cert(&ca)?;
        if hash_bytes(request.hash_alg, &parsed.subject_der) == request.issuer_name_hash
            && hash_bytes(request.hash_alg, &parsed.subject_public_key) == request.issuer_key_hash
        {
            return Ok(ca);
        }
    }
    Err(OcspBuildError::Unauthorized)
}

fn single_response_der(
    resolved: &ResolvedOcspRequest,
    this_update: OffsetDateTime,
    next_update: OffsetDateTime,
) -> Vec<u8> {
    der_sequence(join([
        resolved.request.cert_id_der.clone(),
        cert_status_der(resolved.cert.as_ref()),
        der_generalized_time(&generalized_time(this_update)),
        der_explicit_context(0, der_generalized_time(&generalized_time(next_update))),
    ]))
}

fn cert_status_der(cert: Option<&CertificateRecord>) -> Vec<u8> {
    match cert {
        Some(cert) if cert.status == "revoked" => {
            let revoked_at = cert
                .revoked_at
                .and_then(|value| OffsetDateTime::from_unix_timestamp(value).ok())
                .unwrap_or_else(OffsetDateTime::now_utc);
            let mut content = der_generalized_time(&generalized_time(revoked_at));
            if let Some(reason) = cert
                .revocation_reason
                .as_deref()
                .and_then(revocation_reason_code)
            {
                content.extend(der_explicit_context(0, der_enum(reason)));
            }
            der_context_constructed(1, content)
        }
        Some(cert) if cert.not_after >= now_unix() => der_context_primitive(0, Vec::new()),
        _ => der_context_primitive(2, Vec::new()),
    }
}

fn parse_hash_algorithm(element: &DerElement<'_>) -> Result<HashAlgorithm, String> {
    require_sequence(element, "AlgorithmIdentifier")?;
    let children = parse_children(element.content).map_err(|err| err.to_string())?;
    let oid = children
        .first()
        .ok_or_else(|| "AlgorithmIdentifier.algorithm이 없습니다".to_string())?;
    if oid.tag.class != DerTagClass::Universal || oid.tag.number != 6 {
        return Err("AlgorithmIdentifier.algorithm이 OBJECT IDENTIFIER가 아닙니다".to_string());
    }
    match decode_oid_content(oid.content)
        .map_err(|err| err.to_string())?
        .as_slice()
    {
        [1, 3, 14, 3, 2, 26] => Ok(HashAlgorithm::Sha1),
        [2, 16, 840, 1, 101, 3, 4, 2, 1] => Ok(HashAlgorithm::Sha256),
        other => Err(format!("지원하지 않는 OCSP hashAlgorithm입니다: {other:?}")),
    }
}

fn read_octet_string(element: &DerElement<'_>, name: &str) -> Result<Vec<u8>, String> {
    if element.tag.class != DerTagClass::Universal || element.tag.number != 4 {
        return Err(format!("CertID.{name}가 OCTET STRING이 아닙니다"));
    }
    Ok(element.content.to_vec())
}

fn read_integer_hex(element: &DerElement<'_>) -> Result<String, String> {
    if element.tag.class != DerTagClass::Universal
        || element.tag.number != 2
        || element.content.is_empty()
    {
        return Err("CertID.serialNumber가 INTEGER가 아닙니다".to_string());
    }
    let mut serial_bytes = element.content;
    while serial_bytes.len() > 1 && serial_bytes[0] == 0 {
        serial_bytes = &serial_bytes[1..];
    }
    Ok(hex::encode(serial_bytes))
}

fn require_sequence(element: &DerElement<'_>, name: &str) -> Result<(), String> {
    if is_universal_sequence(element) {
        Ok(())
    } else {
        Err(format!("{name}는 DER SEQUENCE가 아닙니다"))
    }
}

pub fn ocsp_response_status_der(status: OcspResponseStatus) -> Vec<u8> {
    der_sequence(der_enum(status as u8))
}

pub fn malformed_der_response() -> Vec<u8> {
    ocsp_response_status_der(OcspResponseStatus::MalformedRequest)
}

pub fn malformed_response() -> BinaryOcspResponse {
    uncached_response(malformed_der_response())
}

fn cached_response(der: Vec<u8>) -> BinaryOcspResponse {
    BinaryOcspResponse {
        der,
        cache_seconds: Some(OCSP_RESPONSE_CACHE_SECONDS),
    }
}

fn uncached_response(der: Vec<u8>) -> BinaryOcspResponse {
    BinaryOcspResponse {
        der,
        cache_seconds: None,
    }
}

fn parse_ca_cert(ca: &CaRecord) -> Result<ParsedCaCert, OcspBuildError> {
    let (_, cert) = X509Certificate::from_der(&ca.cert_der).map_err(|err| {
        OcspBuildError::Internal(format!("CA 인증서를 파싱할 수 없습니다: {err}"))
    })?;
    Ok(ParsedCaCert {
        subject_der: cert.subject().as_raw().to_vec(),
        subject_public_key: cert
            .tbs_certificate
            .subject_pki
            .subject_public_key
            .data
            .to_vec(),
    })
}

fn hash_bytes(alg: HashAlgorithm, input: &[u8]) -> Vec<u8> {
    match alg {
        HashAlgorithm::Sha1 => Sha1::digest(input).to_vec(),
        HashAlgorithm::Sha256 => Sha256::digest(input).to_vec(),
    }
}

fn ecdsa_sha256_algorithm_identifier() -> Vec<u8> {
    der_sequence(der_oid(&[1, 2, 840, 10045, 4, 3, 2]))
}

fn generalized_time(value: OffsetDateTime) -> String {
    let format = format_description!("[year][month][day][hour][minute][second]Z");
    value
        .format(&format)
        .unwrap_or_else(|_| "19700101000000Z".to_string())
}

fn revocation_reason_code(reason: &str) -> Option<u8> {
    match reason {
        "key_compromise" => Some(1),
        "ca_compromise" => Some(2),
        "affiliation_changed" => Some(3),
        "superseded" => Some(4),
        "cessation_of_operation" => Some(5),
        "certificate_hold" => Some(6),
        "remove_from_crl" => Some(8),
        "privilege_withdrawn" => Some(9),
        "aa_compromise" => Some(10),
        _ => None,
    }
}

fn join(chunks: impl IntoIterator<Item = Vec<u8>>) -> Vec<u8> {
    chunks.into_iter().flatten().collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HashAlgorithm {
    Sha1,
    Sha256,
}

#[derive(Debug, Clone)]
struct ParsedOcspRequest {
    cert_id_der: Vec<u8>,
    hash_alg: HashAlgorithm,
    issuer_name_hash: Vec<u8>,
    issuer_key_hash: Vec<u8>,
    serial_hex: String,
}

#[derive(Debug, Clone)]
struct ResolvedOcspRequest {
    request: ParsedOcspRequest,
    ca: CaRecord,
    cert: Option<CertificateRecord>,
}

#[derive(Debug)]
struct ParsedCaCert {
    subject_der: Vec<u8>,
    subject_public_key: Vec<u8>,
}

#[derive(Debug)]
enum OcspBuildError {
    Unauthorized,
    Internal(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asn1::{der_integer_from_i64, der_octet_string};

    #[test]
    fn writes_malformed_ocsp_response_status() {
        assert_eq!(
            ocsp_response_status_der(OcspResponseStatus::MalformedRequest),
            vec![0x30, 0x03, 0x0a, 0x01, 0x01]
        );
    }

    #[test]
    fn rejects_empty_ocsp_request() {
        assert!(parse_ocsp_requests(&[]).is_err());
    }

    #[test]
    fn parses_ocsp_cert_id_serial() {
        let cert_id = der_sequence(join([
            der_sequence(der_oid(&[1, 3, 14, 3, 2, 26])),
            der_octet_string(vec![0; 20]),
            der_octet_string(vec![1; 20]),
            der_integer_from_i64(42),
        ]));
        let request = der_sequence(cert_id);
        let ocsp = der_sequence(der_sequence(der_sequence(request)));

        let parsed = parse_ocsp_requests(&ocsp).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].serial_hex, "2a");
    }
}
