use crate::{
    AppState,
    asn1::{
        DerElement, DerTagClass, decode_oid_content, der_bit_string, der_context_primitive,
        der_explicit_context, der_integer_from_i64, der_octet_string, der_oid, der_sequence,
        is_universal_sequence, parse_children, parse_single,
    },
    certs::{IssueCsrRequest, IssuePublicKeyRequest, service as cert_service},
    cmp::{CmpMessageSummary, CmpStatusResponse},
    error::{AppError, AppResult},
    profiles::service as profile_service,
    storage::CmpAliasRecord,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384, Sha512};
use subtle::ConstantTimeEq;
use uuid::Uuid;
use x509_parser::prelude::{FromDer, X509Certificate};
use zeroize::Zeroize;

const OID_PASSWORD_BASED_MAC: &[u64] = &[1, 2, 840, 113533, 7, 66, 13];
const OID_SHA1: &[u64] = &[1, 3, 14, 3, 2, 26];
const OID_SHA256: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 2, 1];
const OID_SHA384: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 2, 2];
const OID_SHA512: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 2, 3];
const OID_HMAC_SHA1: &[u64] = &[1, 2, 840, 113549, 2, 7];
const OID_HMAC_SHA256: &[u64] = &[1, 2, 840, 113549, 2, 9];
const OID_HMAC_SHA384: &[u64] = &[1, 2, 840, 113549, 2, 10];
const OID_HMAC_SHA512: &[u64] = &[1, 2, 840, 113549, 2, 11];
const MAX_PBM_SALT_BYTES: usize = 128;
const MAX_PBM_ITERATIONS: usize = 100_000;
const CMP_CLIENT_PBM_ITERATIONS: i64 = 1000;

pub fn build_p10cr_pki_message_der(
    csr_der: &[u8],
    hmac_secret: Option<&[u8]>,
) -> AppResult<Vec<u8>> {
    if csr_der.is_empty() {
        return Err(AppError::BadRequest(
            "CMP p10cr CSR DER가 비어 있습니다".to_string(),
        ));
    }
    let csr = parse_single(csr_der)
        .map_err(|err| AppError::BadRequest(format!("CSR DER 파싱 실패: {err}")))?;
    if !is_universal_sequence(&csr) {
        return Err(AppError::BadRequest(
            "CMP p10cr CSR은 DER SEQUENCE여야 합니다".to_string(),
        ));
    }

    build_pki_message_der(4, csr.full.to_vec(), hmac_secret)
}

pub fn build_rr_pki_message_der(
    serial_hexes: &[String],
    hmac_secret: Option<&[u8]>,
) -> AppResult<Vec<u8>> {
    if serial_hexes.is_empty() {
        return Err(AppError::BadRequest(
            "CMP rr에는 최소 1개의 serial이 필요합니다".to_string(),
        ));
    }
    if serial_hexes.len() > 100 {
        return Err(AppError::BadRequest(
            "CMP rr serial이 너무 많습니다: 최대 100개".to_string(),
        ));
    }
    let rev_details = serial_hexes
        .iter()
        .map(|serial_hex| {
            let serial = cmp_serial_context_der(serial_hex)?;
            let cert_template = der_sequence(serial);
            Ok(der_sequence(cert_template))
        })
        .collect::<AppResult<Vec<_>>>()?;
    build_pki_message_der(11, der_sequence(join(rev_details)), hmac_secret)
}

fn build_pki_message_der(
    body_tag: u8,
    body_content_der: Vec<u8>,
    hmac_secret: Option<&[u8]>,
) -> AppResult<Vec<u8>> {
    let transaction_id = Uuid::new_v4().as_bytes().to_vec();
    let sender_nonce = Uuid::new_v4().as_bytes().to_vec();
    let body = der_explicit_context(body_tag, body_content_der);
    if let Some(secret) = hmac_secret {
        let salt = Uuid::new_v4().as_bytes().to_vec();
        let header = cmp_request_header_der(
            Some(cmp_pbm_protection_alg_der(&salt)),
            transaction_id,
            sender_nonce,
        );
        let protected_part = der_sequence(join([header.clone(), body.clone()]));
        let mut key = derive_pbm_key(
            secret,
            &salt,
            OneWayFunction::Sha256,
            CMP_CLIENT_PBM_ITERATIONS as usize,
        )?;
        let mac = compute_pbm_mac(MacAlgorithm::HmacSha256, &key, &protected_part)?;
        key.zeroize();
        return Ok(der_sequence(join([
            header,
            body,
            der_explicit_context(0, der_bit_string(mac)),
        ])));
    }

    let header = cmp_request_header_der(None, transaction_id, sender_nonce);
    Ok(der_sequence(join([header, body])))
}

fn cmp_serial_context_der(serial_hex: &str) -> AppResult<Vec<u8>> {
    let mut bytes = hex::decode(serial_hex.trim_start_matches("0x")).map_err(|err| {
        AppError::BadRequest(format!(
            "CMP rr serial hex 디코딩 실패: {serial_hex}: {err}"
        ))
    })?;
    while bytes.len() > 1 && bytes[0] == 0 {
        bytes.remove(0);
    }
    if bytes.is_empty() {
        bytes.push(0);
    }
    if bytes[0] & 0x80 != 0 {
        bytes.insert(0, 0);
    }
    Ok(der_context_primitive(1, bytes))
}

fn cmp_request_header_der(
    protection_alg_der: Option<Vec<u8>>,
    transaction_id: Vec<u8>,
    sender_nonce: Vec<u8>,
) -> Vec<u8> {
    let mut fields = join([
        der_integer_from_i64(2),
        der_explicit_context(4, der_sequence(Vec::new())),
        der_explicit_context(4, der_sequence(Vec::new())),
    ]);
    if let Some(protection_alg_der) = protection_alg_der {
        fields.extend(der_explicit_context(1, protection_alg_der));
    }
    fields.extend(der_context_primitive(4, transaction_id));
    fields.extend(der_context_primitive(5, sender_nonce));
    der_sequence(fields)
}

fn cmp_pbm_protection_alg_der(salt: &[u8]) -> Vec<u8> {
    let pbm_params = der_sequence(join([
        der_octet_string(salt.to_vec()),
        algorithm_identifier_der(OID_SHA256),
        der_integer_from_i64(CMP_CLIENT_PBM_ITERATIONS),
        algorithm_identifier_der(OID_HMAC_SHA256),
    ]));
    der_sequence(join([der_oid(OID_PASSWORD_BASED_MAC), pbm_params]))
}

fn algorithm_identifier_der(oid: &[u64]) -> Vec<u8> {
    der_sequence(der_oid(oid))
}

pub fn summarize_pki_message_der(body: &[u8]) -> AppResult<CmpMessageSummary> {
    let message = parse_pki_message(body)?;
    let certificate_serial_hexes = if matches!(message.body_tag, 1 | 3) {
        extract_cert_rep_serial_hexes(&message)?
    } else {
        Vec::new()
    };
    let revocation_status_count = if message.body_tag == 12 {
        Some(extract_rev_rep_status_count(&message)?)
    } else {
        None
    };
    Ok(CmpMessageSummary {
        body_type: message.body_type,
        body_tag: message.body_tag,
        protected: message.protected,
        extra_certs: message.extra_certs,
        certificate_serial_hexes,
        revocation_status_count,
    })
}

pub async fn accept_cmp_envelope(
    state: &AppState,
    alias: &str,
    body: &[u8],
) -> AppResult<CmpStatusResponse> {
    // EJBCA CmpServlet와 동일하게 입력 크기를 선제 제한하고, PKIBody 타입별 handler로 분기한다.
    if body.is_empty() {
        return Err(AppError::BadRequest(
            "CMP 요청 본문이 비어 있습니다".to_string(),
        ));
    }
    if body.len() > state.settings.max_request_bytes {
        return Err(AppError::BadRequest(format!(
            "CMP 요청이 너무 큽니다: {} > {}",
            body.len(),
            state.settings.max_request_bytes
        )));
    }

    let alias_config = state
        .db
        .get_cmp_alias_by_alias(alias)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("CMP alias를 찾을 수 없습니다: {alias}")))?;
    if !alias_config.enabled {
        return Err(AppError::Forbidden(format!(
            "CMP alias가 비활성 상태입니다: {alias}"
        )));
    }

    let mut message = parse_pki_message(body)?;
    message.protection_verified = enforce_cmp_message_protection(alias, &alias_config, &message)?;
    if message.body_tag == 4 {
        return handle_p10cr(state, alias, &alias_config, message).await;
    }
    if matches!(message.body_tag, 0 | 2) {
        return handle_crmf(state, alias, &alias_config, message).await;
    }
    if message.body_tag == 11 {
        return handle_rr(state, alias, &alias_config, message).await;
    }

    state
        .db
        .audit(
            "cmp-client",
            "cmp.receive",
            alias,
            "parsed_unsupported",
            &serde_json::json!({
                "body_type": message.body_type,
                "body_tag": message.body_tag,
                "protected": message.protected,
                "protection_verified": message.protection_verified,
                "extra_certs": message.extra_certs
            })
            .to_string(),
        )
        .await?;
    Ok(CmpStatusResponse {
        alias: alias.to_string(),
        status: "parsed_unsupported".to_string(),
        detail: format!(
            "RFC 4210 PKIMessage를 파싱했지만 이 PKIBody는 아직 지원하지 않습니다: {}({})",
            message.body_type, message.body_tag
        ),
        body_type: Some(message.body_type),
        body_tag: Some(message.body_tag),
        protected: message.protected,
        extra_certs: message.extra_certs,
        issued_certificate_id: None,
        serial_hex: None,
        cert_pem: None,
        issued_certificate_ids: Vec::new(),
        issued_serial_hexes: Vec::new(),
        revoked_certificate_ids: Vec::new(),
        revoked_serial_hexes: Vec::new(),
        pkixcmp_der: None,
        pkixcmp_der_base64: None,
    })
}

#[derive(Debug, Clone)]
struct ParsedPkiMessage {
    header_der: Vec<u8>,
    protected_part_der: Vec<u8>,
    protection_alg_der: Option<Vec<u8>>,
    protection_value: Option<Vec<u8>>,
    body_type: String,
    body_tag: u64,
    body_der: Vec<u8>,
    protected: bool,
    protection_verified: bool,
    extra_certs: bool,
}

#[derive(Debug, Clone)]
struct CrmfCertRequest {
    cert_req_id: i64,
    subject_dn: String,
    dns_names: Vec<String>,
    subject_public_key_info_der: Vec<u8>,
}

#[derive(Debug, Clone, Copy)]
enum OneWayFunction {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

#[derive(Debug, Clone, Copy)]
enum MacAlgorithm {
    HmacSha1,
    HmacSha256,
    HmacSha384,
    HmacSha512,
}

#[derive(Debug, Clone, Copy)]
struct PbmParameter {
    owf: OneWayFunction,
    iteration_count: usize,
    mac: MacAlgorithm,
}

fn parse_pki_message(body: &[u8]) -> AppResult<ParsedPkiMessage> {
    let root = parse_single(body)
        .map_err(|err| AppError::BadRequest(format!("CMP DER 파싱에 실패했습니다: {err}")))?;
    if !is_universal_sequence(&root) {
        return Err(AppError::BadRequest(
            "CMP PKIMessage는 DER SEQUENCE여야 합니다".to_string(),
        ));
    }
    let children = parse_children(root.content).map_err(|err| {
        AppError::BadRequest(format!("CMP PKIMessage가 올바르지 않습니다: {err}"))
    })?;
    if children.len() < 2 {
        return Err(AppError::BadRequest(
            "CMP PKIMessage에는 header와 body가 필요합니다".to_string(),
        ));
    }
    if !is_universal_sequence(&children[0]) {
        return Err(AppError::BadRequest(
            "CMP PKIHeader는 DER SEQUENCE여야 합니다".to_string(),
        ));
    }
    let header_children = parse_children(children[0].content)
        .map_err(|err| AppError::BadRequest(format!("CMP PKIHeader가 올바르지 않습니다: {err}")))?;
    let protection_alg_der = find_header_optional_context(&header_children, 1)
        .map(context_explicit_der)
        .transpose()?;

    let body_element = &children[1];
    if body_element.tag.class != DerTagClass::ContextSpecific {
        return Err(AppError::BadRequest(
            "CMP PKIBody는 context-specific CHOICE여야 합니다".to_string(),
        ));
    }
    let protection_value = children[2..]
        .iter()
        .find(|element| {
            element.tag.class == DerTagClass::ContextSpecific && element.tag.number == 0
        })
        .map(pki_protection_value)
        .transpose()?;
    let protected_part_der = der_sequence(join([
        children[0].full.to_vec(),
        body_element.full.to_vec(),
    ]));

    Ok(ParsedPkiMessage {
        header_der: children[0].full.to_vec(),
        protected_part_der,
        protection_alg_der,
        protection_value,
        body_type: cmp_body_name(body_element.tag.number).to_string(),
        body_tag: body_element.tag.number,
        body_der: body_element.content.to_vec(),
        protected: has_context_tag(&children[2..], 0),
        protection_verified: false,
        extra_certs: has_context_tag(&children[2..], 1),
    })
}

fn enforce_cmp_message_protection(
    alias: &str,
    alias_config: &CmpAliasRecord,
    message: &ParsedPkiMessage,
) -> AppResult<bool> {
    if alias_config.hmac_secret_sha256.is_none() {
        if message.protected {
            return Err(AppError::Forbidden(
                "CMP message protection이 있는 요청은 HMAC secret이 설정된 alias에서만 처리합니다"
                    .to_string(),
            ));
        }
        return Ok(false);
    }
    if !message.protected {
        return Err(AppError::Forbidden(format!(
            "CMP alias에는 message protection이 필요합니다: {alias}"
        )));
    }
    // DB에는 원문 secret을 저장하지 않고, 런타임 환경변수 값이 저장된 KDF hash와 일치할 때만 PBM 검증에 사용한다.
    let mut secret = load_cmp_alias_secret(alias, alias_config)?;
    let result = verify_pbm_message_protection(message, &secret);
    secret.zeroize();
    result?;
    Ok(true)
}

fn load_cmp_alias_secret(alias: &str, alias_config: &CmpAliasRecord) -> AppResult<Vec<u8>> {
    let configured_hash = alias_config
        .hmac_secret_sha256
        .as_deref()
        .ok_or_else(|| AppError::Internal("CMP alias HMAC hash가 없습니다".to_string()))?;
    let env_name = cmp_secret_env_name(alias);
    let mut secret = std::env::var(&env_name)
        .or_else(|_| std::env::var("EJBCA_RS_CMP_SECRET"))
        .map_err(|_| {
            AppError::Forbidden(format!(
                "CMP alias secret 환경변수가 필요합니다: {env_name} 또는 EJBCA_RS_CMP_SECRET"
            ))
        })?;
    if secret.is_empty() {
        return Err(AppError::Forbidden(format!(
            "CMP alias secret 환경변수가 비어 있습니다: {env_name}"
        )));
    }
    if !profile_service::verify_persisted_secret(&secret, configured_hash) {
        secret.zeroize();
        return Err(AppError::Forbidden(format!(
            "CMP alias secret이 저장된 해시와 일치하지 않습니다: {alias}"
        )));
    }
    let bytes = secret.as_bytes().to_vec();
    secret.zeroize();
    Ok(bytes)
}

fn cmp_secret_env_name(alias: &str) -> String {
    let suffix: String = alias
        .bytes()
        .map(|byte| {
            if byte.is_ascii_alphanumeric() {
                char::from(byte.to_ascii_uppercase())
            } else {
                '_'
            }
        })
        .collect();
    format!("EJBCA_RS_CMP_SECRET_{suffix}")
}

fn verify_pbm_message_protection(message: &ParsedPkiMessage, secret: &[u8]) -> AppResult<()> {
    let protection_alg_der = message.protection_alg_der.as_deref().ok_or_else(|| {
        AppError::BadRequest("CMP 보호 메시지에 protectionAlg가 없습니다".to_string())
    })?;
    let received = message.protection_value.as_deref().ok_or_else(|| {
        AppError::BadRequest("CMP 보호 메시지에 PKIProtection 값이 없습니다".to_string())
    })?;
    let protection_alg = parse_single(protection_alg_der)
        .map_err(|err| AppError::BadRequest(format!("CMP protectionAlg DER 파싱 실패: {err}")))?;
    let (oid, params) = parse_algorithm_identifier(&protection_alg, "CMP protectionAlg")?;
    if oid.as_slice() != OID_PASSWORD_BASED_MAC {
        return Err(AppError::Forbidden(format!(
            "지원하지 않는 CMP protectionAlg입니다: {}",
            oid_to_string(&oid)
        )));
    }
    let params = params.ok_or_else(|| {
        AppError::BadRequest(
            "PasswordBasedMac protectionAlg에는 PBMParameter가 필요합니다".to_string(),
        )
    })?;
    let (pbm, salt) = parse_pbm_parameter(&params)?;
    let mut key = derive_pbm_key(secret, &salt, pbm.owf, pbm.iteration_count)?;
    let expected = compute_pbm_mac(pbm.mac, &key, &message.protected_part_der)?;
    key.zeroize();
    if expected.as_slice().ct_eq(received).unwrap_u8() != 1 {
        return Err(AppError::Forbidden(
            "CMP message protection 검증에 실패했습니다".to_string(),
        ));
    }
    Ok(())
}

fn context_explicit_der(element: &DerElement<'_>) -> AppResult<Vec<u8>> {
    let inner = parse_single(element.content)
        .map_err(|err| AppError::BadRequest(format!("CMP explicit context 파싱 실패: {err}")))?;
    Ok(inner.full.to_vec())
}

fn pki_protection_value(element: &DerElement<'_>) -> AppResult<Vec<u8>> {
    let bit_string = parse_single(element.content)
        .ok()
        .filter(|inner| {
            inner.tag.class == DerTagClass::Universal
                && !inner.tag.constructed
                && inner.tag.number == 3
        })
        .map(|inner| inner.content)
        .unwrap_or(element.content);
    if bit_string.is_empty() {
        return Err(AppError::BadRequest(
            "CMP PKIProtection BIT STRING이 비어 있습니다".to_string(),
        ));
    }
    if bit_string[0] != 0 {
        return Err(AppError::BadRequest(
            "CMP PKIProtection BIT STRING은 unused bits가 0이어야 합니다".to_string(),
        ));
    }
    if bit_string.len() - 1 > 1024 {
        return Err(AppError::BadRequest(
            "CMP PKIProtection 값이 너무 큽니다".to_string(),
        ));
    }
    Ok(bit_string[1..].to_vec())
}

fn parse_pbm_parameter(params_der: &[u8]) -> AppResult<(PbmParameter, Vec<u8>)> {
    let params = parse_single(params_der)
        .map_err(|err| AppError::BadRequest(format!("CMP PBMParameter 파싱 실패: {err}")))?;
    if !is_universal_sequence(&params) {
        return Err(AppError::BadRequest(
            "CMP PBMParameter는 SEQUENCE여야 합니다".to_string(),
        ));
    }
    let fields = parse_children(params.content)
        .map_err(|err| AppError::BadRequest(format!("CMP PBMParameter 필드 파싱 실패: {err}")))?;
    if fields.len() != 4 {
        return Err(AppError::BadRequest(
            "CMP PBMParameter에는 salt, owf, iterationCount, mac이 필요합니다".to_string(),
        ));
    }
    let salt = octet_string_value(&fields[0], "CMP PBM salt")?;
    if salt.len() > MAX_PBM_SALT_BYTES {
        return Err(AppError::BadRequest(format!(
            "CMP PBM salt가 너무 큽니다: {} > {}",
            salt.len(),
            MAX_PBM_SALT_BYTES
        )));
    }
    let (owf_oid, _) = parse_algorithm_identifier(&fields[1], "CMP PBM owf")?;
    let (mac_oid, _) = parse_algorithm_identifier(&fields[3], "CMP PBM mac")?;
    let iteration_count = decode_positive_usize(&fields[2], "CMP PBM iterationCount")?;
    if iteration_count > MAX_PBM_ITERATIONS {
        return Err(AppError::BadRequest(format!(
            "CMP PBM iterationCount가 너무 큽니다: {iteration_count} > {MAX_PBM_ITERATIONS}"
        )));
    }
    Ok((
        PbmParameter {
            owf: one_way_function(&owf_oid)?,
            iteration_count,
            mac: mac_algorithm(&mac_oid)?,
        },
        salt,
    ))
}

fn parse_algorithm_identifier(
    element: &DerElement<'_>,
    label: &str,
) -> AppResult<(Vec<u64>, Option<Vec<u8>>)> {
    if !is_universal_sequence(element) {
        return Err(AppError::BadRequest(format!(
            "{label}는 AlgorithmIdentifier SEQUENCE여야 합니다"
        )));
    }
    let fields = parse_children(element.content)
        .map_err(|err| AppError::BadRequest(format!("{label} 파싱 실패: {err}")))?;
    let oid = fields
        .first()
        .ok_or_else(|| AppError::BadRequest(format!("{label}에 OID가 없습니다")))?;
    if oid.tag.class != DerTagClass::Universal || oid.tag.constructed || oid.tag.number != 6 {
        return Err(AppError::BadRequest(format!(
            "{label} 첫 필드는 OID여야 합니다"
        )));
    }
    let arcs = decode_oid_content(oid.content)
        .map_err(|err| AppError::BadRequest(format!("{label} OID 디코딩 실패: {err}")))?;
    Ok((arcs, fields.get(1).map(|field| field.full.to_vec())))
}

fn octet_string_value(element: &DerElement<'_>, label: &str) -> AppResult<Vec<u8>> {
    if element.tag.class != DerTagClass::Universal
        || element.tag.constructed
        || element.tag.number != 4
    {
        return Err(AppError::BadRequest(format!(
            "{label}는 OCTET STRING이어야 합니다"
        )));
    }
    Ok(element.content.to_vec())
}

fn decode_positive_usize(element: &DerElement<'_>, label: &str) -> AppResult<usize> {
    if element.tag.class != DerTagClass::Universal
        || element.tag.constructed
        || element.tag.number != 2
    {
        return Err(AppError::BadRequest(format!(
            "{label}는 INTEGER여야 합니다"
        )));
    }
    if element.content.is_empty() || element.content[0] & 0x80 != 0 {
        return Err(AppError::BadRequest(format!(
            "{label}는 양수 INTEGER여야 합니다"
        )));
    }
    let mut value = 0usize;
    for byte in element.content {
        value = value
            .checked_mul(256)
            .and_then(|current| current.checked_add(usize::from(*byte)))
            .ok_or_else(|| AppError::BadRequest(format!("{label}가 너무 큽니다")))?;
    }
    if value == 0 {
        return Err(AppError::BadRequest(format!(
            "{label}는 1 이상이어야 합니다"
        )));
    }
    Ok(value)
}

fn one_way_function(oid: &[u64]) -> AppResult<OneWayFunction> {
    match oid {
        OID_SHA1 => Ok(OneWayFunction::Sha1),
        OID_SHA256 => Ok(OneWayFunction::Sha256),
        OID_SHA384 => Ok(OneWayFunction::Sha384),
        OID_SHA512 => Ok(OneWayFunction::Sha512),
        _ => Err(AppError::Forbidden(format!(
            "지원하지 않는 CMP PBM OWF입니다: {}",
            oid_to_string(oid)
        ))),
    }
}

fn mac_algorithm(oid: &[u64]) -> AppResult<MacAlgorithm> {
    match oid {
        OID_HMAC_SHA1 => Ok(MacAlgorithm::HmacSha1),
        OID_HMAC_SHA256 => Ok(MacAlgorithm::HmacSha256),
        OID_HMAC_SHA384 => Ok(MacAlgorithm::HmacSha384),
        OID_HMAC_SHA512 => Ok(MacAlgorithm::HmacSha512),
        _ => Err(AppError::Forbidden(format!(
            "지원하지 않는 CMP PBM MAC입니다: {}",
            oid_to_string(oid)
        ))),
    }
}

fn derive_pbm_key(
    secret: &[u8],
    salt: &[u8],
    owf: OneWayFunction,
    iteration_count: usize,
) -> AppResult<Vec<u8>> {
    // RFC 4210 PBM 규칙: shared secret 뒤에 salt를 붙인 값을 첫 OWF 입력으로 사용하고,
    // iterationCount만큼 반복한 최종 BASEKEY를 MAC key로 사용한다.
    let mut input = Vec::with_capacity(secret.len() + salt.len());
    input.extend_from_slice(secret);
    input.extend_from_slice(salt);
    let mut key = digest_once(owf, &input);
    input.zeroize();
    for _ in 1..iteration_count {
        let next = digest_once(owf, &key);
        key.zeroize();
        key = next;
    }
    Ok(key)
}

fn digest_once(owf: OneWayFunction, input: &[u8]) -> Vec<u8> {
    match owf {
        OneWayFunction::Sha1 => Sha1::digest(input).to_vec(),
        OneWayFunction::Sha256 => Sha256::digest(input).to_vec(),
        OneWayFunction::Sha384 => Sha384::digest(input).to_vec(),
        OneWayFunction::Sha512 => Sha512::digest(input).to_vec(),
    }
}

fn compute_pbm_mac(mac: MacAlgorithm, key: &[u8], data: &[u8]) -> AppResult<Vec<u8>> {
    match mac {
        MacAlgorithm::HmacSha1 => {
            let mut hmac = Hmac::<Sha1>::new_from_slice(key)
                .map_err(|err| AppError::Internal(format!("HMAC-SHA1 초기화 실패: {err}")))?;
            hmac.update(data);
            Ok(hmac.finalize().into_bytes().to_vec())
        }
        MacAlgorithm::HmacSha256 => {
            let mut hmac = Hmac::<Sha256>::new_from_slice(key)
                .map_err(|err| AppError::Internal(format!("HMAC-SHA256 초기화 실패: {err}")))?;
            hmac.update(data);
            Ok(hmac.finalize().into_bytes().to_vec())
        }
        MacAlgorithm::HmacSha384 => {
            let mut hmac = Hmac::<Sha384>::new_from_slice(key)
                .map_err(|err| AppError::Internal(format!("HMAC-SHA384 초기화 실패: {err}")))?;
            hmac.update(data);
            Ok(hmac.finalize().into_bytes().to_vec())
        }
        MacAlgorithm::HmacSha512 => {
            let mut hmac = Hmac::<Sha512>::new_from_slice(key)
                .map_err(|err| AppError::Internal(format!("HMAC-SHA512 초기화 실패: {err}")))?;
            hmac.update(data);
            Ok(hmac.finalize().into_bytes().to_vec())
        }
    }
}

fn oid_to_string(oid: &[u64]) -> String {
    oid.iter().map(u64::to_string).collect::<Vec<_>>().join(".")
}

async fn handle_p10cr(
    state: &AppState,
    alias: &str,
    alias_config: &CmpAliasRecord,
    message: ParsedPkiMessage,
) -> AppResult<CmpStatusResponse> {
    let csr_der = extract_p10cr_csr_der(&message)?;
    let csr_pem = pem::encode(&pem::Pem::new("CERTIFICATE REQUEST", csr_der));
    let issued = cert_service::issue_from_csr_with_source(
        state,
        IssueCsrRequest {
            ca_id: alias_config.ca_id.clone(),
            certificate_profile_id: alias_config.certificate_profile_id.clone(),
            end_entity_profile_id: alias_config.end_entity_profile_id.clone(),
            csr_pem,
            validity_days: None,
        },
        "cmp-client",
        "cmp",
    )
    .await?;

    let cert_der = pem::parse(&issued.cert_pem)
        .map_err(|err| AppError::Internal(format!("발급 인증서 PEM 파싱 실패: {err}")))?
        .contents()
        .to_vec();
    let pkixcmp_der = cmp_cert_rep_pki_message_der(&message.header_der, 3, vec![(0, cert_der)])?;

    state
        .db
        .audit(
            "cmp-client",
            "cmp.p10cr.issue",
            alias,
            "success",
            &serde_json::json!({
                "certificate_id": issued.id,
                "serial": issued.serial_hex,
                "ca_id": issued.ca_id,
                "protected": message.protected,
                "protection_verified": message.protection_verified,
                "extra_certs": message.extra_certs
            })
            .to_string(),
        )
        .await?;

    Ok(CmpStatusResponse {
        alias: alias.to_string(),
        status: "issued".to_string(),
        detail: "CMP p10cr PKCS#10 요청을 처리해 인증서를 발급했습니다".to_string(),
        body_type: Some(message.body_type),
        body_tag: Some(message.body_tag),
        protected: message.protected,
        extra_certs: message.extra_certs,
        issued_certificate_id: Some(issued.id),
        serial_hex: Some(issued.serial_hex),
        cert_pem: Some(issued.cert_pem),
        issued_certificate_ids: Vec::new(),
        issued_serial_hexes: Vec::new(),
        revoked_certificate_ids: Vec::new(),
        revoked_serial_hexes: Vec::new(),
        pkixcmp_der_base64: Some(STANDARD.encode(&pkixcmp_der)),
        pkixcmp_der: Some(pkixcmp_der),
    })
}

async fn handle_crmf(
    state: &AppState,
    alias: &str,
    alias_config: &CmpAliasRecord,
    message: ParsedPkiMessage,
) -> AppResult<CmpStatusResponse> {
    let requests = extract_crmf_cert_requests(&message)?;
    let response_body_tag = if message.body_tag == 0 { 1 } else { 3 };
    let mut issued_ids = Vec::with_capacity(requests.len());
    let mut issued_serials = Vec::with_capacity(requests.len());
    let mut issued_cert_pem = None;
    let mut cert_responses = Vec::with_capacity(requests.len());

    for request in requests {
        let cert_req_id = request.cert_req_id;
        let issued = cert_service::issue_from_public_key_with_source(
            state,
            IssuePublicKeyRequest {
                ca_id: alias_config.ca_id.clone(),
                certificate_profile_id: alias_config.certificate_profile_id.clone(),
                end_entity_profile_id: alias_config.end_entity_profile_id.clone(),
                subject_dn: request.subject_dn.clone(),
                dns_names: request.dns_names.clone(),
                subject_public_key_info_der: request.subject_public_key_info_der,
                validity_days: None,
            },
            "cmp-client",
            "cmp",
        )
        .await?;
        let cert_der = pem::parse(&issued.cert_pem)
            .map_err(|err| AppError::Internal(format!("발급 인증서 PEM 파싱 실패: {err}")))?
            .contents()
            .to_vec();
        cert_responses.push((cert_req_id, cert_der));
        issued_cert_pem.get_or_insert_with(|| issued.cert_pem.clone());
        issued_ids.push(issued.id);
        issued_serials.push(issued.serial_hex);
    }

    let pkixcmp_der =
        cmp_cert_rep_pki_message_der(&message.header_der, response_body_tag, cert_responses)?;
    state
        .db
        .audit(
            "cmp-client",
            "cmp.crmf.issue",
            alias,
            "success",
            &serde_json::json!({
                "body_type": message.body_type,
                "body_tag": message.body_tag,
                "response_body_tag": response_body_tag,
                "certificate_ids": &issued_ids,
                "serials": &issued_serials,
                "protected": message.protected,
                "protection_verified": message.protection_verified,
                "extra_certs": message.extra_certs
            })
            .to_string(),
        )
        .await?;

    Ok(CmpStatusResponse {
        alias: alias.to_string(),
        status: "issued".to_string(),
        detail: format!(
            "CMP {} CRMF 요청을 처리해 인증서 {}개를 발급했습니다",
            message.body_type,
            issued_ids.len()
        ),
        body_type: Some(message.body_type),
        body_tag: Some(message.body_tag),
        protected: message.protected,
        extra_certs: message.extra_certs,
        issued_certificate_id: issued_ids.first().cloned(),
        serial_hex: issued_serials.first().cloned(),
        cert_pem: issued_cert_pem,
        issued_certificate_ids: issued_ids,
        issued_serial_hexes: issued_serials,
        revoked_certificate_ids: Vec::new(),
        revoked_serial_hexes: Vec::new(),
        pkixcmp_der_base64: Some(STANDARD.encode(&pkixcmp_der)),
        pkixcmp_der: Some(pkixcmp_der),
    })
}

async fn handle_rr(
    state: &AppState,
    alias: &str,
    alias_config: &CmpAliasRecord,
    message: ParsedPkiMessage,
) -> AppResult<CmpStatusResponse> {
    let ca_id = alias_config.ca_id.as_deref().ok_or_else(|| {
        AppError::BadRequest(format!("CMP alias에 CA가 연결되어 있지 않습니다: {alias}"))
    })?;
    let serial_hexes = extract_rr_serial_hexes(&message)?;
    let mut revoked_ids = Vec::with_capacity(serial_hexes.len());
    let mut revoked_serials = Vec::with_capacity(serial_hexes.len());

    for serial_hex in &serial_hexes {
        let revoked = cert_service::revoke_certificate_by_serial(
            state,
            ca_id,
            serial_hex,
            "cmp-request",
            "cmp-client",
        )
        .await?;
        revoked_ids.push(revoked.id);
        revoked_serials.push(revoked.serial_hex);
    }

    let pkixcmp_der = cmp_rev_rep_pki_message_der(&message.header_der, revoked_serials.len())?;
    state
        .db
        .audit(
            "cmp-client",
            "cmp.rr.revoke",
            alias,
            "success",
            &serde_json::json!({
                "ca_id": ca_id,
                "serials": &revoked_serials,
                "certificate_ids": &revoked_ids,
                "protected": message.protected,
                "protection_verified": message.protection_verified,
                "extra_certs": message.extra_certs
            })
            .to_string(),
        )
        .await?;

    Ok(CmpStatusResponse {
        alias: alias.to_string(),
        status: "revoked".to_string(),
        detail: format!(
            "CMP rr 요청을 처리해 인증서 {}개를 폐기했습니다",
            revoked_serials.len()
        ),
        body_type: Some(message.body_type),
        body_tag: Some(message.body_tag),
        protected: message.protected,
        extra_certs: message.extra_certs,
        issued_certificate_id: None,
        serial_hex: revoked_serials.first().cloned(),
        cert_pem: None,
        issued_certificate_ids: Vec::new(),
        issued_serial_hexes: Vec::new(),
        revoked_certificate_ids: revoked_ids,
        revoked_serial_hexes: revoked_serials,
        pkixcmp_der_base64: Some(STANDARD.encode(&pkixcmp_der)),
        pkixcmp_der: Some(pkixcmp_der),
    })
}

fn extract_p10cr_csr_der(message: &ParsedPkiMessage) -> AppResult<Vec<u8>> {
    if message.body_tag != 4 {
        return Err(AppError::BadRequest(
            "CMP body가 p10cr이 아닙니다".to_string(),
        ));
    }
    let inner = parse_single(&message.body_der)
        .map_err(|err| AppError::BadRequest(format!("CMP p10cr CSR DER 파싱 실패: {err}")))?;
    if !is_universal_sequence(&inner) {
        return Err(AppError::BadRequest(
            "CMP p10cr 본문은 PKCS#10 CertificationRequest SEQUENCE여야 합니다".to_string(),
        ));
    }
    Ok(inner.full.to_vec())
}

fn extract_crmf_cert_requests(message: &ParsedPkiMessage) -> AppResult<Vec<CrmfCertRequest>> {
    if !matches!(message.body_tag, 0 | 2) {
        return Err(AppError::BadRequest(
            "CMP body가 ir/cr이 아닙니다".to_string(),
        ));
    }
    let cert_req_messages = parse_single(&message.body_der).map_err(|err| {
        AppError::BadRequest(format!("CMP CRMF CertReqMessages 파싱 실패: {err}"))
    })?;
    if !is_universal_sequence(&cert_req_messages) {
        return Err(AppError::BadRequest(
            "CMP ir/cr 본문은 CertReqMessages SEQUENCE여야 합니다".to_string(),
        ));
    }
    let messages = parse_children(cert_req_messages.content).map_err(|err| {
        AppError::BadRequest(format!("CMP CRMF CertReqMsg 목록 파싱 실패: {err}"))
    })?;
    if messages.is_empty() {
        return Err(AppError::BadRequest(
            "CMP CRMF 요청에는 최소 1개의 CertReqMsg가 필요합니다".to_string(),
        ));
    }
    if messages.len() > 100 {
        return Err(AppError::BadRequest(
            "CMP CRMF CertReqMsg가 너무 많습니다: 최대 100개".to_string(),
        ));
    }

    messages.into_iter().map(parse_crmf_cert_req_msg).collect()
}

fn parse_crmf_cert_req_msg(message: DerElement<'_>) -> AppResult<CrmfCertRequest> {
    if !is_universal_sequence(&message) {
        return Err(AppError::BadRequest(
            "CMP CRMF CertReqMsg는 SEQUENCE여야 합니다".to_string(),
        ));
    }
    let fields = parse_children(message.content)
        .map_err(|err| AppError::BadRequest(format!("CMP CRMF CertReqMsg 파싱 실패: {err}")))?;
    let cert_request = fields.first().ok_or_else(|| {
        AppError::BadRequest("CMP CRMF CertReqMsg에 certReq가 없습니다".to_string())
    })?;
    if !fields.get(1).is_some_and(is_ra_verified_pop) {
        return Err(AppError::Forbidden(
            "CMP CRMF ir/cr은 현재 ProofOfPossession.raVerified만 지원합니다".to_string(),
        ));
    }
    parse_crmf_cert_request(*cert_request)
}

fn parse_crmf_cert_request(cert_request: DerElement<'_>) -> AppResult<CrmfCertRequest> {
    if !is_universal_sequence(&cert_request) {
        return Err(AppError::BadRequest(
            "CMP CRMF CertRequest는 SEQUENCE여야 합니다".to_string(),
        ));
    }
    let fields = parse_children(cert_request.content)
        .map_err(|err| AppError::BadRequest(format!("CMP CRMF CertRequest 파싱 실패: {err}")))?;
    if fields.len() < 2 {
        return Err(AppError::BadRequest(
            "CMP CRMF CertRequest에는 certReqId와 certTemplate이 필요합니다".to_string(),
        ));
    }
    let cert_req_id = decode_integer_i64(&fields[0])?;
    let cert_template = &fields[1];
    if !is_universal_sequence(cert_template) {
        return Err(AppError::BadRequest(
            "CMP CRMF CertTemplate은 SEQUENCE여야 합니다".to_string(),
        ));
    }
    let template_fields = parse_children(cert_template.content)
        .map_err(|err| AppError::BadRequest(format!("CMP CRMF CertTemplate 파싱 실패: {err}")))?;
    let subject = find_context(&template_fields, 5).ok_or_else(|| {
        AppError::BadRequest("CMP CRMF CertTemplate.subject가 없습니다".to_string())
    })?;
    let public_key = find_context(&template_fields, 6).ok_or_else(|| {
        AppError::BadRequest("CMP CRMF CertTemplate.publicKey가 없습니다".to_string())
    })?;
    let subject_der = context_sequence_der(subject)?;
    let subject_dn = x509_name_der_to_subject_dn(&subject_der)?;
    let subject_public_key_info_der = context_sequence_der(public_key)?;
    let dns_names = find_context(&template_fields, 9)
        .map(extract_dns_names_from_extensions)
        .transpose()?
        .unwrap_or_default();

    Ok(CrmfCertRequest {
        cert_req_id,
        subject_dn,
        dns_names,
        subject_public_key_info_der,
    })
}

fn is_ra_verified_pop(element: &DerElement<'_>) -> bool {
    element.tag.class == DerTagClass::ContextSpecific
        && element.tag.number == 0
        && element.content.is_empty()
}

fn context_sequence_der(element: &DerElement<'_>) -> AppResult<Vec<u8>> {
    if element.tag.class != DerTagClass::ContextSpecific {
        return Err(AppError::BadRequest(
            "CMP CRMF context-specific 필드가 아닙니다".to_string(),
        ));
    }
    Ok(der_sequence(element.content.to_vec()))
}

fn decode_integer_i64(element: &DerElement<'_>) -> AppResult<i64> {
    if element.tag.class != DerTagClass::Universal
        || element.tag.constructed
        || element.tag.number != 2
    {
        return Err(AppError::BadRequest(
            "CMP CRMF INTEGER 필드가 아닙니다".to_string(),
        ));
    }
    if element.content.is_empty() || element.content.len() > 8 {
        return Err(AppError::BadRequest(
            "CMP CRMF INTEGER 크기가 올바르지 않습니다".to_string(),
        ));
    }
    let negative = element.content[0] & 0x80 != 0;
    let mut value = if negative { -1_i64 } else { 0_i64 };
    for byte in element.content {
        value = (value << 8) | i64::from(*byte);
    }
    Ok(value)
}

fn x509_name_der_to_subject_dn(name_der: &[u8]) -> AppResult<String> {
    let name = parse_single(name_der)
        .map_err(|err| AppError::BadRequest(format!("X.509 Name DER 파싱 실패: {err}")))?;
    if !is_universal_sequence(&name) {
        return Err(AppError::BadRequest(
            "X.509 Name은 SEQUENCE여야 합니다".to_string(),
        ));
    }
    let rdns = parse_children(name.content)
        .map_err(|err| AppError::BadRequest(format!("X.509 Name RDN 파싱 실패: {err}")))?;
    let mut parts = Vec::new();
    for rdn in rdns {
        if rdn.tag.class != DerTagClass::Universal || !rdn.tag.constructed || rdn.tag.number != 17 {
            return Err(AppError::BadRequest(
                "X.509 Name RDN은 SET이어야 합니다".to_string(),
            ));
        }
        let attrs = parse_children(rdn.content).map_err(|err| {
            AppError::BadRequest(format!("X.509 Name Attribute 파싱 실패: {err}"))
        })?;
        for attr in attrs {
            if !is_universal_sequence(&attr) {
                return Err(AppError::BadRequest(
                    "X.509 AttributeTypeAndValue는 SEQUENCE여야 합니다".to_string(),
                ));
            }
            let attr_fields = parse_children(attr.content).map_err(|err| {
                AppError::BadRequest(format!("X.509 AttributeTypeAndValue 파싱 실패: {err}"))
            })?;
            if attr_fields.len() != 2 {
                return Err(AppError::BadRequest(
                    "X.509 AttributeTypeAndValue 필드 수가 올바르지 않습니다".to_string(),
                ));
            }
            let label = dn_label_from_oid(&attr_fields[0])?;
            let value = der_string_value(&attr_fields[1])?;
            parts.push(format!("{label}={value}"));
        }
    }
    if parts.is_empty() {
        return Err(AppError::BadRequest(
            "CMP CRMF subject DN이 비어 있습니다".to_string(),
        ));
    }
    Ok(parts.join(","))
}

fn dn_label_from_oid(element: &DerElement<'_>) -> AppResult<&'static str> {
    if element.tag.class != DerTagClass::Universal
        || element.tag.constructed
        || element.tag.number != 6
    {
        return Err(AppError::BadRequest("DN 속성 OID가 아닙니다".to_string()));
    }
    let arcs = decode_oid_content(element.content)
        .map_err(|err| AppError::BadRequest(format!("DN 속성 OID 디코딩 실패: {err}")))?;
    match arcs.as_slice() {
        [2, 5, 4, 3] => Ok("CN"),
        [2, 5, 4, 6] => Ok("C"),
        [2, 5, 4, 7] => Ok("L"),
        [2, 5, 4, 8] => Ok("ST"),
        [2, 5, 4, 10] => Ok("O"),
        [2, 5, 4, 11] => Ok("OU"),
        _ => Err(AppError::BadRequest(format!(
            "지원하지 않는 DN 속성 OID입니다: {}",
            arcs.iter()
                .map(u64::to_string)
                .collect::<Vec<_>>()
                .join(".")
        ))),
    }
}

fn der_string_value(element: &DerElement<'_>) -> AppResult<String> {
    match (element.tag.class, element.tag.number) {
        (DerTagClass::Universal, 12 | 19 | 20 | 22) => String::from_utf8(element.content.to_vec())
            .map_err(|_| AppError::BadRequest("DN 문자열이 UTF-8이 아닙니다".to_string())),
        (DerTagClass::Universal, 30) => utf16be_to_string(element.content),
        _ => Err(AppError::BadRequest(
            "지원하지 않는 DN 문자열 타입입니다".to_string(),
        )),
    }
}

fn utf16be_to_string(input: &[u8]) -> AppResult<String> {
    if !input.len().is_multiple_of(2) {
        return Err(AppError::BadRequest(
            "BMPString 길이가 올바르지 않습니다".to_string(),
        ));
    }
    let code_units = input
        .chunks_exact(2)
        .map(|chunk| u16::from_be_bytes([chunk[0], chunk[1]]));
    String::from_utf16(&code_units.collect::<Vec<_>>())
        .map_err(|_| AppError::BadRequest("BMPString 디코딩 실패".to_string()))
}

fn extract_dns_names_from_extensions(element: &DerElement<'_>) -> AppResult<Vec<String>> {
    let extensions_der = context_sequence_der(element)?;
    let extensions = parse_single(&extensions_der)
        .map_err(|err| AppError::BadRequest(format!("CRMF extensions 파싱 실패: {err}")))?;
    let extension_items = parse_children(extensions.content)
        .map_err(|err| AppError::BadRequest(format!("CRMF extension 목록 파싱 실패: {err}")))?;
    let mut dns_names = Vec::new();
    for extension in extension_items {
        if !is_universal_sequence(&extension) {
            return Err(AppError::BadRequest(
                "CRMF Extension은 SEQUENCE여야 합니다".to_string(),
            ));
        }
        let fields = parse_children(extension.content)
            .map_err(|err| AppError::BadRequest(format!("CRMF Extension 파싱 실패: {err}")))?;
        if fields.len() < 2 {
            return Err(AppError::BadRequest(
                "CRMF Extension 필드 수가 올바르지 않습니다".to_string(),
            ));
        }
        let oid = decode_oid_content(fields[0].content)
            .map_err(|err| AppError::BadRequest(format!("Extension OID 디코딩 실패: {err}")))?;
        if oid.as_slice() != [2, 5, 29, 17] {
            continue;
        }
        let value = fields
            .iter()
            .find(|field| field.tag.class == DerTagClass::Universal && field.tag.number == 4)
            .ok_or_else(|| {
                AppError::BadRequest("subjectAltName extnValue가 없습니다".to_string())
            })?;
        dns_names.extend(extract_dns_names_from_general_names(value.content)?);
    }
    Ok(dns_names)
}

fn extract_dns_names_from_general_names(input: &[u8]) -> AppResult<Vec<String>> {
    let names = parse_single(input)
        .map_err(|err| AppError::BadRequest(format!("GeneralNames 파싱 실패: {err}")))?;
    if !is_universal_sequence(&names) {
        return Err(AppError::BadRequest(
            "GeneralNames는 SEQUENCE여야 합니다".to_string(),
        ));
    }
    let items = parse_children(names.content)
        .map_err(|err| AppError::BadRequest(format!("GeneralName 목록 파싱 실패: {err}")))?;
    let mut dns_names = Vec::new();
    for item in items {
        if item.tag.class == DerTagClass::ContextSpecific && item.tag.number == 2 {
            let dns = String::from_utf8(item.content.to_vec()).map_err(|_| {
                AppError::BadRequest("dNSName GeneralName이 UTF-8이 아닙니다".to_string())
            })?;
            if !dns.is_empty() {
                dns_names.push(dns);
            }
        }
    }
    Ok(dns_names)
}

fn extract_rr_serial_hexes(message: &ParsedPkiMessage) -> AppResult<Vec<String>> {
    if message.body_tag != 11 {
        return Err(AppError::BadRequest("CMP body가 rr이 아닙니다".to_string()));
    }
    let rev_req = parse_single(&message.body_der)
        .map_err(|err| AppError::BadRequest(format!("CMP rr RevReqContent 파싱 실패: {err}")))?;
    if !is_universal_sequence(&rev_req) {
        return Err(AppError::BadRequest(
            "CMP rr 본문은 RevReqContent SEQUENCE여야 합니다".to_string(),
        ));
    }

    let details = parse_children(rev_req.content)
        .map_err(|err| AppError::BadRequest(format!("CMP rr RevDetails 파싱 실패: {err}")))?;
    if details.is_empty() {
        return Err(AppError::BadRequest(
            "CMP rr에는 최소 1개의 RevDetails가 필요합니다".to_string(),
        ));
    }
    if details.len() > 100 {
        return Err(AppError::BadRequest(
            "CMP rr RevDetails가 너무 많습니다: 최대 100개".to_string(),
        ));
    }

    let mut serials = Vec::with_capacity(details.len());
    for detail in details {
        if !is_universal_sequence(&detail) {
            return Err(AppError::BadRequest(
                "CMP rr RevDetails는 SEQUENCE여야 합니다".to_string(),
            ));
        }
        let fields = parse_children(detail.content).map_err(|err| {
            AppError::BadRequest(format!("CMP rr RevDetails 내부 파싱 실패: {err}"))
        })?;
        let cert_template = fields.first().ok_or_else(|| {
            AppError::BadRequest("CMP rr RevDetails에 certDetails가 없습니다".to_string())
        })?;
        if !is_universal_sequence(cert_template) {
            return Err(AppError::BadRequest(
                "CMP rr certDetails는 CertTemplate SEQUENCE여야 합니다".to_string(),
            ));
        }
        let template_fields = parse_children(cert_template.content)
            .map_err(|err| AppError::BadRequest(format!("CMP rr CertTemplate 파싱 실패: {err}")))?;
        let serial = find_context(&template_fields, 1).ok_or_else(|| {
            AppError::BadRequest("CMP rr CertTemplate.serialNumber가 없습니다".to_string())
        })?;
        serials.push(serial_context_to_hex(serial)?);
    }
    Ok(serials)
}

fn extract_cert_rep_serial_hexes(message: &ParsedPkiMessage) -> AppResult<Vec<String>> {
    let cert_rep = parse_single(&message.body_der)
        .map_err(|err| AppError::BadRequest(format!("CMP CertRepMessage 파싱 실패: {err}")))?;
    if !is_universal_sequence(&cert_rep) {
        return Err(AppError::BadRequest(
            "CMP CertRepMessage는 SEQUENCE여야 합니다".to_string(),
        ));
    }
    let fields = parse_children(cert_rep.content)
        .map_err(|err| AppError::BadRequest(format!("CMP CertRepMessage 필드 파싱 실패: {err}")))?;
    let responses = fields
        .iter()
        .find(|field| is_universal_sequence(field))
        .ok_or_else(|| {
            AppError::BadRequest("CMP CertRepMessage response가 없습니다".to_string())
        })?;
    let response_items = parse_children(responses.content)
        .map_err(|err| AppError::BadRequest(format!("CMP CertResponse 목록 파싱 실패: {err}")))?;
    let mut serials = Vec::new();
    for response in response_items {
        if !is_universal_sequence(&response) {
            continue;
        }
        let response_fields = parse_children(response.content)
            .map_err(|err| AppError::BadRequest(format!("CMP CertResponse 파싱 실패: {err}")))?;
        let Some(certified_key_pair) = response_fields.get(2) else {
            continue;
        };
        if !is_universal_sequence(certified_key_pair) {
            continue;
        }
        let ckp_fields = parse_children(certified_key_pair.content).map_err(|err| {
            AppError::BadRequest(format!("CMP CertifiedKeyPair 파싱 실패: {err}"))
        })?;
        let Some(cert_or_enc_cert) = ckp_fields.first() else {
            continue;
        };
        if cert_or_enc_cert.tag.class != DerTagClass::ContextSpecific {
            continue;
        }
        let cmp_certificate = parse_single(cert_or_enc_cert.content)
            .map_err(|err| AppError::BadRequest(format!("CMP CertOrEncCert 파싱 실패: {err}")))?;
        if cmp_certificate.tag.class != DerTagClass::ContextSpecific {
            continue;
        }
        let certificate = parse_single(cmp_certificate.content)
            .map_err(|err| AppError::BadRequest(format!("CMP Certificate 파싱 실패: {err}")))?;
        let (_, parsed) = X509Certificate::from_der(certificate.full)
            .map_err(|err| AppError::BadRequest(format!("CMP 인증서 DER 파싱 실패: {err}")))?;
        serials.push(serial_hex_from_raw(parsed.tbs_certificate.raw_serial()));
    }
    Ok(serials)
}

fn extract_rev_rep_status_count(message: &ParsedPkiMessage) -> AppResult<usize> {
    let rev_rep = parse_single(&message.body_der)
        .map_err(|err| AppError::BadRequest(format!("CMP RevRepContent 파싱 실패: {err}")))?;
    if !is_universal_sequence(&rev_rep) {
        return Err(AppError::BadRequest(
            "CMP RevRepContent는 SEQUENCE여야 합니다".to_string(),
        ));
    }
    let fields = parse_children(rev_rep.content)
        .map_err(|err| AppError::BadRequest(format!("CMP RevRepContent 필드 파싱 실패: {err}")))?;
    let statuses = fields
        .first()
        .ok_or_else(|| AppError::BadRequest("CMP RevRepContent status가 없습니다".to_string()))?;
    if !is_universal_sequence(statuses) {
        return Err(AppError::BadRequest(
            "CMP RevRepContent.status는 SEQUENCE여야 합니다".to_string(),
        ));
    }
    Ok(parse_children(statuses.content)
        .map_err(|err| AppError::BadRequest(format!("CMP PKIStatusInfo 목록 파싱 실패: {err}")))?
        .len())
}

fn serial_hex_from_raw(mut serial: &[u8]) -> String {
    while serial.len() > 1 && serial[0] == 0 {
        serial = &serial[1..];
    }
    hex::encode(serial)
}

fn serial_context_to_hex(element: &DerElement<'_>) -> AppResult<String> {
    let content = if let Ok(inner) = parse_single(element.content) {
        if inner.tag.class == DerTagClass::Universal
            && !inner.tag.constructed
            && inner.tag.number == 2
        {
            inner.content
        } else {
            element.content
        }
    } else {
        element.content
    };
    if content.is_empty() {
        return Err(AppError::BadRequest(
            "CMP rr serialNumber가 비어 있습니다".to_string(),
        ));
    }
    if content[0] & 0x80 != 0 {
        return Err(AppError::BadRequest(
            "CMP rr serialNumber는 양수 INTEGER여야 합니다".to_string(),
        ));
    }
    let mut serial = content;
    while serial.len() > 1 && serial[0] == 0 {
        serial = &serial[1..];
    }
    Ok(hex::encode(serial))
}

fn has_context_tag(elements: &[DerElement<'_>], tag: u64) -> bool {
    elements.iter().any(|element| {
        element.tag.class == DerTagClass::ContextSpecific && element.tag.number == tag
    })
}

fn find_context<'a>(elements: &'a [DerElement<'a>], tag: u64) -> Option<&'a DerElement<'a>> {
    elements.iter().find(|element| {
        element.tag.class == DerTagClass::ContextSpecific && element.tag.number == tag
    })
}

fn find_header_optional_context<'a>(
    elements: &'a [DerElement<'a>],
    tag: u64,
) -> Option<&'a DerElement<'a>> {
    elements.iter().skip(3).find(|element| {
        element.tag.class == DerTagClass::ContextSpecific && element.tag.number == tag
    })
}

fn cmp_cert_rep_pki_message_der(
    request_header_der: &[u8],
    response_body_tag: u8,
    responses: Vec<(i64, Vec<u8>)>,
) -> AppResult<Vec<u8>> {
    let header = cmp_response_header_der(request_header_der)?;
    let body = der_explicit_context(response_body_tag, cmp_cert_rep_message_der(responses));
    Ok(der_sequence(join([header, body])))
}

fn cmp_rev_rep_pki_message_der(
    request_header_der: &[u8],
    status_count: usize,
) -> AppResult<Vec<u8>> {
    let header = cmp_response_header_der(request_header_der)?;
    let body = der_explicit_context(12, cmp_rev_rep_content_der(status_count));
    Ok(der_sequence(join([header, body])))
}

fn cmp_response_header_der(request_header_der: &[u8]) -> AppResult<Vec<u8>> {
    let root = parse_single(request_header_der)
        .map_err(|err| AppError::BadRequest(format!("CMP header DER 파싱 실패: {err}")))?;
    let children = parse_children(root.content)
        .map_err(|err| AppError::BadRequest(format!("CMP header가 올바르지 않습니다: {err}")))?;

    if children.len() < 3 {
        let null_name = der_explicit_context(4, der_sequence(Vec::new()));
        return Ok(der_sequence(join([
            der_integer_from_i64(2),
            null_name.clone(),
            null_name,
        ])));
    }

    let mut content = join([
        children[0].full.to_vec(),
        children[2].full.to_vec(),
        children[1].full.to_vec(),
    ]);
    if let Some(transaction_id) = find_header_optional_context(&children, 4) {
        content.extend(transaction_id.full);
    }
    if let Some(sender_nonce) = find_header_optional_context(&children, 5) {
        content.extend(der_context_primitive(6, sender_nonce.content.to_vec()));
    }
    Ok(der_sequence(content))
}

fn cmp_cert_rep_message_der(responses: Vec<(i64, Vec<u8>)>) -> Vec<u8> {
    let mut response_content = Vec::new();
    for (cert_req_id, cert_der) in responses {
        let pki_status_info = der_sequence(der_integer_from_i64(0));
        let cmp_certificate = der_explicit_context(0, cert_der);
        let cert_or_enc_cert = der_explicit_context(0, cmp_certificate);
        let certified_key_pair = der_sequence(cert_or_enc_cert);
        let cert_response = der_sequence(join([
            der_integer_from_i64(cert_req_id),
            pki_status_info,
            certified_key_pair,
        ]));
        response_content.extend(cert_response);
    }
    der_sequence(der_sequence(response_content))
}

fn cmp_rev_rep_content_der(status_count: usize) -> Vec<u8> {
    let statuses = (0..status_count.max(1)).map(|_| der_sequence(der_integer_from_i64(0)));
    der_sequence(der_sequence(join(statuses)))
}

fn join(chunks: impl IntoIterator<Item = Vec<u8>>) -> Vec<u8> {
    let mut out = Vec::new();
    for chunk in chunks {
        out.extend(chunk);
    }
    out
}

fn cmp_body_name(tag: u64) -> &'static str {
    match tag {
        0 => "ir",
        1 => "ip",
        2 => "cr",
        3 => "cp",
        4 => "p10cr",
        5 => "popdecc",
        6 => "popdecr",
        7 => "kur",
        8 => "kup",
        9 => "krr",
        10 => "krp",
        11 => "rr",
        12 => "rp",
        13 => "ccr",
        14 => "ccp",
        15 => "ckuann",
        16 => "cann",
        17 => "rann",
        18 => "crlann",
        19 => "pkiconf",
        20 => "nested",
        21 => "genm",
        22 => "genp",
        23 => "error",
        24 => "certConf",
        25 => "pollReq",
        26 => "pollRep",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asn1::{
        der_bit_string, der_context_constructed, der_octet_string, der_oid, der_tlv,
    };
    use rcgen::{CertificateParams, KeyPair, PublicKeyData};

    #[test]
    fn identifies_cmp_p10cr_body() {
        let der = [
            0x30, 0x08, // PKIMessage
            0x30, 0x02, 0x05, 0x00, // PKIHeader placeholder sequence
            0xa4, 0x02, 0x05, 0x00, // PKIBody [4] p10cr placeholder
        ];
        let parsed = parse_pki_message(&der).unwrap();
        assert_eq!(parsed.body_tag, 4);
        assert_eq!(parsed.body_type, "p10cr");
    }

    #[test]
    fn rejects_non_sequence_cmp_message() {
        assert!(parse_pki_message(&[0x05, 0x00]).is_err());
    }

    #[test]
    fn verifies_pbm_protected_message() {
        let message = protected_placeholder_message(b"shared-secret");
        let parsed = parse_pki_message(&message).unwrap();

        verify_pbm_message_protection(&parsed, b"shared-secret").unwrap();
    }

    #[test]
    fn rejects_wrong_pbm_secret() {
        let message = protected_placeholder_message(b"shared-secret");
        let parsed = parse_pki_message(&message).unwrap();

        assert!(verify_pbm_message_protection(&parsed, b"wrong-secret").is_err());
    }

    #[test]
    fn extracts_p10cr_inner_der() {
        let der = [
            0x30, 0x08, // PKIMessage
            0x30, 0x02, 0x05, 0x00, // PKIHeader placeholder sequence
            0xa4, 0x02, 0x30, 0x00, // PKIBody [4] empty sequence placeholder
        ];
        let parsed = parse_pki_message(&der).unwrap();
        assert_eq!(extract_p10cr_csr_der(&parsed).unwrap(), vec![0x30, 0x00]);
    }

    #[test]
    fn builds_unprotected_p10cr_request_message() {
        let message = build_p10cr_pki_message_der(&der_sequence(Vec::new()), None).unwrap();
        let parsed = parse_pki_message(&message).unwrap();

        assert_eq!(parsed.body_tag, 4);
        assert_eq!(parsed.body_type, "p10cr");
        assert!(!parsed.protected);
        assert_eq!(
            extract_p10cr_csr_der(&parsed).unwrap(),
            der_sequence(Vec::new())
        );
    }

    #[test]
    fn builds_pbm_protected_p10cr_request_message() {
        let message =
            build_p10cr_pki_message_der(&der_sequence(Vec::new()), Some(b"shared-secret")).unwrap();
        let parsed = parse_pki_message(&message).unwrap();

        assert_eq!(parsed.body_tag, 4);
        assert!(parsed.protected);
        verify_pbm_message_protection(&parsed, b"shared-secret").unwrap();
        assert!(verify_pbm_message_protection(&parsed, b"wrong-secret").is_err());
    }

    #[test]
    fn builds_rr_request_message() {
        let message = build_rr_pki_message_der(&["abcd".to_string()], None).unwrap();
        let parsed = parse_pki_message(&message).unwrap();

        assert_eq!(parsed.body_tag, 11);
        assert_eq!(parsed.body_type, "rr");
        assert_eq!(extract_rr_serial_hexes(&parsed).unwrap(), vec!["abcd"]);
    }

    #[test]
    fn builds_cert_rep_pki_message_der() {
        let request_header = [
            0x30, 0x10, // PKIHeader
            0x02, 0x01, 0x02, // pvno
            0xa4, 0x02, 0x30, 0x00, // sender
            0xa4, 0x02, 0x30, 0x00, // recipient
            0x84, 0x03, 0x01, 0x02, 0x03, // transactionID
        ];
        let der =
            cmp_cert_rep_pki_message_der(&request_header, 3, vec![(0, vec![0x30, 0x00])]).unwrap();
        let parsed = parse_single(&der).unwrap();
        let children = parse_children(parsed.content).unwrap();
        assert!(is_universal_sequence(&children[0]));
        let response_header = parse_children(children[0].content).unwrap();
        assert_eq!(response_header[3].tag.number, 4);
        assert_eq!(response_header[3].content, &[0x01, 0x02, 0x03]);
        assert_eq!(children[1].tag.class, DerTagClass::ContextSpecific);
        assert_eq!(children[1].tag.number, 3);
    }

    #[test]
    fn extracts_crmf_cert_request() {
        let key_pair = KeyPair::generate().unwrap();
        let spki = key_pair.subject_public_key_info();
        let name = test_name_der("device-crmf");
        let general_names = der_sequence(der_tlv(0x82, b"device-crmf.example.com".to_vec()));
        let san_ext = der_sequence(join([
            der_oid(&[2, 5, 29, 17]),
            der_octet_string(general_names),
        ]));
        let extensions = der_sequence(san_ext);
        let cert_template = der_sequence(join([
            implicit_sequence(5, &name),
            implicit_sequence(6, &spki),
            implicit_sequence(9, &extensions),
        ]));
        let cert_request = der_sequence(join([der_integer_from_i64(7), cert_template]));
        let cert_req_msg = der_sequence(join([cert_request, der_context_primitive(0, Vec::new())]));
        let cert_req_messages = der_sequence(cert_req_msg);
        let der = der_sequence(join([
            der_sequence(vec![0x05, 0x00]),
            der_explicit_context(0, cert_req_messages),
        ]));

        let parsed = parse_pki_message(&der).unwrap();
        let requests = extract_crmf_cert_requests(&parsed).unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].cert_req_id, 7);
        assert_eq!(requests[0].subject_dn, "CN=device-crmf");
        assert_eq!(requests[0].dns_names, vec!["device-crmf.example.com"]);
        assert_eq!(requests[0].subject_public_key_info_der, spki);
    }

    #[test]
    fn extracts_rr_serial_numbers() {
        let cert_template = der_sequence(der_context_primitive(1, vec![0x00, 0xab, 0xcd]));
        let rev_details = der_sequence(cert_template);
        let rev_req_content = der_sequence(rev_details);
        let der = der_sequence(join([
            der_sequence(vec![0x05, 0x00]),
            der_explicit_context(11, rev_req_content),
        ]));
        let parsed = parse_pki_message(&der).unwrap();
        assert_eq!(parsed.body_tag, 11);
        assert_eq!(extract_rr_serial_hexes(&parsed).unwrap(), vec!["abcd"]);
    }

    #[test]
    fn builds_rev_rep_pki_message_der() {
        let request_header = [
            0x30, 0x10, // PKIHeader
            0x02, 0x01, 0x02, // pvno
            0xa4, 0x02, 0x30, 0x00, // sender
            0xa4, 0x02, 0x30, 0x00, // recipient
            0x84, 0x03, 0x01, 0x02, 0x03, // transactionID
        ];
        let der = cmp_rev_rep_pki_message_der(&request_header, 2).unwrap();
        let parsed = parse_single(&der).unwrap();
        let children = parse_children(parsed.content).unwrap();
        assert!(is_universal_sequence(&children[0]));
        assert_eq!(children[1].tag.class, DerTagClass::ContextSpecific);
        assert_eq!(children[1].tag.number, 12);
    }

    #[test]
    fn summarizes_cert_rep_serials_and_rev_rep_status_count() {
        let key_pair = KeyPair::generate().unwrap();
        let cert = CertificateParams::new(vec!["summary.example.com".to_string()])
            .unwrap()
            .self_signed(&key_pair)
            .unwrap();
        let request_header = [
            0x30, 0x10, // PKIHeader
            0x02, 0x01, 0x02, // pvno
            0xa4, 0x02, 0x30, 0x00, // sender
            0xa4, 0x02, 0x30, 0x00, // recipient
            0x84, 0x03, 0x01, 0x02, 0x03, // transactionID
        ];
        let cert_rep =
            cmp_cert_rep_pki_message_der(&request_header, 3, vec![(0, cert.der().to_vec())])
                .unwrap();
        let summary = summarize_pki_message_der(&cert_rep).unwrap();
        assert_eq!(summary.body_type, "cp");
        assert_eq!(summary.body_tag, 3);
        assert_eq!(summary.certificate_serial_hexes.len(), 1);

        let rev_rep = cmp_rev_rep_pki_message_der(&request_header, 2).unwrap();
        let summary = summarize_pki_message_der(&rev_rep).unwrap();
        assert_eq!(summary.body_type, "rp");
        assert_eq!(summary.revocation_status_count, Some(2));
    }

    fn implicit_sequence(tag: u8, sequence_der: &[u8]) -> Vec<u8> {
        let sequence = parse_single(sequence_der).unwrap();
        der_context_constructed(tag, sequence.content.to_vec())
    }

    fn test_name_der(common_name: &str) -> Vec<u8> {
        der_sequence(der_tlv(
            0x31,
            der_sequence(join([
                der_oid(&[2, 5, 4, 3]),
                der_tlv(0x0c, common_name.as_bytes().to_vec()),
            ])),
        ))
    }

    fn protected_placeholder_message(secret: &[u8]) -> Vec<u8> {
        let salt = b"12345678".to_vec();
        let pbm_params = der_sequence(join([
            der_octet_string(salt.clone()),
            algorithm_identifier(OID_SHA256),
            der_integer_from_i64(1000),
            algorithm_identifier(OID_HMAC_SHA256),
        ]));
        let protection_alg = der_sequence(join([der_oid(OID_PASSWORD_BASED_MAC), pbm_params]));
        let header = der_sequence(join([
            der_integer_from_i64(2),
            der_explicit_context(4, der_sequence(Vec::new())),
            der_explicit_context(4, der_sequence(Vec::new())),
            der_explicit_context(1, protection_alg),
        ]));
        let body = der_explicit_context(4, der_sequence(Vec::new()));
        let protected_part = der_sequence(join([header.clone(), body.clone()]));
        let key = derive_pbm_key(secret, &salt, OneWayFunction::Sha256, 1000).unwrap();
        let mac = compute_pbm_mac(MacAlgorithm::HmacSha256, &key, &protected_part).unwrap();
        der_sequence(join([
            header,
            body,
            der_explicit_context(0, der_bit_string(mac)),
        ]))
    }

    fn algorithm_identifier(oid: &[u64]) -> Vec<u8> {
        der_sequence(der_oid(oid))
    }
}
