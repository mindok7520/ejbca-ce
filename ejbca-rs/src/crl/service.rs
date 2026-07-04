use rcgen::{
    CertificateRevocationListParams, CrlDistributionPoint, CrlIssuingDistributionPoint, CrlScope,
    KeyIdMethod, RevocationReason, RevokedCertParams, SerialNumber, SigningKey,
};
use sha2::{Digest, Sha256};
use time::{Duration, OffsetDateTime, macros::format_description};
use uuid::Uuid;
use x509_parser::prelude::{FromDer, X509Certificate};

use crate::{
    AppState,
    asn1::{
        der_bit_string, der_bool, der_context_constructed, der_context_primitive,
        der_explicit_context, der_generalized_time, der_integer_bytes_positive, der_octet_string,
        der_oid, der_sequence, der_tlv,
    },
    ca::service::load_issuer,
    crl::{CrlResponse, GenerateCrlRequest},
    error::{AppError, AppResult},
    key_provider,
    storage::{CaRecord, CertificateRecord, CrlRecord},
    util::{now, serial_from_hex},
};

pub async fn generate_crl(
    state: &AppState,
    request: GenerateCrlRequest,
    actor: &str,
) -> AppResult<CrlResponse> {
    let ca =
        state.db.get_ca(&request.ca_id).await?.ok_or_else(|| {
            AppError::NotFound(format!("CA를 찾을 수 없습니다: {}", request.ca_id))
        })?;
    let options = CrlGenerationOptions::from_request(&request)?;
    generate_crl_for_ca_with_options(
        state,
        ca,
        request.validity_days.unwrap_or(7),
        options,
        actor,
    )
    .await
}

pub async fn generate_crl_for_ca_with_options(
    state: &AppState,
    ca: CaRecord,
    validity_days: i64,
    options: CrlGenerationOptions,
    actor: &str,
) -> AppResult<CrlResponse> {
    let issuer = load_issuer(&ca).await?;
    let this_update = now();
    let next_update = this_update + Duration::days(validity_days.clamp(1, 90));
    let crl_number = state.db.next_crl_number(&ca.id).await?;
    let base_crl = if options.is_delta {
        Some(
            state
                .db
                .latest_crl_for_ca_scope(&ca.id, options.partition_index, false)
                .await?
                .ok_or_else(|| {
                    AppError::BadRequest(
                        "delta CRL을 만들려면 같은 partition의 base CRL이 먼저 필요합니다"
                            .to_string(),
                    )
                })?,
        )
    } else {
        None
    };
    let revoked = filtered_revoked_certificates(state, &ca.id, &options, base_crl.as_ref()).await?;
    let mut revoked_certs = Vec::with_capacity(revoked.len());
    for cert in &revoked {
        revoked_certs.push(RevokedCertParams {
            serial_number: serial_from_hex(&cert.serial_hex)?,
            revocation_time: cert
                .revoked_at
                .and_then(|ts| time::OffsetDateTime::from_unix_timestamp(ts).ok())
                .unwrap_or(this_update),
            reason_code: cert
                .revocation_reason
                .as_deref()
                .map(map_revocation_reason)
                .or(Some(RevocationReason::Unspecified)),
            invalidity_date: None,
        });
    }

    let (der, pem) = if options.is_delta {
        let base_number = base_crl
            .as_ref()
            .map(|record| record.crl_number)
            .ok_or_else(|| AppError::Internal("base CRL 번호가 없습니다".to_string()))?;
        let der = build_delta_crl_der(
            &ca,
            this_update,
            next_update,
            crl_number,
            base_number,
            &revoked,
            &options,
        )
        .await?;
        let pem = pem::encode(&pem::Pem::new("X509 CRL", der.clone()));
        (der, pem)
    } else {
        let crl = CertificateRevocationListParams {
            this_update,
            next_update,
            crl_number: SerialNumber::from(crl_number as u64),
            issuing_distribution_point: issuing_distribution_point(state, &ca.id, &options),
            revoked_certs,
            key_identifier_method: KeyIdMethod::Sha256,
        }
        .signed_by(&issuer)?;

        (crl.der().as_ref().to_vec(), crl.pem()?)
    };
    let record = CrlRecord {
        id: Uuid::new_v4().to_string(),
        ca_id: ca.id,
        crl_number,
        partition_index: options.partition_index,
        is_delta: options.is_delta,
        pem,
        der,
        this_update: this_update.unix_timestamp(),
        next_update: next_update.unix_timestamp(),
        revoked_count: revoked.len() as i64,
        created_at: now().unix_timestamp(),
    };
    state.db.insert_crl(&record).await?;
    state
        .db
        .audit(
            actor,
            "crl.generate",
            &record.id,
            "success",
            &serde_json::json!({
                "ca_id": record.ca_id,
                "crl_number": record.crl_number,
                "revoked_count": record.revoked_count,
                "partition_index": record.partition_index,
                "is_delta": record.is_delta
            })
            .to_string(),
        )
        .await?;
    Ok(record.into())
}

pub async fn list_crls(state: &AppState, limit: i64) -> AppResult<Vec<CrlResponse>> {
    Ok(state
        .db
        .list_crls(limit.clamp(1, 500))
        .await?
        .into_iter()
        .map(Into::into)
        .collect())
}

pub async fn latest_crl_der_for_scope(
    state: &AppState,
    ca_id: &str,
    partition_index: i64,
    is_delta: bool,
) -> AppResult<Option<Vec<u8>>> {
    Ok(state
        .db
        .latest_crl_for_ca_scope(ca_id, partition_index, is_delta)
        .await?
        .map(|record| record.der))
}

#[derive(Debug, Clone, Copy)]
pub struct CrlGenerationOptions {
    pub is_delta: bool,
    pub partition_index: i64,
    pub partition_count: i64,
}

impl Default for CrlGenerationOptions {
    fn default() -> Self {
        Self {
            is_delta: false,
            partition_index: -1,
            partition_count: 1,
        }
    }
}

impl CrlGenerationOptions {
    fn from_request(request: &GenerateCrlRequest) -> AppResult<Self> {
        let partition_index = request.partition_index.unwrap_or(-1);
        let partition_count = request.partition_count.unwrap_or(1).clamp(1, 1024);
        if partition_index < -1 || partition_index >= partition_count {
            return Err(AppError::BadRequest(format!(
                "partition_index는 -1 또는 0..{} 범위여야 합니다",
                partition_count - 1
            )));
        }
        if partition_index == -1 && partition_count != 1 {
            return Err(AppError::BadRequest(
                "partition_count를 2 이상으로 쓰려면 partition_index가 필요합니다".to_string(),
            ));
        }
        Ok(Self {
            is_delta: request.is_delta.unwrap_or(false),
            partition_index,
            partition_count,
        })
    }
}

async fn filtered_revoked_certificates(
    state: &AppState,
    ca_id: &str,
    options: &CrlGenerationOptions,
    base_crl: Option<&CrlRecord>,
) -> AppResult<Vec<CertificateRecord>> {
    let mut revoked = state.db.revoked_certificates_for_ca(ca_id).await?;
    if options.partition_index >= 0 {
        revoked.retain(|cert| {
            serial_partition(&cert.serial_hex, options.partition_count) == options.partition_index
        });
    }
    if let Some(base_crl) = base_crl {
        revoked.retain(|cert| cert.revoked_at.unwrap_or(0) >= base_crl.this_update);
    }
    Ok(revoked)
}

fn serial_partition(serial_hex: &str, partition_count: i64) -> i64 {
    let mut acc = 0u64;
    for byte in serial_hex.as_bytes() {
        acc = acc.wrapping_mul(131).wrapping_add(u64::from(*byte));
    }
    (acc % partition_count.max(1) as u64) as i64
}

fn issuing_distribution_point(
    state: &AppState,
    ca_id: &str,
    options: &CrlGenerationOptions,
) -> Option<CrlIssuingDistributionPoint> {
    if options.partition_index < 0 {
        return None;
    }
    Some(CrlIssuingDistributionPoint {
        distribution_point: CrlDistributionPoint {
            uris: vec![format!(
                "{}/crl/{}/latest?partition={}",
                state.settings.public_base_url.trim_end_matches('/'),
                ca_id,
                options.partition_index
            )],
        },
        scope: Some(CrlScope::UserCertsOnly),
    })
}

async fn build_delta_crl_der(
    ca: &CaRecord,
    this_update: OffsetDateTime,
    next_update: OffsetDateTime,
    crl_number: i64,
    base_crl_number: i64,
    revoked: &[CertificateRecord],
    options: &CrlGenerationOptions,
) -> AppResult<Vec<u8>> {
    let (_, ca_cert) = X509Certificate::from_der(&ca.cert_der)
        .map_err(|err| AppError::Internal(format!("CA 인증서를 파싱할 수 없습니다: {err}")))?;
    let signing_key = key_provider::load_ca_signing_key(ca).await?;
    let tbs = tbs_delta_crl_der(
        ca_cert.subject().as_raw(),
        &ca_cert.tbs_certificate.subject_pki.subject_public_key.data,
        this_update,
        next_update,
        crl_number,
        base_crl_number,
        revoked,
        options,
    )?;
    let signature = signing_key.sign(&tbs)?;
    Ok(der_sequence(join([
        tbs,
        ecdsa_sha256_algorithm_identifier(),
        der_bit_string(signature),
    ])))
}

fn tbs_delta_crl_der(
    issuer_subject_der: &[u8],
    issuer_public_key: &[u8],
    this_update: OffsetDateTime,
    next_update: OffsetDateTime,
    crl_number: i64,
    base_crl_number: i64,
    revoked: &[CertificateRecord],
    options: &CrlGenerationOptions,
) -> AppResult<Vec<u8>> {
    let mut content = join([
        der_integer_bytes_positive(&[1]), // v2 CRL
        ecdsa_sha256_algorithm_identifier(),
        issuer_subject_der.to_vec(),
        der_generalized_time(&generalized_time(this_update)),
        der_generalized_time(&generalized_time(next_update)),
    ]);

    let revoked_der = revoked_entries_der(revoked, this_update)?;
    if !revoked_der.is_empty() {
        content.extend(der_sequence(revoked_der));
    }

    let mut extensions = join([
        crl_extension(
            &[2, 5, 29, 35],
            false,
            authority_key_identifier_der(issuer_public_key),
        ),
        crl_extension(
            &[2, 5, 29, 20],
            false,
            der_integer_bytes_positive(&i64_to_u64_bytes(crl_number)?),
        ),
        crl_extension(
            &[2, 5, 29, 27],
            true,
            der_integer_bytes_positive(&i64_to_u64_bytes(base_crl_number)?),
        ),
    ]);
    if options.partition_index >= 0 {
        extensions.extend(crl_extension(
            &[2, 5, 29, 28],
            true,
            issuing_distribution_point_der(options.partition_index),
        ));
    }
    content.extend(der_explicit_context(0, der_sequence(extensions)));
    Ok(der_sequence(content))
}

fn revoked_entries_der(
    revoked: &[CertificateRecord],
    default_time: OffsetDateTime,
) -> AppResult<Vec<u8>> {
    let mut out = Vec::new();
    for cert in revoked {
        let revocation_time = cert
            .revoked_at
            .and_then(|ts| OffsetDateTime::from_unix_timestamp(ts).ok())
            .unwrap_or(default_time);
        let mut entry = join([
            der_integer_bytes_positive(&hex::decode(&cert.serial_hex).map_err(|err| {
                AppError::Internal(format!("인증서 serial을 디코딩할 수 없습니다: {err}"))
            })?),
            der_generalized_time(&generalized_time(revocation_time)),
        ]);
        if let Some(reason) = cert
            .revocation_reason
            .as_deref()
            .map(revocation_reason_code)
        {
            entry.extend(der_sequence(crl_extension(
                &[2, 5, 29, 21],
                false,
                der_tlv(0x0a, vec![reason]),
            )));
        }
        out.extend(der_sequence(entry));
    }
    Ok(out)
}

fn crl_extension(oid: &[u64], critical: bool, value_der: Vec<u8>) -> Vec<u8> {
    let mut content = der_oid(oid);
    if critical {
        content.extend(der_bool(true));
    }
    content.extend(der_octet_string(value_der));
    der_sequence(content)
}

fn authority_key_identifier_der(public_key: &[u8]) -> Vec<u8> {
    let key_identifier = Sha256::digest(public_key).to_vec();
    der_sequence(der_context_primitive(0, key_identifier))
}

fn issuing_distribution_point_der(partition_index: i64) -> Vec<u8> {
    let uri = format!("urn:ejbca-rs:crl-partition:{partition_index}");
    let uri_name = der_tlv(0x86, uri.into_bytes());
    let general_names = der_sequence(uri_name);
    let full_name = der_context_constructed(0, general_names);
    let distribution_point_name = der_sequence(full_name);
    der_sequence(join([
        der_context_constructed(0, distribution_point_name),
        der_context_primitive(1, vec![0xff]), // onlyContainsUserCerts TRUE
    ]))
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

fn i64_to_u64_bytes(value: i64) -> AppResult<[u8; 8]> {
    let value = u64::try_from(value).map_err(|_| {
        AppError::Internal(format!(
            "음수 값을 CRL INTEGER로 인코딩할 수 없습니다: {value}"
        ))
    })?;
    Ok(value.to_be_bytes())
}

fn revocation_reason_code(reason: &str) -> u8 {
    match reason.to_ascii_lowercase().as_str() {
        "key_compromise" | "keycompromise" => 1,
        "ca_compromise" | "cacompromise" => 2,
        "affiliation_changed" => 3,
        "superseded" => 4,
        "cessation_of_operation" => 5,
        "certificate_hold" => 6,
        "remove_from_crl" => 8,
        "privilege_withdrawn" => 9,
        "aa_compromise" => 10,
        _ => 0,
    }
}

fn join(chunks: impl IntoIterator<Item = Vec<u8>>) -> Vec<u8> {
    chunks.into_iter().flatten().collect()
}

fn map_revocation_reason(reason: &str) -> RevocationReason {
    match reason.to_ascii_lowercase().as_str() {
        "key_compromise" | "keycompromise" => RevocationReason::KeyCompromise,
        "ca_compromise" | "cacompromise" => RevocationReason::CaCompromise,
        "affiliation_changed" => RevocationReason::AffiliationChanged,
        "superseded" => RevocationReason::Superseded,
        "cessation_of_operation" => RevocationReason::CessationOfOperation,
        "certificate_hold" => RevocationReason::CertificateHold,
        "remove_from_crl" => RevocationReason::RemoveFromCrl,
        "privilege_withdrawn" => RevocationReason::PrivilegeWithdrawn,
        "aa_compromise" => RevocationReason::AaCompromise,
        _ => RevocationReason::Unspecified,
    }
}

impl From<CrlRecord> for CrlResponse {
    fn from(value: CrlRecord) -> Self {
        Self {
            id: value.id,
            ca_id: value.ca_id,
            crl_number: value.crl_number,
            partition_index: value.partition_index,
            is_delta: value.is_delta,
            partition_count: None,
            pem: value.pem,
            this_update: value.this_update,
            next_update: value.next_update,
            revoked_count: value.revoked_count,
            created_at: value.created_at,
        }
    }
}
