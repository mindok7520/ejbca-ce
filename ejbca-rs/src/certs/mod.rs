pub mod service;

use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct IssueCertificateRequest {
    pub end_entity_id: Option<String>,
    pub approval_id: Option<String>,
    pub ca_id: Option<String>,
    pub certificate_profile_id: Option<String>,
    pub end_entity_profile_id: Option<String>,
    pub subject_dn: String,
    #[serde(default)]
    pub dns_names: Vec<String>,
    pub validity_days: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct IssuePkcs12Request {
    pub end_entity_id: Option<String>,
    pub approval_id: Option<String>,
    pub ca_id: Option<String>,
    pub certificate_profile_id: Option<String>,
    pub end_entity_profile_id: Option<String>,
    pub subject_dn: String,
    #[serde(default)]
    pub dns_names: Vec<String>,
    pub validity_days: Option<i64>,
    pub pkcs12_password: String,
    pub friendly_name: Option<String>,
}

impl From<&IssuePkcs12Request> for IssueCertificateRequest {
    fn from(value: &IssuePkcs12Request) -> Self {
        Self {
            end_entity_id: value.end_entity_id.clone(),
            approval_id: value.approval_id.clone(),
            ca_id: value.ca_id.clone(),
            certificate_profile_id: value.certificate_profile_id.clone(),
            end_entity_profile_id: value.end_entity_profile_id.clone(),
            subject_dn: value.subject_dn.clone(),
            dns_names: value.dns_names.clone(),
            validity_days: value.validity_days,
        }
    }
}

#[derive(Debug)]
pub struct Pkcs12IssueResponse {
    pub certificate_id: String,
    pub serial_hex: String,
    pub filename: String,
    pub der: Vec<u8>,
}

#[derive(Debug, Deserialize)]
pub struct IssueCsrRequest {
    pub end_entity_id: Option<String>,
    pub approval_id: Option<String>,
    pub ca_id: Option<String>,
    pub certificate_profile_id: Option<String>,
    pub end_entity_profile_id: Option<String>,
    pub csr_pem: String,
    pub validity_days: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct IssuePublicKeyRequest {
    pub ca_id: Option<String>,
    pub certificate_profile_id: Option<String>,
    pub end_entity_profile_id: Option<String>,
    pub subject_dn: String,
    pub dns_names: Vec<String>,
    pub subject_public_key_info_der: Vec<u8>,
    pub validity_days: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct RevokeCertificateRequest {
    pub reason: Option<String>,
    pub approval_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct CertificateResponse {
    pub id: String,
    pub ca_id: String,
    pub certificate_profile_id: Option<String>,
    pub end_entity_profile_id: Option<String>,
    pub serial_hex: String,
    pub subject_dn: String,
    pub dns_names: Vec<String>,
    pub cert_pem: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub private_key_pem: Option<String>,
    pub status: String,
    pub revocation_reason: Option<String>,
    pub revoked_at: Option<i64>,
    pub not_before: i64,
    pub not_after: i64,
    pub fingerprint_sha256: String,
    pub created_at: i64,
}

#[derive(Debug, Serialize)]
pub struct CertificateSummaryResponse {
    pub id: String,
    pub ca_id: String,
    pub certificate_profile_id: Option<String>,
    pub end_entity_profile_id: Option<String>,
    pub serial_hex: String,
    pub subject_dn: String,
    pub dns_names: Vec<String>,
    pub status: String,
    pub revocation_reason: Option<String>,
    pub revoked_at: Option<i64>,
    pub not_before: i64,
    pub not_after: i64,
    pub fingerprint_sha256: String,
    pub created_at: i64,
}
