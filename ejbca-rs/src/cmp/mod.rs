pub mod service;

use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct CmpStatusResponse {
    pub alias: String,
    pub status: String,
    pub detail: String,
    pub body_type: Option<String>,
    pub body_tag: Option<u64>,
    pub protected: bool,
    pub extra_certs: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issued_certificate_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub serial_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cert_pem: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub issued_certificate_ids: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub issued_serial_hexes: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub revoked_certificate_ids: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub revoked_serial_hexes: Vec<String>,
    #[serde(skip)]
    pub pkixcmp_der: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pkixcmp_der_base64: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct CmpMessageSummary {
    pub body_type: String,
    pub body_tag: u64,
    pub protected: bool,
    pub extra_certs: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub certificate_serial_hexes: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revocation_status_count: Option<usize>,
}
