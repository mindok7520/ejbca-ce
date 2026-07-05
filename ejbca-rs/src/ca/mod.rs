pub mod service;

use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct CreateCaRequest {
    pub name: String,
    pub subject_dn: String,
    pub validity_days: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct ImportCaRequest {
    pub name: String,
    pub cert_pem: String,
    pub key_ref: String,
}

#[derive(Debug, Deserialize)]
pub struct UpdateCaRequest {
    pub name: Option<String>,
    pub status: Option<String>,
    pub make_default: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct RenewCaRequest {
    pub validity_days: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct RolloverCaRequest {
    pub name: Option<String>,
    pub subject_dn: Option<String>,
    pub validity_days: Option<i64>,
    pub make_default: Option<bool>,
    pub disable_old: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct CaResponse {
    pub id: String,
    pub name: String,
    pub subject_dn: String,
    pub cert_pem: String,
    pub key_provider: String,
    pub status: String,
    pub is_default: bool,
    pub created_at: i64,
    pub not_after: i64,
}
