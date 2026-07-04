pub mod service;

use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct CreateCertificateProfileRequest {
    pub name: String,
    pub validity_days: Option<i64>,
    #[serde(default)]
    pub key_usages: Vec<String>,
    #[serde(default)]
    pub extended_key_usages: Vec<String>,
    pub allow_server_generated_key: Option<bool>,
    pub require_san: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateCertificateProfileRequest {
    pub name: Option<String>,
    pub validity_days: Option<i64>,
    pub key_usages: Option<Vec<String>>,
    pub extended_key_usages: Option<Vec<String>>,
    pub allow_server_generated_key: Option<bool>,
    pub require_san: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct CertificateProfileResponse {
    pub id: String,
    pub name: String,
    pub validity_days: i64,
    pub key_usages: Vec<String>,
    pub extended_key_usages: Vec<String>,
    pub allow_server_generated_key: bool,
    pub require_san: bool,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Deserialize)]
pub struct CreateEndEntityProfileRequest {
    pub name: String,
    pub subject_regex: Option<String>,
    #[serde(default)]
    pub allowed_dns_domains: Vec<String>,
    pub default_certificate_profile_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateEndEntityProfileRequest {
    pub name: Option<String>,
    pub subject_regex: Option<String>,
    pub allowed_dns_domains: Option<Vec<String>>,
    pub default_certificate_profile_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct EndEntityProfileResponse {
    pub id: String,
    pub name: String,
    pub subject_regex: Option<String>,
    pub allowed_dns_domains: Vec<String>,
    pub default_certificate_profile_id: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Deserialize)]
pub struct CreateCmpAliasRequest {
    pub alias: String,
    pub ca_id: Option<String>,
    pub certificate_profile_id: Option<String>,
    pub end_entity_profile_id: Option<String>,
    pub enabled: Option<bool>,
    pub hmac_secret: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateCmpAliasRequest {
    pub alias: Option<String>,
    pub ca_id: Option<String>,
    pub certificate_profile_id: Option<String>,
    pub end_entity_profile_id: Option<String>,
    pub enabled: Option<bool>,
    pub hmac_secret: Option<String>,
    pub clear_hmac_secret: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct CmpAliasResponse {
    pub id: String,
    pub alias: String,
    pub ca_id: Option<String>,
    pub certificate_profile_id: Option<String>,
    pub end_entity_profile_id: Option<String>,
    pub enabled: bool,
    pub hmac_secret_configured: bool,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Deserialize)]
pub struct CreateAccessRoleRequest {
    pub name: String,
    #[serde(default)]
    pub permissions: Vec<String>,
    pub api_token: Option<String>,
    pub certificate_issuer_dn: Option<String>,
    pub certificate_match_key: Option<String>,
    pub certificate_match_value: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateAccessRoleRequest {
    pub name: Option<String>,
    pub permissions: Option<Vec<String>>,
    pub api_token: Option<String>,
    pub clear_api_token: Option<bool>,
    pub certificate_issuer_dn: Option<String>,
    pub certificate_match_key: Option<String>,
    pub certificate_match_value: Option<String>,
    pub clear_certificate_member: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct AccessRoleResponse {
    pub id: String,
    pub name: String,
    pub permissions: Vec<String>,
    pub api_token_configured: bool,
    pub certificate_issuer_dn: Option<String>,
    pub certificate_match_key: Option<String>,
    pub certificate_match_value: Option<String>,
    pub certificate_member_configured: bool,
    pub created_at: i64,
    pub updated_at: i64,
}
