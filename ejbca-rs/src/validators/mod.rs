pub mod service;

use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Deserialize)]
pub struct CreateValidatorRequest {
    pub name: String,
    pub kind: String,
    pub config: Value,
    pub enabled: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateValidatorRequest {
    pub name: Option<String>,
    pub kind: Option<String>,
    pub config: Option<Value>,
    pub enabled: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct ValidatorResponse {
    pub id: String,
    pub name: String,
    pub kind: String,
    pub config: Value,
    pub enabled: bool,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ValidationContext {
    pub ca_id: String,
    pub subject_dn: String,
    pub dns_names: Vec<String>,
    pub csr_pem: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ValidatorConfig {
    DenySubjectKeywords {
        keywords: Vec<String>,
    },
    DnsAllowlist {
        domains: Vec<String>,
    },
    DnsDenylist {
        domains: Vec<String>,
    },
    ExternalWebhook {
        url: String,
        token: Option<String>,
        timeout_ms: Option<u64>,
    },
}

#[derive(Debug, Serialize)]
pub struct WebhookValidationRequest<'a> {
    pub phase: &'a str,
    pub context: &'a ValidationContext,
}

#[derive(Debug, Deserialize)]
pub struct WebhookValidationResponse {
    pub allowed: bool,
    pub message: Option<String>,
}
