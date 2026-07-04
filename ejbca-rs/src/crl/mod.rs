pub mod service;

use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct GenerateCrlRequest {
    pub ca_id: String,
    pub validity_days: Option<i64>,
    pub is_delta: Option<bool>,
    pub partition_index: Option<i64>,
    pub partition_count: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct CrlResponse {
    pub id: String,
    pub ca_id: String,
    pub crl_number: i64,
    pub partition_index: i64,
    pub is_delta: bool,
    pub partition_count: Option<i64>,
    pub pem: String,
    pub this_update: i64,
    pub next_update: i64,
    pub revoked_count: i64,
    pub created_at: i64,
}
