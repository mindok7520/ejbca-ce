pub mod service;

use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct OcspStatusResponse {
    pub ca_id: String,
    pub serial_hex: String,
    pub status: String,
    pub revocation_reason: Option<String>,
    pub revoked_at: Option<i64>,
    pub this_update: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OcspResponseStatus {
    Successful = 0,
    MalformedRequest = 1,
    InternalError = 2,
    Unauthorized = 6,
}

#[derive(Debug, Clone)]
pub struct BinaryOcspResponse {
    pub der: Vec<u8>,
    pub cache_seconds: Option<u64>,
}
