pub mod service;

use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct MaintenanceRequest {
    pub backup: Option<bool>,
    pub purge_expired_certificates: Option<bool>,
    pub purge_expired_crls: Option<bool>,
    pub purge_metric_events: Option<bool>,
    pub purge_audit_events: Option<bool>,
    pub optimize: Option<bool>,
    pub older_than_days: Option<i64>,
    pub batch_size: Option<i64>,
    pub generate_crls: Option<bool>,
    pub crl_validity_days: Option<i64>,
    pub crl_partition_count: Option<i64>,
}

#[derive(Debug, Default, Deserialize)]
pub struct UpdateMaintenanceConfigRequest {
    pub enabled: Option<bool>,
    pub interval_seconds: Option<u64>,
    pub backup: Option<bool>,
    pub purge_expired_certificates: Option<bool>,
    pub purge_expired_crls: Option<bool>,
    pub purge_metric_events: Option<bool>,
    pub purge_audit_events: Option<bool>,
    pub optimize: Option<bool>,
    pub older_than_days: Option<i64>,
    pub batch_size: Option<i64>,
    pub generate_crls: Option<bool>,
    pub crl_validity_days: Option<i64>,
    pub crl_partition_count: Option<i64>,
    pub metrics_enabled: Option<bool>,
    pub metrics_public: Option<bool>,
    pub metrics_device_limit: Option<i64>,
    pub metrics_event_retention_days: Option<i64>,
    pub audit_event_retention_days: Option<i64>,
    pub log_level: Option<String>,
    pub log_output: Option<String>,
    pub log_dir: Option<String>,
    pub log_retention_days: Option<u64>,
    pub log_retention_files: Option<usize>,
    pub cors_allowed_origins: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct MaintenanceResponse {
    pub backup_path: Option<String>,
    pub purged_certificates: u64,
    pub purged_crls: u64,
    pub purged_metric_events: u64,
    pub purged_audit_events: u64,
    pub generated_crls: u64,
    pub optimized: bool,
}

#[derive(Debug, Serialize)]
pub struct MaintenanceConfigResponse {
    pub enabled: bool,
    pub interval_seconds: u64,
    pub backup: bool,
    pub purge_expired_certificates: bool,
    pub purge_expired_crls: bool,
    pub optimize: bool,
    pub older_than_days: i64,
    pub batch_size: i64,
    pub generate_crls: bool,
    pub crl_validity_days: i64,
    pub crl_partition_count: i64,
    pub metrics_event_retention_days: i64,
    pub audit_event_retention_days: i64,
    pub purge_audit_events: bool,
    pub metrics_enabled: bool,
    pub metrics_public: bool,
    pub metrics_device_limit: i64,
    pub log_level: String,
    pub log_output: String,
    pub log_dir: String,
    pub log_retention_days: u64,
    pub log_retention_files: usize,
    pub cors_allowed_origins: String,
    pub restart_required_fields: Vec<String>,
}
