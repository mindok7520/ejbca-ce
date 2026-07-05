use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
    sync::{OnceLock, RwLock},
};

use clap::{Parser, Subcommand};
use serde::Deserialize;

const DEFAULT_CONFIG_FILE: &str = "ejbca-rs.toml";

#[derive(Clone, Debug, Default)]
struct RuntimeSecretConfig {
    cmp_default_secret: Option<String>,
    cmp_alias_secrets: HashMap<String, String>,
    ca_key_encryption_secret: Option<String>,
}

static RUNTIME_SECRET_CONFIG: OnceLock<RwLock<RuntimeSecretConfig>> = OnceLock::new();

#[derive(Clone, Debug, Parser)]
#[command(name = "ejbca-rs", about = "Rust 기반 경량 CA/CMP/OCSP/CRL 관리 서버")]
pub struct Settings {
    #[arg(long, global = true)]
    pub config_file: Option<String>,

    #[arg(long, env = "EJBCA_RS_BIND", default_value = "127.0.0.1:8080")]
    pub bind_addr: std::net::SocketAddr,

    #[arg(long, env = "EJBCA_RS_DATA_DIR", default_value = "./data")]
    pub data_dir: String,

    #[arg(long, env = "EJBCA_RS_DATABASE_URL")]
    pub database_url: Option<String>,

    #[arg(long, env = "EJBCA_RS_ADMIN_TOKEN")]
    pub admin_token: Option<String>,

    #[arg(
        long,
        env = "EJBCA_RS_PUBLIC_BASE_URL",
        default_value = "http://127.0.0.1:8080"
    )]
    pub public_base_url: String,

    #[arg(long, env = "EJBCA_RS_CA_KEY_PROVIDER", default_value = "database")]
    pub ca_key_provider: String,

    #[arg(long, env = "EJBCA_RS_CA_KEY_DIR")]
    pub ca_key_dir: Option<String>,

    #[arg(long, env = "EJBCA_RS_MAX_REQUEST_BYTES", default_value_t = 100_000)]
    pub max_request_bytes: usize,

    #[arg(long, env = "EJBCA_RS_MAX_LIST_LIMIT", default_value_t = 1000)]
    pub max_list_limit: i64,

    #[arg(long, env = "EJBCA_RS_CORS_ALLOWED_ORIGINS", default_value = "")]
    pub cors_allowed_origins: String,

    #[arg(
        long,
        env = "EJBCA_RS_ADMINWEB_CLIENT_CERT_REQUIRED",
        default_value_t = true
    )]
    pub adminweb_client_cert_required: bool,

    #[arg(
        long,
        env = "EJBCA_RS_ADMINWEB_CLIENT_CERT_HEADER",
        default_value = "x-admin-client-cert-pem"
    )]
    pub adminweb_client_cert_header: String,

    #[arg(long, env = "EJBCA_RS_ADMINWEB_CLIENT_CERT_PROXY_SECRET")]
    pub adminweb_client_cert_proxy_secret: Option<String>,

    #[arg(
        long,
        env = "EJBCA_RS_ADMINWEB_CLIENT_CERT_ALLOWED_FINGERPRINTS",
        default_value = ""
    )]
    pub adminweb_client_cert_allowed_fingerprints: String,

    #[arg(
        long,
        env = "EJBCA_RS_ADMINWEB_CLIENT_CERT_ALLOWED_SUBJECTS",
        default_value = ""
    )]
    pub adminweb_client_cert_allowed_subjects: String,

    #[arg(long, env = "EJBCA_RS_DATABASE_MAX_CONNECTIONS", default_value_t = 32)]
    pub database_max_connections: u32,

    #[arg(
        long,
        env = "EJBCA_RS_DATABASE_BUSY_TIMEOUT_SECONDS",
        default_value_t = 30
    )]
    pub database_busy_timeout_seconds: u64,

    #[arg(long, env = "EJBCA_RS_MAX_CONCURRENT_ISSUANCE", default_value_t = 128)]
    pub max_concurrent_issuance: usize,

    #[arg(
        long,
        env = "EJBCA_RS_VALIDATOR_WEBHOOK_DEFAULT_TIMEOUT_MS",
        default_value_t = 3000
    )]
    pub validator_webhook_default_timeout_ms: u64,

    #[arg(
        long,
        env = "EJBCA_RS_VALIDATOR_WEBHOOK_MAX_TIMEOUT_MS",
        default_value_t = 30_000
    )]
    pub validator_webhook_max_timeout_ms: u64,

    #[arg(
        long,
        env = "EJBCA_RS_VALIDATOR_WEBHOOK_MAX_RESPONSE_BYTES",
        default_value_t = 8192
    )]
    pub validator_webhook_max_response_bytes: usize,

    #[arg(long, env = "EJBCA_RS_JSON_LOGS", default_value_t = false)]
    pub json_logs: bool,

    #[arg(long, env = "EJBCA_RS_LOG_LEVEL", default_value = "info")]
    pub log_level: String,

    #[arg(long, env = "EJBCA_RS_LOG_OUTPUT", default_value = "stdout")]
    pub log_output: String,

    #[arg(long, env = "EJBCA_RS_LOG_DIR")]
    pub log_dir: Option<String>,

    #[arg(long, env = "EJBCA_RS_LOG_RETENTION_DAYS", default_value_t = 14)]
    pub log_retention_days: u64,

    #[arg(long, env = "EJBCA_RS_LOG_RETENTION_FILES", default_value_t = 30)]
    pub log_retention_files: usize,

    #[arg(long, env = "EJBCA_RS_METRICS_ENABLED", default_value_t = true)]
    pub metrics_enabled: bool,

    #[arg(long, env = "EJBCA_RS_METRICS_PUBLIC", default_value_t = false)]
    pub metrics_public: bool,

    #[arg(long, env = "EJBCA_RS_METRICS_DEVICE_LIMIT", default_value_t = 100)]
    pub metrics_device_limit: i64,

    #[arg(
        long,
        env = "EJBCA_RS_METRICS_EVENT_RETENTION_DAYS",
        default_value_t = 90
    )]
    pub metrics_event_retention_days: i64,

    #[arg(
        long,
        env = "EJBCA_RS_AUDIT_EVENT_RETENTION_DAYS",
        default_value_t = 365
    )]
    pub audit_event_retention_days: i64,

    #[arg(long, env = "EJBCA_RS_MAINTENANCE_ENABLED", default_value_t = false)]
    pub maintenance_enabled: bool,

    #[arg(
        long,
        env = "EJBCA_RS_MAINTENANCE_INTERVAL_SECONDS",
        default_value_t = 3600
    )]
    pub maintenance_interval_seconds: u64,

    #[arg(long, env = "EJBCA_RS_MAINTENANCE_BACKUP", default_value_t = false)]
    pub maintenance_backup: bool,

    #[arg(
        long,
        env = "EJBCA_RS_MAINTENANCE_PURGE_EXPIRED_CERTIFICATES",
        default_value_t = false
    )]
    pub maintenance_purge_expired_certificates: bool,

    #[arg(
        long,
        env = "EJBCA_RS_MAINTENANCE_PURGE_EXPIRED_CRLS",
        default_value_t = false
    )]
    pub maintenance_purge_expired_crls: bool,

    #[arg(
        long,
        env = "EJBCA_RS_MAINTENANCE_PURGE_AUDIT_EVENTS",
        default_value_t = false
    )]
    pub maintenance_purge_audit_events: bool,

    #[arg(long, env = "EJBCA_RS_MAINTENANCE_OPTIMIZE", default_value_t = false)]
    pub maintenance_optimize: bool,

    #[arg(
        long,
        env = "EJBCA_RS_MAINTENANCE_OLDER_THAN_DAYS",
        default_value_t = 30
    )]
    pub maintenance_older_than_days: i64,

    #[arg(long, env = "EJBCA_RS_MAINTENANCE_BATCH_SIZE", default_value_t = 100)]
    pub maintenance_batch_size: i64,

    #[arg(
        long,
        env = "EJBCA_RS_MAINTENANCE_GENERATE_CRLS",
        default_value_t = false
    )]
    pub maintenance_generate_crls: bool,

    #[arg(
        long,
        env = "EJBCA_RS_MAINTENANCE_CRL_VALIDITY_DAYS",
        default_value_t = 7
    )]
    pub maintenance_crl_validity_days: i64,

    #[arg(
        long,
        env = "EJBCA_RS_MAINTENANCE_CRL_PARTITION_COUNT",
        default_value_t = 1
    )]
    pub maintenance_crl_partition_count: i64,

    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Clone, Debug, Subcommand)]
pub enum Command {
    Serve,
    ListCas,
    CreateCa {
        #[arg(long)]
        name: String,
        #[arg(long)]
        subject_dn: String,
        #[arg(long)]
        validity_days: Option<i64>,
    },
    UpdateCa {
        #[arg(long)]
        id: String,
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        status: Option<String>,
        #[arg(long)]
        make_default: bool,
    },
    RenewCa {
        #[arg(long)]
        id: String,
        #[arg(long)]
        validity_days: Option<i64>,
    },
    RolloverCa {
        #[arg(long)]
        id: String,
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        subject_dn: Option<String>,
        #[arg(long)]
        validity_days: Option<i64>,
        #[arg(long)]
        make_default: bool,
        #[arg(long)]
        disable_old: bool,
    },
    ImportCa {
        #[arg(long)]
        name: String,
        #[arg(long)]
        cert_pem_file: String,
        #[arg(long)]
        key_ref: String,
    },
    BuildCommandKeyRef {
        #[arg(long)]
        command: String,
        #[arg(long)]
        args_json: Option<String>,
        #[arg(long)]
        timeout_ms: Option<u64>,
        #[arg(long)]
        max_output_bytes: Option<usize>,
    },
    BuildEncryptedKeyRef {
        #[arg(long)]
        key_pem_file: String,
    },
    ListClusterNodes {
        #[arg(long)]
        limit: Option<i64>,
    },
    ClusterHeartbeat {
        #[arg(long)]
        node_id: String,
        #[arg(long)]
        role: Option<String>,
        #[arg(long)]
        status: Option<String>,
        #[arg(long)]
        metadata_json: Option<String>,
    },
    ListCertificateProfiles,
    CreateCertificateProfile {
        #[arg(long)]
        name: String,
        #[arg(long)]
        validity_days: Option<i64>,
        #[arg(long)]
        deny_server_generated_key: bool,
        #[arg(long)]
        require_san: bool,
    },
    UpdateCertificateProfile {
        #[arg(long)]
        id: String,
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        validity_days: Option<i64>,
        #[arg(long, value_delimiter = ',')]
        key_usages: Vec<String>,
        #[arg(long, value_delimiter = ',')]
        extended_key_usages: Vec<String>,
        #[arg(long)]
        allow_server_generated_key: Option<bool>,
        #[arg(long)]
        require_san: Option<bool>,
    },
    DeleteCertificateProfile {
        #[arg(long)]
        id: String,
    },
    ListEndEntityProfiles,
    CreateEndEntityProfile {
        #[arg(long)]
        name: String,
        #[arg(long)]
        subject_regex: Option<String>,
        #[arg(long, value_delimiter = ',')]
        allowed_dns_domains: Vec<String>,
        #[arg(long)]
        default_certificate_profile_id: Option<String>,
    },
    UpdateEndEntityProfile {
        #[arg(long)]
        id: String,
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        subject_regex: Option<String>,
        #[arg(long, value_delimiter = ',')]
        allowed_dns_domains: Vec<String>,
        #[arg(long)]
        default_certificate_profile_id: Option<String>,
    },
    DeleteEndEntityProfile {
        #[arg(long)]
        id: String,
    },
    ListEndEntities {
        #[arg(long)]
        username: Option<String>,
        #[arg(long)]
        status: Option<String>,
        #[arg(long)]
        ca_id: Option<String>,
        #[arg(long)]
        limit: Option<i64>,
    },
    CreateEndEntity {
        #[arg(long)]
        username: String,
        #[arg(long)]
        subject_dn: String,
        #[arg(long, value_delimiter = ',')]
        dns_names: Vec<String>,
        #[arg(long)]
        email: Option<String>,
        #[arg(long)]
        ca_id: Option<String>,
        #[arg(long)]
        certificate_profile_id: Option<String>,
        #[arg(long)]
        end_entity_profile_id: Option<String>,
        #[arg(long)]
        status: Option<String>,
        #[arg(long)]
        password: Option<String>,
        #[arg(long)]
        token_type: Option<String>,
    },
    UpdateEndEntity {
        #[arg(long)]
        id: String,
        #[arg(long)]
        username: Option<String>,
        #[arg(long)]
        subject_dn: Option<String>,
        #[arg(long, value_delimiter = ',')]
        dns_names: Vec<String>,
        #[arg(long)]
        email: Option<String>,
        #[arg(long)]
        ca_id: Option<String>,
        #[arg(long)]
        certificate_profile_id: Option<String>,
        #[arg(long)]
        end_entity_profile_id: Option<String>,
        #[arg(long)]
        status: Option<String>,
        #[arg(long)]
        password: Option<String>,
        #[arg(long)]
        token_type: Option<String>,
    },
    DeleteEndEntity {
        #[arg(long)]
        id: String,
    },
    ListApprovals {
        #[arg(long)]
        action: Option<String>,
        #[arg(long)]
        target_id: Option<String>,
        #[arg(long)]
        status: Option<String>,
        #[arg(long)]
        limit: Option<i64>,
    },
    CreateApproval {
        #[arg(long)]
        action: String,
        #[arg(long)]
        target_id: String,
        #[arg(long, default_value = "{}")]
        request_json: String,
        #[arg(long)]
        expires_at: Option<i64>,
    },
    DecideApproval {
        #[arg(long)]
        id: String,
        #[arg(long)]
        status: String,
        #[arg(long, default_value = "{}")]
        decision_json: String,
    },
    ListCmpAliases,
    CreateCmpAlias {
        #[arg(long)]
        alias: String,
        #[arg(long)]
        ca_id: Option<String>,
        #[arg(long)]
        certificate_profile_id: Option<String>,
        #[arg(long)]
        end_entity_profile_id: Option<String>,
        #[arg(long)]
        disabled: bool,
        #[arg(long)]
        hmac_secret: Option<String>,
    },
    UpdateCmpAlias {
        #[arg(long)]
        id: String,
        #[arg(long)]
        alias: Option<String>,
        #[arg(long)]
        ca_id: Option<String>,
        #[arg(long)]
        certificate_profile_id: Option<String>,
        #[arg(long)]
        end_entity_profile_id: Option<String>,
        #[arg(long)]
        enabled: Option<bool>,
        #[arg(long)]
        hmac_secret: Option<String>,
        #[arg(long)]
        clear_hmac_secret: bool,
    },
    DeleteCmpAlias {
        #[arg(long)]
        id: String,
    },
    CmpP10crSmoke {
        #[arg(long, default_value = "http://127.0.0.1:8080")]
        server_url: String,
        #[arg(long)]
        alias: String,
        #[arg(long, default_value = "CN=cmp-smoke,O=ejbca-rs")]
        subject_dn: String,
        #[arg(long, value_delimiter = ',')]
        dns_names: Vec<String>,
        #[arg(long)]
        hmac_secret: Option<String>,
        #[arg(long)]
        request_der_file: Option<String>,
        #[arg(long)]
        response_der_file: Option<String>,
    },
    CmpIssueRevokeSmoke {
        #[arg(long, default_value = "http://127.0.0.1:8080")]
        server_url: String,
        #[arg(long)]
        alias: String,
        #[arg(long, default_value = "CN=cmp-issue-revoke,O=ejbca-rs")]
        subject_dn: String,
        #[arg(long, value_delimiter = ',')]
        dns_names: Vec<String>,
        #[arg(long)]
        hmac_secret: Option<String>,
    },
    SimulateDevice {
        #[arg(long, default_value = "config/virtual-device.example.toml")]
        device_config: String,
        #[arg(long)]
        output_dir: Option<String>,
    },
    ListAccessRoles,
    CreateAccessRole {
        #[arg(long)]
        name: String,
        #[arg(long, value_delimiter = ',', default_value = "admin")]
        permissions: Vec<String>,
        #[arg(long)]
        api_token: Option<String>,
        #[arg(long)]
        certificate_issuer_dn: Option<String>,
        #[arg(long)]
        certificate_match_key: Option<String>,
        #[arg(long)]
        certificate_match_value: Option<String>,
    },
    UpdateAccessRole {
        #[arg(long)]
        id: String,
        #[arg(long)]
        name: Option<String>,
        #[arg(long, value_delimiter = ',')]
        permissions: Vec<String>,
        #[arg(long)]
        api_token: Option<String>,
        #[arg(long)]
        clear_api_token: bool,
        #[arg(long)]
        certificate_issuer_dn: Option<String>,
        #[arg(long)]
        certificate_match_key: Option<String>,
        #[arg(long)]
        certificate_match_value: Option<String>,
        #[arg(long)]
        clear_certificate_member: bool,
    },
    DeleteAccessRole {
        #[arg(long)]
        id: String,
    },
    ListEjbcaFeatures {
        #[arg(long)]
        feature_type: Option<String>,
        #[arg(long)]
        status: Option<String>,
        #[arg(long)]
        limit: Option<i64>,
    },
    CreateEjbcaFeature {
        #[arg(long)]
        feature_type: String,
        #[arg(long)]
        name: String,
        #[arg(long, default_value = "active")]
        status: String,
        #[arg(long, default_value = "{}")]
        config_json: String,
    },
    UpdateEjbcaFeature {
        #[arg(long)]
        id: String,
        #[arg(long)]
        feature_type: Option<String>,
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        status: Option<String>,
        #[arg(long)]
        config_json: Option<String>,
    },
    DeleteEjbcaFeature {
        #[arg(long)]
        id: String,
    },
    ListCertificates {
        #[arg(long)]
        limit: Option<i64>,
        #[arg(long)]
        ca_id: Option<String>,
        #[arg(long)]
        status: Option<String>,
        #[arg(long)]
        serial_hex: Option<String>,
        #[arg(long)]
        subject: Option<String>,
        #[arg(long)]
        expires_before: Option<i64>,
        #[arg(long)]
        expires_after: Option<i64>,
    },
    GetCertificate {
        #[arg(long)]
        id: String,
    },
    ExportCertificate {
        #[arg(long)]
        id: String,
        #[arg(long, default_value = "pem")]
        format: String,
        #[arg(long)]
        output_file: Option<String>,
    },
    IssueCertificate {
        #[arg(long)]
        end_entity_id: Option<String>,
        #[arg(long)]
        approval_id: Option<String>,
        #[arg(long)]
        ca_id: Option<String>,
        #[arg(long)]
        certificate_profile_id: Option<String>,
        #[arg(long)]
        end_entity_profile_id: Option<String>,
        #[arg(long)]
        subject_dn: String,
        #[arg(long, value_delimiter = ',')]
        dns_names: Vec<String>,
        #[arg(long)]
        validity_days: Option<i64>,
    },
    IssueBrowserCertificate {
        #[arg(long)]
        end_entity_id: Option<String>,
        #[arg(long)]
        approval_id: Option<String>,
        #[arg(long)]
        ca_id: Option<String>,
        #[arg(long)]
        certificate_profile_id: Option<String>,
        #[arg(long)]
        end_entity_profile_id: Option<String>,
        #[arg(long)]
        subject_dn: String,
        #[arg(long, value_delimiter = ',')]
        dns_names: Vec<String>,
        #[arg(long)]
        validity_days: Option<i64>,
        #[arg(long)]
        pkcs12_password: String,
        #[arg(long)]
        friendly_name: Option<String>,
        #[arg(long)]
        output_file: String,
    },
    LoadTestIssuance {
        #[arg(long, default_value_t = 100)]
        total: usize,
        #[arg(long, default_value_t = 32)]
        concurrency: usize,
        #[arg(long, default_value_t = 0)]
        start_index: usize,
        #[arg(long, default_value = "load-device")]
        subject_prefix: String,
        #[arg(long, default_value = "load.example.com")]
        dns_suffix: String,
        #[arg(long)]
        ca_id: Option<String>,
        #[arg(long)]
        certificate_profile_id: Option<String>,
        #[arg(long)]
        end_entity_profile_id: Option<String>,
        #[arg(long)]
        validity_days: Option<i64>,
        #[arg(long, default_value_t = 10)]
        sample_failures: usize,
    },
    SoakTestIssuance {
        #[arg(long, default_value_t = 300)]
        duration_seconds: u64,
        #[arg(long, default_value_t = 32)]
        concurrency: usize,
        #[arg(long)]
        max_total: Option<usize>,
        #[arg(long, default_value_t = 0)]
        start_index: usize,
        #[arg(long, default_value = "soak-device")]
        subject_prefix: String,
        #[arg(long, default_value = "soak.example.com")]
        dns_suffix: String,
        #[arg(long)]
        ca_id: Option<String>,
        #[arg(long)]
        certificate_profile_id: Option<String>,
        #[arg(long)]
        end_entity_profile_id: Option<String>,
        #[arg(long)]
        validity_days: Option<i64>,
        #[arg(long, default_value_t = 10)]
        sample_failures: usize,
    },
    IssueCsr {
        #[arg(long)]
        end_entity_id: Option<String>,
        #[arg(long)]
        approval_id: Option<String>,
        #[arg(long)]
        ca_id: Option<String>,
        #[arg(long)]
        certificate_profile_id: Option<String>,
        #[arg(long)]
        end_entity_profile_id: Option<String>,
        #[arg(long)]
        csr_pem_file: String,
        #[arg(long)]
        validity_days: Option<i64>,
    },
    RevokeCertificate {
        #[arg(long)]
        id: String,
        #[arg(long)]
        reason: Option<String>,
        #[arg(long)]
        approval_id: Option<String>,
    },
    ListCrls {
        #[arg(long)]
        limit: Option<i64>,
    },
    GenerateCrl {
        #[arg(long)]
        ca_id: String,
        #[arg(long)]
        validity_days: Option<i64>,
        #[arg(long)]
        delta: bool,
        #[arg(long)]
        partition_index: Option<i64>,
        #[arg(long)]
        partition_count: Option<i64>,
    },
    ListValidators,
    CreateValidator {
        #[arg(long)]
        name: String,
        #[arg(long)]
        kind: String,
        #[arg(long)]
        config_json: String,
        #[arg(long)]
        disabled: bool,
    },
    UpdateValidator {
        #[arg(long)]
        id: String,
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        kind: Option<String>,
        #[arg(long)]
        config_json: Option<String>,
        #[arg(long)]
        enabled: Option<bool>,
    },
    DeleteValidator {
        #[arg(long)]
        id: String,
    },
    MaintenanceConfig,
    SetMaintenanceConfig {
        #[arg(long)]
        enabled: Option<bool>,
        #[arg(long)]
        interval_seconds: Option<u64>,
        #[arg(long)]
        backup: Option<bool>,
        #[arg(long)]
        purge_expired_certificates: Option<bool>,
        #[arg(long)]
        purge_expired_crls: Option<bool>,
        #[arg(long)]
        purge_metric_events: Option<bool>,
        #[arg(long)]
        purge_audit_events: Option<bool>,
        #[arg(long)]
        optimize: Option<bool>,
        #[arg(long)]
        older_than_days: Option<i64>,
        #[arg(long)]
        batch_size: Option<i64>,
        #[arg(long)]
        generate_crls: Option<bool>,
        #[arg(long)]
        crl_validity_days: Option<i64>,
        #[arg(long)]
        crl_partition_count: Option<i64>,
        #[arg(long)]
        metrics_enabled: Option<bool>,
        #[arg(long)]
        metrics_public: Option<bool>,
        #[arg(long)]
        metrics_device_limit: Option<i64>,
        #[arg(long)]
        metrics_event_retention_days: Option<i64>,
        #[arg(long)]
        audit_event_retention_days: Option<i64>,
        #[arg(long)]
        log_level: Option<String>,
        #[arg(long)]
        log_output: Option<String>,
        #[arg(long)]
        log_dir: Option<String>,
        #[arg(long)]
        log_retention_days: Option<u64>,
        #[arg(long)]
        log_retention_files: Option<usize>,
        #[arg(long)]
        cors_allowed_origins: Option<String>,
    },
    RunMaintenance {
        #[arg(long)]
        backup: bool,
        #[arg(long)]
        purge_expired_certificates: bool,
        #[arg(long)]
        purge_expired_crls: bool,
        #[arg(long)]
        purge_metric_events: bool,
        #[arg(long)]
        purge_audit_events: bool,
        #[arg(long)]
        optimize: bool,
        #[arg(long)]
        older_than_days: Option<i64>,
        #[arg(long)]
        batch_size: Option<i64>,
        #[arg(long)]
        generate_crls: bool,
        #[arg(long)]
        crl_validity_days: Option<i64>,
        #[arg(long)]
        crl_partition_count: Option<i64>,
    },
    ListAuditEvents {
        #[arg(long)]
        limit: Option<i64>,
        #[arg(long)]
        actor: Option<String>,
        #[arg(long)]
        action: Option<String>,
        #[arg(long)]
        target: Option<String>,
        #[arg(long)]
        status: Option<String>,
        #[arg(long)]
        since: Option<i64>,
        #[arg(long)]
        until: Option<i64>,
    },
    VerifyAuditEvents,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
struct FileSettings {
    bind_addr: Option<std::net::SocketAddr>,
    data_dir: Option<String>,
    database_url: Option<String>,
    admin_token: Option<String>,
    public_base_url: Option<String>,
    ca_key_provider: Option<String>,
    ca_key_dir: Option<String>,
    max_request_bytes: Option<usize>,
    max_list_limit: Option<i64>,
    cors_allowed_origins: Option<String>,
    adminweb_client_cert_required: Option<bool>,
    adminweb_client_cert_header: Option<String>,
    adminweb_client_cert_proxy_secret: Option<String>,
    adminweb_client_cert_allowed_fingerprints: Option<String>,
    adminweb_client_cert_allowed_subjects: Option<String>,
    database_max_connections: Option<u32>,
    database_busy_timeout_seconds: Option<u64>,
    max_concurrent_issuance: Option<usize>,
    validator_webhook_default_timeout_ms: Option<u64>,
    validator_webhook_max_timeout_ms: Option<u64>,
    validator_webhook_max_response_bytes: Option<usize>,
    json_logs: Option<bool>,
    log_level: Option<String>,
    log_output: Option<String>,
    log_dir: Option<String>,
    log_retention_days: Option<u64>,
    log_retention_files: Option<usize>,
    metrics_enabled: Option<bool>,
    metrics_public: Option<bool>,
    metrics_device_limit: Option<i64>,
    metrics_event_retention_days: Option<i64>,
    audit_event_retention_days: Option<i64>,
    maintenance_enabled: Option<bool>,
    maintenance_interval_seconds: Option<u64>,
    maintenance_backup: Option<bool>,
    maintenance_purge_expired_certificates: Option<bool>,
    maintenance_purge_expired_crls: Option<bool>,
    maintenance_purge_audit_events: Option<bool>,
    maintenance_optimize: Option<bool>,
    maintenance_older_than_days: Option<i64>,
    maintenance_batch_size: Option<i64>,
    maintenance_generate_crls: Option<bool>,
    maintenance_crl_validity_days: Option<i64>,
    maintenance_crl_partition_count: Option<i64>,
    ca_key_encryption_secret: Option<String>,
    cmp_secret: Option<String>,
    cmp_alias_secrets: HashMap<String, String>,
}

impl Settings {
    pub fn parse() -> Self {
        let mut settings = <Self as Parser>::parse();
        if let Some(config_file) = resolve_config_file(settings.config_file.as_deref()) {
            let file_settings = load_file_settings(&config_file).unwrap_or_else(|err| {
                eprintln!(
                    "설정 파일을 읽을 수 없습니다: {}: {err}",
                    config_file.display()
                );
                std::process::exit(2);
            });
            settings.apply_file_settings(file_settings);
        }
        settings
    }

    pub fn database_url(&self) -> String {
        self.database_url
            .clone()
            .unwrap_or_else(|| format!("sqlite://{}/ejbca-rs.sqlite", self.data_dir))
    }

    pub fn with_admin_token(mut self, token: String) -> Self {
        self.admin_token = Some(token);
        self
    }

    pub fn admin_token(&self) -> &str {
        self.admin_token
            .as_deref()
            .expect("관리자 토큰은 시작 시점에 항상 채워집니다")
    }

    fn apply_file_settings(&mut self, file: FileSettings) {
        if let Some(value) = file.bind_addr {
            self.bind_addr = value;
        }
        if let Some(value) = file.data_dir {
            self.data_dir = value;
        }
        if let Some(value) = file.database_url {
            self.database_url = Some(value);
        }
        if let Some(value) = file.admin_token {
            self.admin_token = Some(value);
        }
        if let Some(value) = file.public_base_url {
            self.public_base_url = value;
        }
        if let Some(value) = file.ca_key_provider {
            self.ca_key_provider = value;
        }
        if let Some(value) = file.ca_key_dir {
            self.ca_key_dir = Some(value);
        }
        if let Some(value) = file.max_request_bytes {
            self.max_request_bytes = value;
        }
        if let Some(value) = file.max_list_limit {
            self.max_list_limit = value;
        }
        if let Some(value) = file.cors_allowed_origins {
            self.cors_allowed_origins = value;
        }
        if let Some(value) = file.adminweb_client_cert_required {
            self.adminweb_client_cert_required = value;
        }
        if let Some(value) = file.adminweb_client_cert_header {
            self.adminweb_client_cert_header = value;
        }
        if let Some(value) = file.adminweb_client_cert_proxy_secret {
            self.adminweb_client_cert_proxy_secret = Some(value);
        }
        if let Some(value) = file.adminweb_client_cert_allowed_fingerprints {
            self.adminweb_client_cert_allowed_fingerprints = value;
        }
        if let Some(value) = file.adminweb_client_cert_allowed_subjects {
            self.adminweb_client_cert_allowed_subjects = value;
        }
        if let Some(value) = file.database_max_connections {
            self.database_max_connections = value;
        }
        if let Some(value) = file.database_busy_timeout_seconds {
            self.database_busy_timeout_seconds = value;
        }
        if let Some(value) = file.max_concurrent_issuance {
            self.max_concurrent_issuance = value;
        }
        if let Some(value) = file.validator_webhook_default_timeout_ms {
            self.validator_webhook_default_timeout_ms = value;
        }
        if let Some(value) = file.validator_webhook_max_timeout_ms {
            self.validator_webhook_max_timeout_ms = value;
        }
        if let Some(value) = file.validator_webhook_max_response_bytes {
            self.validator_webhook_max_response_bytes = value;
        }
        if let Some(value) = file.json_logs {
            self.json_logs = value;
        }
        if let Some(value) = file.log_level {
            self.log_level = value;
        }
        if let Some(value) = file.log_output {
            self.log_output = value;
        }
        if let Some(value) = file.log_dir {
            self.log_dir = Some(value);
        }
        if let Some(value) = file.log_retention_days {
            self.log_retention_days = value;
        }
        if let Some(value) = file.log_retention_files {
            self.log_retention_files = value;
        }
        if let Some(value) = file.metrics_enabled {
            self.metrics_enabled = value;
        }
        if let Some(value) = file.metrics_public {
            self.metrics_public = value;
        }
        if let Some(value) = file.metrics_device_limit {
            self.metrics_device_limit = value;
        }
        if let Some(value) = file.metrics_event_retention_days {
            self.metrics_event_retention_days = value;
        }
        if let Some(value) = file.audit_event_retention_days {
            self.audit_event_retention_days = value;
        }
        if let Some(value) = file.maintenance_enabled {
            self.maintenance_enabled = value;
        }
        if let Some(value) = file.maintenance_interval_seconds {
            self.maintenance_interval_seconds = value;
        }
        if let Some(value) = file.maintenance_backup {
            self.maintenance_backup = value;
        }
        if let Some(value) = file.maintenance_purge_expired_certificates {
            self.maintenance_purge_expired_certificates = value;
        }
        if let Some(value) = file.maintenance_purge_expired_crls {
            self.maintenance_purge_expired_crls = value;
        }
        if let Some(value) = file.maintenance_purge_audit_events {
            self.maintenance_purge_audit_events = value;
        }
        if let Some(value) = file.maintenance_optimize {
            self.maintenance_optimize = value;
        }
        if let Some(value) = file.maintenance_older_than_days {
            self.maintenance_older_than_days = value;
        }
        if let Some(value) = file.maintenance_batch_size {
            self.maintenance_batch_size = value;
        }
        if let Some(value) = file.maintenance_generate_crls {
            self.maintenance_generate_crls = value;
        }
        if let Some(value) = file.maintenance_crl_validity_days {
            self.maintenance_crl_validity_days = value;
        }
        if let Some(value) = file.maintenance_crl_partition_count {
            self.maintenance_crl_partition_count = value;
        }
        set_runtime_secret_config(
            file.cmp_secret,
            file.cmp_alias_secrets,
            file.ca_key_encryption_secret,
        );
    }
}

pub fn configured_cmp_alias_secret(alias: &str) -> Option<String> {
    let secrets = runtime_secret_config().read().ok()?;
    let normalized = normalize_cmp_alias(alias);
    secrets
        .cmp_alias_secrets
        .get(alias)
        .or_else(|| secrets.cmp_alias_secrets.get(&alias.to_ascii_lowercase()))
        .or_else(|| secrets.cmp_alias_secrets.get(&normalized))
        .cloned()
        .or_else(|| secrets.cmp_default_secret.clone())
}

pub fn configured_ca_key_encryption_secret() -> Option<String> {
    runtime_secret_config()
        .read()
        .ok()?
        .ca_key_encryption_secret
        .clone()
}

fn resolve_config_file(explicit: Option<&str>) -> Option<PathBuf> {
    if let Some(path) = explicit {
        return Some(PathBuf::from(path));
    }
    let default_path = Path::new(DEFAULT_CONFIG_FILE);
    default_path.exists().then(|| default_path.to_path_buf())
}

fn load_file_settings(path: &Path) -> anyhow::Result<FileSettings> {
    let content = fs::read_to_string(path)?;
    if path.extension().and_then(|value| value.to_str()) == Some("json") {
        Ok(serde_json::from_str(&content)?)
    } else {
        Ok(toml::from_str(&content)?)
    }
}

fn set_runtime_secret_config(
    cmp_default_secret: Option<String>,
    cmp_alias_secrets: HashMap<String, String>,
    ca_key_encryption_secret: Option<String>,
) {
    let mut secrets = runtime_secret_config()
        .write()
        .expect("runtime secret config lock poisoned");
    secrets.cmp_default_secret = cmp_default_secret;
    secrets.cmp_alias_secrets = cmp_alias_secrets;
    secrets.ca_key_encryption_secret = ca_key_encryption_secret;
}

fn runtime_secret_config() -> &'static RwLock<RuntimeSecretConfig> {
    RUNTIME_SECRET_CONFIG.get_or_init(|| RwLock::new(RuntimeSecretConfig::default()))
}

fn normalize_cmp_alias(alias: &str) -> String {
    alias
        .bytes()
        .map(|byte| {
            if byte.is_ascii_alphanumeric() {
                char::from(byte.to_ascii_uppercase())
            } else {
                '_'
            }
        })
        .collect()
}
