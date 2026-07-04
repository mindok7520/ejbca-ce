use clap::{Parser, Subcommand};

#[derive(Clone, Debug, Parser)]
#[command(name = "ejbca-rs", about = "Rust 기반 경량 CA/CMP/OCSP/CRL 관리 서버")]
pub struct Settings {
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

impl Settings {
    pub fn parse() -> Self {
        <Self as Parser>::parse()
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
}
