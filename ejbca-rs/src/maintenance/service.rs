use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    time::Duration,
};

use tokio::fs;
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::{
    AppState,
    crl::{GenerateCrlRequest, service as crl_service},
    error::{AppError, AppResult},
    maintenance::{
        MaintenanceConfigResponse, MaintenanceRequest, MaintenanceResponse,
        UpdateMaintenanceConfigRequest,
    },
    util::now_unix,
};

#[derive(Debug, Clone)]
struct RuntimeMaintenanceConfig {
    enabled: bool,
    interval_seconds: u64,
    backup: bool,
    purge_expired_certificates: bool,
    purge_expired_crls: bool,
    purge_metric_events: bool,
    purge_audit_events: bool,
    optimize: bool,
    older_than_days: i64,
    batch_size: i64,
    generate_crls: bool,
    crl_validity_days: i64,
    crl_partition_count: i64,
    metrics_enabled: bool,
    metrics_public: bool,
    metrics_device_limit: i64,
    metrics_event_retention_days: i64,
    audit_event_retention_days: i64,
    log_level: String,
    log_output: String,
    log_dir: String,
    log_retention_days: u64,
    log_retention_files: usize,
    cors_allowed_origins: String,
    restart_required_fields: Vec<String>,
}

impl RuntimeMaintenanceConfig {
    fn from_state(state: &AppState) -> Self {
        Self {
            enabled: state.settings.maintenance_enabled,
            interval_seconds: state.settings.maintenance_interval_seconds.max(60),
            backup: state.settings.maintenance_backup,
            purge_expired_certificates: state.settings.maintenance_purge_expired_certificates,
            purge_expired_crls: state.settings.maintenance_purge_expired_crls,
            purge_metric_events: true,
            purge_audit_events: state.settings.maintenance_purge_audit_events,
            optimize: state.settings.maintenance_optimize,
            older_than_days: state.settings.maintenance_older_than_days.clamp(0, 3650),
            batch_size: state.settings.maintenance_batch_size.clamp(1, 10_000),
            generate_crls: state.settings.maintenance_generate_crls,
            crl_validity_days: state.settings.maintenance_crl_validity_days.clamp(1, 90),
            crl_partition_count: state
                .settings
                .maintenance_crl_partition_count
                .clamp(1, 1024),
            metrics_enabled: state.settings.metrics_enabled,
            metrics_public: state.settings.metrics_public,
            metrics_device_limit: state.settings.metrics_device_limit.clamp(1, 10_000),
            metrics_event_retention_days: state
                .settings
                .metrics_event_retention_days
                .clamp(1, 3650),
            audit_event_retention_days: state.settings.audit_event_retention_days.clamp(1, 3650),
            log_level: state.settings.log_level.clone(),
            log_output: state.settings.log_output.clone(),
            log_dir: state
                .settings
                .log_dir
                .clone()
                .unwrap_or_else(|| format!("{}/logs", state.settings.data_dir)),
            log_retention_days: state.settings.log_retention_days,
            log_retention_files: state.settings.log_retention_files,
            cors_allowed_origins: state.settings.cors_allowed_origins.clone(),
            restart_required_fields: Vec::new(),
        }
    }

    fn to_response(&self) -> MaintenanceConfigResponse {
        MaintenanceConfigResponse {
            enabled: self.enabled,
            interval_seconds: self.interval_seconds,
            backup: self.backup,
            purge_expired_certificates: self.purge_expired_certificates,
            purge_expired_crls: self.purge_expired_crls,
            optimize: self.optimize,
            older_than_days: self.older_than_days,
            batch_size: self.batch_size,
            generate_crls: self.generate_crls,
            crl_validity_days: self.crl_validity_days,
            crl_partition_count: self.crl_partition_count,
            metrics_event_retention_days: self.metrics_event_retention_days,
            audit_event_retention_days: self.audit_event_retention_days,
            purge_audit_events: self.purge_audit_events,
            metrics_enabled: self.metrics_enabled,
            metrics_public: self.metrics_public,
            metrics_device_limit: self.metrics_device_limit,
            log_level: self.log_level.clone(),
            log_output: self.log_output.clone(),
            log_dir: self.log_dir.clone(),
            log_retention_days: self.log_retention_days,
            log_retention_files: self.log_retention_files,
            cors_allowed_origins: self.cors_allowed_origins.clone(),
            restart_required_fields: self.restart_required_fields.clone(),
        }
    }
}

pub async fn config_response(state: &AppState) -> AppResult<MaintenanceConfigResponse> {
    Ok(effective_config(state).await?.to_response())
}

pub async fn update_config(
    state: &AppState,
    request: UpdateMaintenanceConfigRequest,
    actor: &str,
) -> AppResult<MaintenanceConfigResponse> {
    let mut changed = Vec::new();
    upsert_bool(state, &mut changed, "maintenance.enabled", request.enabled).await?;
    upsert_u64(
        state,
        &mut changed,
        "maintenance.interval_seconds",
        request.interval_seconds.map(|value| value.max(60)),
        60,
        86_400,
    )
    .await?;
    upsert_bool(state, &mut changed, "maintenance.backup", request.backup).await?;
    upsert_bool(
        state,
        &mut changed,
        "maintenance.purge_expired_certificates",
        request.purge_expired_certificates,
    )
    .await?;
    upsert_bool(
        state,
        &mut changed,
        "maintenance.purge_expired_crls",
        request.purge_expired_crls,
    )
    .await?;
    upsert_bool(
        state,
        &mut changed,
        "maintenance.purge_metric_events",
        request.purge_metric_events,
    )
    .await?;
    upsert_bool(
        state,
        &mut changed,
        "maintenance.purge_audit_events",
        request.purge_audit_events,
    )
    .await?;
    upsert_bool(
        state,
        &mut changed,
        "maintenance.optimize",
        request.optimize,
    )
    .await?;
    upsert_i64(
        state,
        &mut changed,
        "maintenance.older_than_days",
        request.older_than_days,
        0,
        3650,
    )
    .await?;
    upsert_i64(
        state,
        &mut changed,
        "maintenance.batch_size",
        request.batch_size,
        1,
        10_000,
    )
    .await?;
    upsert_bool(
        state,
        &mut changed,
        "maintenance.generate_crls",
        request.generate_crls,
    )
    .await?;
    upsert_i64(
        state,
        &mut changed,
        "maintenance.crl_validity_days",
        request.crl_validity_days,
        1,
        90,
    )
    .await?;
    upsert_i64(
        state,
        &mut changed,
        "maintenance.crl_partition_count",
        request.crl_partition_count,
        1,
        1024,
    )
    .await?;
    upsert_bool(
        state,
        &mut changed,
        "metrics.enabled",
        request.metrics_enabled,
    )
    .await?;
    upsert_bool(
        state,
        &mut changed,
        "metrics.public",
        request.metrics_public,
    )
    .await?;
    upsert_i64(
        state,
        &mut changed,
        "metrics.device_limit",
        request.metrics_device_limit,
        1,
        10_000,
    )
    .await?;
    upsert_i64(
        state,
        &mut changed,
        "metrics.event_retention_days",
        request.metrics_event_retention_days,
        1,
        3650,
    )
    .await?;
    upsert_i64(
        state,
        &mut changed,
        "audit.event_retention_days",
        request.audit_event_retention_days,
        1,
        3650,
    )
    .await?;
    upsert_string(
        state,
        &mut changed,
        "log.level",
        request.log_level.map(validate_log_level).transpose()?,
    )
    .await?;
    upsert_string(
        state,
        &mut changed,
        "log.output",
        request.log_output.map(validate_log_output).transpose()?,
    )
    .await?;
    upsert_string(state, &mut changed, "log.dir", request.log_dir).await?;
    upsert_u64(
        state,
        &mut changed,
        "log.retention_days",
        request.log_retention_days,
        0,
        3650,
    )
    .await?;
    upsert_usize(
        state,
        &mut changed,
        "log.retention_files",
        request.log_retention_files,
        0,
        10_000,
    )
    .await?;
    upsert_string(
        state,
        &mut changed,
        "cors.allowed_origins",
        request.cors_allowed_origins,
    )
    .await?;

    state
        .db
        .audit(
            actor,
            "maintenance.config.update",
            "app_config",
            "success",
            &serde_json::json!({ "changed": changed }).to_string(),
        )
        .await?;

    config_response(state).await
}

pub async fn metrics_config(state: &AppState) -> AppResult<(bool, bool, i64)> {
    let config = effective_config(state).await?;
    Ok((
        config.metrics_enabled,
        config.metrics_public,
        config.metrics_device_limit,
    ))
}

async fn effective_config(state: &AppState) -> AppResult<RuntimeMaintenanceConfig> {
    let mut config = RuntimeMaintenanceConfig::from_state(state);
    let values = state
        .db
        .list_app_config()
        .await?
        .into_iter()
        .map(|record| (record.key, record.value))
        .collect::<HashMap<_, _>>();

    apply_bool(&values, "maintenance.enabled", &mut config.enabled);
    apply_u64(
        &values,
        "maintenance.interval_seconds",
        &mut config.interval_seconds,
        60,
        86_400,
    );
    apply_bool(&values, "maintenance.backup", &mut config.backup);
    apply_bool(
        &values,
        "maintenance.purge_expired_certificates",
        &mut config.purge_expired_certificates,
    );
    apply_bool(
        &values,
        "maintenance.purge_expired_crls",
        &mut config.purge_expired_crls,
    );
    apply_bool(
        &values,
        "maintenance.purge_metric_events",
        &mut config.purge_metric_events,
    );
    apply_bool(
        &values,
        "maintenance.purge_audit_events",
        &mut config.purge_audit_events,
    );
    apply_bool(&values, "maintenance.optimize", &mut config.optimize);
    apply_i64(
        &values,
        "maintenance.older_than_days",
        &mut config.older_than_days,
        0,
        3650,
    );
    apply_i64(
        &values,
        "maintenance.batch_size",
        &mut config.batch_size,
        1,
        10_000,
    );
    apply_bool(
        &values,
        "maintenance.generate_crls",
        &mut config.generate_crls,
    );
    apply_i64(
        &values,
        "maintenance.crl_validity_days",
        &mut config.crl_validity_days,
        1,
        90,
    );
    apply_i64(
        &values,
        "maintenance.crl_partition_count",
        &mut config.crl_partition_count,
        1,
        1024,
    );
    apply_bool(&values, "metrics.enabled", &mut config.metrics_enabled);
    apply_bool(&values, "metrics.public", &mut config.metrics_public);
    apply_i64(
        &values,
        "metrics.device_limit",
        &mut config.metrics_device_limit,
        1,
        10_000,
    );
    apply_i64(
        &values,
        "metrics.event_retention_days",
        &mut config.metrics_event_retention_days,
        1,
        3650,
    );
    apply_i64(
        &values,
        "audit.event_retention_days",
        &mut config.audit_event_retention_days,
        1,
        3650,
    );
    apply_string(&values, "log.level", &mut config.log_level);
    apply_string(&values, "log.output", &mut config.log_output);
    apply_string(&values, "log.dir", &mut config.log_dir);
    apply_u64(
        &values,
        "log.retention_days",
        &mut config.log_retention_days,
        0,
        3650,
    );
    apply_usize(
        &values,
        "log.retention_files",
        &mut config.log_retention_files,
        0,
        10_000,
    );
    apply_string(
        &values,
        "cors.allowed_origins",
        &mut config.cors_allowed_origins,
    );

    config.restart_required_fields = restart_required_fields(state, &config);
    Ok(config)
}

fn restart_required_fields(state: &AppState, config: &RuntimeMaintenanceConfig) -> Vec<String> {
    let current_log_dir = state
        .settings
        .log_dir
        .clone()
        .unwrap_or_else(|| format!("{}/logs", state.settings.data_dir));
    let mut fields = Vec::new();
    if config.log_level != state.settings.log_level {
        fields.push("log_level".to_string());
    }
    if config.log_output != state.settings.log_output {
        fields.push("log_output".to_string());
    }
    if config.log_dir != current_log_dir {
        fields.push("log_dir".to_string());
    }
    if config.log_retention_days != state.settings.log_retention_days {
        fields.push("log_retention_days".to_string());
    }
    if config.log_retention_files != state.settings.log_retention_files {
        fields.push("log_retention_files".to_string());
    }
    if config.cors_allowed_origins != state.settings.cors_allowed_origins {
        fields.push("cors_allowed_origins".to_string());
    }
    fields
}

async fn upsert_bool(
    state: &AppState,
    changed: &mut Vec<String>,
    key: &str,
    value: Option<bool>,
) -> AppResult<()> {
    if let Some(value) = value {
        state.db.upsert_app_config(key, bool_text(value)).await?;
        changed.push(key.to_string());
    }
    Ok(())
}

async fn upsert_i64(
    state: &AppState,
    changed: &mut Vec<String>,
    key: &str,
    value: Option<i64>,
    min: i64,
    max: i64,
) -> AppResult<()> {
    if let Some(value) = value {
        state
            .db
            .upsert_app_config(key, &value.clamp(min, max).to_string())
            .await?;
        changed.push(key.to_string());
    }
    Ok(())
}

async fn upsert_u64(
    state: &AppState,
    changed: &mut Vec<String>,
    key: &str,
    value: Option<u64>,
    min: u64,
    max: u64,
) -> AppResult<()> {
    if let Some(value) = value {
        state
            .db
            .upsert_app_config(key, &value.clamp(min, max).to_string())
            .await?;
        changed.push(key.to_string());
    }
    Ok(())
}

async fn upsert_usize(
    state: &AppState,
    changed: &mut Vec<String>,
    key: &str,
    value: Option<usize>,
    min: usize,
    max: usize,
) -> AppResult<()> {
    if let Some(value) = value {
        state
            .db
            .upsert_app_config(key, &value.clamp(min, max).to_string())
            .await?;
        changed.push(key.to_string());
    }
    Ok(())
}

async fn upsert_string(
    state: &AppState,
    changed: &mut Vec<String>,
    key: &str,
    value: Option<String>,
) -> AppResult<()> {
    if let Some(value) = value {
        state.db.upsert_app_config(key, value.trim()).await?;
        changed.push(key.to_string());
    }
    Ok(())
}

fn apply_bool(values: &HashMap<String, String>, key: &str, target: &mut bool) {
    if let Some(value) = values.get(key).and_then(|value| parse_bool(value)) {
        *target = value;
    }
}

fn apply_i64(values: &HashMap<String, String>, key: &str, target: &mut i64, min: i64, max: i64) {
    if let Some(value) = values.get(key).and_then(|value| value.parse::<i64>().ok()) {
        *target = value.clamp(min, max);
    }
}

fn apply_u64(values: &HashMap<String, String>, key: &str, target: &mut u64, min: u64, max: u64) {
    if let Some(value) = values.get(key).and_then(|value| value.parse::<u64>().ok()) {
        *target = value.clamp(min, max);
    }
}

fn apply_usize(
    values: &HashMap<String, String>,
    key: &str,
    target: &mut usize,
    min: usize,
    max: usize,
) {
    if let Some(value) = values
        .get(key)
        .and_then(|value| value.parse::<usize>().ok())
    {
        *target = value.clamp(min, max);
    }
}

fn apply_string(values: &HashMap<String, String>, key: &str, target: &mut String) {
    if let Some(value) = values.get(key) {
        *target = value.clone();
    }
}

fn parse_bool(value: &str) -> Option<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    }
}

fn bool_text(value: bool) -> &'static str {
    if value { "true" } else { "false" }
}

fn validate_log_level(value: String) -> AppResult<String> {
    let value = value.trim().to_ascii_lowercase();
    match value.as_str() {
        "trace" | "tracing" | "debug" | "info" | "warn" | "warning" | "error" => Ok(value),
        _ if value.contains('=') || value.contains(',') => Ok(value),
        _ => Err(AppError::BadRequest(
            "log_level은 trace/tracing/debug/info/warn/warning/error 또는 tracing filter여야 합니다"
                .to_string(),
        )),
    }
}

fn validate_log_output(value: String) -> AppResult<String> {
    let value = value.trim().to_ascii_lowercase();
    match value.as_str() {
        "stdout" | "file" | "both" => Ok(value),
        _ => Err(AppError::BadRequest(
            "log_output은 stdout, file, both 중 하나여야 합니다".to_string(),
        )),
    }
}

pub fn spawn_scheduler(state: AppState) {
    tokio::spawn(async move {
        info!("자동 DB 유지보수 워커를 시작했습니다");
        loop {
            let config = match effective_config(&state).await {
                Ok(config) => config,
                Err(err) => {
                    error!("자동 DB 유지보수 설정 로드 실패: {err}");
                    tokio::time::sleep(Duration::from_secs(60)).await;
                    continue;
                }
            };
            let interval = Duration::from_secs(config.interval_seconds.max(60));
            tokio::time::sleep(interval).await;
            let config = match effective_config(&state).await {
                Ok(config) => config,
                Err(err) => {
                    error!("자동 DB 유지보수 설정 로드 실패: {err}");
                    continue;
                }
            };
            let request = scheduled_request(&config);
            if !config.enabled {
                continue;
            }
            if !has_work(&request) {
                warn!("자동 DB 유지보수가 켜졌지만 수행할 작업이 없습니다");
                continue;
            }
            match run_maintenance(&state, request, "maintenance-scheduler").await {
                Ok(response) => info!(
                    purged_certificates = response.purged_certificates,
                    purged_crls = response.purged_crls,
                    purged_audit_events = response.purged_audit_events,
                    generated_crls = response.generated_crls,
                    optimized = response.optimized,
                    backup_path = response.backup_path.as_deref().unwrap_or("-"),
                    "자동 DB 유지보수를 완료했습니다"
                ),
                Err(err) => error!("자동 DB 유지보수 실패: {err}"),
            }
        }
    });
}

pub async fn run_maintenance(
    state: &AppState,
    request: MaintenanceRequest,
    actor: &str,
) -> AppResult<MaintenanceResponse> {
    let config = effective_config(state).await?;
    let older_than_days = request
        .older_than_days
        .unwrap_or(config.older_than_days)
        .clamp(0, 3650);
    let batch_size = request
        .batch_size
        .unwrap_or(config.batch_size)
        .clamp(1, 10_000);
    let crl_validity_days = request
        .crl_validity_days
        .unwrap_or(config.crl_validity_days)
        .clamp(1, 90);
    let crl_partition_count = request
        .crl_partition_count
        .unwrap_or(config.crl_partition_count)
        .clamp(1, 1024);
    let older_than_unix = now_unix() - older_than_days * 86_400;

    let mut response = MaintenanceResponse {
        backup_path: None,
        purged_certificates: 0,
        purged_crls: 0,
        purged_metric_events: 0,
        purged_audit_events: 0,
        generated_crls: 0,
        optimized: false,
    };

    if request.backup.unwrap_or(false) {
        response.backup_path = Some(backup_sqlite(state).await?);
    }
    if request.purge_expired_certificates.unwrap_or(false) {
        response.purged_certificates = state
            .db
            .purge_expired_certificates(older_than_unix, batch_size)
            .await?;
    }
    if request.purge_expired_crls.unwrap_or(false) {
        response.purged_crls = state
            .db
            .purge_expired_crls(older_than_unix, batch_size)
            .await?;
    }
    if request.purge_metric_events.unwrap_or(false) {
        let metric_cutoff = now_unix() - config.metrics_event_retention_days * 86_400;
        response.purged_metric_events = state
            .db
            .purge_certificate_events(metric_cutoff, batch_size)
            .await?;
    }
    if request.purge_audit_events.unwrap_or(false) {
        let audit_cutoff = now_unix() - config.audit_event_retention_days * 86_400;
        response.purged_audit_events = state
            .db
            .purge_audit_events(audit_cutoff, batch_size)
            .await?;
    }
    if request.generate_crls.unwrap_or(false) {
        response.generated_crls =
            generate_scheduled_crls(state, crl_validity_days, crl_partition_count, actor).await?;
    }
    if request.optimize.unwrap_or(false) {
        state.db.optimize().await?;
        response.optimized = true;
    }

    state
        .db
        .audit(
            actor,
            "maintenance.run",
            "database",
            "success",
            &serde_json::to_string(&response).unwrap_or_else(|_| "{}".to_string()),
        )
        .await?;
    Ok(response)
}

fn scheduled_request(config: &RuntimeMaintenanceConfig) -> MaintenanceRequest {
    MaintenanceRequest {
        backup: Some(config.backup),
        purge_expired_certificates: Some(config.purge_expired_certificates),
        purge_expired_crls: Some(config.purge_expired_crls),
        purge_metric_events: Some(config.purge_metric_events),
        purge_audit_events: Some(config.purge_audit_events),
        optimize: Some(config.optimize),
        older_than_days: Some(config.older_than_days),
        batch_size: Some(config.batch_size),
        generate_crls: Some(config.generate_crls),
        crl_validity_days: Some(config.crl_validity_days),
        crl_partition_count: Some(config.crl_partition_count),
    }
}

fn has_work(request: &MaintenanceRequest) -> bool {
    request.backup.unwrap_or(false)
        || request.purge_expired_certificates.unwrap_or(false)
        || request.purge_expired_crls.unwrap_or(false)
        || request.purge_metric_events.unwrap_or(false)
        || request.purge_audit_events.unwrap_or(false)
        || request.generate_crls.unwrap_or(false)
        || request.optimize.unwrap_or(false)
}

async fn generate_scheduled_crls(
    state: &AppState,
    validity_days: i64,
    partition_count: i64,
    actor: &str,
) -> AppResult<u64> {
    let cas = state.db.list_cas().await?;
    let active_cas = cas.into_iter().filter(|ca| ca.status == "active");
    let mut generated = 0_u64;
    let now = now_unix();
    let refresh_before_expiry = (validity_days.clamp(1, 90) * 86_400 / 2).clamp(3_600, 86_400);
    for ca in active_cas {
        let latest_revoked_at = state.db.latest_revocation_time_for_ca(&ca.id).await?;
        if partition_count <= 1 {
            if should_generate_scheduled_crl(
                state,
                &ca.id,
                -1,
                now,
                refresh_before_expiry,
                latest_revoked_at,
            )
            .await?
            {
                crl_service::generate_crl(
                    state,
                    GenerateCrlRequest {
                        ca_id: ca.id,
                        validity_days: Some(validity_days),
                        is_delta: Some(false),
                        partition_index: Some(-1),
                        partition_count: Some(1),
                    },
                    actor,
                )
                .await?;
                generated += 1;
            }
            continue;
        }
        for partition_index in 0..partition_count {
            if should_generate_scheduled_crl(
                state,
                &ca.id,
                partition_index,
                now,
                refresh_before_expiry,
                latest_revoked_at,
            )
            .await?
            {
                crl_service::generate_crl(
                    state,
                    GenerateCrlRequest {
                        ca_id: ca.id.clone(),
                        validity_days: Some(validity_days),
                        is_delta: Some(false),
                        partition_index: Some(partition_index),
                        partition_count: Some(partition_count),
                    },
                    actor,
                )
                .await?;
                generated += 1;
            }
        }
    }
    Ok(generated)
}

async fn should_generate_scheduled_crl(
    state: &AppState,
    ca_id: &str,
    partition_index: i64,
    now: i64,
    refresh_before_expiry: i64,
    latest_revoked_at: Option<i64>,
) -> AppResult<bool> {
    let Some(latest) = state
        .db
        .latest_crl_for_ca_scope(ca_id, partition_index, false)
        .await?
    else {
        return Ok(true);
    };
    if latest.next_update <= now + refresh_before_expiry {
        return Ok(true);
    }
    if let Some(latest_revoked_at) = latest_revoked_at
        && latest_revoked_at > latest.this_update
    {
        return Ok(true);
    }
    Ok(false)
}

async fn backup_sqlite(state: &AppState) -> AppResult<String> {
    let _db_path = sqlite_path_from_url(&state.settings.database_url())?;
    let backup_dir = Path::new(&state.settings.data_dir).join("backups");
    fs::create_dir_all(&backup_dir)
        .await
        .map_err(|err| AppError::Internal(format!("백업 디렉터리를 만들 수 없습니다: {err}")))?;
    let target = backup_dir.join(format!("ejbca-rs-{}-{}.sqlite", now_unix(), Uuid::new_v4()));
    let sql = format!("VACUUM main INTO {}", sqlite_string_literal(&target));
    sqlx::query(&sql).execute(state.db.pool()).await?;
    Ok(target.display().to_string())
}

fn sqlite_path_from_url(url: &str) -> AppResult<PathBuf> {
    let path = url.strip_prefix("sqlite://").ok_or_else(|| {
        AppError::BadRequest("현재 백업은 sqlite:// DB URL만 지원합니다".to_string())
    })?;
    Ok(PathBuf::from(path))
}

fn sqlite_string_literal(path: &Path) -> String {
    format!("'{}'", path.to_string_lossy().replace('\'', "''"))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use sqlx::Row;
    use tokio::sync::Semaphore;

    use super::*;
    use crate::{config::Settings, storage::Db};

    async fn test_state() -> (AppState, PathBuf) {
        let data_dir =
            std::env::temp_dir().join(format!("ejbca-rs-maintenance-test-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&data_dir).unwrap();
        let settings = Arc::new(Settings {
            config_file: None,
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            data_dir: data_dir.to_string_lossy().to_string(),
            database_url: None,
            admin_token: Some("test-admin-token".to_string()),
            public_base_url: "http://127.0.0.1:0".to_string(),
            ca_key_provider: "database".to_string(),
            ca_key_dir: None,
            max_request_bytes: 100_000,
            max_list_limit: 1000,
            cors_allowed_origins: String::new(),
            adminweb_client_cert_required: false,
            adminweb_client_cert_header: "x-admin-client-cert-pem".to_string(),
            adminweb_client_cert_proxy_secret: None,
            adminweb_client_cert_allowed_fingerprints: String::new(),
            adminweb_client_cert_allowed_subjects: String::new(),
            database_max_connections: 4,
            database_busy_timeout_seconds: 30,
            max_concurrent_issuance: 4,
            validator_webhook_default_timeout_ms: 3000,
            validator_webhook_max_timeout_ms: 30_000,
            validator_webhook_max_response_bytes: 8192,
            json_logs: false,
            log_level: "error".to_string(),
            log_output: "stdout".to_string(),
            log_dir: None,
            log_retention_days: 14,
            log_retention_files: 30,
            metrics_enabled: true,
            metrics_public: false,
            metrics_device_limit: 100,
            metrics_event_retention_days: 90,
            audit_event_retention_days: 365,
            maintenance_enabled: false,
            maintenance_interval_seconds: 3600,
            maintenance_backup: false,
            maintenance_purge_expired_certificates: false,
            maintenance_purge_expired_crls: false,
            maintenance_purge_audit_events: false,
            maintenance_optimize: false,
            maintenance_older_than_days: 30,
            maintenance_batch_size: 100,
            maintenance_generate_crls: false,
            maintenance_crl_validity_days: 7,
            maintenance_crl_partition_count: 1,
            command: None,
        });
        let db = Db::connect(
            &settings.database_url(),
            settings.database_max_connections,
            settings.database_busy_timeout_seconds,
        )
        .await
        .unwrap();
        db.migrate().await.unwrap();
        let state = AppState {
            db,
            settings: settings.clone(),
            http: reqwest::Client::new(),
            issue_limiter: Arc::new(Semaphore::new(4)),
        };
        (state, data_dir)
    }

    #[tokio::test]
    async fn backup_sqlite_creates_restorable_snapshot() {
        let (state, data_dir) = test_state().await;
        state
            .db
            .audit("test", "backup.source", "database", "success", "{}")
            .await
            .unwrap();

        let response = run_maintenance(
            &state,
            MaintenanceRequest {
                backup: Some(true),
                purge_expired_certificates: Some(false),
                purge_expired_crls: Some(false),
                purge_metric_events: Some(false),
                purge_audit_events: Some(false),
                optimize: Some(false),
                older_than_days: None,
                batch_size: None,
                generate_crls: Some(false),
                crl_validity_days: None,
                crl_partition_count: None,
            },
            "test",
        )
        .await
        .unwrap();
        let backup_path = response.backup_path.unwrap();
        assert!(Path::new(&backup_path).exists());

        let backup_db = Db::connect(&format!("sqlite://{backup_path}"), 1, 30)
            .await
            .unwrap();
        let count = sqlx::query(
            "SELECT COUNT(*) AS count FROM audit_events WHERE action = 'backup.source'",
        )
        .fetch_one(backup_db.pool())
        .await
        .unwrap()
        .try_get::<i64, _>("count")
        .unwrap();
        assert_eq!(count, 1);

        std::fs::remove_dir_all(data_dir).ok();
    }

    #[tokio::test]
    async fn run_maintenance_generates_partitioned_crls_for_active_cas() {
        let (state, data_dir) = test_state().await;
        crate::ca::service::ensure_default_ca(&state).await.unwrap();

        let response = run_maintenance(
            &state,
            MaintenanceRequest {
                backup: Some(false),
                purge_expired_certificates: Some(false),
                purge_expired_crls: Some(false),
                purge_metric_events: Some(false),
                purge_audit_events: Some(false),
                optimize: Some(false),
                older_than_days: None,
                batch_size: None,
                generate_crls: Some(true),
                crl_validity_days: Some(3),
                crl_partition_count: Some(2),
            },
            "test",
        )
        .await
        .unwrap();

        assert_eq!(response.generated_crls, 2);
        let crls = state.db.list_crls(10).await.unwrap();
        assert_eq!(crls.len(), 2);
        assert!(crls.iter().all(|crl| !crl.is_delta));
        assert!(crls.iter().any(|crl| crl.partition_index == 0));
        assert!(crls.iter().any(|crl| crl.partition_index == 1));

        let second_response = run_maintenance(
            &state,
            MaintenanceRequest {
                backup: Some(false),
                purge_expired_certificates: Some(false),
                purge_expired_crls: Some(false),
                purge_metric_events: Some(false),
                purge_audit_events: Some(false),
                optimize: Some(false),
                older_than_days: None,
                batch_size: None,
                generate_crls: Some(true),
                crl_validity_days: Some(3),
                crl_partition_count: Some(2),
            },
            "test",
        )
        .await
        .unwrap();
        assert_eq!(second_response.generated_crls, 0);
        assert_eq!(state.db.list_crls(10).await.unwrap().len(), 2);

        std::fs::remove_dir_all(data_dir).ok();
    }

    #[tokio::test]
    async fn update_config_persists_runtime_overrides() {
        let (state, data_dir) = test_state().await;

        let response = update_config(
            &state,
            UpdateMaintenanceConfigRequest {
                enabled: Some(true),
                interval_seconds: Some(120),
                backup: Some(true),
                purge_metric_events: Some(true),
                metrics_public: Some(true),
                metrics_device_limit: Some(7),
                metrics_event_retention_days: Some(12),
                audit_event_retention_days: Some(34),
                generate_crls: Some(true),
                crl_validity_days: Some(5),
                crl_partition_count: Some(3),
                log_output: Some("file".to_string()),
                ..Default::default()
            },
            "test",
        )
        .await
        .unwrap();

        assert!(response.enabled);
        assert_eq!(response.interval_seconds, 120);
        assert!(response.backup);
        assert!(response.metrics_public);
        assert_eq!(response.metrics_device_limit, 7);
        assert_eq!(response.metrics_event_retention_days, 12);
        assert_eq!(response.audit_event_retention_days, 34);
        assert!(response.generate_crls);
        assert_eq!(response.crl_validity_days, 5);
        assert_eq!(response.crl_partition_count, 3);
        assert!(
            response
                .restart_required_fields
                .contains(&"log_output".to_string())
        );

        let (metrics_enabled, metrics_public, device_limit) = metrics_config(&state).await.unwrap();
        assert!(metrics_enabled);
        assert!(metrics_public);
        assert_eq!(device_limit, 7);

        let audit_count = sqlx::query(
            "SELECT COUNT(*) AS count FROM audit_events WHERE action = 'maintenance.config.update'",
        )
        .fetch_one(state.db.pool())
        .await
        .unwrap()
        .try_get::<i64, _>("count")
        .unwrap();
        assert_eq!(audit_count, 1);

        std::fs::remove_dir_all(data_dir).ok();
    }

    #[test]
    fn sqlite_string_literal_escapes_single_quotes() {
        let literal = sqlite_string_literal(Path::new("/tmp/ejbca's backup.sqlite"));
        assert_eq!(literal, "'/tmp/ejbca''s backup.sqlite'");
    }
}
