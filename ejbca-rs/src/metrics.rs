use crate::{AppState, error::AppResult};

const ISSUE_LATENCY_BUCKETS_MS: &[i64] = &[25, 50, 100, 250, 500, 1000, 2500, 5000, 10000, 30000];

pub async fn prometheus_text(state: &AppState, device_limit: i64) -> AppResult<String> {
    let mut out = String::new();
    out.push_str("# HELP ejbca_rs_certificates_total Certificates by current lifecycle status.\n");
    out.push_str("# TYPE ejbca_rs_certificates_total gauge\n");
    for row in state.db.metric_certificate_status_counts().await? {
        out.push_str(&format!(
            "ejbca_rs_certificates_total{{status=\"{}\"}} {}\n",
            escape_label(&row.status),
            row.count
        ));
    }

    out.push_str("# HELP ejbca_rs_certificate_events_total Certificate lifecycle events by type and status.\n");
    out.push_str("# TYPE ejbca_rs_certificate_events_total counter\n");
    for row in state.db.metric_event_counts().await? {
        out.push_str(&format!(
            "ejbca_rs_certificate_events_total{{event=\"{}\",status=\"{}\"}} {}\n",
            escape_label(&row.label),
            escape_label(&row.status),
            row.count
        ));
    }

    out.push_str("# HELP ejbca_rs_issue_latency_ms Certificate issue latency in milliseconds.\n");
    out.push_str("# TYPE ejbca_rs_issue_latency_ms histogram\n");
    for row in state
        .db
        .metric_issue_latency_histograms(ISSUE_LATENCY_BUCKETS_MS)
        .await?
    {
        for bucket in row.buckets {
            out.push_str(&format!(
                "ejbca_rs_issue_latency_ms_bucket{{status=\"{}\",le=\"{}\"}} {}\n",
                escape_label(&row.status),
                bucket.le_ms,
                bucket.count
            ));
        }
        out.push_str(&format!(
            "ejbca_rs_issue_latency_ms_bucket{{status=\"{}\",le=\"+Inf\"}} {}\n",
            escape_label(&row.status),
            row.count
        ));
        out.push_str(&format!(
            "ejbca_rs_issue_latency_ms_sum{{status=\"{}\"}} {}\n",
            escape_label(&row.status),
            row.sum_ms
        ));
        out.push_str(&format!(
            "ejbca_rs_issue_latency_ms_count{{status=\"{}\"}} {}\n",
            escape_label(&row.status),
            row.count
        ));
    }

    out.push_str("# HELP ejbca_rs_issue_events_by_device_total Top device issue events. Limit is controlled by EJBCA_RS_METRICS_DEVICE_LIMIT.\n");
    out.push_str("# TYPE ejbca_rs_issue_events_by_device_total counter\n");
    for row in state.db.metric_device_issue_counts(device_limit).await? {
        out.push_str(&format!(
            "ejbca_rs_issue_events_by_device_total{{device_id=\"{}\",status=\"{}\"}} {}\n",
            escape_label(&row.device_id),
            escape_label(&row.status),
            row.count
        ));
    }

    let summary = state.db.summary().await?;
    out.push_str("# HELP ejbca_rs_ca_total Number of configured certificate authorities.\n");
    out.push_str("# TYPE ejbca_rs_ca_total gauge\n");
    out.push_str(&format!("ejbca_rs_ca_total {}\n", summary.ca_count));
    out.push_str(
        "# HELP ejbca_rs_ca_status_total Certificate authorities by administrative status.\n",
    );
    out.push_str("# TYPE ejbca_rs_ca_status_total gauge\n");
    let cas = state.db.list_cas().await?;
    for status in ["active", "disabled"] {
        let count = cas.iter().filter(|ca| ca.status == status).count();
        out.push_str(&format!(
            "ejbca_rs_ca_status_total{{status=\"{}\"}} {}\n",
            status, count
        ));
    }
    out.push_str("# HELP ejbca_rs_ca_not_after_timestamp_seconds CA certificate expiration timestamp in Unix seconds.\n");
    out.push_str("# TYPE ejbca_rs_ca_not_after_timestamp_seconds gauge\n");
    for ca in &cas {
        out.push_str(&format!(
            "ejbca_rs_ca_not_after_timestamp_seconds{{ca_id=\"{}\",ca_name=\"{}\",status=\"{}\",is_default=\"{}\"}} {}\n",
            escape_label(&ca.id),
            escape_label(&ca.name),
            escape_label(&ca.status),
            ca.is_default,
            ca.not_after
        ));
    }
    out.push_str("# HELP ejbca_rs_crl_total Number of stored CRLs.\n");
    out.push_str("# TYPE ejbca_rs_crl_total gauge\n");
    out.push_str(&format!("ejbca_rs_crl_total {}\n", summary.crl_count));
    Ok(out)
}

fn escape_label(value: &str) -> String {
    value
        .replace('\\', r"\\")
        .replace('"', r#"\""#)
        .replace('\n', r"\n")
}

#[cfg(test)]
mod tests {
    use std::{path::PathBuf, sync::Arc};

    use tokio::sync::Semaphore;
    use uuid::Uuid;

    use super::*;
    use crate::{
        config::Settings,
        storage::{CaRecord, Db, NewCertificateEvent},
    };

    async fn test_state() -> (AppState, PathBuf) {
        let data_dir =
            std::env::temp_dir().join(format!("ejbca-rs-metrics-test-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&data_dir).expect("테스트 data dir 생성 실패");
        let settings = Arc::new(Settings {
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
        (
            AppState {
                db,
                settings: settings.clone(),
                http: reqwest::Client::new(),
                issue_limiter: Arc::new(Semaphore::new(settings.max_concurrent_issuance.max(1))),
            },
            data_dir,
        )
    }

    async fn insert_issue_event(state: &AppState, status: &str, latency_ms: i64) {
        state
            .db
            .record_certificate_event(NewCertificateEvent {
                event_type: "issue".to_string(),
                status: status.to_string(),
                ca_id: None,
                certificate_id: None,
                serial_hex: None,
                device_id: Some(format!("device-{status}-{latency_ms}")),
                subject_dn: None,
                source: "test".to_string(),
                error_code: None,
                latency_ms: Some(latency_ms),
            })
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn prometheus_text_includes_issue_latency_histogram() {
        let (state, data_dir) = test_state().await;
        insert_issue_event(&state, "success", 20).await;
        insert_issue_event(&state, "success", 120).await;
        insert_issue_event(&state, "failure", 600).await;

        let text = prometheus_text(&state, state.settings.metrics_device_limit)
            .await
            .unwrap();
        assert!(text.contains("# TYPE ejbca_rs_issue_latency_ms histogram"));
        assert!(text.contains("ejbca_rs_issue_latency_ms_bucket{status=\"success\",le=\"25\"} 1"));
        assert!(text.contains("ejbca_rs_issue_latency_ms_bucket{status=\"success\",le=\"250\"} 2"));
        assert!(
            text.contains("ejbca_rs_issue_latency_ms_bucket{status=\"success\",le=\"+Inf\"} 2")
        );
        assert!(text.contains("ejbca_rs_issue_latency_ms_sum{status=\"success\"} 140"));
        assert!(text.contains("ejbca_rs_issue_latency_ms_count{status=\"success\"} 2"));
        assert!(text.contains("ejbca_rs_issue_latency_ms_bucket{status=\"failure\",le=\"500\"} 0"));
        assert!(
            text.contains("ejbca_rs_issue_latency_ms_bucket{status=\"failure\",le=\"1000\"} 1")
        );
        assert!(text.contains("ejbca_rs_issue_latency_ms_count{status=\"failure\"} 1"));

        std::fs::remove_dir_all(data_dir).ok();
    }

    #[tokio::test]
    async fn prometheus_text_includes_ca_status_and_expiration_metrics() {
        let (state, data_dir) = test_state().await;
        for (name, status, is_default, not_after) in [
            ("root-a", "active", true, 1_800_000_000),
            ("root-b", "disabled", false, 1_900_000_000),
        ] {
            state
                .db
                .insert_ca(&CaRecord {
                    id: format!("{name}-id"),
                    name: name.to_string(),
                    subject_dn: format!("CN={name},O=Test"),
                    cert_pem: format!(
                        "-----BEGIN CERTIFICATE-----\n{name}\n-----END CERTIFICATE-----"
                    ),
                    key_pem: "test-key-ref".to_string(),
                    cert_der: vec![1, 2, 3],
                    status: status.to_string(),
                    is_default,
                    created_at: 1_700_000_000,
                    not_after,
                })
                .await
                .unwrap();
        }

        let text = prometheus_text(&state, state.settings.metrics_device_limit)
            .await
            .unwrap();
        assert!(text.contains("# TYPE ejbca_rs_ca_status_total gauge"));
        assert!(text.contains("ejbca_rs_ca_status_total{status=\"active\"} 1"));
        assert!(text.contains("ejbca_rs_ca_status_total{status=\"disabled\"} 1"));
        assert!(text.contains("# TYPE ejbca_rs_ca_not_after_timestamp_seconds gauge"));
        assert!(text.contains("ca_name=\"root-a\",status=\"active\",is_default=\"true\""));
        assert!(text.contains("ca_name=\"root-b\",status=\"disabled\",is_default=\"false\""));
        assert!(text.contains(" 1800000000"));
        assert!(text.contains(" 1900000000"));

        std::fs::remove_dir_all(data_dir).ok();
    }
}
