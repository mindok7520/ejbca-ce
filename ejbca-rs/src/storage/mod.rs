use std::{str::FromStr, sync::Arc, time::Duration as StdDuration};

use futures_util::TryStreamExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{
    FromRow, Row, Sqlite, SqlitePool, Transaction,
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions},
};
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::{error::AppResult, util::now_unix};

#[derive(Clone)]
pub struct Db {
    pool: SqlitePool,
    audit_lock: Arc<Mutex<()>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct CaRecord {
    pub id: String,
    pub name: String,
    pub subject_dn: String,
    pub cert_pem: String,
    pub key_pem: String,
    pub cert_der: Vec<u8>,
    pub status: String,
    pub is_default: bool,
    pub created_at: i64,
    pub not_after: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct CertificateRecord {
    pub id: String,
    pub ca_id: String,
    pub serial_hex: String,
    pub subject_dn: String,
    pub san_json: String,
    pub cert_pem: String,
    pub cert_der: Vec<u8>,
    pub csr_pem: Option<String>,
    pub status: String,
    pub revocation_reason: Option<String>,
    pub revoked_at: Option<i64>,
    pub not_before: i64,
    pub not_after: i64,
    pub fingerprint_sha256: String,
    pub created_at: i64,
}

#[derive(Debug, Clone, Default)]
pub struct CertificateFilter {
    pub ca_id: Option<String>,
    pub status: Option<String>,
    pub serial_hex: Option<String>,
    pub subject_contains: Option<String>,
    pub expires_before: Option<i64>,
    pub expires_after: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct CrlRecord {
    pub id: String,
    pub ca_id: String,
    pub crl_number: i64,
    pub partition_index: i64,
    pub is_delta: bool,
    pub pem: String,
    pub der: Vec<u8>,
    pub this_update: i64,
    pub next_update: i64,
    pub revoked_count: i64,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct ValidatorRecord {
    pub id: String,
    pub name: String,
    pub kind: String,
    pub config_json: String,
    pub enabled: bool,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct CertificateProfileRecord {
    pub id: String,
    pub name: String,
    pub validity_days: i64,
    pub key_usages_json: String,
    pub extended_key_usages_json: String,
    pub allow_server_generated_key: bool,
    pub require_san: bool,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct EndEntityProfileRecord {
    pub id: String,
    pub name: String,
    pub subject_regex: Option<String>,
    pub allowed_dns_domains_json: String,
    pub default_certificate_profile_id: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct CmpAliasRecord {
    pub id: String,
    pub alias: String,
    pub ca_id: Option<String>,
    pub certificate_profile_id: Option<String>,
    pub end_entity_profile_id: Option<String>,
    pub enabled: bool,
    pub hmac_secret_sha256: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct AccessRoleRecord {
    pub id: String,
    pub name: String,
    pub permissions_json: String,
    pub api_token_sha256: Option<String>,
    pub certificate_issuer_dn: Option<String>,
    pub certificate_match_key: Option<String>,
    pub certificate_match_value: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct AuditEventRecord {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chain_index: Option<i64>,
    pub ts: i64,
    pub actor: String,
    pub action: String,
    pub target: String,
    pub status: String,
    pub details_json: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entry_hash: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct AuditEventFilter {
    pub actor: Option<String>,
    pub action: Option<String>,
    pub target: Option<String>,
    pub status: Option<String>,
    pub since: Option<i64>,
    pub until: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuditChainStatus {
    pub valid: bool,
    pub checked_events: u64,
    pub legacy_events: u64,
    pub broken_event_id: Option<String>,
    pub error: Option<String>,
    pub latest_hash: Option<String>,
}

#[derive(Debug, Clone, FromRow)]
struct AuditChainRow {
    id: String,
    chain_index: Option<i64>,
    ts: i64,
    actor: String,
    action: String,
    target: String,
    status: String,
    details_json: String,
    prev_hash: Option<String>,
    entry_hash: Option<String>,
}

#[derive(Debug, Clone)]
pub struct NewCertificateEvent {
    pub event_type: String,
    pub status: String,
    pub ca_id: Option<String>,
    pub certificate_id: Option<String>,
    pub serial_hex: Option<String>,
    pub device_id: Option<String>,
    pub subject_dn: Option<String>,
    pub source: String,
    pub error_code: Option<String>,
    pub latency_ms: Option<i64>,
}

#[derive(Debug, Clone, FromRow)]
pub struct MetricCount {
    pub label: String,
    pub status: String,
    pub count: i64,
}

#[derive(Debug, Clone, FromRow)]
pub struct DeviceMetricCount {
    pub device_id: String,
    pub status: String,
    pub count: i64,
}

#[derive(Debug, Clone)]
pub struct LatencyBucketCount {
    pub le_ms: i64,
    pub count: i64,
}

#[derive(Debug, Clone)]
pub struct IssueLatencyHistogram {
    pub status: String,
    pub buckets: Vec<LatencyBucketCount>,
    pub count: i64,
    pub sum_ms: i64,
}

#[derive(Debug, Clone, FromRow)]
pub struct AppConfigRecord {
    pub key: String,
    pub value: String,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct DashboardSummary {
    pub ca_count: i64,
    pub active_certificates: i64,
    pub revoked_certificates: i64,
    pub expired_certificates: i64,
    pub crl_count: i64,
    pub validator_count: i64,
    pub certificate_profile_count: i64,
    pub end_entity_profile_count: i64,
    pub cmp_alias_count: i64,
    pub access_role_count: i64,
    pub issue_success_count: i64,
    pub issue_failure_count: i64,
}

impl Db {
    pub async fn connect(
        database_url: &str,
        max_connections: u32,
        busy_timeout_seconds: u64,
    ) -> AppResult<Self> {
        let options = SqliteConnectOptions::from_str(database_url)?
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal)
            .foreign_keys(true)
            .busy_timeout(StdDuration::from_secs(busy_timeout_seconds));
        let pool = SqlitePoolOptions::new()
            .max_connections(max_connections.max(1))
            .connect_with(options)
            .await?;
        Ok(Self {
            pool,
            audit_lock: Arc::new(Mutex::new(())),
        })
    }

    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    pub async fn migrate(&self) -> AppResult<()> {
        // 스키마는 초기 버전에서 코드 내 마이그레이션으로 유지한다.
        // 운영 버전에서는 sqlx migrations 디렉터리로 이동시키면 된다.
        for statement in SCHEMA.split(';') {
            let statement = statement.trim();
            if !statement.is_empty() {
                sqlx::query(statement).execute(&self.pool).await?;
            }
        }
        self.ensure_column("audit_events", "prev_hash", "TEXT")
            .await?;
        self.ensure_column("audit_events", "entry_hash", "TEXT")
            .await?;
        self.ensure_column("audit_events", "chain_index", "INTEGER")
            .await?;
        self.ensure_column("cas", "status", "TEXT NOT NULL DEFAULT 'active'")
            .await?;
        self.ensure_column("cas", "is_default", "INTEGER NOT NULL DEFAULT 0")
            .await?;
        self.ensure_column("access_roles", "certificate_issuer_dn", "TEXT")
            .await?;
        self.ensure_column("access_roles", "certificate_match_key", "TEXT")
            .await?;
        self.ensure_column("access_roles", "certificate_match_value", "TEXT")
            .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS audit_hash_idx ON audit_events(entry_hash)")
            .execute(&self.pool)
            .await?;
        sqlx::query(
            "CREATE UNIQUE INDEX IF NOT EXISTS audit_chain_index_uidx ON audit_events(chain_index) WHERE chain_index IS NOT NULL",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS audit_chain_scan_idx ON audit_events(chain_index, ts, id) WHERE chain_index IS NOT NULL",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS audit_legacy_ts_idx ON audit_events(ts, id) WHERE chain_index IS NULL",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS cas_default_status_idx ON cas(is_default, status, created_at DESC)",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS access_roles_cert_member_idx ON access_roles(certificate_issuer_dn, certificate_match_key, certificate_match_value) WHERE certificate_match_key IS NOT NULL",
        )
        .execute(&self.pool)
        .await?;
        self.ensure_ca_default().await?;
        Ok(())
    }

    async fn ensure_column(&self, table: &str, column: &str, definition: &str) -> AppResult<()> {
        let pragma = format!("PRAGMA table_info({table})");
        let rows = sqlx::query(&pragma).fetch_all(&self.pool).await?;
        let exists = rows
            .iter()
            .filter_map(|row| row.try_get::<String, _>("name").ok())
            .any(|name| name.eq_ignore_ascii_case(column));
        if !exists {
            let sql = format!("ALTER TABLE {table} ADD COLUMN {column} {definition}");
            sqlx::query(&sql).execute(&self.pool).await?;
        }
        Ok(())
    }

    async fn ensure_ca_default(&self) -> AppResult<()> {
        let total = scalar_i64(&self.pool, "SELECT COUNT(*) FROM cas").await?;
        if total == 0 {
            return Ok(());
        }
        let has_default =
            scalar_i64(&self.pool, "SELECT COUNT(*) FROM cas WHERE is_default = 1").await?;
        if has_default > 0 {
            return Ok(());
        }
        let default_id = sqlx::query(
            r#"
            SELECT id
            FROM cas
            ORDER BY status = 'active' DESC, created_at DESC
            LIMIT 1
            "#,
        )
        .fetch_one(&self.pool)
        .await?
        .try_get::<String, _>("id")?;
        sqlx::query("UPDATE cas SET is_default = CASE WHEN id = ? THEN 1 ELSE 0 END")
            .bind(default_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn ca_count(&self) -> AppResult<i64> {
        scalar_i64(&self.pool, "SELECT COUNT(*) FROM cas").await
    }

    pub async fn insert_ca(&self, ca: &CaRecord) -> AppResult<()> {
        sqlx::query(
            r#"
            INSERT INTO cas
                (id, name, subject_dn, cert_pem, key_pem, cert_der, status, is_default, created_at, not_after)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&ca.id)
        .bind(&ca.name)
        .bind(&ca.subject_dn)
        .bind(&ca.cert_pem)
        .bind(&ca.key_pem)
        .bind(&ca.cert_der)
        .bind(&ca.status)
        .bind(ca.is_default)
        .bind(ca.created_at)
        .bind(ca.not_after)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn list_cas(&self) -> AppResult<Vec<CaRecord>> {
        Ok(sqlx::query_as::<_, CaRecord>(
            "SELECT * FROM cas ORDER BY is_default DESC, status = 'active' DESC, created_at DESC",
        )
        .fetch_all(&self.pool)
        .await?)
    }

    pub async fn get_ca(&self, ca_id: &str) -> AppResult<Option<CaRecord>> {
        Ok(
            sqlx::query_as::<_, CaRecord>("SELECT * FROM cas WHERE id = ?")
                .bind(ca_id)
                .fetch_optional(&self.pool)
                .await?,
        )
    }

    pub async fn update_ca(&self, ca: &CaRecord) -> AppResult<u64> {
        let mut tx = self.pool.begin().await?;
        if ca.is_default {
            sqlx::query("UPDATE cas SET is_default = 0")
                .execute(&mut *tx)
                .await?;
        }
        let result = sqlx::query(
            r#"
            UPDATE cas
            SET name = ?, status = ?, is_default = ?
            WHERE id = ?
            "#,
        )
        .bind(&ca.name)
        .bind(&ca.status)
        .bind(ca.is_default)
        .bind(&ca.id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(result.rows_affected())
    }

    pub async fn insert_certificate(&self, cert: &CertificateRecord) -> AppResult<()> {
        sqlx::query(
            r#"
            INSERT INTO certificates
                (id, ca_id, serial_hex, subject_dn, san_json, cert_pem, cert_der, csr_pem,
                 status, revocation_reason, revoked_at, not_before, not_after, fingerprint_sha256, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&cert.id)
        .bind(&cert.ca_id)
        .bind(&cert.serial_hex)
        .bind(&cert.subject_dn)
        .bind(&cert.san_json)
        .bind(&cert.cert_pem)
        .bind(&cert.cert_der)
        .bind(&cert.csr_pem)
        .bind(&cert.status)
        .bind(&cert.revocation_reason)
        .bind(cert.revoked_at)
        .bind(cert.not_before)
        .bind(cert.not_after)
        .bind(&cert.fingerprint_sha256)
        .bind(cert.created_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn insert_certificate_with_audit(
        &self,
        cert: &CertificateRecord,
        actor: &str,
        action: &str,
        target: &str,
        status: &str,
        details_json: &str,
    ) -> AppResult<()> {
        let _guard = self.audit_lock.lock().await;
        let mut tx = self.pool.begin().await?;
        sqlx::query(
            r#"
            INSERT INTO certificates
                (id, ca_id, serial_hex, subject_dn, san_json, cert_pem, cert_der, csr_pem,
                 status, revocation_reason, revoked_at, not_before, not_after, fingerprint_sha256, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&cert.id)
        .bind(&cert.ca_id)
        .bind(&cert.serial_hex)
        .bind(&cert.subject_dn)
        .bind(&cert.san_json)
        .bind(&cert.cert_pem)
        .bind(&cert.cert_der)
        .bind(&cert.csr_pem)
        .bind(&cert.status)
        .bind(&cert.revocation_reason)
        .bind(cert.revoked_at)
        .bind(cert.not_before)
        .bind(cert.not_after)
        .bind(&cert.fingerprint_sha256)
        .bind(cert.created_at)
        .execute(&mut *tx)
        .await?;
        insert_audit_in_tx(&mut tx, actor, action, target, status, details_json).await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn list_certificates(
        &self,
        filter: &CertificateFilter,
        limit: i64,
    ) -> AppResult<Vec<CertificateRecord>> {
        Ok(sqlx::query_as::<_, CertificateRecord>(
            r#"
            SELECT *
            FROM certificates
            WHERE (? IS NULL OR ca_id = ?)
              AND (? IS NULL OR status = ?)
              AND (? IS NULL OR serial_hex = ?)
              AND (? IS NULL OR instr(lower(subject_dn), lower(?)) > 0)
              AND (? IS NULL OR not_after <= ?)
              AND (? IS NULL OR not_after >= ?)
            ORDER BY created_at DESC
            LIMIT ?
            "#,
        )
        .bind(filter.ca_id.as_deref())
        .bind(filter.ca_id.as_deref())
        .bind(filter.status.as_deref())
        .bind(filter.status.as_deref())
        .bind(filter.serial_hex.as_deref())
        .bind(filter.serial_hex.as_deref())
        .bind(filter.subject_contains.as_deref())
        .bind(filter.subject_contains.as_deref())
        .bind(filter.expires_before)
        .bind(filter.expires_before)
        .bind(filter.expires_after)
        .bind(filter.expires_after)
        .bind(limit.clamp(1, 10_000))
        .fetch_all(&self.pool)
        .await?)
    }

    pub async fn get_certificate(&self, cert_id: &str) -> AppResult<Option<CertificateRecord>> {
        Ok(
            sqlx::query_as::<_, CertificateRecord>("SELECT * FROM certificates WHERE id = ?")
                .bind(cert_id)
                .fetch_optional(&self.pool)
                .await?,
        )
    }

    pub async fn get_certificate_by_serial(
        &self,
        ca_id: &str,
        serial_hex: &str,
    ) -> AppResult<Option<CertificateRecord>> {
        Ok(sqlx::query_as::<_, CertificateRecord>(
            "SELECT * FROM certificates WHERE ca_id = ? AND serial_hex = ?",
        )
        .bind(ca_id)
        .bind(serial_hex)
        .fetch_optional(&self.pool)
        .await?)
    }

    pub async fn list_certificates_by_serial(
        &self,
        serial_hex: &str,
    ) -> AppResult<Vec<CertificateRecord>> {
        Ok(sqlx::query_as::<_, CertificateRecord>(
            "SELECT * FROM certificates WHERE serial_hex = ?",
        )
        .bind(serial_hex)
        .fetch_all(&self.pool)
        .await?)
    }

    pub async fn revoke_certificate(&self, cert_id: &str, reason: &str) -> AppResult<u64> {
        let result = sqlx::query(
            r#"
            UPDATE certificates
            SET status = 'revoked', revocation_reason = ?, revoked_at = ?
            WHERE id = ? AND status <> 'revoked'
            "#,
        )
        .bind(reason)
        .bind(now_unix())
        .bind(cert_id)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected())
    }

    pub async fn revoke_certificate_with_audit(
        &self,
        cert_id: &str,
        reason: &str,
        actor: &str,
        details_json: &str,
    ) -> AppResult<u64> {
        let _guard = self.audit_lock.lock().await;
        let mut tx = self.pool.begin().await?;
        let result = sqlx::query(
            r#"
            UPDATE certificates
            SET status = 'revoked', revocation_reason = ?, revoked_at = ?
            WHERE id = ? AND status <> 'revoked'
            "#,
        )
        .bind(reason)
        .bind(now_unix())
        .bind(cert_id)
        .execute(&mut *tx)
        .await?;
        let changed = result.rows_affected();
        if changed > 0 {
            insert_audit_in_tx(
                &mut tx,
                actor,
                "certificate.revoke",
                cert_id,
                "success",
                details_json,
            )
            .await?;
        }
        tx.commit().await?;
        Ok(changed)
    }

    pub async fn revoked_certificates_for_ca(
        &self,
        ca_id: &str,
    ) -> AppResult<Vec<CertificateRecord>> {
        Ok(sqlx::query_as::<_, CertificateRecord>(
            "SELECT * FROM certificates WHERE ca_id = ? AND status = 'revoked' ORDER BY revoked_at ASC",
        )
        .bind(ca_id)
        .fetch_all(&self.pool)
        .await?)
    }

    pub async fn latest_revocation_time_for_ca(&self, ca_id: &str) -> AppResult<Option<i64>> {
        let row = sqlx::query(
            r#"
            SELECT MAX(revoked_at) AS latest_revoked_at
            FROM certificates
            WHERE ca_id = ? AND status = 'revoked'
            "#,
        )
        .bind(ca_id)
        .fetch_one(&self.pool)
        .await?;
        Ok(row.try_get::<Option<i64>, _>("latest_revoked_at")?)
    }

    pub async fn insert_crl(&self, crl: &CrlRecord) -> AppResult<()> {
        sqlx::query(
            r#"
            INSERT INTO crls
                (id, ca_id, crl_number, partition_index, is_delta, pem, der, this_update,
                 next_update, revoked_count, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&crl.id)
        .bind(&crl.ca_id)
        .bind(crl.crl_number)
        .bind(crl.partition_index)
        .bind(crl.is_delta)
        .bind(&crl.pem)
        .bind(&crl.der)
        .bind(crl.this_update)
        .bind(crl.next_update)
        .bind(crl.revoked_count)
        .bind(crl.created_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn next_crl_number(&self, ca_id: &str) -> AppResult<i64> {
        let row = sqlx::query("SELECT COALESCE(MAX(crl_number), 0) + 1 FROM crls WHERE ca_id = ?")
            .bind(ca_id)
            .fetch_one(&self.pool)
            .await?;
        Ok(row.try_get::<i64, _>(0)?)
    }

    pub async fn list_crls(&self, limit: i64) -> AppResult<Vec<CrlRecord>> {
        Ok(
            sqlx::query_as::<_, CrlRecord>("SELECT * FROM crls ORDER BY created_at DESC LIMIT ?")
                .bind(limit)
                .fetch_all(&self.pool)
                .await?,
        )
    }

    pub async fn latest_crl_for_ca(&self, ca_id: &str) -> AppResult<Option<CrlRecord>> {
        self.latest_crl_for_ca_scope(ca_id, -1, false).await
    }

    pub async fn latest_crl_for_ca_scope(
        &self,
        ca_id: &str,
        partition_index: i64,
        is_delta: bool,
    ) -> AppResult<Option<CrlRecord>> {
        Ok(sqlx::query_as::<_, CrlRecord>(
            r#"
            SELECT * FROM crls
            WHERE ca_id = ? AND partition_index = ? AND is_delta = ?
            ORDER BY crl_number DESC
            LIMIT 1
            "#,
        )
        .bind(ca_id)
        .bind(partition_index)
        .bind(is_delta)
        .fetch_optional(&self.pool)
        .await?)
    }

    pub async fn get_crl(&self, id: &str) -> AppResult<Option<CrlRecord>> {
        Ok(
            sqlx::query_as::<_, CrlRecord>("SELECT * FROM crls WHERE id = ?")
                .bind(id)
                .fetch_optional(&self.pool)
                .await?,
        )
    }

    pub async fn insert_validator(&self, validator: &ValidatorRecord) -> AppResult<()> {
        sqlx::query(
            r#"
            INSERT INTO validators (id, name, kind, config_json, enabled, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&validator.id)
        .bind(&validator.name)
        .bind(&validator.kind)
        .bind(&validator.config_json)
        .bind(validator.enabled)
        .bind(validator.created_at)
        .bind(validator.updated_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn list_validators(&self, enabled_only: bool) -> AppResult<Vec<ValidatorRecord>> {
        let sql = if enabled_only {
            "SELECT * FROM validators WHERE enabled = 1 ORDER BY created_at DESC"
        } else {
            "SELECT * FROM validators ORDER BY created_at DESC"
        };
        Ok(sqlx::query_as::<_, ValidatorRecord>(sql)
            .fetch_all(&self.pool)
            .await?)
    }

    pub async fn get_validator(&self, id: &str) -> AppResult<Option<ValidatorRecord>> {
        Ok(
            sqlx::query_as::<_, ValidatorRecord>("SELECT * FROM validators WHERE id = ?")
                .bind(id)
                .fetch_optional(&self.pool)
                .await?,
        )
    }

    pub async fn update_validator(&self, validator: &ValidatorRecord) -> AppResult<u64> {
        Ok(sqlx::query(
            r#"
            UPDATE validators
            SET name = ?,
                kind = ?,
                config_json = ?,
                enabled = ?,
                updated_at = ?
            WHERE id = ?
            "#,
        )
        .bind(&validator.name)
        .bind(&validator.kind)
        .bind(&validator.config_json)
        .bind(validator.enabled)
        .bind(validator.updated_at)
        .bind(&validator.id)
        .execute(&self.pool)
        .await?
        .rows_affected())
    }

    pub async fn delete_validator(&self, id: &str) -> AppResult<u64> {
        Ok(sqlx::query("DELETE FROM validators WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await?
            .rows_affected())
    }

    pub async fn audit(
        &self,
        actor: &str,
        action: &str,
        target: &str,
        status: &str,
        details_json: &str,
    ) -> AppResult<()> {
        let _guard = self.audit_lock.lock().await;
        let id = Uuid::new_v4().to_string();
        let ts = now_unix();
        let chain_index = self.next_audit_chain_index().await?;
        let prev_hash = self.latest_audit_hash().await?;
        let entry_hash = audit_entry_hash(
            chain_index,
            &id,
            ts,
            actor,
            action,
            target,
            status,
            details_json,
            prev_hash.as_deref(),
        );
        sqlx::query(
            r#"
            INSERT INTO audit_events
                (id, chain_index, ts, actor, action, target, status, details_json, prev_hash, entry_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(id)
        .bind(chain_index)
        .bind(ts)
        .bind(actor)
        .bind(action)
        .bind(target)
        .bind(status)
        .bind(details_json)
        .bind(prev_hash)
        .bind(entry_hash)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn next_audit_chain_index(&self) -> AppResult<i64> {
        let row = sqlx::query(
            "SELECT COALESCE(MAX(chain_index), 0) + 1 FROM audit_events WHERE chain_index IS NOT NULL",
        )
        .fetch_one(&self.pool)
        .await?;
        Ok(row.try_get::<i64, _>(0)?)
    }

    async fn latest_audit_hash(&self) -> AppResult<Option<String>> {
        Ok(sqlx::query("SELECT entry_hash FROM audit_events WHERE chain_index IS NOT NULL AND entry_hash IS NOT NULL ORDER BY chain_index DESC LIMIT 1")
            .fetch_optional(&self.pool)
            .await?
            .and_then(|row| row.try_get::<String, _>("entry_hash").ok()))
    }

    pub async fn list_audit_events(
        &self,
        filter: &AuditEventFilter,
        limit: i64,
    ) -> AppResult<Vec<AuditEventRecord>> {
        Ok(sqlx::query_as::<_, AuditEventRecord>(
            r#"
            SELECT *
            FROM audit_events
            WHERE (? IS NULL OR actor = ?)
              AND (? IS NULL OR action = ?)
              AND (? IS NULL OR target = ?)
              AND (? IS NULL OR status = ?)
              AND (? IS NULL OR ts >= ?)
              AND (? IS NULL OR ts <= ?)
            ORDER BY ts DESC
            LIMIT ?
            "#,
        )
        .bind(filter.actor.as_deref())
        .bind(filter.actor.as_deref())
        .bind(filter.action.as_deref())
        .bind(filter.action.as_deref())
        .bind(filter.target.as_deref())
        .bind(filter.target.as_deref())
        .bind(filter.status.as_deref())
        .bind(filter.status.as_deref())
        .bind(filter.since)
        .bind(filter.since)
        .bind(filter.until)
        .bind(filter.until)
        .bind(limit.clamp(1, 10_000))
        .fetch_all(&self.pool)
        .await?)
    }

    pub async fn verify_audit_chain(&self) -> AppResult<AuditChainStatus> {
        let first_chain_ts = sqlx::query(
            "SELECT MIN(ts) AS first_chain_ts FROM audit_events WHERE chain_index IS NOT NULL",
        )
        .fetch_one(&self.pool)
        .await?
        .try_get::<Option<i64>, _>("first_chain_ts")?;
        if let Some(first_chain_ts) = first_chain_ts {
            if let Some(row) = sqlx::query(
                r#"
                SELECT id FROM audit_events
                WHERE chain_index IS NULL AND ts > ?
                ORDER BY ts ASC, id ASC
                LIMIT 1
                "#,
            )
            .bind(first_chain_ts)
            .fetch_optional(&self.pool)
            .await?
            {
                return Ok(AuditChainStatus {
                    valid: false,
                    checked_events: 0,
                    legacy_events: 0,
                    broken_event_id: row.try_get::<String, _>("id").ok(),
                    error: Some(
                        "hash chain 시작 이후 보호되지 않은 audit row가 있습니다".to_string(),
                    ),
                    latest_hash: None,
                });
            }
        }

        let mut rows = sqlx::query_as::<_, AuditChainRow>(
            r#"
            SELECT id, chain_index, ts, actor, action, target, status, details_json, prev_hash, entry_hash
            FROM audit_events
            ORDER BY
                CASE WHEN chain_index IS NULL THEN 0 ELSE 1 END,
                chain_index ASC,
                ts ASC,
                id ASC
            "#,
        )
        .fetch(&self.pool);

        let mut expected_prev: Option<String> = None;
        let mut checked_events = 0;
        let mut legacy_events = 0;

        while let Some(row) = rows.try_next().await? {
            match (row.chain_index, row.entry_hash.as_deref()) {
                (Some(chain_index), Some(entry_hash)) => {
                    if let Some(expected) = expected_prev.as_deref()
                        && row.prev_hash.as_deref() != Some(expected)
                    {
                        return Ok(AuditChainStatus {
                            valid: false,
                            checked_events,
                            legacy_events,
                            broken_event_id: Some(row.id),
                            error: Some(
                                "prev_hash가 이전 entry_hash와 일치하지 않습니다".to_string(),
                            ),
                            latest_hash: expected_prev,
                        });
                    }
                    let computed = audit_entry_hash(
                        chain_index,
                        &row.id,
                        row.ts,
                        &row.actor,
                        &row.action,
                        &row.target,
                        &row.status,
                        &row.details_json,
                        row.prev_hash.as_deref(),
                    );
                    if computed != entry_hash {
                        return Ok(AuditChainStatus {
                            valid: false,
                            checked_events,
                            legacy_events,
                            broken_event_id: Some(row.id),
                            error: Some("entry_hash가 row 내용과 일치하지 않습니다".to_string()),
                            latest_hash: expected_prev,
                        });
                    }
                    checked_events += 1;
                    expected_prev = Some(entry_hash.to_string());
                }
                (Some(_), None) => {
                    return Ok(AuditChainStatus {
                        valid: false,
                        checked_events,
                        legacy_events,
                        broken_event_id: Some(row.id),
                        error: Some("chain_index는 있지만 entry_hash가 없습니다".to_string()),
                        latest_hash: expected_prev,
                    });
                }
                (None, _) => {
                    legacy_events += 1;
                }
            }
        }

        Ok(AuditChainStatus {
            valid: true,
            checked_events,
            legacy_events,
            broken_event_id: None,
            error: None,
            latest_hash: expected_prev,
        })
    }

    pub async fn summary(&self) -> AppResult<DashboardSummary> {
        Ok(DashboardSummary {
            ca_count: scalar_i64(&self.pool, "SELECT COUNT(*) FROM cas").await?,
            active_certificates: scalar_i64(
                &self.pool,
                "SELECT COUNT(*) FROM certificates WHERE status = 'active'",
            )
            .await?,
            revoked_certificates: scalar_i64(
                &self.pool,
                "SELECT COUNT(*) FROM certificates WHERE status = 'revoked'",
            )
            .await?,
            expired_certificates: scalar_i64(
                &self.pool,
                "SELECT COUNT(*) FROM certificates WHERE not_after < strftime('%s','now')",
            )
            .await?,
            crl_count: scalar_i64(&self.pool, "SELECT COUNT(*) FROM crls").await?,
            validator_count: scalar_i64(&self.pool, "SELECT COUNT(*) FROM validators").await?,
            certificate_profile_count: scalar_i64(
                &self.pool,
                "SELECT COUNT(*) FROM certificate_profiles",
            )
            .await?,
            end_entity_profile_count: scalar_i64(
                &self.pool,
                "SELECT COUNT(*) FROM end_entity_profiles",
            )
            .await?,
            cmp_alias_count: scalar_i64(&self.pool, "SELECT COUNT(*) FROM cmp_aliases").await?,
            access_role_count: scalar_i64(&self.pool, "SELECT COUNT(*) FROM access_roles").await?,
            issue_success_count: scalar_i64(
                &self.pool,
                "SELECT COUNT(*) FROM certificate_events WHERE event_type = 'issue' AND status = 'success'",
            )
            .await?,
            issue_failure_count: scalar_i64(
                &self.pool,
                "SELECT COUNT(*) FROM certificate_events WHERE event_type = 'issue' AND status = 'failure'",
            )
            .await?,
        })
    }

    pub async fn list_app_config(&self) -> AppResult<Vec<AppConfigRecord>> {
        Ok(sqlx::query_as::<_, AppConfigRecord>(
            "SELECT key, value, updated_at FROM app_config ORDER BY key",
        )
        .fetch_all(&self.pool)
        .await?)
    }

    pub async fn upsert_app_config(&self, key: &str, value: &str) -> AppResult<()> {
        sqlx::query(
            r#"
            INSERT INTO app_config (key, value, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET
                value = excluded.value,
                updated_at = excluded.updated_at
            "#,
        )
        .bind(key)
        .bind(value)
        .bind(now_unix())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn record_certificate_event(&self, event: NewCertificateEvent) -> AppResult<()> {
        sqlx::query(
            r#"
            INSERT INTO certificate_events
                (id, ts, event_type, status, ca_id, certificate_id, serial_hex, device_id,
                 subject_dn, source, error_code, latency_ms)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(Uuid::new_v4().to_string())
        .bind(now_unix())
        .bind(event.event_type)
        .bind(event.status)
        .bind(event.ca_id)
        .bind(event.certificate_id)
        .bind(event.serial_hex)
        .bind(event.device_id)
        .bind(event.subject_dn)
        .bind(event.source)
        .bind(event.error_code)
        .bind(event.latency_ms)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn metric_event_counts(&self) -> AppResult<Vec<MetricCount>> {
        Ok(sqlx::query_as::<_, MetricCount>(
            r#"
            SELECT event_type AS label, status, COUNT(*) AS count
            FROM certificate_events
            GROUP BY event_type, status
            "#,
        )
        .fetch_all(&self.pool)
        .await?)
    }

    pub async fn metric_certificate_status_counts(&self) -> AppResult<Vec<MetricCount>> {
        Ok(sqlx::query_as::<_, MetricCount>(
            r#"
            SELECT 'certificate' AS label, status, COUNT(*) AS count
            FROM certificates
            GROUP BY status
            "#,
        )
        .fetch_all(&self.pool)
        .await?)
    }

    pub async fn metric_device_issue_counts(
        &self,
        limit: i64,
    ) -> AppResult<Vec<DeviceMetricCount>> {
        Ok(sqlx::query_as::<_, DeviceMetricCount>(
            r#"
            SELECT device_id, status, COUNT(*) AS count
            FROM certificate_events
            WHERE event_type = 'issue' AND device_id IS NOT NULL
            GROUP BY device_id, status
            ORDER BY count DESC
            LIMIT ?
            "#,
        )
        .bind(limit.clamp(1, 10_000))
        .fetch_all(&self.pool)
        .await?)
    }

    pub async fn metric_issue_latency_histograms(
        &self,
        buckets_ms: &[i64],
    ) -> AppResult<Vec<IssueLatencyHistogram>> {
        let statuses = sqlx::query(
            r#"
            SELECT DISTINCT status
            FROM certificate_events
            WHERE event_type = 'issue' AND latency_ms IS NOT NULL
            ORDER BY status
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        let mut histograms = Vec::with_capacity(statuses.len());
        for status_row in statuses {
            let status: String = status_row.try_get("status")?;
            let totals = sqlx::query(
                r#"
                SELECT COUNT(*) AS count, COALESCE(SUM(latency_ms), 0) AS sum_ms
                FROM certificate_events
                WHERE event_type = 'issue' AND status = ? AND latency_ms IS NOT NULL
                "#,
            )
            .bind(&status)
            .fetch_one(&self.pool)
            .await?;
            let count: i64 = totals.try_get("count")?;
            let sum_ms: i64 = totals.try_get("sum_ms")?;
            let mut buckets = Vec::with_capacity(buckets_ms.len());
            for bucket in buckets_ms.iter().copied() {
                let bucket_count = scalar_i64_with_bind(
                    &self.pool,
                    r#"
                    SELECT COUNT(*)
                    FROM certificate_events
                    WHERE event_type = 'issue'
                      AND status = ?
                      AND latency_ms IS NOT NULL
                      AND latency_ms <= ?
                    "#,
                    &status,
                    bucket,
                )
                .await?;
                buckets.push(LatencyBucketCount {
                    le_ms: bucket,
                    count: bucket_count,
                });
            }
            histograms.push(IssueLatencyHistogram {
                status,
                buckets,
                count,
                sum_ms,
            });
        }
        Ok(histograms)
    }

    pub async fn certificate_profile_count(&self) -> AppResult<i64> {
        scalar_i64(&self.pool, "SELECT COUNT(*) FROM certificate_profiles").await
    }

    pub async fn insert_certificate_profile(
        &self,
        profile: &CertificateProfileRecord,
    ) -> AppResult<()> {
        sqlx::query(
            r#"
            INSERT INTO certificate_profiles
                (id, name, validity_days, key_usages_json, extended_key_usages_json,
                 allow_server_generated_key, require_san, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&profile.id)
        .bind(&profile.name)
        .bind(profile.validity_days)
        .bind(&profile.key_usages_json)
        .bind(&profile.extended_key_usages_json)
        .bind(profile.allow_server_generated_key)
        .bind(profile.require_san)
        .bind(profile.created_at)
        .bind(profile.updated_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn list_certificate_profiles(&self) -> AppResult<Vec<CertificateProfileRecord>> {
        Ok(sqlx::query_as::<_, CertificateProfileRecord>(
            "SELECT * FROM certificate_profiles ORDER BY created_at DESC",
        )
        .fetch_all(&self.pool)
        .await?)
    }

    pub async fn get_certificate_profile(
        &self,
        id: &str,
    ) -> AppResult<Option<CertificateProfileRecord>> {
        Ok(sqlx::query_as::<_, CertificateProfileRecord>(
            "SELECT * FROM certificate_profiles WHERE id = ?",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?)
    }

    pub async fn update_certificate_profile(
        &self,
        profile: &CertificateProfileRecord,
    ) -> AppResult<u64> {
        Ok(sqlx::query(
            r#"
            UPDATE certificate_profiles
            SET name = ?,
                validity_days = ?,
                key_usages_json = ?,
                extended_key_usages_json = ?,
                allow_server_generated_key = ?,
                require_san = ?,
                updated_at = ?
            WHERE id = ?
            "#,
        )
        .bind(&profile.name)
        .bind(profile.validity_days)
        .bind(&profile.key_usages_json)
        .bind(&profile.extended_key_usages_json)
        .bind(profile.allow_server_generated_key)
        .bind(profile.require_san)
        .bind(profile.updated_at)
        .bind(&profile.id)
        .execute(&self.pool)
        .await?
        .rows_affected())
    }

    pub async fn delete_certificate_profile(&self, id: &str) -> AppResult<u64> {
        Ok(sqlx::query("DELETE FROM certificate_profiles WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await?
            .rows_affected())
    }

    pub async fn end_entity_profile_count(&self) -> AppResult<i64> {
        scalar_i64(&self.pool, "SELECT COUNT(*) FROM end_entity_profiles").await
    }

    pub async fn insert_end_entity_profile(
        &self,
        profile: &EndEntityProfileRecord,
    ) -> AppResult<()> {
        sqlx::query(
            r#"
            INSERT INTO end_entity_profiles
                (id, name, subject_regex, allowed_dns_domains_json,
                 default_certificate_profile_id, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&profile.id)
        .bind(&profile.name)
        .bind(&profile.subject_regex)
        .bind(&profile.allowed_dns_domains_json)
        .bind(&profile.default_certificate_profile_id)
        .bind(profile.created_at)
        .bind(profile.updated_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn list_end_entity_profiles(&self) -> AppResult<Vec<EndEntityProfileRecord>> {
        Ok(sqlx::query_as::<_, EndEntityProfileRecord>(
            "SELECT * FROM end_entity_profiles ORDER BY created_at DESC",
        )
        .fetch_all(&self.pool)
        .await?)
    }

    pub async fn get_end_entity_profile(
        &self,
        id: &str,
    ) -> AppResult<Option<EndEntityProfileRecord>> {
        Ok(sqlx::query_as::<_, EndEntityProfileRecord>(
            "SELECT * FROM end_entity_profiles WHERE id = ?",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?)
    }

    pub async fn update_end_entity_profile(
        &self,
        profile: &EndEntityProfileRecord,
    ) -> AppResult<u64> {
        Ok(sqlx::query(
            r#"
            UPDATE end_entity_profiles
            SET name = ?,
                subject_regex = ?,
                allowed_dns_domains_json = ?,
                default_certificate_profile_id = ?,
                updated_at = ?
            WHERE id = ?
            "#,
        )
        .bind(&profile.name)
        .bind(&profile.subject_regex)
        .bind(&profile.allowed_dns_domains_json)
        .bind(&profile.default_certificate_profile_id)
        .bind(profile.updated_at)
        .bind(&profile.id)
        .execute(&self.pool)
        .await?
        .rows_affected())
    }

    pub async fn delete_end_entity_profile(&self, id: &str) -> AppResult<u64> {
        Ok(sqlx::query("DELETE FROM end_entity_profiles WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await?
            .rows_affected())
    }

    pub async fn cmp_alias_count(&self) -> AppResult<i64> {
        scalar_i64(&self.pool, "SELECT COUNT(*) FROM cmp_aliases").await
    }

    pub async fn insert_cmp_alias(&self, alias: &CmpAliasRecord) -> AppResult<()> {
        sqlx::query(
            r#"
            INSERT INTO cmp_aliases
                (id, alias, ca_id, certificate_profile_id, end_entity_profile_id,
                 enabled, hmac_secret_sha256, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&alias.id)
        .bind(&alias.alias)
        .bind(&alias.ca_id)
        .bind(&alias.certificate_profile_id)
        .bind(&alias.end_entity_profile_id)
        .bind(alias.enabled)
        .bind(&alias.hmac_secret_sha256)
        .bind(alias.created_at)
        .bind(alias.updated_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn list_cmp_aliases(&self) -> AppResult<Vec<CmpAliasRecord>> {
        Ok(sqlx::query_as::<_, CmpAliasRecord>(
            "SELECT * FROM cmp_aliases ORDER BY created_at DESC",
        )
        .fetch_all(&self.pool)
        .await?)
    }

    pub async fn get_cmp_alias_by_alias(&self, alias: &str) -> AppResult<Option<CmpAliasRecord>> {
        Ok(
            sqlx::query_as::<_, CmpAliasRecord>("SELECT * FROM cmp_aliases WHERE alias = ?")
                .bind(alias)
                .fetch_optional(&self.pool)
                .await?,
        )
    }

    pub async fn get_cmp_alias(&self, id: &str) -> AppResult<Option<CmpAliasRecord>> {
        Ok(
            sqlx::query_as::<_, CmpAliasRecord>("SELECT * FROM cmp_aliases WHERE id = ?")
                .bind(id)
                .fetch_optional(&self.pool)
                .await?,
        )
    }

    pub async fn delete_cmp_alias(&self, id: &str) -> AppResult<u64> {
        Ok(sqlx::query("DELETE FROM cmp_aliases WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await?
            .rows_affected())
    }

    pub async fn update_cmp_alias(&self, alias: &CmpAliasRecord) -> AppResult<u64> {
        Ok(sqlx::query(
            r#"
            UPDATE cmp_aliases
            SET alias = ?,
                ca_id = ?,
                certificate_profile_id = ?,
                end_entity_profile_id = ?,
                enabled = ?,
                hmac_secret_sha256 = ?,
                updated_at = ?
            WHERE id = ?
            "#,
        )
        .bind(&alias.alias)
        .bind(&alias.ca_id)
        .bind(&alias.certificate_profile_id)
        .bind(&alias.end_entity_profile_id)
        .bind(alias.enabled)
        .bind(&alias.hmac_secret_sha256)
        .bind(alias.updated_at)
        .bind(&alias.id)
        .execute(&self.pool)
        .await?
        .rows_affected())
    }

    pub async fn access_role_count(&self) -> AppResult<i64> {
        scalar_i64(&self.pool, "SELECT COUNT(*) FROM access_roles").await
    }

    pub async fn insert_access_role(&self, role: &AccessRoleRecord) -> AppResult<()> {
        sqlx::query(
            r#"
            INSERT INTO access_roles
                (id, name, permissions_json, api_token_sha256, certificate_issuer_dn,
                 certificate_match_key, certificate_match_value, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&role.id)
        .bind(&role.name)
        .bind(&role.permissions_json)
        .bind(&role.api_token_sha256)
        .bind(&role.certificate_issuer_dn)
        .bind(&role.certificate_match_key)
        .bind(&role.certificate_match_value)
        .bind(role.created_at)
        .bind(role.updated_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn list_access_roles(&self) -> AppResult<Vec<AccessRoleRecord>> {
        Ok(sqlx::query_as::<_, AccessRoleRecord>(
            "SELECT * FROM access_roles ORDER BY created_at DESC",
        )
        .fetch_all(&self.pool)
        .await?)
    }

    pub async fn get_access_role(&self, id: &str) -> AppResult<Option<AccessRoleRecord>> {
        Ok(
            sqlx::query_as::<_, AccessRoleRecord>("SELECT * FROM access_roles WHERE id = ?")
                .bind(id)
                .fetch_optional(&self.pool)
                .await?,
        )
    }

    pub async fn find_access_role_by_token_hash(
        &self,
        token_hash: &str,
    ) -> AppResult<Option<AccessRoleRecord>> {
        Ok(sqlx::query_as::<_, AccessRoleRecord>(
            "SELECT * FROM access_roles WHERE api_token_sha256 = ?",
        )
        .bind(token_hash)
        .fetch_optional(&self.pool)
        .await?)
    }

    pub async fn list_access_roles_by_certificate_issuer(
        &self,
        issuer_dn: &str,
    ) -> AppResult<Vec<AccessRoleRecord>> {
        Ok(sqlx::query_as::<_, AccessRoleRecord>(
            r#"
            SELECT * FROM access_roles
            WHERE certificate_match_key IS NOT NULL
              AND certificate_issuer_dn = ?
            ORDER BY created_at DESC
            "#,
        )
        .bind(issuer_dn)
        .fetch_all(&self.pool)
        .await?)
    }

    pub async fn update_access_role(&self, role: &AccessRoleRecord) -> AppResult<u64> {
        Ok(sqlx::query(
            r#"
            UPDATE access_roles
            SET name = ?,
                permissions_json = ?,
                api_token_sha256 = ?,
                certificate_issuer_dn = ?,
                certificate_match_key = ?,
                certificate_match_value = ?,
                updated_at = ?
            WHERE id = ?
            "#,
        )
        .bind(&role.name)
        .bind(&role.permissions_json)
        .bind(&role.api_token_sha256)
        .bind(&role.certificate_issuer_dn)
        .bind(&role.certificate_match_key)
        .bind(&role.certificate_match_value)
        .bind(role.updated_at)
        .bind(&role.id)
        .execute(&self.pool)
        .await?
        .rows_affected())
    }

    pub async fn delete_access_role(&self, id: &str) -> AppResult<u64> {
        Ok(sqlx::query("DELETE FROM access_roles WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await?
            .rows_affected())
    }

    pub async fn purge_expired_certificates(
        &self,
        older_than_unix: i64,
        batch: i64,
    ) -> AppResult<u64> {
        let result = sqlx::query(
            r#"
            DELETE FROM certificates
            WHERE id IN (
                SELECT id FROM certificates
                WHERE not_after < ?
                ORDER BY not_after ASC
                LIMIT ?
            )
            "#,
        )
        .bind(older_than_unix)
        .bind(batch)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected())
    }

    pub async fn purge_expired_crls(&self, older_than_unix: i64, batch: i64) -> AppResult<u64> {
        let result = sqlx::query(
            r#"
            DELETE FROM crls
            WHERE id IN (
                SELECT id FROM crls
                WHERE next_update < ?
                ORDER BY next_update ASC
                LIMIT ?
            )
            "#,
        )
        .bind(older_than_unix)
        .bind(batch)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected())
    }

    pub async fn purge_certificate_events(
        &self,
        older_than_unix: i64,
        batch: i64,
    ) -> AppResult<u64> {
        let result = sqlx::query(
            r#"
            DELETE FROM certificate_events
            WHERE id IN (
                SELECT id FROM certificate_events
                WHERE ts < ?
                ORDER BY ts ASC
                LIMIT ?
            )
            "#,
        )
        .bind(older_than_unix)
        .bind(batch)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected())
    }

    pub async fn purge_audit_events(&self, older_than_unix: i64, batch: i64) -> AppResult<u64> {
        let result = sqlx::query(
            r#"
            DELETE FROM audit_events
            WHERE id IN (
                SELECT id FROM audit_events
                WHERE ts < ?
                ORDER BY
                    CASE WHEN chain_index IS NULL THEN 0 ELSE 1 END,
                    chain_index ASC,
                    ts ASC,
                    id ASC
                LIMIT ?
            )
            "#,
        )
        .bind(older_than_unix)
        .bind(batch)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected())
    }

    pub async fn optimize(&self) -> AppResult<()> {
        sqlx::query("PRAGMA optimize").execute(&self.pool).await?;
        sqlx::query("VACUUM").execute(&self.pool).await?;
        Ok(())
    }
}

async fn scalar_i64(pool: &SqlitePool, sql: &str) -> AppResult<i64> {
    let row = sqlx::query(sql).fetch_one(pool).await?;
    Ok(row.try_get::<i64, _>(0)?)
}

async fn scalar_i64_with_bind(
    pool: &SqlitePool,
    sql: &str,
    status: &str,
    bucket: i64,
) -> AppResult<i64> {
    let row = sqlx::query(sql)
        .bind(status)
        .bind(bucket)
        .fetch_one(pool)
        .await?;
    Ok(row.try_get::<i64, _>(0)?)
}

async fn insert_audit_in_tx(
    tx: &mut Transaction<'_, Sqlite>,
    actor: &str,
    action: &str,
    target: &str,
    status: &str,
    details_json: &str,
) -> AppResult<()> {
    let id = Uuid::new_v4().to_string();
    let ts = now_unix();
    let chain_index = next_audit_chain_index_in_tx(tx).await?;
    let prev_hash = latest_audit_hash_in_tx(tx).await?;
    let entry_hash = audit_entry_hash(
        chain_index,
        &id,
        ts,
        actor,
        action,
        target,
        status,
        details_json,
        prev_hash.as_deref(),
    );
    sqlx::query(
        r#"
        INSERT INTO audit_events
            (id, chain_index, ts, actor, action, target, status, details_json, prev_hash, entry_hash)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(id)
    .bind(chain_index)
    .bind(ts)
    .bind(actor)
    .bind(action)
    .bind(target)
    .bind(status)
    .bind(details_json)
    .bind(prev_hash)
    .bind(entry_hash)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

async fn next_audit_chain_index_in_tx(tx: &mut Transaction<'_, Sqlite>) -> AppResult<i64> {
    let row = sqlx::query(
        "SELECT COALESCE(MAX(chain_index), 0) + 1 FROM audit_events WHERE chain_index IS NOT NULL",
    )
    .fetch_one(&mut **tx)
    .await?;
    Ok(row.try_get::<i64, _>(0)?)
}

async fn latest_audit_hash_in_tx(tx: &mut Transaction<'_, Sqlite>) -> AppResult<Option<String>> {
    Ok(sqlx::query("SELECT entry_hash FROM audit_events WHERE chain_index IS NOT NULL AND entry_hash IS NOT NULL ORDER BY chain_index DESC LIMIT 1")
        .fetch_optional(&mut **tx)
        .await?
        .and_then(|row| row.try_get::<String, _>("entry_hash").ok()))
}

fn audit_entry_hash(
    chain_index: i64,
    id: &str,
    ts: i64,
    actor: &str,
    action: &str,
    target: &str,
    status: &str,
    details_json: &str,
    prev_hash: Option<&str>,
) -> String {
    let mut hasher = Sha256::new();
    let chain_index = chain_index.to_string();
    let ts = ts.to_string();
    for part in [
        chain_index.as_str(),
        id,
        ts.as_str(),
        actor,
        action,
        target,
        status,
        details_json,
        prev_hash.unwrap_or(""),
    ] {
        let bytes = part.as_bytes();
        hasher.update(bytes.len().to_string().as_bytes());
        hasher.update(b":");
        hasher.update(bytes);
        hasher.update(b";");
    }
    hex::encode(hasher.finalize())
}

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS cas (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    subject_dn TEXT NOT NULL,
    cert_pem TEXT NOT NULL,
    key_pem TEXT NOT NULL,
    cert_der BLOB NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    is_default INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    not_after INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS certificates (
    id TEXT PRIMARY KEY,
    ca_id TEXT NOT NULL REFERENCES cas(id) ON DELETE CASCADE,
    serial_hex TEXT NOT NULL,
    subject_dn TEXT NOT NULL,
    san_json TEXT NOT NULL,
    cert_pem TEXT NOT NULL,
    cert_der BLOB NOT NULL,
    csr_pem TEXT,
    status TEXT NOT NULL,
    revocation_reason TEXT,
    revoked_at INTEGER,
    not_before INTEGER NOT NULL,
    not_after INTEGER NOT NULL,
    fingerprint_sha256 TEXT NOT NULL UNIQUE,
    created_at INTEGER NOT NULL,
    UNIQUE(ca_id, serial_hex)
);

CREATE INDEX IF NOT EXISTS certs_ca_status_idx ON certificates(ca_id, status);
CREATE INDEX IF NOT EXISTS certs_not_after_idx ON certificates(not_after);
CREATE INDEX IF NOT EXISTS certs_serial_idx ON certificates(serial_hex);
CREATE INDEX IF NOT EXISTS certs_created_idx ON certificates(created_at DESC);
CREATE INDEX IF NOT EXISTS certs_ca_created_idx ON certificates(ca_id, created_at DESC);
CREATE INDEX IF NOT EXISTS certs_status_created_idx ON certificates(status, created_at DESC);
CREATE INDEX IF NOT EXISTS certs_ca_status_created_idx ON certificates(ca_id, status, created_at DESC);
CREATE INDEX IF NOT EXISTS certs_status_not_after_idx ON certificates(status, not_after);
CREATE INDEX IF NOT EXISTS certs_ca_status_not_after_idx ON certificates(ca_id, status, not_after);

CREATE TABLE IF NOT EXISTS crls (
    id TEXT PRIMARY KEY,
    ca_id TEXT NOT NULL REFERENCES cas(id) ON DELETE CASCADE,
    crl_number INTEGER NOT NULL,
    partition_index INTEGER NOT NULL DEFAULT -1,
    is_delta INTEGER NOT NULL DEFAULT 0,
    pem TEXT NOT NULL,
    der BLOB NOT NULL,
    this_update INTEGER NOT NULL,
    next_update INTEGER NOT NULL,
    revoked_count INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    UNIQUE(ca_id, partition_index, is_delta, crl_number)
);

CREATE INDEX IF NOT EXISTS crls_ca_number_idx ON crls(ca_id, crl_number);
CREATE INDEX IF NOT EXISTS crls_next_update_idx ON crls(next_update);

CREATE TABLE IF NOT EXISTS validators (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    kind TEXT NOT NULL,
    config_json TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS certificate_profiles (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    validity_days INTEGER NOT NULL,
    key_usages_json TEXT NOT NULL,
    extended_key_usages_json TEXT NOT NULL,
    allow_server_generated_key INTEGER NOT NULL,
    require_san INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS end_entity_profiles (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    subject_regex TEXT,
    allowed_dns_domains_json TEXT NOT NULL,
    default_certificate_profile_id TEXT REFERENCES certificate_profiles(id) ON DELETE SET NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS cmp_aliases (
    id TEXT PRIMARY KEY,
    alias TEXT NOT NULL UNIQUE,
    ca_id TEXT REFERENCES cas(id) ON DELETE SET NULL,
    certificate_profile_id TEXT REFERENCES certificate_profiles(id) ON DELETE SET NULL,
    end_entity_profile_id TEXT REFERENCES end_entity_profiles(id) ON DELETE SET NULL,
    enabled INTEGER NOT NULL,
    hmac_secret_sha256 TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS access_roles (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    permissions_json TEXT NOT NULL,
    api_token_sha256 TEXT UNIQUE,
    certificate_issuer_dn TEXT,
    certificate_match_key TEXT,
    certificate_match_value TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_events (
    id TEXT PRIMARY KEY,
    chain_index INTEGER,
    ts INTEGER NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT NOT NULL,
    status TEXT NOT NULL,
    details_json TEXT NOT NULL,
    prev_hash TEXT,
    entry_hash TEXT
);

CREATE INDEX IF NOT EXISTS audit_ts_idx ON audit_events(ts DESC);
CREATE INDEX IF NOT EXISTS audit_action_status_ts_idx ON audit_events(action, status, ts DESC);
CREATE INDEX IF NOT EXISTS audit_actor_ts_idx ON audit_events(actor, ts DESC);
CREATE INDEX IF NOT EXISTS audit_target_ts_idx ON audit_events(target, ts DESC);

CREATE TABLE IF NOT EXISTS certificate_events (
    id TEXT PRIMARY KEY,
    ts INTEGER NOT NULL,
    event_type TEXT NOT NULL,
    status TEXT NOT NULL,
    ca_id TEXT REFERENCES cas(id) ON DELETE SET NULL,
    certificate_id TEXT REFERENCES certificates(id) ON DELETE SET NULL,
    serial_hex TEXT,
    device_id TEXT,
    subject_dn TEXT,
    source TEXT NOT NULL,
    error_code TEXT,
    latency_ms INTEGER
);

CREATE INDEX IF NOT EXISTS cert_events_type_status_ts_idx ON certificate_events(event_type, status, ts DESC);
CREATE INDEX IF NOT EXISTS cert_events_ts_idx ON certificate_events(ts);
CREATE INDEX IF NOT EXISTS cert_events_device_ts_idx ON certificate_events(device_id, ts DESC);
CREATE INDEX IF NOT EXISTS cert_events_ca_ts_idx ON certificate_events(ca_id, ts DESC);
CREATE INDEX IF NOT EXISTS cert_events_serial_idx ON certificate_events(serial_hex);
CREATE INDEX IF NOT EXISTS cert_events_issue_device_status_idx
    ON certificate_events(device_id, status)
    WHERE event_type = 'issue' AND device_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS cert_events_issue_status_latency_idx
    ON certificate_events(status, latency_ms)
    WHERE event_type = 'issue' AND latency_ms IS NOT NULL;

CREATE TABLE IF NOT EXISTS app_config (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at INTEGER NOT NULL
);
"#;

#[cfg(test)]
mod tests {
    use super::*;

    async fn temp_db() -> (Db, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!("ejbca-rs-storage-test-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let db = Db::connect(
            &format!("sqlite://{}", dir.join("test.sqlite").display()),
            4,
            30,
        )
        .await
        .unwrap();
        (db, dir)
    }

    async fn sqlite_index_exists(db: &Db, name: &str) -> bool {
        sqlx::query("SELECT name FROM sqlite_master WHERE type = 'index' AND name = ?")
            .bind(name)
            .fetch_optional(db.pool())
            .await
            .unwrap()
            .is_some()
    }

    #[tokio::test]
    async fn migrate_creates_large_dataset_indexes() {
        let (db, dir) = temp_db().await;
        db.migrate().await.unwrap();

        for index in [
            "certs_created_idx",
            "certs_ca_status_created_idx",
            "certs_status_not_after_idx",
            "certs_ca_status_not_after_idx",
            "cert_events_type_status_ts_idx",
            "cert_events_ts_idx",
            "cert_events_issue_device_status_idx",
            "cert_events_issue_status_latency_idx",
            "cas_default_status_idx",
            "audit_hash_idx",
            "audit_chain_index_uidx",
            "audit_chain_scan_idx",
            "audit_legacy_ts_idx",
        ] {
            assert!(
                sqlite_index_exists(&db, index).await,
                "missing index {index}"
            );
        }

        std::fs::remove_dir_all(dir).ok();
    }

    #[tokio::test]
    async fn migrate_adds_audit_chain_indexes_to_legacy_schema() {
        let (db, dir) = temp_db().await;
        sqlx::query(
            r#"
            CREATE TABLE audit_events (
                id TEXT PRIMARY KEY,
                ts INTEGER NOT NULL,
                actor TEXT NOT NULL,
                action TEXT NOT NULL,
                target TEXT NOT NULL,
                status TEXT NOT NULL,
                details_json TEXT NOT NULL
            )
            "#,
        )
        .execute(db.pool())
        .await
        .unwrap();

        db.migrate().await.unwrap();

        for column in ["prev_hash", "entry_hash", "chain_index"] {
            let exists =
                sqlx::query("SELECT name FROM pragma_table_info('audit_events') WHERE name = ?")
                    .bind(column)
                    .fetch_optional(db.pool())
                    .await
                    .unwrap()
                    .is_some();
            assert!(exists, "missing migrated column {column}");
        }
        for index in [
            "audit_hash_idx",
            "audit_chain_index_uidx",
            "audit_chain_scan_idx",
            "audit_legacy_ts_idx",
        ] {
            assert!(
                sqlite_index_exists(&db, index).await,
                "missing index {index}"
            );
        }

        std::fs::remove_dir_all(dir).ok();
    }
}
