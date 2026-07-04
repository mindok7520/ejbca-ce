use std::{
    fs,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime},
};

use anyhow::{Context, Result};
use tracing::warn;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

use crate::config::Settings;

pub fn init(settings: &Settings) -> Result<Vec<WorkerGuard>> {
    let output = LogOutput::parse(&settings.log_output);
    let filter = EnvFilter::try_new(log_filter(settings))
        .unwrap_or_else(|_| EnvFilter::new("ejbca_rs=info,tower_http=info,axum=info"));
    let mut guards = Vec::new();

    if output.writes_file() {
        let log_dir = log_dir(settings);
        fs::create_dir_all(&log_dir)
            .with_context(|| format!("로그 디렉터리를 만들 수 없습니다: {}", log_dir.display()))?;
        purge_old_logs(
            &log_dir,
            settings.log_retention_days,
            settings.log_retention_files,
        )?;
    }

    match (settings.json_logs, output) {
        (true, LogOutput::Stdout) => {
            tracing_subscriber::registry()
                .with(filter)
                .with(fmt::layer().json().with_writer(std::io::stdout))
                .init();
        }
        (false, LogOutput::Stdout) => {
            tracing_subscriber::registry()
                .with(filter)
                .with(fmt::layer().with_writer(std::io::stdout))
                .init();
        }
        (true, LogOutput::File) => {
            let (writer, guard) = file_writer(settings);
            guards.push(guard);
            tracing_subscriber::registry()
                .with(filter)
                .with(fmt::layer().json().with_writer(writer))
                .init();
        }
        (false, LogOutput::File) => {
            let (writer, guard) = file_writer(settings);
            guards.push(guard);
            tracing_subscriber::registry()
                .with(filter)
                .with(fmt::layer().with_writer(writer))
                .init();
        }
        (true, LogOutput::Both) => {
            let (writer, guard) = file_writer(settings);
            guards.push(guard);
            tracing_subscriber::registry()
                .with(filter)
                .with(fmt::layer().json().with_writer(std::io::stdout))
                .with(fmt::layer().json().with_writer(writer))
                .init();
        }
        (false, LogOutput::Both) => {
            let (writer, guard) = file_writer(settings);
            guards.push(guard);
            tracing_subscriber::registry()
                .with(filter)
                .with(fmt::layer().with_writer(std::io::stdout))
                .with(fmt::layer().with_writer(writer))
                .init();
        }
    }

    Ok(guards)
}

pub fn spawn_retention_worker(settings: Arc<Settings>) {
    let output = LogOutput::parse(&settings.log_output);
    if !output.writes_file() {
        return;
    }

    let log_dir = log_dir(&settings);
    let retention_days = settings.log_retention_days;
    let retention_files = settings.log_retention_files;
    tokio::spawn(async move {
        let interval = Duration::from_secs(3600);
        loop {
            tokio::time::sleep(interval).await;
            if let Err(err) = purge_old_logs(&log_dir, retention_days, retention_files) {
                warn!("로그 보존 정책 적용 실패: {err}");
            }
        }
    });
}

fn log_filter(settings: &Settings) -> String {
    if settings.log_level.contains('=') || settings.log_level.contains(',') {
        settings.log_level.clone()
    } else {
        let level = normalize_level(&settings.log_level);
        format!(
            "ejbca_rs={level},tower_http={level},axum={level}",
            level = level
        )
    }
}

fn normalize_level(value: &str) -> &str {
    match value.trim().to_ascii_lowercase().as_str() {
        "warning" => "warn",
        "tracing" => "trace",
        "verbose" => "debug",
        "critical" => "error",
        "trace" => "trace",
        "debug" => "debug",
        "info" => "info",
        "warn" => "warn",
        "error" => "error",
        _ => value,
    }
}

fn file_writer(
    settings: &Settings,
) -> (
    tracing_appender::non_blocking::NonBlocking,
    tracing_appender::non_blocking::WorkerGuard,
) {
    let appender = tracing_appender::rolling::daily(log_dir(settings), "ejbca-rs.log");
    tracing_appender::non_blocking(appender)
}

fn log_dir(settings: &Settings) -> PathBuf {
    settings
        .log_dir
        .as_ref()
        .map(PathBuf::from)
        .unwrap_or_else(|| Path::new(&settings.data_dir).join("logs"))
}

fn purge_old_logs(dir: &Path, retention_days: u64, retention_files: usize) -> Result<()> {
    let now = SystemTime::now();
    let max_age = Duration::from_secs(retention_days.saturating_mul(86_400));
    let mut entries = Vec::new();

    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let Some(file_name) = path.file_name().and_then(|value| value.to_str()) else {
            continue;
        };
        if !file_name.starts_with("ejbca-rs.log") {
            continue;
        }
        let metadata = entry.metadata()?;
        let modified = metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH);
        if retention_days > 0
            && now
                .duration_since(modified)
                .map(|age| age > max_age)
                .unwrap_or(false)
        {
            let _ = fs::remove_file(&path);
            continue;
        }
        entries.push((path, modified));
    }

    if retention_files > 0 && entries.len() > retention_files {
        entries.sort_by_key(|(_, modified)| *modified);
        let remove_count = entries.len() - retention_files;
        for (path, _) in entries.into_iter().take(remove_count) {
            let _ = fs::remove_file(path);
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy)]
enum LogOutput {
    Stdout,
    File,
    Both,
}

impl LogOutput {
    fn parse(value: &str) -> Self {
        match value.to_ascii_lowercase().as_str() {
            "file" => Self::File,
            "both" => Self::Both,
            _ => Self::Stdout,
        }
    }

    fn writes_file(self) -> bool {
        matches!(self, Self::File | Self::Both)
    }
}
