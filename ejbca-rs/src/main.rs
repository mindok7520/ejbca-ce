mod access_rules;
mod api;
mod asn1;
mod ca;
mod certs;
mod cli;
mod cluster;
mod cmp;
mod compat;
mod config;
mod crl;
mod enrollment;
mod error;
mod key_provider;
mod logging;
mod maintenance;
mod metrics;
mod ocsp;
mod profiles;
mod publisher;
mod ra;
mod storage;
mod util;
mod validators;

use std::sync::Arc;

use anyhow::Context;
use axum::Router;
use config::Settings;
use storage::Db;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tower_http::trace::TraceLayer;
use tracing::{info, warn};
use uuid::Uuid;

#[derive(Clone)]
pub struct AppState {
    pub db: Db,
    pub settings: Arc<Settings>,
    pub http: reqwest::Client,
    pub issue_limiter: Arc<Semaphore>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let settings = Settings::parse();
    let command = settings.command.clone();
    let _log_guards = logging::init(&settings)?;
    let is_serve_command = matches!(command, None | Some(config::Command::Serve));

    let admin_token = settings
        .admin_token
        .clone()
        .unwrap_or_else(|| Uuid::new_v4().to_string());
    if is_serve_command && settings.admin_token.is_none() {
        warn!(
            "EJBCA_RS_ADMIN_TOKEN이 없어 일회용 관리자 토큰을 생성했습니다. x-admin-token={}",
            admin_token
        );
    }

    let settings = Arc::new(settings.with_admin_token(admin_token));
    logging::spawn_retention_worker(settings.clone());
    tokio::fs::create_dir_all(&settings.data_dir)
        .await
        .with_context(|| format!("데이터 디렉터리를 만들 수 없습니다: {}", settings.data_dir))?;

    let db = Db::connect(
        &settings.database_url(),
        settings.database_max_connections,
        settings.database_busy_timeout_seconds,
    )
    .await?;
    db.migrate().await?;

    let state = AppState {
        db,
        settings: settings.clone(),
        http: reqwest::Client::new(),
        issue_limiter: Arc::new(Semaphore::new(settings.max_concurrent_issuance.max(1))),
    };

    ca::service::ensure_default_ca(&state).await?;
    profiles::service::ensure_default_profiles(&state).await?;
    compat::ensure_default_features(&state).await?;

    if let Some(command) = command {
        if !matches!(command, config::Command::Serve) {
            cli::run(command, &state).await?;
            return Ok(());
        }
    }

    maintenance::service::spawn_scheduler(state.clone());

    let app: Router = api::router(state).layer(TraceLayer::new_for_http());
    let listener = TcpListener::bind(settings.bind_addr).await?;
    info!("ejbca-rs listening on http://{}", settings.bind_addr);
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("ctrl-c handler를 설치할 수 없습니다");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("terminate handler를 설치할 수 없습니다")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}
