use anyhow::Result;
use std::path::PathBuf;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

pub struct LoggingGuard {
    _worker_guard: tracing_appender::non_blocking::WorkerGuard,
}

pub fn init(app_name: &str) -> Result<LoggingGuard> {
    let log_dir = std::env::var("RADII_LOG_DIR").unwrap_or_else(|_| "logs".to_string());
    let log_dir = PathBuf::from(log_dir);
    std::fs::create_dir_all(&log_dir)?;

    let file_appender = tracing_appender::rolling::daily(&log_dir, format!("{app_name}.log"));
    let (file_writer, guard) = tracing_appender::non_blocking(file_appender);

    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));

    let stdout_layer = tracing_subscriber::fmt::layer()
        .with_writer(std::io::stdout)
        .with_ansi(true)
        .with_target(true);

    let file_layer = tracing_subscriber::fmt::layer()
        .with_writer(file_writer)
        .with_ansi(false)
        .with_target(true)
        .with_thread_ids(true)
        .with_thread_names(true);

    tracing_subscriber::registry()
        .with(env_filter)
        .with(stdout_layer)
        .with(file_layer)
        .init();

    Ok(LoggingGuard {
        _worker_guard: guard,
    })
}
