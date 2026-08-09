use clap::Parser;
use radii_fetch::{config, server};
use std::path::PathBuf;

#[derive(Parser)]
struct Args {
    #[arg(long, default_value = "crates/fetch/fetch.example.toml")]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _log_guard = radii_core::logging::init("radii-fetch")?;

    let args = Args::parse();
    let config = config::load(&args.config)?;
    server::run(&config.bind, &config.upstream).await
}
