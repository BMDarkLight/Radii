use clap::Parser;
use radii_head::config;
use std::path::PathBuf;

#[derive(Parser)]
struct Args {
    #[arg(long, default_value = "crates/head/head.example.toml")]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _log_guard = radii_core::logging::init("radii-head")?;

    let args = Args::parse();
    let config = config::load(&args.config)?;
    radii_head::run(config).await
}
