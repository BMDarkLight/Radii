use clap::Parser;
use radii_crawl::{config, server};
use std::path::PathBuf;

#[derive(Parser)]
struct Args {
    #[arg(long, default_value = "crates/crawl/crawl.example.toml")]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _log_guard = radii_core::logging::init("radii-crawl")?;

    let args = Args::parse();
    let config = config::load(&args.config)?;
    server::run(&config.bind).await
}
