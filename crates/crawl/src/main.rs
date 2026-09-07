// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 BMDarkLight
//
// This file is part of Radii.
//
// Radii is free software: you can redistribute it and/or modify it under
// the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. See the LICENSE file for the full text and
// additional terms.

use clap::Parser;
use radii_crawl::{config, server};
use radii_proto::tls::TlsIdentity;
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
    let tls = config.tls.as_ref().map(TlsIdentity::load).transpose()?;
    let relay_peers = config.relay_peers.iter().cloned().collect();
    server::run(&config.bind, tls, Some(config.node_ttl_ms), relay_peers).await
}
