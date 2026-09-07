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
use radii_fetch::config;
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
    radii_fetch::run(config).await
}
