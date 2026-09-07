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

use anyhow::Result;
use std::future::Future;
use std::pin::Pin;

pub type BoxFuture<'a> = Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>>;

pub trait ProtocolRunner: Send + Sync {
    fn name(&self) -> &'static str;
    fn start(&self) -> BoxFuture<'_>;
}

pub struct ProtocolRegistry {
    runners: Vec<Box<dyn ProtocolRunner>>,
}

impl ProtocolRegistry {
    pub fn new() -> Self {
        Self {
            runners: Vec::new(),
        }
    }

    pub fn register(mut self, runner: impl ProtocolRunner + 'static) -> Self {
        self.runners.push(Box::new(runner));
        self
    }

    pub async fn run_all(self) -> Result<()> {
        let mut handles = Vec::new();
        for runner in self.runners {
            let name = runner.name();
            handles.push(tokio::spawn(async move {
                runner.start().await.map_err(|err| {
                    tracing::error!(protocol = name, error = %err, "protocol runner failed");
                    err
                })
            }));
        }

        for handle in handles {
            handle.await??;
        }

        Ok(())
    }
}

impl Default for ProtocolRegistry {
    fn default() -> Self {
        Self::new()
    }
}
