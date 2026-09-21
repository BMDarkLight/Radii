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

    /// Runs every registered runner until one fails, then aborts the rest and
    /// returns that failure.
    ///
    /// Joined in *completion* order, not registration order. Awaiting handles
    /// in the order they were registered meant a runner that never returns —
    /// which is every listener, by design — blocked the loop from ever
    /// observing a later runner's failure. Head registers its HTTP listener
    /// first, so a Radii bridge or graph poller that failed to bind left the
    /// error sitting in a finished task nobody awaited: the process kept
    /// serving HTTP, `/health` kept answering 200, and the missing listener
    /// was visible only as a log line. Dropping the `JoinSet` on the way out
    /// aborts the survivors, so a partial failure takes the process down
    /// rather than leaving it half-serving.
    pub async fn run_all(self) -> Result<()> {
        let mut set = tokio::task::JoinSet::new();
        for runner in self.runners {
            let name = runner.name();
            set.spawn(async move {
                runner.start().await.map_err(|err| {
                    tracing::error!(protocol = name, error = %err, "protocol runner failed");
                    err
                })
            });
        }

        while let Some(joined) = set.join_next().await {
            joined??;
        }

        Ok(())
    }
}

impl Default for ProtocolRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A listener: bound successfully, now serving forever.
    struct NeverReturns;

    impl ProtocolRunner for NeverReturns {
        fn name(&self) -> &'static str {
            "never-returns"
        }

        fn start(&self) -> BoxFuture<'_> {
            Box::pin(async {
                std::future::pending::<()>().await;
                Ok(())
            })
        }
    }

    /// A listener whose bind failed — the case that used to vanish.
    struct FailsImmediately;

    impl ProtocolRunner for FailsImmediately {
        fn name(&self) -> &'static str {
            "fails-immediately"
        }

        fn start(&self) -> BoxFuture<'_> {
            Box::pin(async { anyhow::bail!("address already in use") })
        }
    }

    /// Registration order must not decide whether a failure is noticed. This
    /// is Head's exact shape: the HTTP listener is registered first and never
    /// returns, and the runner that failed to bind is registered after it.
    ///
    /// Written with a timeout because the regression is a *hang*, not a wrong
    /// value: without joining in completion order this never resolves, and a
    /// failing assertion is a far better signal than a stuck test binary.
    #[tokio::test]
    async fn a_later_runners_failure_surfaces_past_one_that_never_returns() {
        let registry = ProtocolRegistry::new()
            .register(NeverReturns)
            .register(FailsImmediately);

        let outcome = tokio::time::timeout(std::time::Duration::from_secs(5), registry.run_all())
            .await
            .expect("run_all must not block on a runner that never returns");

        let err = outcome.expect_err("the failing runner's error must reach the caller");
        assert!(
            err.to_string().contains("address already in use"),
            "the original error must survive, got: {err}"
        );
    }

    /// The healthy path still joins every runner rather than returning at the
    /// first completion.
    #[tokio::test]
    async fn runners_that_all_succeed_join_cleanly() {
        struct Completes;
        impl ProtocolRunner for Completes {
            fn name(&self) -> &'static str {
                "completes"
            }
            fn start(&self) -> BoxFuture<'_> {
                Box::pin(async { Ok(()) })
            }
        }

        let registry = ProtocolRegistry::new()
            .register(Completes)
            .register(Completes);

        tokio::time::timeout(std::time::Duration::from_secs(5), registry.run_all())
            .await
            .expect("must not hang")
            .expect("no runner failed");
    }
}
