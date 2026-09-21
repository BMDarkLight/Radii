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

use crate::graph::SharedRoutes;
use radii_core::routing::ResolvedRoute;
use radii_proto::tls::TlsIdentity;
use radii_proto::BoxedStream;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};

pub async fn run(bind: &str, upstream: &str) -> anyhow::Result<()> {
    let listener = TcpListener::bind(bind).await?;
    tracing::info!(%bind, %upstream, "fetch tunnel listening");
    run_on(listener, upstream).await
}

pub async fn run_on(listener: TcpListener, upstream: &str) -> anyhow::Result<()> {
    run_on_with_tls(listener, upstream.to_string(), None, None).await
}

/// Like [`run_on`], but resolves the upstream for each new connection from a
/// live-updated graph target, falling back to `static_upstream` when no
/// graph-resolved route is available yet.
pub async fn run_on_dynamic(
    listener: TcpListener,
    static_upstream: String,
    routes: SharedRoutes,
) -> anyhow::Result<()> {
    run_on_dynamic_with_tls(listener, static_upstream, routes, 3000, None, None).await
}

/// Like [`run_on`], additionally requiring mTLS on the inbound side
/// (`listener_tls`) and/or dialing the upstream over mTLS (`upstream_tls`)
/// when configured.
pub async fn run_on_with_tls(
    listener: TcpListener,
    upstream: String,
    listener_tls: Option<TlsIdentity>,
    upstream_tls: Option<TlsIdentity>,
) -> anyhow::Result<()> {
    loop {
        let (stream, addr) = listener.accept().await?;
        let upstream = upstream.clone();
        let listener_tls = listener_tls.clone();
        let upstream_tls = upstream_tls.clone();
        tokio::spawn(async move {
            if let Err(err) =
                accept_and_tunnel(stream, addr, upstream, listener_tls, upstream_tls).await
            {
                tracing::warn!(source = %addr, error = %err, "fetch tunnel failed");
            }
        });
    }
}

/// [`run_on_dynamic`] plus the mTLS options from [`run_on_with_tls`].
pub async fn run_on_dynamic_with_tls(
    listener: TcpListener,
    static_upstream: String,
    routes: SharedRoutes,
    attempt_timeout_ms: u64,
    listener_tls: Option<TlsIdentity>,
    upstream_tls: Option<TlsIdentity>,
) -> anyhow::Result<()> {
    loop {
        let (stream, addr) = listener.accept().await?;
        let static_upstream = static_upstream.clone();
        let routes = routes.clone();
        let listener_tls = listener_tls.clone();
        let upstream_tls = upstream_tls.clone();
        tokio::spawn(async move {
            if let Err(err) = accept_and_tunnel_dynamic(
                stream,
                addr,
                static_upstream,
                routes,
                attempt_timeout_ms,
                listener_tls,
                upstream_tls,
            )
            .await
            {
                tracing::warn!(source = %addr, error = %err, "fetch tunnel failed");
            }
        });
    }
}

async fn accept_and_tunnel(
    inbound: TcpStream,
    source: std::net::SocketAddr,
    upstream: String,
    listener_tls: Option<TlsIdentity>,
    upstream_tls: Option<TlsIdentity>,
) -> anyhow::Result<()> {
    let (inbound, _peer_identity) =
        radii_proto::tls::accept(inbound, listener_tls.as_ref()).await?;

    let target = normalize_upstream(&upstream);
    tracing::info!(source = %source, upstream = %target, "fetch tunneling");
    let outbound = radii_proto::tls::dial(&target, upstream_tls.as_ref()).await?;

    handle_connection(inbound, outbound).await
}

async fn accept_and_tunnel_dynamic(
    inbound: TcpStream,
    source: std::net::SocketAddr,
    static_upstream: String,
    routes: SharedRoutes,
    attempt_timeout_ms: u64,
    listener_tls: Option<TlsIdentity>,
    upstream_tls: Option<TlsIdentity>,
) -> anyhow::Result<()> {
    let (inbound, _peer_identity) =
        radii_proto::tls::accept(inbound, listener_tls.as_ref()).await?;

    let outbound = connect_upstream(
        &routes,
        &static_upstream,
        attempt_timeout_ms,
        upstream_tls.as_ref(),
    )
    .await?;
    tracing::info!(source = %source, "fetch tunneling");

    handle_connection(inbound, outbound).await
}

/// Walks the ranked candidates until one chain comes up, then splices.
///
/// Retry stops the moment the end-to-end handshake succeeds: after that,
/// application bytes may have flowed and TCP offers no way to migrate the
/// stream, so a later failure is terminal by construction rather than by
/// choice. See the design spec's "Retry boundary".
async fn connect_upstream(
    routes: &SharedRoutes,
    static_upstream: &str,
    attempt_timeout_ms: u64,
    upstream_tls: Option<&TlsIdentity>,
) -> anyhow::Result<BoxedStream> {
    // A poisoned lock (the graph poller panicked while holding the write
    // side, see `graph.rs`) silently degrades every connection to the
    // static-upstream fallback below — a permanent, hard-to-notice failure
    // mode unless it is logged here rather than swallowed by
    // `unwrap_or_default`.
    let candidates: Vec<ResolvedRoute> = match routes.read() {
        Ok(guard) => guard.clone(),
        Err(_) => {
            tracing::warn!(
                "fetch routes lock is poisoned; falling back to the static upstream for this \
                 connection"
            );
            Vec::new()
        }
    };

    let bound = Duration::from_millis(attempt_timeout_ms.max(1));
    for (index, route) in candidates.iter().enumerate() {
        // The whole `establish` call — every await inside it, including the
        // TCP dial, the hop-local TLS handshake, the TunnelOpen write, its
        // ack, and the nested end-to-end handshake — is unbounded on its
        // own, so the timeout has to wrap the entire call. Anything awaited
        // outside this `timeout` would leave a hole a stalled relay could
        // hang the connection on.
        let attempt = tokio::time::timeout(
            bound,
            crate::chain::establish(route, upstream_tls, upstream_tls),
        )
        .await;

        // The first hop's address is what was actually dialed, and is the
        // single highest-value field for diagnosing a misconfigured
        // registry: since Task 10 every route target must run a relay
        // listener, and an operator whose registry still advertises a plain
        // tunnel port needs to see which address failed, not just which
        // node id. `hops` is documented non-empty, but `.first()` guards
        // the index rather than trusting that.
        let addr = route
            .hops
            .first()
            .map(|hop| hop.addr.as_str())
            .unwrap_or("<no-hops>");

        match attempt {
            Ok(Ok(stream)) => {
                tracing::info!(
                    candidate = index,
                    target = %route.target().0,
                    hops = route.hops.len(),
                    %addr,
                    "fetch established a chain"
                );
                return Ok(stream);
            }
            Ok(Err(err)) => tracing::warn!(
                candidate = index,
                target = %route.target().0,
                %addr,
                error = %err,
                "candidate failed; trying the next"
            ),
            Err(_) => tracing::warn!(
                candidate = index,
                target = %route.target().0,
                %addr,
                timeout_ms = attempt_timeout_ms,
                "candidate timed out; trying the next"
            ),
        }
    }

    // No candidate worked. The static upstream came from the operator's own
    // config, which is trusted by definition and may legitimately point at a
    // host with no Radii identity at all, so it carries no expected node id.
    tracing::warn!(
        candidates = candidates.len(),
        upstream = %static_upstream,
        "every candidate failed; falling back to the static upstream"
    );
    // `attempt_timeout_ms` exists to bound connect latency for a candidate
    // attempt; this fallback dial is the last leg of that same connection
    // and must not be able to escape it. Without this timeout, a
    // black-holed static upstream would hang the connection indefinitely —
    // and today, before the relay listener is wired into `run()`, every
    // graph-resolved candidate fails on every connection, so every
    // connection reaches this fallback.
    match tokio::time::timeout(
        bound,
        radii_proto::tls::dial(&normalize_upstream(static_upstream), upstream_tls),
    )
    .await
    {
        Ok(result) => result,
        Err(_) => anyhow::bail!(
            "static upstream fallback to {static_upstream} timed out after {attempt_timeout_ms}ms"
        ),
    }
}

async fn handle_connection(inbound: BoxedStream, outbound: BoxedStream) -> anyhow::Result<()> {
    let (mut ri, mut wi) = tokio::io::split(inbound);
    let (mut ro, mut wo) = tokio::io::split(outbound);

    let client_to_server = tokio::io::copy(&mut ri, &mut wo);
    let server_to_client = tokio::io::copy(&mut ro, &mut wi);
    tokio::try_join!(client_to_server, server_to_client)?;

    Ok(())
}

/// Normalize configured upstream addresses by stripping known URL-style prefixes.
///
/// Every scheme listed here means the same thing to a caller: open a plain TCP
/// connection to this host and port. `http://` is included because it is the
/// spelling the shipped configs use for a backend — `routing.default_backend`
/// and every `routing.host_map` value in `head.example.toml` carry it — and
/// Head hands the result straight to `TcpStream::connect`. Leaving it on made
/// the whole static-backend path fail name resolution and answer 502, on the
/// example config, out of the box.
///
/// `https://` is deliberately NOT stripped. Nothing in this project speaks TLS
/// to a backend — Head runs a cleartext HTTP/1 handshake over whatever stream
/// it gets — so stripping it would turn a misconfiguration into cleartext sent
/// at a TLS port, which is worse than the connection failing.
pub fn normalize_upstream(upstream: &str) -> String {
    let trimmed = upstream.trim();
    for scheme in ["ssh://", "tcp://", "http://"] {
        if let Some(stripped) = trimmed.strip_prefix(scheme) {
            return stripped.to_string();
        }
    }
    trimmed.to_string()
}

#[cfg(test)]
mod tests {
    use super::normalize_upstream;

    #[test]
    fn strips_known_prefixes_and_whitespace() {
        assert_eq!(normalize_upstream("  ssh://127.0.0.1:22 "), "127.0.0.1:22");
        assert_eq!(normalize_upstream("tcp://10.0.0.1:443"), "10.0.0.1:443");
        assert_eq!(normalize_upstream("127.0.0.1:9000"), "127.0.0.1:9000");
    }

    /// The exact spelling `head.example.toml` ships for `default_backend` and
    /// for every `host_map` value. Left unstripped, Head passed it to
    /// `TcpStream::connect`, name resolution failed, and every request to a
    /// statically configured backend answered 502.
    #[test]
    fn strips_the_http_scheme_the_example_configs_use() {
        assert_eq!(
            normalize_upstream("http://127.0.0.1:9000"),
            "127.0.0.1:9000"
        );
        assert_eq!(
            normalize_upstream("http://10.0.0.10:9000"),
            "10.0.0.10:9000"
        );
    }

    /// Not stripped on purpose: nothing here speaks TLS to a backend, so
    /// accepting the spelling would send cleartext at a TLS port rather than
    /// failing. The dial fails instead, which is the honest outcome.
    #[test]
    fn leaves_https_alone_rather_than_downgrading_it() {
        assert_eq!(
            normalize_upstream("https://10.0.0.10:443"),
            "https://10.0.0.10:443"
        );
    }
}
