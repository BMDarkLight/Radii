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

use crate::decision::{
    BackendDecision, BackendTarget, DecisionEngine, DecisionInput, DecisionReason, Protocol,
};
use anyhow::Context;
use axum::extract::{ConnectInfo, Host, Request, State};
use axum::http::header::HeaderMap;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get};
use axum::{Json, Router};
use radii_proto::tls::TlsIdentity;
use serde::Serialize;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::TcpListener;

#[derive(Clone)]
pub struct AppState {
    decision: DecisionEngine,
    protocol: Protocol,
    attempt_timeout: Duration,
    response_timeout: Duration,
    /// Identity used for both layers of a chain to a graph-resolved backend.
    /// Absent means plaintext, matching the rest of the project's opt-in TLS.
    chain_tls: Option<TlsIdentity>,
    health: HealthWatch,
}

/// What `/health` inspects before answering.
///
/// The protocol registry already takes the process down when a runner
/// *fails*. What it cannot see is a runner that is merely *degraded*: the
/// graph poller logs a warning and retries on every failed query, by design,
/// so a Head cut off from Crawl keeps serving from a snapshot that gets
/// older every interval. Nothing else in the process distinguishes that from
/// healthy, which is exactly what a health check is for.
#[derive(Clone, Default)]
pub struct HealthWatch {
    graph: Option<(crate::graph::SharedGraphState, Duration)>,
}

impl HealthWatch {
    /// No `[graph]` configured: Head serves its static routing config, and
    /// there is no freshness to report on.
    pub fn none() -> Self {
        Self { graph: None }
    }

    /// Reports the graph stale once no successful poll has landed within
    /// `max_age`.
    pub fn graph(state: crate::graph::SharedGraphState, max_age: Duration) -> Self {
        Self {
            graph: Some((state, max_age)),
        }
    }

    /// How many poll intervals may be missed before the graph is stale.
    ///
    /// Three rather than one: a single missed poll is a transient blip —
    /// Crawl restarting, a dropped packet — and flapping a load balancer on
    /// that would cause more disruption than it prevents. Three consecutive
    /// failures is a pattern.
    pub const STALE_AFTER_INTERVALS: u32 = 3;

    /// The watch implied by a `[graph]` config's poll interval.
    pub fn from_graph_config(state: crate::graph::SharedGraphState, poll_interval_ms: u64) -> Self {
        let interval = Duration::from_millis(poll_interval_ms.max(1));
        Self::graph(state, interval * Self::STALE_AFTER_INTERVALS)
    }

    /// `(healthy, graph state label)`.
    fn evaluate(&self) -> (bool, &'static str) {
        let Some((state, max_age)) = &self.graph else {
            return (true, "not_configured");
        };
        let Ok(guard) = state.read() else {
            // The poller panicked holding the write side. Every route
            // decision from here reads a poisoned lock and falls back, which
            // is precisely a degraded Head.
            return (false, "poisoned");
        };
        match guard.last_refresh {
            None => (false, "never_refreshed"),
            Some(at) if at.elapsed() > *max_age => (false, "stale"),
            Some(_) => (true, "fresh"),
        }
    }
}

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    /// `not_configured`, `fresh`, `stale`, `never_refreshed`, or `poisoned`.
    graph: &'static str,
}

#[derive(Serialize)]
struct HeadResponse {
    source_ip: String,
    host: Option<String>,
    backend: String,
    /// Every reachable backend, best first, `backend` being the first.
    /// Head fails over across these itself when a chain will not open, so
    /// the list is diagnostic — it shows what Head *would* try, in order.
    candidates: Vec<String>,
    decision_reason: String,
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        // The decision JSON used to be returned on EVERY path, disclosing
        // the backend map to any request. It lives on one route now, which
        // an operator can firewall. That narrows the disclosure; it does not
        // authenticate it — see SECURITY.md.
        .route("/_radii/decision", get(decision_json))
        .fallback(any(proxy_request))
        .with_state(state)
}

/// State with the defaults, for callers that do not configure timeouts.
pub fn default_state(decision: DecisionEngine) -> AppState {
    AppState {
        decision,
        protocol: Protocol::Http,
        attempt_timeout: Duration::from_millis(3000),
        response_timeout: Duration::from_millis(30_000),
        chain_tls: None,
        health: HealthWatch::none(),
    }
}

pub fn state_with(
    decision: DecisionEngine,
    attempt_timeout: Duration,
    response_timeout: Duration,
    chain_tls: Option<TlsIdentity>,
) -> AppState {
    AppState {
        decision,
        protocol: Protocol::Http,
        attempt_timeout,
        response_timeout,
        chain_tls,
        health: HealthWatch::none(),
    }
}

impl AppState {
    /// Points `/health` at what this Head actually depends on.
    pub fn with_health(mut self, health: HealthWatch) -> Self {
        self.health = health;
        self
    }
}

pub async fn serve_http(bind: &str, decision: DecisionEngine) -> anyhow::Result<()> {
    let listener = TcpListener::bind(bind).await?;
    serve_http_on(listener, decision).await
}

pub async fn serve_http_on(listener: TcpListener, decision: DecisionEngine) -> anyhow::Result<()> {
    serve_http_on_with(listener, default_state(decision)).await
}

pub async fn serve_http_on_with(listener: TcpListener, state: AppState) -> anyhow::Result<()> {
    let addr = listener.local_addr()?;
    tracing::info!(%addr, "head http listening");

    axum::serve(
        listener,
        router(state).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;

    Ok(())
}

/// Reports whether Head can currently do its job, not merely that its HTTP
/// listener is up.
///
/// Returns 503 rather than 200 when the graph poller has gone stale, so a
/// load balancer can route around a Head that is serving from an
/// increasingly old view of the mesh. The body names the reason: an operator
/// seeing a 503 needs to know whether Crawl is unreachable or this Head
/// simply has not finished starting.
async fn health(State(state): State<AppState>) -> (StatusCode, Json<HealthResponse>) {
    let (healthy, graph) = state.health.evaluate();
    let code = if healthy {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (
        code,
        Json(HealthResponse {
            status: if healthy { "ok" } else { "degraded" },
            graph,
        }),
    )
}

async fn decision_json(
    State(state): State<AppState>,
    connect: ConnectInfo<SocketAddr>,
    host: Option<Host>,
) -> Result<Json<HeadResponse>, StatusCode> {
    let host_value = host.as_ref().map(|value| value.0.clone());
    let decision = state.decision.decide(DecisionInput {
        protocol: state.protocol,
        protocol_label: None,
        host: host_value.as_deref(),
        source: Some(connect.0),
        destination_port: None,
        attributes: &[],
    });

    tracing::info!(
        source = %connect.0,
        host = ?host_value,
        backend = %decision.backend(),
        reason = ?decision.reason,
        "head received request"
    );

    let reason = match decision.reason {
        DecisionReason::GraphRoute => "graph_route",
        DecisionReason::HostMatch => "host_map",
        DecisionReason::Default => "default",
    };

    Ok(Json(HeadResponse {
        source_ip: connect.0.to_string(),
        host: host_value,
        backend: decision.backend(),
        candidates: decision.candidates(),
        decision_reason: reason.to_string(),
    }))
}

/// Forwards a request to the decided backend and streams the response back.
async fn proxy_request(
    State(state): State<AppState>,
    connect: ConnectInfo<SocketAddr>,
    mut request: Request,
) -> Response {
    let host = request
        .headers()
        .get(axum::http::header::HOST)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);

    let decision = state.decision.decide(DecisionInput {
        protocol: state.protocol,
        protocol_label: None,
        host: host.as_deref(),
        source: Some(connect.0),
        destination_port: None,
        attributes: &[],
    });

    add_forwarded_headers(request.headers_mut(), &connect.0, host.as_deref());

    let stream = match connect_backend(&state, &decision).await {
        Ok(stream) => stream,
        Err(err) => {
            tracing::warn!(
                source = %connect.0,
                host = ?host,
                backend = %decision.backend(),
                error = %err,
                "no backend could be reached"
            );
            return StatusCode::BAD_GATEWAY.into_response();
        }
    };

    match crate::proxy::forward(stream, request, state.response_timeout).await {
        Ok(response) => response,
        Err(err) => {
            // Past this point the request has been written, so this is not
            // retried: Head cannot know whether the backend processed it.
            tracing::warn!(
                source = %connect.0,
                backend = %decision.backend(),
                error = %err,
                "proxy forward failed after the request was sent"
            );
            StatusCode::BAD_GATEWAY.into_response()
        }
    }
}

/// Records the immediate peer in the `X-Forwarded-*` headers.
///
/// An inbound `X-Forwarded-For` is appended to, never replaced — and never
/// believed. Any client can send one, Head makes no access-control decision
/// on it, and nothing downstream should treat it as authenticated. It is
/// provenance for a log, not a credential.
fn add_forwarded_headers(headers: &mut HeaderMap, peer: &SocketAddr, host: Option<&str>) {
    let chain = match headers
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
    {
        Some(prior) => format!("{prior}, {}", peer.ip()),
        None => peer.ip().to_string(),
    };
    if let Ok(value) = chain.parse() {
        headers.insert("x-forwarded-for", value);
    }
    if let Ok(value) = "http".parse() {
        headers.insert("x-forwarded-proto", value);
    }
    if let Some(host) = host {
        if let Ok(value) = host.parse() {
            headers.insert("x-forwarded-host", value);
        }
    }
}

/// Opens a connection to the decided backend.
async fn connect_backend(
    state: &AppState,
    decision: &BackendDecision,
) -> anyhow::Result<radii_proto::BoxedStream> {
    match &decision.target {
        // A statically configured backend has no node identity — it came
        // from the operator's own config and may point at a host that is not
        // part of the mesh — so it is dialed directly, exactly as Fetch
        // dials its static `upstream` fallback and for the same reason.
        BackendTarget::Direct(addr) => {
            let addr = radii_fetch::server::normalize_upstream(addr);
            let stream =
                tokio::time::timeout(state.attempt_timeout, tokio::net::TcpStream::connect(&addr))
                    .await
                    .context("timed out dialing the configured backend")?
                    .context("could not dial the configured backend")?;
            Ok(Box::new(stream))
        }
        BackendTarget::Chain(routes) => {
            let mut last: anyhow::Error = anyhow::anyhow!("no reachable candidate");
            for (index, route) in routes.iter().enumerate() {
                // Retrying is safe here and ONLY here: a chain that failed
                // to establish never delivered the request, so replaying it
                // is unambiguous for any method, POST included. Once the
                // request has been written, a failure is terminal — Head
                // cannot know whether the backend processed it — and the
                // caller turns it into a 502 rather than trying elsewhere.
                let attempt = tokio::time::timeout(
                    state.attempt_timeout,
                    radii_fetch::chain::establish(
                        route,
                        state.chain_tls.as_ref(),
                        state.chain_tls.as_ref(),
                    ),
                )
                .await;

                let addr = route
                    .hops
                    .last()
                    .map(|hop| hop.addr.as_str())
                    .unwrap_or("<no-hops>");

                match attempt {
                    Ok(Ok(stream)) => {
                        tracing::info!(
                            candidate = index,
                            target = %route.target().0,
                            %addr,
                            "head established a chain to a backend"
                        );
                        return Ok(stream);
                    }
                    Ok(Err(err)) => {
                        tracing::warn!(
                            candidate = index,
                            target = %route.target().0,
                            %addr,
                            error = %err,
                            "candidate failed; trying the next"
                        );
                        last = err;
                    }
                    Err(_) => {
                        tracing::warn!(
                            candidate = index,
                            target = %route.target().0,
                            %addr,
                            timeout_ms = state.attempt_timeout.as_millis(),
                            "candidate timed out; trying the next"
                        );
                        last = anyhow::anyhow!("candidate timed out");
                    }
                }
            }
            Err(last)
        }
    }
}
