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

//! Head's control plane, which the CLI could not see at all.
//!
//! Head answers `/health` and `/_radii/decision` locally and proxies
//! everything else. Both are operator surfaces — one says whether Head's view
//! of the graph is fresh enough to route on, the other says where a given
//! host would actually go and what it would fail over to.

use anyhow::{Context, Result};
use serde::Deserialize;

use crate::brand::{self, Format, Term};

/// `/health`, as `crates/head/src/http.rs` serialises it.
#[derive(Debug, Deserialize)]
struct Health {
    status: String,
    /// `not_configured`, `fresh`, `stale`, `never_refreshed` or `poisoned`.
    graph: String,
}

/// `/_radii/decision`.
#[derive(Debug, Deserialize)]
struct Decision {
    source_ip: String,
    host: Option<String>,
    backend: String,
    candidates: Vec<String>,
    decision_reason: String,
}

/// Joins a path onto a base URL without depending on a URL parser.
///
/// Operators type `--url localhost:8080` as readily as a full URL, so a
/// missing scheme is filled in rather than rejected.
fn endpoint(base: &str, path: &str) -> String {
    let base = base.trim_end_matches('/');
    if base.contains("://") {
        format!("{base}{path}")
    } else {
        format!("http://{base}{path}")
    }
}

fn client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .user_agent(concat!("radii/", env!("CARGO_PKG_VERSION")))
        .build()
        .context("building the http client")
}

pub async fn health(base: &str, json: bool, term: &Term) -> Result<()> {
    let url = endpoint(base, "/health");
    let response = client()?
        .get(&url)
        .send()
        .await
        .with_context(|| format!("querying {url}"))?;

    // A degraded Head answers 503 with a body that says why, so the body is
    // read regardless of status and the status is reported, not raised.
    let status = response.status();
    let health: Health = response
        .json()
        .await
        .with_context(|| format!("reading the health response from {url}"))?;

    match brand::format(term, json) {
        Format::Json => println!(
            "{}",
            serde_json::json!({
                "http_status": status.as_u16(),
                "status": health.status,
                "graph": health.graph,
            })
        ),
        Format::Plain => println!(
            "health http_status={} status={} graph={}",
            status.as_u16(),
            health.status,
            health.graph
        ),
        Format::Pretty => {
            let ok = health.status == "ok";
            println!(
                "{} {}  {}",
                brand::reach_glyph(Some(ok), term),
                brand::literal(&health.status, term),
                brand::dim(&format!("http {}", status.as_u16()), term),
            );
            println!(
                "  {} {}",
                brand::dim("graph", term),
                graph_state(&health.graph, term)
            );
        }
    }

    Ok(())
}

/// Head's graph freshness, coloured by what it means for routing: `fresh` is
/// the only state it can route on, `not_configured` is a deliberate choice
/// rather than a fault, and the rest are degradation.
fn graph_state(state: &str, term: &Term) -> String {
    match state {
        "fresh" => brand::tinted(state, brand::REACH, term),
        "not_configured" => brand::dim(state, term),
        _ => brand::tinted(state, brand::SEVERED, term),
    }
}

pub async fn decision(base: &str, host: Option<&str>, json: bool, term: &Term) -> Result<()> {
    let url = endpoint(base, "/_radii/decision");
    let mut request = client()?.get(&url);
    if let Some(host) = host {
        // Head decides on the Host header, so asking about a host means
        // sending it — not putting it in the path.
        request = request.header(reqwest::header::HOST, host);
    }
    let response = request
        .send()
        .await
        .with_context(|| format!("querying {url}"))?;

    let status = response.status();
    if !status.is_success() {
        anyhow::bail!("{url} answered {status}");
    }
    let decision: Decision = response
        .json()
        .await
        .with_context(|| format!("reading the decision response from {url}"))?;

    match brand::format(term, json) {
        Format::Json => println!(
            "{}",
            serde_json::json!({
                "source_ip": decision.source_ip,
                "host": decision.host,
                "backend": decision.backend,
                "candidates": decision.candidates,
                "decision_reason": decision.decision_reason,
            })
        ),
        Format::Plain => {
            println!(
                "decision host={} backend={} reason={} candidates={}",
                decision.host.as_deref().unwrap_or("-"),
                decision.backend,
                decision.decision_reason,
                if decision.candidates.is_empty() {
                    "-".to_string()
                } else {
                    decision.candidates.join(",")
                }
            );
        }
        Format::Pretty => {
            println!(
                "{} {}",
                brand::reach_glyph(Some(true), term),
                brand::literal(&decision.backend, term)
            );
            println!(
                "  {} {}",
                brand::dim("host   ", term),
                decision.host.as_deref().unwrap_or("(none)")
            );
            println!(
                "  {} {}",
                brand::dim("reason ", term),
                decision.decision_reason
            );
            println!("  {} {}", brand::dim("source ", term), decision.source_ip);
            // The list is what Head would try in order, so the one it chose is
            // already first; showing the rest is the failover story.
            if decision.candidates.len() > 1 {
                println!("  {}", brand::dim("failover", term));
                for (rank, candidate) in decision.candidates.iter().skip(1).enumerate() {
                    println!(
                        "    {}  {candidate}",
                        brand::dim(&format!("{}.", rank + 2), term)
                    );
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bare_host_and_port_gets_a_scheme() {
        assert_eq!(
            endpoint("localhost:8080", "/health"),
            "http://localhost:8080/health"
        );
        assert_eq!(
            endpoint("127.0.0.1:80", "/health"),
            "http://127.0.0.1:80/health"
        );
    }

    #[test]
    fn an_explicit_scheme_is_left_alone() {
        assert_eq!(
            endpoint("https://head.example.com", "/health"),
            "https://head.example.com/health"
        );
        assert_eq!(
            endpoint("http://localhost:8080", "/_radii/decision"),
            "http://localhost:8080/_radii/decision"
        );
    }

    #[test]
    fn a_trailing_slash_does_not_double_up() {
        assert_eq!(
            endpoint("http://localhost:8080/", "/health"),
            "http://localhost:8080/health"
        );
        assert_eq!(
            endpoint("localhost:8080/", "/health"),
            "http://localhost:8080/health"
        );
    }

    #[test]
    fn graph_states_colour_by_what_they_mean_for_routing() {
        // Without colour every state renders as itself, so the mapping is
        // asserted on the tinted variant instead.
        let term = Term {
            stdout_is_tty: true,
            wt_session: true,
            ..Term::default()
        };
        assert!(graph_state("fresh", &term).contains("22"), "fresh is Reach");
        assert!(
            graph_state("stale", &term).contains("242"),
            "stale is Severed"
        );
        assert!(
            graph_state("never_refreshed", &term).contains("242"),
            "never_refreshed is Severed"
        );
        assert!(
            graph_state("not_configured", &term).contains("124"),
            "not_configured is Unknown"
        );
    }
}
