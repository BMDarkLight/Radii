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

mod brand;
mod graph;
mod head;

use anyhow::Result;
use clap::{Args, CommandFactory, FromArgMatches, Parser, Subcommand};
use radii_core::routing::{
    DefaultScorer, GraphSnapshot, NodeId, ProtocolId, ReachabilityReport, RoutePlanner,
    RouteRequest,
};
use radii_proto::tls::{TlsIdentity, TlsIdentityConfig};
use radii_proto::RadiiMessage;
use std::io::{stdin, BufRead};
use std::path::PathBuf;

/// Commands grouped the way the system is: Crawl's discovery surface, then
/// Fetch's routing surface. A flat list of three hides the architecture that
/// the whole project is organised around.
///
/// `every_command_is_grouped` keeps this honest when a command is added.
const GROUPS: &[(&str, &[&str])] = &[
    ("Discovery", &["hello", "report", "graph"]),
    ("Routing", &["plan"]),
    ("Control plane", &["health", "decision"]),
];

#[derive(Parser)]
#[command(
    name = "radii",
    version,
    about = brand::TAGLINE,
    styles = brand::clap_styles(),
    disable_help_subcommand = true,
    arg_required_else_help = true
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

/// Renders the grouped command list plus the reachability legend, reading the
/// names and descriptions back off the built `Command` so this can never drift
/// from what the CLI actually accepts.
fn command_sections(cmd: &clap::Command, term: &brand::Term) -> String {
    let mut out = String::new();
    for (i, (heading, names)) in GROUPS.iter().enumerate() {
        if i > 0 {
            out.push('\n');
        }
        out.push_str(&brand::heading(heading, term));
        out.push('\n');
        for name in *names {
            let Some(sub) = cmd.get_subcommands().find(|s| s.get_name() == *name) else {
                continue;
            };
            let about = sub.get_about().map(|a| a.to_string()).unwrap_or_default();
            // Pad on the name's own width: a tint adds bytes that occupy no
            // columns, so `{:<10}` on the styled string would indent short.
            let pad = " ".repeat(10usize.saturating_sub(name.chars().count()));
            out.push_str(&format!("  {}{pad}{about}\n", brand::literal(name, term)));
        }
    }
    out.truncate(out.trim_end().len());
    out
}

/// The banner already carries the name and the tagline, so the template drops
/// clap's about line. `{subcommands}` goes too — clap has no notion of
/// subcommand groups, so the compartments come through `{after-help}` — and
/// that puts commands ahead of options, which is the order they matter in.
fn help_template(term: &brand::Term) -> String {
    format!(
        "{{before-help}}{{usage-heading}} {{usage}}{{after-help}}\n\n{}\n{{options}}\n\n{}\n",
        brand::heading("Options", term),
        brand::legend(term),
    )
}

fn build_command(term: &brand::Term) -> clap::Command {
    let base = Cli::command();
    let after = command_sections(&base, term);
    let mut cmd = base.help_template(help_template(term)).after_help(after);
    if let Some(banner) = brand::banner(term, env!("CARGO_PKG_VERSION")) {
        cmd = cmd.before_help(banner);
    }
    // clap prints `{name} {version}`, so the long form adds the tagline rather
    // than the mark — artwork behind that prefix reads as a stray word.
    // `-V` stays the bare one-liner scripts parse.
    cmd.long_version(format!("{}\n{}", env!("CARGO_PKG_VERSION"), brand::TAGLINE))
}

/// mTLS options for talking to a Crawl (or Crawl-speaking) listener that has
/// `[tls]` configured. All three must be given together, or none at all —
/// mixing plaintext and TLS on one connection isn't meaningful.
#[derive(Args, Clone)]
struct TlsArgs {
    /// This client's TLS certificate (PEM). Requires --tls-key and --tls-ca.
    #[arg(long)]
    tls_cert: Option<PathBuf>,
    /// This client's TLS private key (PEM).
    #[arg(long)]
    tls_key: Option<PathBuf>,
    /// CA bundle (PEM) used to verify the server's certificate.
    #[arg(long)]
    tls_ca: Option<PathBuf>,
    /// Optional certificate revocation list (PEM). When given, a server
    /// whose certificate it names is refused.
    #[arg(long)]
    tls_crl: Option<PathBuf>,
}

impl TlsArgs {
    fn load(&self) -> Result<Option<TlsIdentity>> {
        match (&self.tls_cert, &self.tls_key, &self.tls_ca) {
            (None, None, None) => Ok(None),
            (Some(cert), Some(key), Some(ca)) => Ok(Some(TlsIdentity::load(&TlsIdentityConfig {
                cert: cert.clone(),
                key: key.clone(),
                ca: ca.clone(),
                crl: self.tls_crl.clone(),
            })?)),
            _ => anyhow::bail!("--tls-cert, --tls-key, and --tls-ca must all be provided together"),
        }
    }
}

#[derive(Subcommand)]
enum Commands {
    /// Send a Radii NodeHello message
    Hello {
        #[arg(long)]
        addr: String,
        #[arg(long)]
        node_id: String,
        #[arg(long, value_delimiter = ',')]
        roles: Vec<String>,
        #[arg(long = "listen-addr", value_parser = parse_listen_addr)]
        listen_addrs: Vec<radii_proto::ListenAddr>,
        #[command(flatten)]
        tls: TlsArgs,
    },
    /// Send a reachability report
    Report {
        #[arg(long)]
        addr: String,
        #[arg(long)]
        from: String,
        #[arg(long)]
        target: String,
        #[arg(long)]
        protocol: String,
        #[arg(long, num_args = 1, value_parser = clap::builder::BoolishValueParser::new())]
        reachable: bool,
        #[arg(long)]
        rtt_ms: Option<u32>,
        #[arg(long)]
        observed_addr: Option<String>,
        #[command(flatten)]
        tls: TlsArgs,
    },
    /// Read Crawl's node registry and reachability graph
    Graph {
        #[arg(long)]
        addr: String,
        /// Emit one JSON document instead of a table.
        #[arg(long)]
        json: bool,
        #[command(flatten)]
        tls: TlsArgs,
    },
    /// Plan ranked routes, from a live Crawl or from JSONL on stdin
    Plan {
        #[arg(long)]
        source: String,
        #[arg(long)]
        target: String,
        #[arg(long, value_delimiter = ',')]
        protocols: Vec<String>,
        #[arg(long, default_value_t = 4)]
        max_hops: usize,
        #[arg(long, default_value_t = 3)]
        limit: usize,
        /// Plan against this Crawl's graph. Without it, reports are read as
        /// JSONL on stdin.
        #[arg(long)]
        addr: Option<String>,
        #[arg(long)]
        json: bool,
        #[command(flatten)]
        tls: TlsArgs,
    },
    /// Check a Head's status and how fresh its graph is
    Health {
        /// Head's base URL. A bare host:port gets http:// filled in.
        #[arg(long)]
        url: String,
        #[arg(long)]
        json: bool,
    },
    /// Ask a Head where a host would go, and what it would fail over to
    Decision {
        #[arg(long)]
        url: String,
        /// The Host header to decide on.
        #[arg(long)]
        host: Option<String>,
        #[arg(long)]
        json: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let _log_guard = radii_core::logging::init("radii-cli")?;
    let term = brand::Term::detect();
    let matches = build_command(&term).get_matches();
    let cli = Cli::from_arg_matches(&matches).unwrap_or_else(|e| e.exit());

    match cli.command {
        Commands::Hello {
            addr,
            node_id,
            roles,
            listen_addrs,
            tls,
        } => send_hello(&addr, node_id, roles, listen_addrs, tls).await,
        Commands::Report {
            addr,
            from,
            target,
            protocol,
            reachable,
            rtt_ms,
            observed_addr,
            tls,
        } => {
            send_report(
                &addr,
                from,
                target,
                protocol,
                reachable,
                rtt_ms,
                observed_addr,
                tls,
            )
            .await
        }
        Commands::Graph { addr, json, tls } => {
            let tls = tls.load()?;
            graph::run(&addr, tls.as_ref(), json, &term).await
        }
        Commands::Plan {
            source,
            target,
            protocols,
            max_hops,
            limit,
            addr,
            json,
            tls,
        } => {
            plan_routes(
                source, target, protocols, max_hops, limit, addr, json, tls, &term,
            )
            .await
        }
        Commands::Health { url, json } => head::health(&url, json, &term).await,
        Commands::Decision { url, host, json } => {
            head::decision(&url, host.as_deref(), json, &term).await
        }
    }
}

async fn send_hello(
    addr: &str,
    node_id: String,
    roles: Vec<String>,
    listen_addrs: Vec<radii_proto::ListenAddr>,
    tls: TlsArgs,
) -> Result<()> {
    let tls = tls.load()?;
    let mut stream = radii_proto::tls::dial(addr, tls.as_ref()).await?;
    let reply = radii_proto::send_hello_on(&mut stream, node_id, roles, listen_addrs).await?;
    print_reply(reply);
    Ok(())
}

/// Parses `role=addr`.
///
/// `role=addr` rather than `addr:role` because a colon already means a port,
/// and doubly so in an IPv6 literal.
fn parse_listen_addr(value: &str) -> Result<radii_proto::ListenAddr, String> {
    let (role, addr) = value
        .split_once('=')
        .ok_or_else(|| format!("expected role=addr, got {value:?}"))?;
    if role.is_empty() || addr.is_empty() {
        return Err(format!(
            "expected role=addr with both parts set, got {value:?}"
        ));
    }
    Ok(radii_proto::ListenAddr {
        addr: addr.to_string(),
        role: role.to_string(),
    })
}

// Mirrors radii_proto::send_report_on's parameter shape, which itself mirrors
// the ReachabilityReport message's fields.
#[allow(clippy::too_many_arguments)]
async fn send_report(
    addr: &str,
    from: String,
    target: String,
    protocol: String,
    reachable: bool,
    rtt_ms: Option<u32>,
    observed_addr: Option<String>,
    tls: TlsArgs,
) -> Result<()> {
    let tls = tls.load()?;
    let mut stream = radii_proto::tls::dial(addr, tls.as_ref()).await?;
    let reply = radii_proto::send_report_on(
        &mut stream,
        from,
        target,
        protocol,
        reachable,
        rtt_ms,
        observed_addr,
    )
    .await?;
    print_reply(reply);
    Ok(())
}

// Both send_hello_on and send_report_on fuse the write and the ack-read into
// a single Result. Every message handler in this codebase (crates/crawl/src/server.rs)
// always sends an Ack for every message type it recognizes, so the historical
// "some early listeners may close without an ack" scenario no longer applies to
// any real Radii component today. Any error here is a genuine connection failure
// (on either the write or the read side) and propagates as a hard CLI error via `?`.
fn print_reply(message: RadiiMessage) {
    match message {
        RadiiMessage::Ack { status } => {
            tracing::info!(%status, "received ack");
            println!("ack={status}");
        }
        other => {
            tracing::info!(message = ?other, "received reply");
            println!("reply={other:?}");
        }
    }
}

/// Plans over a graph taken either from a live Crawl or from JSONL on stdin.
///
/// The stdin path is the offline planner the CLI has always had; `--addr`
/// plans against what Crawl actually holds, which is the same view Head and
/// Fetch route on.
#[allow(clippy::too_many_arguments)]
async fn plan_routes(
    source: String,
    target: String,
    protocols: Vec<String>,
    max_hops: usize,
    limit: usize,
    addr: Option<String>,
    json: bool,
    tls: TlsArgs,
    term: &brand::Term,
) -> Result<()> {
    let snapshot = match addr {
        Some(addr) => {
            let tls = tls.load()?;
            let (_nodes, reports) = graph::fetch(&addr, tls.as_ref()).await?;
            graph::to_snapshot(&reports)
        }
        None => {
            let mut reports = Vec::new();
            let stdin = stdin();
            for line in stdin.lock().lines() {
                let line = line?;
                if line.trim().is_empty() {
                    continue;
                }
                let report: ReachabilityReport = serde_json::from_str(&line)?;
                reports.push(report);
            }
            GraphSnapshot::from_reports(reports)
        }
    };

    // A snapshot at its size cap drops links rather than growing without
    // bound, so a plan made from one is partial. Say so on stderr, which
    // leaves stdout parseable.
    if snapshot.dropped_links() > 0 {
        eprintln!(
            "warning: the graph exceeded the local size cap; {} link(s) dropped, planning from a partial view",
            snapshot.dropped_links()
        );
    }

    let allowed = protocols
        .into_iter()
        .map(ProtocolId::new)
        .collect::<Vec<_>>();
    let request = RouteRequest {
        source: NodeId(source),
        target: NodeId(target),
        allowed_protocols: allowed,
        max_hops,
    };

    let planner = RoutePlanner::new(DefaultScorer);
    let results = planner.plan(&snapshot, &request, limit);

    match brand::format(term, json) {
        brand::Format::Json => {
            let routes = results
                .iter()
                .map(|route| {
                    serde_json::json!({
                        "score": route.score,
                        "protocol": route.protocol.0,
                        "path": route.hops.iter().map(|n| n.0.as_str()).collect::<Vec<_>>(),
                    })
                })
                .collect::<Vec<_>>();
            println!("{}", serde_json::json!({ "routes": routes }));
        }
        // The original key=value line, unchanged: something out there parses it.
        brand::Format::Plain => {
            for route in &results {
                let names = route.hops.iter().map(|n| n.0.as_str()).collect::<Vec<_>>();
                println!(
                    "score={:.1} protocol={} path={}",
                    route.score,
                    route.protocol.0,
                    names.join(" -> ")
                );
            }
        }
        brand::Format::Pretty => {
            if results.is_empty() {
                println!("{}", brand::dim("no route", term));
            }
            for (rank, route) in results.iter().enumerate() {
                let names = route.hops.iter().map(|n| n.0.as_str()).collect::<Vec<_>>();
                println!(
                    "{} {:>2}  {:>6.1}  {:<8}  {}",
                    brand::reach_glyph(Some(true), term),
                    rank + 1,
                    route.score,
                    route.protocol.0,
                    names.join(" \u{2192} "),
                );
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_command_tree_is_valid() {
        Cli::command().debug_assert();
    }

    /// The grouped help is hand-curated, so a command added to `Commands` and
    /// forgotten in `GROUPS` would silently vanish from `--help`.
    #[test]
    fn every_command_is_grouped() {
        let cmd = Cli::command();
        for sub in cmd.get_subcommands() {
            let name = sub.get_name();
            let groups = GROUPS
                .iter()
                .filter(|(_, names)| names.contains(&name))
                .count();
            assert_eq!(groups, 1, "{name} should appear in exactly one help group");
        }
    }

    #[test]
    fn the_grouped_help_lists_every_command_with_its_description() {
        let cmd = Cli::command();
        let sections = command_sections(&cmd, &brand::Term::default());
        for sub in cmd.get_subcommands() {
            assert!(
                sections.contains(sub.get_name()),
                "{} missing from the help sections",
                sub.get_name()
            );
        }
        assert!(sections.contains("Discovery"));
        assert!(sections.contains("Routing"));
    }

    #[test]
    fn tls_args_none_means_plaintext() {
        let args = TlsArgs {
            tls_cert: None,
            tls_key: None,
            tls_ca: None,
            tls_crl: None,
        };
        assert!(args.load().unwrap().is_none());
    }

    #[test]
    fn tls_args_reject_partial_configuration() {
        let args = TlsArgs {
            tls_cert: Some("cert.pem".into()),
            tls_key: None,
            tls_ca: None,
            tls_crl: None,
        };
        assert!(args.load().is_err());
    }

    #[test]
    fn parses_role_equals_addr() {
        let parsed = parse_listen_addr("relay=10.0.0.5:2224").unwrap();
        assert_eq!(parsed.role, "relay");
        assert_eq!(parsed.addr, "10.0.0.5:2224");
    }

    #[test]
    fn keeps_ipv6_colons_in_the_address() {
        let parsed = parse_listen_addr("http=[::1]:9000").unwrap();
        assert_eq!(parsed.addr, "[::1]:9000");
    }

    #[test]
    fn rejects_a_value_without_a_role() {
        assert!(parse_listen_addr("10.0.0.5:2224").is_err());
        assert!(parse_listen_addr("=10.0.0.5:2224").is_err());
        assert!(parse_listen_addr("relay=").is_err());
    }
}
