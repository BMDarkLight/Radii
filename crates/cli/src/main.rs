use anyhow::Result;
use clap::{Args, Parser, Subcommand};
use radii_core::routing::{
    DefaultScorer, GraphSnapshot, NodeId, ProtocolId, ReachabilityReport, RoutePlanner,
    RouteRequest,
};
use radii_proto::tls::{TlsIdentity, TlsIdentityConfig};
use radii_proto::{read_message, write_message, RadiiMessage};
use std::io::{stdin, BufRead};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "radii", version, about = "Radii operator CLI")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
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
}

impl TlsArgs {
    fn load(&self) -> Result<Option<TlsIdentity>> {
        match (&self.tls_cert, &self.tls_key, &self.tls_ca) {
            (None, None, None) => Ok(None),
            (Some(cert), Some(key), Some(ca)) => Ok(Some(TlsIdentity::load(&TlsIdentityConfig {
                cert: cert.clone(),
                key: key.clone(),
                ca: ca.clone(),
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
        #[arg(long, value_delimiter = ',')]
        listen_addrs: Vec<String>,
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
    /// Plan ranked routes from JSONL reachability reports on stdin
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
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let _log_guard = radii_core::logging::init("radii-cli")?;
    let cli = Cli::parse();

    match cli.command {
        Commands::Hello {
            addr,
            node_id,
            roles,
            listen_addrs,
            tls,
        } => {
            send_message(
                &addr,
                RadiiMessage::NodeHello {
                    node_id,
                    roles,
                    listen_addrs,
                },
                tls,
            )
            .await
        }
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
            send_message(
                &addr,
                RadiiMessage::ReachabilityReport {
                    from,
                    target,
                    protocol,
                    reachable,
                    rtt_ms,
                    observed_addr,
                },
                tls,
            )
            .await
        }
        Commands::Plan {
            source,
            target,
            protocols,
            max_hops,
            limit,
        } => plan_routes(source, target, protocols, max_hops, limit),
    }
}

async fn send_message(addr: &str, message: RadiiMessage, tls: TlsArgs) -> Result<()> {
    let tls = tls.load()?;
    let mut stream = radii_proto::tls::dial(addr, tls.as_ref()).await?;
    write_message(&mut stream, &message).await?;
    match read_message(&mut stream).await {
        Ok(RadiiMessage::Ack { status }) => {
            tracing::info!(%status, "received ack");
            println!("ack={status}");
        }
        Ok(other) => {
            tracing::info!(message = ?other, "received reply");
            println!("reply={other:?}");
        }
        Err(err) => {
            // Some early listeners may close without an ack; still treat send as success.
            tracing::warn!(error = %err, "no ack received");
        }
    }
    Ok(())
}

fn plan_routes(
    source: String,
    target: String,
    protocols: Vec<String>,
    max_hops: usize,
    limit: usize,
) -> Result<()> {
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

    let snapshot = GraphSnapshot::from_reports(reports);
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

    for route in results {
        let hops = route
            .hops
            .iter()
            .map(|n| n.0.as_str())
            .collect::<Vec<_>>()
            .join(" -> ");
        println!(
            "score={:.1} protocol={} path={}",
            route.score, route.protocol.0, hops
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls_args_none_means_plaintext() {
        let args = TlsArgs {
            tls_cert: None,
            tls_key: None,
            tls_ca: None,
        };
        assert!(args.load().unwrap().is_none());
    }

    #[test]
    fn tls_args_reject_partial_configuration() {
        let args = TlsArgs {
            tls_cert: Some("cert.pem".into()),
            tls_key: None,
            tls_ca: None,
        };
        assert!(args.load().is_err());
    }
}
