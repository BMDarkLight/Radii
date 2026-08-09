use anyhow::Result;
use clap::{Parser, Subcommand};
use radii_core::routing::{
    DefaultScorer, GraphSnapshot, NodeId, ProtocolId, ReachabilityReport, RoutePlanner,
    RouteRequest,
};
use radii_proto::{read_message, write_message, RadiiMessage};
use std::io::{stdin, BufRead};
use tokio::net::TcpStream;

#[derive(Parser)]
#[command(name = "radii", version, about = "Radii operator CLI")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
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
        } => {
            send_message(
                &addr,
                RadiiMessage::NodeHello {
                    node_id,
                    roles,
                    listen_addrs,
                },
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

async fn send_message(addr: &str, message: RadiiMessage) -> Result<()> {
    let mut stream = TcpStream::connect(addr).await?;
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
