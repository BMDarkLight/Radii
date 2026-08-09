# Radii

A runtime for header-less content delivery. Radii routes traffic over dedicated infrastructure or P2P mesh paths so services stay reachable despite IP churn, NAT, and partial network failure.

**Status:** early foundation — not production-ready. The workspace ships the three-compartment architecture and a minimal working path (discovery, decision, tunnel). Read [`SECURITY.md`](SECURITY.md) before exposing any listener.

## Why Radii

- Survive IP churn and shifting topologies.
- Prefer continuity of reachability over a single “best” path.
- Run across heterogeneous nodes: access points, resource nodes, data nodes, and donated public nodes.
- Reduce reliance on centralized choke points so regional filtering or blackouts cannot fully suppress a service.

## Architecture

Radii is split into three compartments with clear boundaries:

| Compartment | Role |
|---|---|
| **Crawl** | Discovery and reachability mapping |
| **Head** | Public access plane and control-plane bridge |
| **Fetch** | Path selection and traffic delivery |

```
     [Crawl Agents] -----> [Crawl Graph / Reachability]
            |                          |
            |                          v
            |                     [Head / Control]
            |                          |
            v                          v
       [Node Links]  <-------->   [Fetch / Routing]
```

Conceptual flow:

1. Crawl agents probe and exchange reachability data.
2. Crawl aggregates a time-bounded graph snapshot.
3. Head exposes a stable entry point and control metadata.
4. Fetch uses that metadata to deliver traffic over a viable path.

## Design goals

- Resilience under churn, NAT, and partial outages
- Observability of reachability and route health
- Low-dependency operation on diverse hosts
- Authenticated peers and authorized routes (early model)

## Non-goals (for now)

- Full CDN feature parity
- Application-level content logic
- Heavy control-plane features before routing is stable

## Workspace

```
crates/
  core/     shared graph/routing types, logging, protocol registry
  proto/    RadiiMessage + length-prefixed framing
  crawl/    discovery listener
  head/     HTTP entry + decision engine + Radii→Crawl bridge
  fetch/    TCP tunnel delivery
  cli/      operator probe + offline planner (`radii`)
```

Stack: Rust 2021, tokio, axum (Head), clap, serde/toml, tracing, bincode.

## Build

```bash
cargo build --workspace
cargo test --workspace
```

## Quick start

```bash
# Discovery
cargo run -p radii-crawl -- --config crates/crawl/crawl.example.toml

# Public access + Crawl bridge
cargo run -p radii-head -- --config crates/head/head.example.toml

# Delivery tunnel
cargo run -p radii-fetch -- --config crates/fetch/fetch.example.toml
```

Probe Crawl with the CLI:

```bash
cargo run -p radii-cli -- hello --addr 127.0.0.1:7100 --node-id node-a --roles crawl
cargo run -p radii-cli -- report --addr 127.0.0.1:7100 \
  --from node-a --target node-b --protocol radii --reachable true --rtt-ms 42
```

Plan routes from JSONL reports on stdin:

```bash
printf '%s\n' \
  '{"from":"a","target":"b","protocol":"radii","reachable":true,"rtt_ms":50}' \
  '{"from":"b","target":"c","protocol":"radii","reachable":true,"rtt_ms":40}' \
| cargo run -p radii-cli -- plan --source a --target c --protocols radii
```

## What works today

- **Crawl:** accepts `NodeHello`, probes, and reports over the Radii TCP protocol; keeps an in-memory view; acknowledges messages.
- **Head:** HTTP `/health`; other paths return a JSON backend decision (host map + default); optional Radii listener that forwards to Crawl.
- **Fetch:** TCP tunnel from `bind` to `upstream` (`ssh://` / `tcp://` prefixes stripped).
- **core/cli:** graph snapshot + route planner; CLI hello/report/plan.

## Configuration

See example files:

- `crates/crawl/crawl.example.toml`
- `crates/head/head.example.toml`
- `crates/fetch/fetch.example.toml`

## Next steps

Per-compartment detail lives in:

- [`crates/crawl/README.md`](crates/crawl/README.md)
- [`crates/head/README.md`](crates/head/README.md)
- [`crates/fetch/README.md`](crates/fetch/README.md)
- [`crates/cli/README.md`](crates/cli/README.md)

## Contributing

This project is early. Open an issue for proposed protocol or architecture changes before large experiments.

## Security

Radii is a network-facing project. See [`SECURITY.md`](SECURITY.md) for the threat model, known gaps, deployment checklist, and vulnerability reporting process. Do not expose Crawl / Radii / Fetch listeners to untrusted networks without additional controls.

## License

MIT — see [`LICENSE`](LICENSE).
