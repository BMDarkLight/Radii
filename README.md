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
- Authenticated peers and authorized routes — opt-in mutual TLS ships (see [`docs/tls.md`](docs/tls.md)); not yet mandatory by default

## Non-goals (for now)

- Full CDN feature parity
- Application-level content logic
- Heavy control-plane features before routing is stable

## Workspace

```
crates/
  core/     shared graph/routing types, logging, protocol registry
  proto/    RadiiMessage + length-prefixed framing + mutual TLS
  crawl/    discovery listener
  head/     HTTP entry + decision engine + Radii→Crawl bridge
  fetch/    TCP tunnel delivery
  cli/      operator probe + offline planner (`radii`)
docs/       operational docs (mutual TLS setup, key lifecycle)
scripts/    dev tooling (throwaway cert generation for local TLS testing)
```

Stack: Rust 2021, tokio, axum (Head), clap, serde/toml, tracing, postcard.

## Build

```bash
cargo build --workspace
cargo test --workspace
```

Release binaries for Linux (x86_64, aarch64, riscv64), macOS, and Windows (x86_64 and aarch64) can be built via the [CD workflow](.github/workflows/cd.yml) (`radii-<target>` artifacts). It's currently manual-only (`workflow_dispatch`) — the project isn't at a release stage yet — rather than triggered automatically on `main` / version tags.

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

Read the graph back, plan over it, and ask Head where a host would go:

```bash
cargo run -p radii-cli -- graph --addr 127.0.0.1:7100
cargo run -p radii-cli -- plan --addr 127.0.0.1:7100 --source node-a --target node-b --protocols radii
cargo run -p radii-cli -- health --url localhost:8080
cargo run -p radii-cli -- decision --url localhost:8080 --host example.com
```

Against a `[tls]`-enabled Crawl/Head, add `--tls-cert`, `--tls-key`, and `--tls-ca` to `hello`, `report`, `graph` and `plan --addr` — see [`docs/tls.md`](docs/tls.md).

The CLI's `hello` command only sends one `NodeHello`; a real participant needs to repeat it periodically (well under Crawl's default 60s liveness TTL, `node_ttl_ms`) to stay live in Crawl's registry.

Plan routes from JSONL reports on stdin:

```bash
printf '%s\n' \
  '{"from":"a","target":"b","protocol":"radii","reachable":true,"rtt_ms":50}' \
  '{"from":"b","target":"c","protocol":"radii","reachable":true,"rtt_ms":40}' \
| cargo run -p radii-cli -- plan --source a --target c --protocols radii
```

## What works today

- **Crawl:** accepts `NodeHello`, probes, and reports over the Radii TCP protocol; keeps an in-memory view; acknowledges messages. Advertised node addresses are role-tagged, so a single registry entry can describe several listeners. Both Fetch and Head resolve the `relay` role — a chain terminates at the target's relay listener, whichever of them opened it — so a node that should be reachable needs `--listen-addr relay=HOST:PORT`. No other role is resolved today.
- **Head:** a reverse proxy. It forwards HTTP requests to the backend it decides on and streams the response back, reaching graph-resolved backends over source-routed relay chains and failing over across ranked candidates when a chain will not open. `/health` and `/_radii/decision` are answered locally; everything else is proxied. Statically configured backends (host map, default) are dialed directly, since they carry no node identity. A fresh chain per request is a known limitation — see [`crates/head/README.md`](crates/head/README.md). Optional Radii listener that forwards to Crawl.
- **Fetch:** TCP tunnel from `bind` to an upstream, reached either directly or over a source-routed chain of relays. Routes come from Crawl's reachability graph as a ranked candidate list spanning several paths *and* several target nodes; a failed candidate falls over to the next, and an exhausted list falls back to the static `upstream` (`ssh://` / `tcp://` prefixes stripped). When both the originating and terminal nodes have `[tunnel_tls]` identities configured, relays carry end-to-end-encrypted bytes they cannot read; without those identities the end-to-end layer falls back to plaintext and a carrying relay can read it. Relaying is opt-in per node (`[relay]`), requires mutual TLS, and is bounded by per-peer and global concurrency caps, a handshake deadline, and an idle deadline.
- **core/cli:** graph snapshot + route planner. The `radii` CLI now covers all three compartments: `hello`/`report`/`graph` against Crawl — `graph` reads the registry and reachability graph back out, marking each node reachable, severed or unprobed — `plan` against either a live Crawl (`--addr`) or JSONL on stdin, and `health`/`decision` against a Head. Output is a table on a terminal, stable `key=value` lines when piped, or `--json`.
- **Security:** opt-in mutual TLS (peer authentication + transport encryption + route authorization) for the Radii protocol and Fetch's tunnel data path; mandatory mutual TLS on the relay listener, with admission by CA membership (narrowable via `allow_peers`) and enforced resource bounds — see [`docs/tls.md`](docs/tls.md) and [`SECURITY.md`](SECURITY.md).

## Configuration

See example files:

- `crates/crawl/crawl.example.toml`
- `crates/head/head.example.toml`
- `crates/fetch/fetch.example.toml`

For mutual TLS setup (certificate provisioning, rotation, revocation), see [`docs/tls.md`](docs/tls.md).

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

Licensed under the **GNU Affero General Public License v3.0 (AGPL-3.0)**, with additional terms permitted under AGPLv3 Section 7. See [LICENSE](LICENSE).

This means: you're free to use, study, modify, and redistribute this code, including running it as a network service — but any modified version (or service built on one) must also be released as source under AGPL-3.0, must keep author attribution intact, and must be clearly marked as a different, unaffiliated project (see the Trademark Notice below and the additional terms in [LICENSE](LICENSE)).

### Trademark Notice

"Radii," the Radii name, and its logo/branding are **not** licensed under AGPL-3.0 and are not covered by the code license above. They are trademarks/branding of the original author. The AGPL-3.0 license grants rights to the *source code* — it does not grant permission to use the "Radii" name, logo, or branding for a fork, modified version, or derivative service.

If you fork or modify this project, please:
- Use a different name and logo that isn't confusingly similar to "Radii"
- Clearly state that your version is unaffiliated with and not endorsed by the original project

## Author

Built with ❤️ by **Behdad**