# radii-crawl

Crawl is Radii’s discovery compartment. It listens for proprietary Radii protocol messages, records node hellos and reachability reports in memory, and acknowledges clients.

## Run

```bash
cargo run -p radii-crawl -- --config crates/crawl/crawl.example.toml
```

## Today

- TCP listener (`bind` in config)
- Handles `NodeHello`, `ReachabilityProbe`, `ReachabilityReport`, `FromHead`, and `GraphQuery`
- In-memory node address map + report list
- Nodes carry free-form roles from `NodeHello` (e.g. `["wave"]`), returned via `GraphQuery`'s `NodeInfo.roles` — Crawl doesn't interpret them, just stores and reports them back
- Configurable node liveness (`node_ttl_ms`): a node that stops sending hellos drops out of `GraphQuery` replies once its TTL elapses
- Ack replies for accepted messages
- Optional mutual TLS (`[tls]` config): requires every connection to present a certificate from the trusted CA, and — when enabled — rejects `NodeHello`/`ReachabilityReport` claims whose `node_id`/`from` don't match the connecting peer's authenticated identity. See [`docs/tls.md`](../../docs/tls.md).

## Next

- Persist and expire graph snapshots
- Gossip / sync between Crawl agents
- Probe scheduling and NAT traversal helpers
- Replay protection / bounded clock skew for reports (see `SECURITY.md`)
