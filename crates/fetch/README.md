# radii-fetch

Fetch is the delivery compartment. In this foundation it is a TCP tunnel used to forward traffic toward an upstream (often behind Head) — either a static address or one resolved live from Crawl's reachability graph.

## Run

```bash
cargo run -p radii-fetch -- --config crates/fetch/fetch.example.toml
```

## Today

- Accepts inbound TCP on `bind`
- Tunnels bidirectionally to an upstream, resolved per new connection:
  - **Graph target** (optional, `[graph]` config) — polls Crawl on an interval and plans a route from `source_node_id` to `target_node_id`, resolving to that node's registered listen address.
  - **Static `upstream`** — used when `[graph]` isn't configured, or as the fallback while no reachable route exists yet.
- Strips `ssh://` and `tcp://` prefixes from upstream addresses
- Optional mutual TLS, independently configurable for two distinct connections:
  - `[tls]` — the graph poller's connection to Crawl (mirrors Head/Crawl)
  - `[tunnel_tls.listener]` / `[tunnel_tls.upstream]` — the tunnel data path itself; require inbound clients to authenticate, and/or dial the upstream over mTLS, independently
  
  See [`docs/tls.md`](../../docs/tls.md).

## Next

- Failover / retry across candidates within a single connection
- Move beyond single-upstream tunnels (multiplexed / multi-target delivery)
