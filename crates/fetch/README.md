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

## Next

- Failover / retry across candidates within a single connection
- Encrypt and authenticate relay links
- Move beyond single-upstream tunnels (multiplexed / multi-target delivery)
