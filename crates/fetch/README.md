# radii-fetch

Fetch is the delivery compartment. In this foundation it is a TCP tunnel used to forward traffic toward a configured upstream (often behind Head).

## Run

```bash
cargo run -p radii-fetch -- --config crates/fetch/fetch.example.toml
```

## Today

- Accepts inbound TCP on `bind`
- Tunnels bidirectionally to `upstream`
- Strips `ssh://` and `tcp://` prefixes from upstream addresses

## Next

- Consume Crawl graph snapshots for path selection
- Failover / retry across candidates
- Encrypt and authenticate relay links
- Move beyond static single-upstream tunnels
