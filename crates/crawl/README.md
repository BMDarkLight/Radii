# radii-crawl

Crawl is Radii’s discovery compartment. It listens for proprietary Radii protocol messages, records node hellos and reachability reports in memory, and acknowledges clients.

## Run

```bash
cargo run -p radii-crawl -- --config crates/crawl/crawl.example.toml
```

## Today

- TCP listener (`bind` in config)
- Handles `NodeHello`, `ReachabilityProbe`, `ReachabilityReport`, and `FromHead`
- In-memory node address map + report list
- Ack replies for accepted messages

## Next

- Persist and expire graph snapshots
- Gossip / sync between Crawl agents
- Expose snapshots for Fetch to consume
- Probe scheduling and NAT traversal helpers
