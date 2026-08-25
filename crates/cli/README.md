# radii-cli

Operator CLI (`radii`) for exercising Crawl and planning routes offline.

## Commands

```bash
cargo run -p radii-cli -- hello --addr 127.0.0.1:7100 --node-id node-a --roles crawl
cargo run -p radii-cli -- report --addr 127.0.0.1:7100 \
  --from node-a --target node-b --protocol radii --reachable true --rtt-ms 42
cargo run -p radii-cli -- plan --source a --target c --protocols radii < reports.jsonl
```

## Today

- `hello` / `report` send framed Radii messages and print acks when present
- `plan` reads JSONL `ReachabilityReport` lines from stdin and prints scored paths
- `hello` / `report` accept `--tls-cert` / `--tls-key` / `--tls-ca` to speak mTLS to a `[tls]`-enabled Crawl or Head bridge (all three or none — see [`docs/tls.md`](../../docs/tls.md))

## Next

- Query live Crawl snapshots
- Launch local node helpers without hunting binaries
