# radii-cli

Operator CLI (`radii`) for Crawl's discovery surface, route planning, and Head's
control plane.

## Commands

Grouped in `--help` the way the system is, one section per compartment.

### Discovery — Crawl

```bash
radii hello --addr 127.0.0.1:7100 --node-id node-a --roles crawl \
  --listen-addr relay=127.0.0.1:2224
radii report --addr 127.0.0.1:7100 \
  --from node-a --target node-b --protocol radii --reachable true --rtt-ms 42
radii graph --addr 127.0.0.1:7100
```

`graph` reads the node registry and reachability graph back out — the same
`GraphQuery` Head polls to route on. Each node carries the state the graph has
actually observed:

| State | Meaning |
|---|---|
| `reachable` | at least one live observation touches it |
| `severed` | observed, and every observation says unreachable |
| `unprobed` | known from a `NodeHello`, but nothing has probed it |

`unprobed` is not `severed`. A node that has only just registered, or that no
agent has reached yet, is an absence of evidence rather than evidence of
absence — and one live path is enough to call a node reachable however many
dead ones sit beside it.

### Routing — Fetch and the planner

```bash
# against the live graph
radii plan --addr 127.0.0.1:7100 --source node-a --target node-c --protocols radii

# offline, from JSONL ReachabilityReport lines
radii plan --source a --target c --protocols radii < reports.jsonl
```

`--addr` plans over what Crawl actually holds, which is the view Head and Fetch
route on. Without it, reports are read from stdin as before.

### Control plane — Head

```bash
radii health --url localhost:8080
radii decision --url localhost:8080 --host example.com
```

`health` reports Head's status and how fresh its copy of the graph is —
`fresh` is the only state it can route from, `not_configured` is a deliberate
choice, and the rest are degradation. `decision` says where a host would go,
why, and what Head would fail over to if the first candidate's chain would not
open. A bare `host:port` gets `http://` filled in.

## Output

Three shapes, so the same command serves a human and a script:

- a terminal gets aligned columns, the reachability glyphs and colour
- a pipe gets stable `key=value` lines
- `--json` gets one JSON document, on `graph`, `plan`, `health` and `decision`

`plan`'s piped output is unchanged from before `--json` existed; anything
parsing it keeps working.

Colour follows `NO_COLOR`, and the banner follows
`RADII_BANNER=braille|ascii|none` — see
[`assets/brand/ascii/README.md`](../../assets/brand/ascii/README.md).

## mTLS

`hello`, `report`, `graph` and `plan --addr` accept `--tls-cert` /
`--tls-key` / `--tls-ca` (all three or none) plus an optional `--tls-crl`, to
speak mTLS to a `[tls]`-enabled Crawl or Head bridge — see
[`docs/tls.md`](../../docs/tls.md).

## Next

- Watch mode for `graph`, so churn is visible without re-running
- Probe from the CLI, rather than only submitting observations made elsewhere
- Launch local node helpers without hunting binaries
