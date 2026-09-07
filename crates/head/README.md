# radii-head

Head is the public access plane. It accepts inbound HTTP, decides a backend from Crawl's live reachability graph (falling back to a static host map, then a default), and can bridge Radii protocol traffic to Crawl.

## Run

```bash
cargo run -p radii-head -- --config crates/head/head.example.toml
```

## Today

- HTTP listener with `GET /health`
- Catch-all handler returns JSON: source IP, host, chosen backend, decision reason
- Decision engine, in priority order:
  1. **Graph route** (optional, `[graph]` config) — polls Crawl for its reachability graph on an interval and plans a route from Head's `source_node_id` to the node mapped to the request host in `node_map`; resolves to that node's registered listen address. Falls through if the host isn't mapped or no reachable route exists.
  2. **Host map** — static `routing.host_map` lookup.
  3. **Default** — `routing.default_backend`.
- Optional Radii TCP bridge that wraps inbound messages as `FromHead` and forwards to Crawl over a single persistent upstream session per client connection (opened lazily on the first message, reconnected transparently if Crawl drops it) rather than dialing Crawl anew for every message
- Optional mutual TLS (`[tls]` config): requires mTLS on the bridge listener *and* on every outbound connection Head makes to Crawl (the bridge relay, the graph poller). See [`docs/tls.md`](../../docs/tls.md).

## Next

- Reverse-proxy HTTP to the selected backend
- Authenticated control-plane surface
- Live config reload
- HTTPS / SSH / DNS surfaces (deferred until the HTTP path is solid)

## Ranked backend candidates

A host in `[graph.node_map]` may name several nodes:

```toml
[graph.node_map]
"example.com" = ["node-b", "node-c"]
"single.example.com" = "node-b"     # the bare-string form still works
```

Head plans to all of them, ranks the reachable ones by the same cost function
the route planner uses, and reports up to `max_candidates` of them in the
decision JSON:

```json
{
  "backend": "10.0.0.12:9000",
  "candidates": ["10.0.0.12:9000", "10.0.0.11:9000"],
  "decision_reason": "graph_route"
}
```

`backend` is always the first candidate — on the graph path, on the
host-map and default fallbacks, and on the no-policy-matched sentinel alike —
so existing consumers reading only `backend` are unaffected, and a consumer
iterating `candidates` never has to special-case an empty list.

**Head does not proxy**, so it cannot fail over itself — it returns a decision
and the caller dials it. The `candidates` list is what lets that caller fail
over, and it is the seam a future reverse proxy will read.

### One caveat worth knowing

Head and Fetch read the *same* node registry but disagree about what an
address means. Fetch treats a node's advertised address as a relay listener —
one that requires mutual TLS and a `TunnelOpen` preamble. Head assumes the
plain-backend reading and hands the address to its caller to dial directly. A
node advertising a relay listener will therefore be given to Head's callers as
though it were an HTTP backend, and the failure will look like a backend
outage. Resolving this needs separate address roles per node, or a role tag in
the registry; both are protocol changes. See the residual-risk table in
[`SECURITY.md`](../../SECURITY.md).
