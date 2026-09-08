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

### Address roles

Head and Fetch read the same node registry, but each resolves a different
role from a node's advertised addresses: Head resolves the `http` role for
the backend it hands its callers, Fetch resolves the `relay` role for every
hop it plans. A node that should serve both must advertise both, e.g.
`--listen-addr relay=HOST:PORT --listen-addr http=HOST:PORT`.

## Proxying

Head forwards the request to the backend it decides on and streams the
response back. Bodies are never buffered in either direction, so memory per
connection stays constant regardless of upload or download size.

### Two ways to reach a backend

A **graph-resolved** backend is a *node*. Head opens a source-routed chain to
it; the chain terminates at that node's relay listener, which splices to the
node's own configured `upstream` — and that upstream is the web server. Head
therefore resolves `relay` addresses, exactly as Fetch does.

A **statically configured** backend (`[routing.host_map]`, `default_backend`)
carries no node identity at all — it came from the operator's own config and
may point at a host that is not part of the mesh. It is dialed directly, the
same way Fetch dials its static `upstream` fallback and for the same reason.
It has one address, so there is nothing to fail over to.

### The retry boundary

A candidate is retried **only when its chain failed to establish** — the
request was never delivered, so replaying it is unambiguous for any method,
POST included.

Once the request has been written, a failure is terminal and reaches the
client as a 502. Head cannot know whether the backend processed it, and
replaying could duplicate a POST. This is why no request body is buffered:
buffering exists only to enable replay, and replay stops at that boundary.

The rule is narrower than it sounds, because a relay dials its own upstream
*before* acknowledging a chain — so a dead origin fails at establishment, and
is covered.

### Headers

Hop-by-hop headers are stripped in both directions: `Connection`,
`Keep-Alive`, `Proxy-Authenticate`, `Proxy-Authorization`, `TE`, `Trailer`,
`Transfer-Encoding`, `Upgrade`, **and every header named inside the message's
own `Connection` header**. That last set is what implementations usually miss,
and forwarding one to a backend is request-smuggling surface.

`Host` is forwarded unchanged, so the backend can serve the right virtual
host — that is what makes the host-to-node mapping mean anything.

`X-Forwarded-For` gets the immediate peer appended to any inbound value. The
inbound value is **recorded, not believed**: any client can send one, Head
makes no access-control decision on it, and nothing downstream should treat it
as authenticated.

### Known limitation: a fresh chain per request

Chain setup is a TCP connect, a hop-local TLS handshake, a `TunnelOpen` round
trip, and an end-to-end TLS handshake — roughly three round trips.
Sub-millisecond on a LAN; 100ms+ per request over a WAN, which makes a page
with thirty assets unusable.

This is a deliberate first-version choice. Pooling chains would fix the
latency but holds a relay's concurrency slot continuously rather than per
request — on donated public nodes that is someone else's bandwidth and
someone else's `max_concurrent_per_peer` budget, held whether or not traffic
flows. That deserves its own decision.
