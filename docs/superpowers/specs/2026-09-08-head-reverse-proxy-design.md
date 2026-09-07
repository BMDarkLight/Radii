# Head as a Reverse Proxy

**Status:** design, approved 2026-09-08
**Implements:** follow-up #1 of `docs/superpowers/specs/2026-09-05-source-routing-and-ranked-candidates-design.md`
**Related:** `docs/superpowers/specs/2026-09-07-role-tagged-listen-addresses-design.md`

## The problem

Head answers every request with a JSON document describing which backend it
*would* pick:

```json
{"source_ip":"…","host":"…","backend":"10.0.0.12:9000","candidates":[…],"decision_reason":"graph_route"}
```

A browser pointed at a Radii-fronted domain gets that JSON, not the site. So
none of the source-routing work — ranked candidates, path diversity, target
redundancy, failover — reaches HTTP traffic. Head is a decision oracle that
nothing consumes.

This makes Head forward the request and stream the response, so that a site
behind Radii survives a dead path or a dead origin.

## Design

### 1. The request path

`/health` is unchanged. The fallback route becomes the proxy:

1. `DecisionEngine` produces a `BackendDecision` (unchanged).
2. For a graph-resolved decision, walk its ranked candidates. For each:
   `chain::establish` → hyper `client::conn::http1::handshake` over the
   returned stream → forward the request → stream the response body back.
3. For a statically configured decision (host map, default), dial the
   configured address directly — see §4.

Head keeps `DecisionEngine`, `GraphRoutePolicy`, and ranked candidates exactly
as they are. Only what it *does* with the winner changes.

**New crate edge:** `radii-head` → `radii-fetch`, for `chain::establish` and
`ResolvedRoute`. `chain` is the only thing Head needs from Fetch; if that edge
becomes awkward, lifting `chain.rs` into a shared crate is the natural move.
Not done pre-emptively.

**No new external dependencies.** axum 0.7 already brings hyper 1.x,
`http-body-util`, and `hyper-util` into the lock file; they are promoted to
direct dependencies of `radii-head`.

### 2. Head resolves `relay`, and what that costs

Reaching backends over chains means Head resolves **`relay`** addresses:
`GraphRoutePolicy`'s `target_role` changes from `HTTP` to `RELAY`. A chain to
node-b terminates at node-b's relay listener, which splices to node-b's own
configured `upstream` — that upstream is the web server.

**This leaves `RoleId::HTTP` with no consumer.** Stated plainly because the
role-tagging spec justified itself partly on Head and Fetch disagreeing about
what an address means. The role *mechanism* remains load-bearing — it is what
distinguishes a node's relay listener from its other listeners, and what
bounds the address list — but that specific conflict is now resolved a
different way than that spec assumed: not by each consumer reading its own
role, but by Head joining Fetch on the relay path.

`RoleId::HTTP` stays **defined and documented as reserved, with no consumer
today**. It is not removed, because churning the wire for it now buys nothing.
It is not left looking load-bearing either. This project already carries one
decorative field — node-level `roles`, which nothing reads — and a second
should not accumulate silently.

**Follow-up:** delete `RoleId::HTTP` if no consumer appears, or give it one by
adding a direct-dial mode for backends that are not behind a Radii node.

### 3. Failover and the retry boundary

**A candidate is retried only when the chain failed to establish** — that is,
when the request was never delivered. Replaying a request that never arrived
is unambiguously safe for every method, POST included, so no idempotency rule
and no method allowlist is needed.

**Head never buffers request bodies.** Bodies stream from client to backend
and responses stream back, so memory per connection is constant regardless of
upload size. Buffering exists only to enable replay, and replay is out of
scope by the rule above.

**Once the request has been written, a failure is terminal** and surfaces to
the client. Head cannot know whether the backend processed it.

This is narrower than it sounds, because of a property the relay already has:
`relay::terminate` dials its own upstream *before* acking `tunnel_ready`, so a
dead origin server fails at chain establishment rather than after. The cheap
rule therefore covers both "the node is down" and "the origin behind it is
down" — the two failures that matter for keeping a site up.

**Not covered:** an origin that accepts the connection and then fails
mid-request. That reaches the client as a 502.

### 4. Statically configured backends are dialed directly

`HostMapPolicy` and `DefaultPolicy` return a configured address string, not a
route — there is no node id, so there is no chain to open. Head dials these
directly over plain TCP.

This mirrors Fetch's static `upstream` fallback exactly, and for the same
reason: the address came from the operator's own config, is trusted by
definition, and may legitimately point at a host with no Radii identity at all.
It is not a reintroduction of the direct-dial data path that was considered and
declined for *graph-resolved* nodes.

A statically configured backend has exactly one address, so there is nothing to
fail over to. Its failure is a 502.

### 5. Headers

**Hop-by-hop headers are stripped** in both directions, per RFC 9110:
`Connection`, `Keep-Alive`, `Proxy-Authenticate`, `Proxy-Authorization`, `TE`,
`Trailer`, `Transfer-Encoding`, `Upgrade` — plus every header named in the
request's own `Connection` header, which is the part implementations most
often miss.

**`Host` is forwarded unchanged.** The backend needs it to serve the right
virtual host; forwarding it is what makes Head's host-to-node mapping mean
anything.

**`X-Forwarded-For`** gets the immediate peer's address appended to any
existing value. **The inbound value is untrusted** — any client can send one —
so it is recorded, not believed. Head makes no access-control decision on it,
and the docs must say so rather than implying the header is authenticated.
`X-Forwarded-Proto` and `X-Forwarded-Host` are set from what Head actually
observed.

### 6. Timeouts

`SECURITY.md` records that Head has no connection timeouts. Proxying makes that
untenable, so this adds two knobs under `[http]`:

- `attempt_timeout_ms` (default 3000) — bounds one candidate's chain
  establishment plus HTTP handshake. Same name and meaning as Fetch's.
- `response_timeout_ms` (default 30000) — bounds waiting for response headers
  after the request is sent. Not a limit on body streaming duration: a slow
  large download is legitimate.

### 7. The decision JSON moves, and stops leaking

The JSON document moves from *every path* to `GET /_radii/decision`, which
reports what Head would choose for the `Host` header it is given.

This is a **security improvement, not merely a relocation**. Today every
request to Head discloses the backend map — `SECURITY.md` already lists "Head
information disclosure" and "No authorization on Head HTTP" as known gaps.
Afterwards exactly one path does, and an operator can firewall or reverse-proxy
that single path. The underlying gap (no authorization) is unchanged and stays
in the register.

## Security

- **Head becomes a data path**, so its failure modes stop being informational.
  A misrouted request now delivers user traffic to the wrong backend rather
  than printing a wrong address. The identity guarantees that make this safe
  are the ones the chain already provides: the end-to-end TLS session
  authenticates the target node, and a relay carrying the chain cannot read or
  impersonate it.
- **`X-Forwarded-For` is recorded, not trusted.** No decision keys on it.
- **Hop-by-hop header stripping is a correctness *and* security control** —
  forwarding a `Connection`-named header to a backend is request smuggling
  surface.
- **Timeouts** close, for Head's proxy path, part of the connection-timeout gap
  the register records. Head's Radii bridge listener is unaffected and remains
  a gap.
- **The decision endpoint** narrows an existing disclosure from every path to
  one path; it does not authenticate it.

## Testing

The acceptance test: **a client makes an ordinary HTTP request to Head and
receives the origin's response body, having traversed a relay chain — and when
the first candidate's node is down, the client still receives the response from
the second, never observing the failure.** That is the whole feature.

Around it:

- `/health` still answers, and is not proxied.
- The response body streams: a body larger than any internal buffer arrives
  intact.
- Hop-by-hop headers, including one named in `Connection`, do not reach the
  backend.
- `Host` reaches the backend unchanged.
- `X-Forwarded-For` appends rather than replaces.
- All candidates failing yields 502.
- A statically configured host-map backend is dialed directly and served.
- `GET /_radii/decision` reports the decision; other paths no longer do.

## Known limitations

**A fresh chain per request.** Chain setup is a TCP connect, a hop-local TLS
handshake, a `TunnelOpen` round trip, and an end-to-end TLS handshake — about
three round trips. Sub-millisecond on a LAN; 100ms+ per request over a WAN,
which makes a page with thirty assets unusable.

This is a deliberate first-version choice, not an oversight. Pooling chains
would fix the latency but holds a relay's concurrency slot continuously rather
than per request — on donated public nodes that is someone else's bandwidth
and someone else's `max_concurrent_per_peer` budget, held whether or not
traffic flows. It also has to interact with `idle_timeout_ms` reaping, pool
sizing, and eviction. That deserves its own decision rather than being
smuggled into the proxy's first version.

The reversal is cheap: pooling sits behind the same "get me a connection to
this candidate" interface either way, and the design keeps that seam explicit.

**Follow-ups, not in scope:** chain pooling with keep-alive; HTTP/2 to the
backend; TLS termination on Head's public side; WebSocket/`Upgrade` support,
which the hop-by-hop rules currently strip.
