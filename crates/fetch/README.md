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

## Relaying (`[relay]`)

A Fetch node carries other peers' traffic only when `[relay]` is present.
Absent it, no second listener is opened and the node neither forwards a chain
nor terminates one — an upgrade never silently turns a node into a relay.

The relay listener is separate from the tunnel listener on purpose: the tunnel
listener carries raw bytes with no framing, so a `TunnelOpen` preamble cannot
be read there without breaking every existing plain client. Keeping them apart
also lets you firewall relay capability independently, which matters when its
whole point is exposure to peers you do not run.

`[relay.tls]` is mandatory — config load fails without it, because a relay
listener that does not verify client certificates is an open proxy.

### `allow_peers` narrows the previous hop, not the originator

Admission (`allow_peers`) checks the inbound mTLS peer on *this* hop. At
chain length one that peer is the chain's originator, so `allow_peers` really
does restrict who may start a chain here. Beyond one hop it is not: the
inbound peer is the upstream relay that forwarded the request, not whoever
originated it. An operator who sets `allow_peers` on a terminal node expecting
it to restrict who may reach that node's upstream gets no such restriction for
traffic arriving via any admitted relay. A multi-hop chain's originator is
authenticated separately, by the end-to-end session — not by this check.

### Two hop limits, and which applies where

- `[graph] max_hops` bounds how long a route this node will *plan* for itself.
- `[relay] max_hops` bounds how long a path this node will *carry* for someone
  else, and is enforced regardless of what an originator asks for. A node that
  should only ever be a chain's endpoint sets `max_hops = 1`: it will accept a
  frame naming just itself and refuse anything longer.

Both sit under `radii_core::routing::MAX_ROUTE_HOPS` (32), which no config can
raise.

### The retry boundary

A candidate route is retryable only until the end-to-end handshake with the
target completes. After that, application bytes may have flowed, and TCP
offers no way to migrate a stream — so a later failure is terminal and reaches
the client as a closed connection rather than being retried onto another
candidate. This is deliberate, not an omission: making it otherwise would mean
buffering client traffic in the hope of replaying it.

### Deployment requirement

Any node that can appear in a resolved route — **including as a route's
target** — must run `[relay]` and advertise *that listener's* address in its
`listen_addrs`. See the source-routing section of [`SECURITY.md`](../../SECURITY.md)
for why, and for what breaks if it advertises a plain tunnel port instead.

### Two allowances, and why they cannot be one

Relay resources are rationed in two separate stages:

- `max_concurrent_total` / `max_concurrent_per_peer` bound **admitted chains**,
  keyed by the authenticated peer id.
- `max_pending_total` / `max_pending_per_addr` bound connections still in the
  **handshake window**, keyed by source address.

They cannot be merged, because the authenticated identity is precisely what
the handshake produces. Refusing to spend a handshake means refusing to learn
who is asking, so a pre-admission allowance has nothing to key on but the
source address — blunt where peers share a NAT, which is why it is set well
above a legitimate peer's concurrent-chain allowance rather than tuned tightly.

A connection turned away pre-admission gets a plain TCP close rather than a
Radii status, for the same reason: sending it a status would require
completing the handshake being declined.

A pre-admission slot is released the moment a chain is admitted, so a
long-lived tunnel occupies a chain slot but not a handshake slot.
