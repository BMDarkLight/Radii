# Source routing and ranked route candidates

**Date:** 2026-09-05
**Status:** design approved, not implemented
**Scope:** `radii-proto`, `radii-core`, `radii-fetch`, `radii-head`

## Problem

Radii plans routes but does not use them, and it keeps only one.

`RoutePlanner::plan` (`crates/core/src/routing.rs`) is a full Yen's k-shortest-paths
implementation: it returns up to `limit` distinct loop-free routes in genuine
cost order, clamped to `MAX_ROUTE_RESULTS`. Both call sites pass `limit = 1`.

Worse, the route that comes back is discarded. `plan_backend`
(`crates/head/src/graph.rs`) and `resolve_once` (`crates/fetch/src/graph.rs`)
plan a path and then dial the target node's *first listen address directly*:

```rust
let route = planner.plan(&guard.snapshot, &request, 1).into_iter().next()?;
let addr = guard.listen_addrs.get(&target.0)?.first()?.clone();
```

The intermediate hops serve only as a reachability proof and a score. There is
no forwarding, so `a→b→c` and `a→d→c` resolve to the same dial address. Raising
`limit` alone would therefore buy nothing.

The consequences on the data path:

- A dial failure fails the client's connection. Nothing tries a second route.
- A single target node is a single point of failure for the service behind it.
- Path diversity is unreachable in principle, because there is no forwarding.

## Goals

1. Traffic survives an intermediate network path failing (source routing).
2. Traffic survives a target node dying (multiple target nodes per service).
3. Both failure modes are handled by **one** ordered retry loop, not two.
4. Intermediate relays cannot read the traffic they carry, so donated public
   nodes can participate in the data path.
5. Relaying is opt-in, admission-controlled, and bounded.

## Non-goals

- Head as a reverse proxy. Head still returns a JSON backend decision; it gains
  a ranked `candidates` array but cannot itself fail over until it proxies.
- Mid-stream failover. See "Retry boundary" below — this is a hard limit, not
  an omission.
- Anonymity. Relays cannot read payloads but do observe volume, timing, and
  their neighbours. There is no padding and no cover traffic.
- Expanding a node's multiple `listen_addrs` into separate candidates.
- Crawl high availability, active health checking, and shortening the ~60s
  liveness TTL. Each is a separate concern with its own spec.

## Decisions

| Decision | Choice | Rationale |
|---|---|---|
| Redundancy axes | Source routing **and** multiple target nodes | Both collapse into one ranked candidate list, so the retry loop is designed once |
| Relay trust | End-to-end TLS through opaque relays | The README's donated public nodes cannot be given plaintext; hop-by-hop mTLS would require every relay to be operator-trusted |
| Path selection | Initiator-pinned explicit source route | If relays re-planned locally, retrying candidate 2 would be meaningless — the initiator's ranking would not survive the first hop |
| Relay admission | Any peer with a CA-valid cert, opt-in per node, with mandatory limits | CA membership becomes the trust boundary, which is what makes donated nodes workable |
| Attempt strategy | Ordered list, serial retry | Simplest correct thing; happy-eyeballs racing is a strict extension of the same list |

## Design

### 1. Protocol and chain establishment

New wire types in `crates/proto/src/lib.rs`. `radii-proto` does not depend on
`radii-core` — it duplicates wire shapes (`GraphReport`, `NodeInfo`) and Fetch
converts at the boundary. `RouteHop` follows that convention rather than adding
a crate edge.

```rust
pub struct RouteHop { pub node_id: String, pub addr: String }

RadiiMessage::TunnelOpen { hops: Vec<RouteHop> }
```

`TunnelOpen` carries a `Vec` of a flat struct, never a boxed `RadiiMessage`, so
the non-recursion property established for `RelayedMessage` holds here too.

**Framing invariant:** the frame a node receives lists hops *starting with
itself*. A node receiving `[R1, R2, T]` verifies `hops[0].node_id` is its own
id, then forwards `TunnelOpen { hops: hops[1..] }` to `hops[1]`. When
`hops.len() == 1` the node is terminal.

**Establishment sequence** (initiator `I`, relay `R1`, target `T`):

1. `I` dials `R1.addr` with `tls::dial_expecting(.., Some(R1.node_id))` —
   hop-local mTLS, unchanged from today's code.
2. `I` writes `TunnelOpen { hops: [R1, R2, T] }`.
3. `R1` verifies `hops[0]` names itself, dials `hops[1]` the same way, and
   forwards the tail.
4. `T` sees `hops.len() == 1`, replies `Ack { status: "tunnel_ready" }`.
5. Each relay forwards that single frame back verbatim, then splices both
   directions with `tokio::io::copy`.
6. `I` reads the Ack, then runs a **second** `tls::dial_expecting(..,
   Some(T.node_id))` over the spliced pipe.
7. `T` runs a second `tls::accept` on its own spliced stream and tunnels to its
   configured upstream.

Two nested TLS layers result. The hop-local layer carries authorization and
neighbour authentication; the end-to-end layer carries the payload. Each relay
decrypts only the outer layer and re-encrypts opaque inner records onward.
`dial_expecting`'s node-identity check is unchanged — it simply runs over the
spliced pipe rather than a raw socket, which preserves the property documented
on `ResolvedTarget`: an address from the peer-written registry is a claim, and
the node id travelling beside it is what makes the claim checkable.

The Ack costs one chain round-trip. It buys an unambiguous chain-up signal,
which is the retry trigger, so it earns its latency. A hop that cannot reach
its successor sends `Ack { status: "tunnel_hop_unreachable" }` toward the
initiator and closes.

**Per-relay validation**, all local and cheap:

- reject empty `hops`
- reject `hops[0].node_id != self`
- reject `hops.len() > relay.max_hops`, itself capped by `MAX_ROUTE_HOPS`
- reject any path containing a duplicate node id — this eliminates cycles
  outright rather than merely bounding their cost

### 2. Candidate resolution and retry

Resolution moves into `radii-core`. `plan_backend` and `resolve_once` already
duplicate the build-snapshot → plan → resolve-address sequence, and multi-target
× multi-path makes that duplication worse.

```rust
pub struct ResolvedHop { pub node_id: NodeId, pub addr: String }

pub struct ResolvedRoute {
    /// Source excluded; the last entry is the target, which is therefore
    /// `hops.last()` rather than a separate field that could drift from it.
    pub hops: Vec<ResolvedHop>,
    pub score: f64,
}

pub fn resolve_candidates(
    snapshot: &GraphSnapshot,
    listen_addrs: &HashMap<String, Vec<String>>,
    source: &NodeId,
    targets: &[NodeId],
    allowed_protocols: &[ProtocolId],
    max_hops: usize,
    limit: usize,
) -> Vec<ResolvedRoute>
```

Algorithm: plan to each target with the planner's existing `limit`; resolve
**every** hop's address, not only the target's; drop any route with an
unregistered intermediate, since it is undialable; sort ascending by score;
dedupe by node-id sequence; truncate to `limit`.

Resolving every hop is new. Today only the target's address is looked up,
because intermediates were never dialed.

Each hop uses `listen_addrs[0]`. Expanding a node's several addresses into
separate candidates multiplies combinatorially and is a follow-up, not part of
this spec.

The result is one ordered list in which a broken path and a dead target node
are indistinguishable — which is exactly what lets a single loop handle both.

`limit` is supplied from the initiator's `max_candidates`, so the stored list
is already truncated and the retry loop simply walks all of it.

**Two distinct hop limits**, easily confused and deliberately separate:

- `[graph] max_hops` bounds route *planning* at the initiator.
- `[relay] max_hops` bounds what a relay will *forward*, enforced locally
  regardless of what any initiator asked for.

**State.** `SharedTarget` becomes:

```rust
pub type SharedRoutes = Arc<RwLock<Vec<ResolvedRoute>>>;
```

An empty vec means "no route resolved yet" and preserves today's fallback to
the static `upstream` with no expected node id — correct, because that address
came from the operator's own config and may legitimately point at a host with
no Radii identity at all.

**Retry loop** in `accept_and_tunnel`: snapshot the list under the read lock,
walk it, wrap each attempt in `attempt_timeout_ms`, log and continue on
failure, and fall back to the static `upstream` once the list is exhausted.

**Retry boundary.** An attempt is retryable only until the end-to-end handshake
with the target completes. After that, application bytes may have flowed and
TCP offers no way to migrate a stream; a later failure is terminal and reaches
the client as a closed connection. This limit is stated in `docs/` as well —
it is the honest edge of what the feature provides.

**Head.** Head gains `plan_backends` returning the ranked list and an ordered
`candidates` array in its JSON response. The existing `backend` field continues
to return `candidates[0]`, so the wire stays compatible. Head cannot retry
anything until it proxies.

### 3. Relay admission and limits

Relaying gets its **own listener**. Fetch's existing `bind` does raw
`tokio::io::copy` with no framing, so reading a `TunnelOpen` preamble there
would break every current plain client. A separate listener also makes relay
capability independently firewall-able, which matters when its whole purpose is
exposure to strangers.

```toml
[relay]
bind = "0.0.0.0:2224"
max_hops = 8
max_concurrent_total = 256
max_concurrent_per_peer = 8
idle_timeout_ms = 30000
allow_peers = []                  # empty = any CA-valid peer

[relay.tls]                       # REQUIRED — config load fails without it
cert = "/etc/radii/relay.cert.pem"
key  = "/etc/radii/relay.key.pem"
ca   = "/etc/radii/ca.cert.pem"
```

Absent `[relay]`, a node does not relay and answers `TunnelOpen` with
`Ack { status: "relay_disabled" }`. Upgrading never turns an existing
deployment into a relay.

**This listener serves both chain roles.** A `TunnelOpen` arrives here whether
the node must forward it or is the chain's terminal node, because the tunnel
listener has no framing to carry it. So a node that is only ever a *target*
still needs `[relay]` enabled to be reachable through a chain at all. To accept
chains addressed to it while refusing to forward for anyone, such a node sets
`max_hops = 1`: a frame with `hops.len() == 1` names itself and terminates,
and anything longer is rejected. The block is named `[relay]` because
forwarding is the capability that carries risk and needs the limits.

**mTLS is mandatory on this listener**, unlike the tunnel listener where it is
optional. A relay listener without client-certificate verification is an open
proxy for the internet; config load fails rather than allowing it. Admission is
then CA membership, narrowed by `allow_peers` when an operator wants the
stricter posture the project has today.

**Limits**, mandatory because admission is open:

| Limit | Purpose |
|---|---|
| `max_concurrent_per_peer` | Keyed by the authenticated node id from the cert. The load-bearing one: without it the global cap is meaningless under abuse, since one peer consumes all of it |
| `max_concurrent_total` | Global ceiling; beyond it, `Ack { status: "relay_busy" }` and close |
| `idle_timeout_ms` | Drops a chain with no bytes in either direction. Closes, for this path, the connection-timeout gap `SECURITY.md` lists as outstanding |
| `max_hops` (relay-local) | Enforced regardless of what the initiator asked |

An n-hop path costs n relay-side connections, so one peer can cost the network
at most `max_concurrent_per_peer × max_hops` — 64 at the defaults above.

## Config migration

| Where | Before | After |
|---|---|---|
| `fetch` `[graph]` | `target_node_id: String` | `target_node_ids: Vec<String>` |
| `head` `[graph]` | `node_map: HashMap<String, String>` | `HashMap<String, Vec<String>>` |
| `fetch` `[graph]` | — | `max_candidates` (default 3), `attempt_timeout_ms` (default 3000) |
| `fetch` | — | `[relay]` block, absent by default |

Both changed fields accept the old scalar form through an untagged `OneOrMany`
shim, so existing configs keep loading unchanged. Example TOML files and
`crates/*/README.md` are updated alongside.

## Security impact

Additions to `SECURITY.md`:

**Threat model** — a data-plane relay row. The existing entry "poisoned
topology can steer Fetch toward attacker-controlled relays" gains real teeth
once relays forward bytes, and the mitigation is the end-to-end identity check
rather than trust in the graph.

**Implemented controls** — relay admission (mandatory mTLS, CA membership,
optional allowlist), the concurrency and idle limits, and the path validation
rules from section 1.

**Residual risks:**

- Open admission makes **the CA the entire trust boundary**. Issuing a Radii
  certificate now grants bandwidth, not only graph-write rights. This changes
  what a certificate means and belongs in `docs/tls.md`'s lifecycle section.
- Relays observe volume, timing, and their immediate neighbours. Payloads are
  opaque; traffic patterns are not. Documentation must not imply anonymity.
- A malicious relay can stall or drop traffic. It cannot forge the target (the
  end-to-end identity check) or read it (end-to-end TLS), but denial remains
  available. Ranked-candidate retry is the mitigation.

## Testing

**Unit, `radii-core`:** `resolve_candidates` orders by score, dedupes identical
node sequences, drops routes whose intermediate hop has no registered listen
address, respects `limit`, and returns an empty vec when no target is reachable.

**Unit, `radii-proto`:** `TunnelOpen` round-trips through postcard; an
over-length `hops` vec is refused at decode.

**Integration, `crates/integration/tests/`:**

- `source_routing.rs` — a three-node chain carries bytes end to end, and the
  initiator's identity check binds to the *target*, not to the first relay.
- A relay rejects a `TunnelOpen` not addressed to it; rejects a path with a
  duplicate node id; rejects one longer than its `max_hops`.
- `candidate_retry.rs` — the first candidate's relay refuses the connection and
  the second candidate succeeds, with the client observing only success.
- Multi-target: target A is down, target B is up, traffic lands on B.
- Every candidate fails, and Fetch falls back to the static `upstream`.
- A node with no `[relay]` block answers `relay_disabled`.
- A relay listener configured without `[relay.tls]` fails config load.
- A peer holding a cert from an untrusted CA is rejected at handshake.
- The `max_concurrent_per_peer + 1`-th chain receives `relay_busy`.
- A silent chain is dropped after `idle_timeout_ms`.

## Suggested implementation phasing

This is a large spec. It is one coherent feature, but it does not have to land
as one change, and each phase below is independently testable:

1. **Core resolution** — `ResolvedRoute`, `resolve_candidates`, unit tests. No
   behaviour change; both existing call sites adopt it at `limit = 1`.
2. **Protocol** — `RouteHop`, `TunnelOpen`, decode bounds, round-trip tests.
3. **Chain establishment** — relay listener, forwarding, nested TLS, path
   validation. Source routing works; still one candidate.
4. **Ranked candidates and retry** — `SharedRoutes`, multi-target config, the
   retry loop. This is where the goals are actually met.
5. **Admission and limits** — mTLS requirement, concurrency caps, idle timeout.
6. **Head candidates array**, docs, and `SECURITY.md`.

Phase 5 must land before any relay is exposed to an untrusted network. Phases
1–4 are safe to run between operator-controlled nodes in the meantime.

## Follow-ups, explicitly out of scope

1. Head as a reverse proxy — without it, goals 1 and 2 do not reach real HTTP
   traffic. This is the highest-value next spec.
2. Expanding a node's multiple `listen_addrs` into separate candidates.
3. Happy-eyeballs racing across the top candidates.
4. Pre-warmed chains, if serial retry latency proves too slow in practice.
5. Active health checking, so reachability is measured rather than asserted by
   peers.
6. Crawl HA and a shorter liveness TTL, which together bound how long a dead
   node stays in the graph.

## Files touched

| File | Change |
|---|---|
| `crates/proto/src/lib.rs` | `RouteHop`, `RadiiMessage::TunnelOpen`, decode bounds |
| `crates/core/src/routing.rs` | `ResolvedHop`, `ResolvedRoute`, `resolve_candidates` |
| `crates/fetch/src/config.rs` | `target_node_ids`, `max_candidates`, `attempt_timeout_ms`, `RelayConfig` |
| `crates/fetch/src/graph.rs` | `SharedRoutes`, poller populates the ranked list |
| `crates/fetch/src/server.rs` | Chain establishment, retry loop, relay listener |
| `crates/head/src/config.rs` | `node_map` becomes multi-valued |
| `crates/head/src/graph.rs` | `plan_backends` |
| `crates/head/src/decision.rs` | `GraphRoutePolicy` carries ranked candidates |
| `crates/head/src/http.rs` | `candidates` array in the JSON response |
| `SECURITY.md`, `docs/tls.md` | Threat model, controls, residual risks, CA semantics |
| `crates/*/README.md`, `*.example.toml` | Config and behaviour documentation |
