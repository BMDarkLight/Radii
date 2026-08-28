# Radii capability: peer-discovery substrate for Wave

**Date:** 2026-08-29
**Status:** Approved for implementation (Radii side only)

## Context

Wave (a separate Rust/Tauri music player, `~/Projects/Wave`) wants devices running
it to discover each other, stay reachable across NAT/network changes, and
background-cache songs from peers based on its existing listening-pattern
prediction (the `track_transitions` table already driving `get_home_suggestions`).
Wave asked to use Radii as the underlying discovery/transport substrate.

Radii's non-goals explicitly exclude "application-level content logic." This
spec covers only the generic, content-agnostic pieces that belong in Radii:
node role tagging, node liveness/expiry, and small library ergonomics for a
Rust consumer joining the mesh. Catalog data, song transfer, library merging,
and cache/prefetch decisions are entirely Wave-side and out of scope here —
they consume what this spec adds, but no music-specific concept enters Radii.

## Goals

- A node can declare one or more free-form roles in `NodeHello` (the field
  already exists) and have those roles queryable via `GraphQuery`, so a
  consumer can ask "which reachable nodes declared role X" without Radii
  knowing or caring what "X" means.
- A node that stops sending hellos drops out of the graph after a
  configurable TTL, instead of lingering forever.
- A Rust consumer (Wave, or anything else) can join the mesh — send a hello,
  send reachability reports, query the graph — via small library functions
  instead of hand-rolling frame writes, matching what `radii-cli` already does
  inline today.

## Non-goals

- No catalog/content/song semantics anywhere in Radii.
- No Crawl-to-Crawl gossip / multi-instance sync (a real distributed-systems
  feature; stays a documented future option, not built now).
- No new opaque-blob "advertise" message type in `RadiiMessage` — HTTP
  (via Head's reverse proxy) already covers arbitrary payload exchange between
  nodes once they can find each other, so this isn't needed for the roles/
  liveness/ergonomics scope.
- No changes to Head's or Fetch's decision/routing logic — role filtering is
  a client-side concern (via `GraphQuery`'s reply), not a new routing policy.

## Architecture

### 1. Node roles through the graph query

`radii-proto::NodeInfo` gains `roles: Vec<String>`. Crawl's registry changes
from `HashMap<String, Vec<String>>` (node_id → listen_addrs) to
`HashMap<String, NodeEntry>` where `NodeEntry { listen_addrs: Vec<String>,
roles: Vec<String>, last_seen_unix_ms: u64 }`. `NodeHello` handling (both the
direct-connection path and the `FromHead`-wrapped path) stores `roles` and
refreshes `last_seen_unix_ms` on every hello. `GraphQuery`'s reply carries the
stored roles per node in `NodeInfo`.

### 2. Liveness / TTL expiry

`CrawlConfig` (crawl's `config.rs`) gains `node_ttl_ms` (default 60_000,
`#[serde(default = ...)]` matching the existing pattern for e.g.
`poll_interval_ms`). When building a `GraphQuery` reply, Crawl filters out any
node whose `last_seen_unix_ms` is older than `now - node_ttl_ms`, from both
the node list and any reachability reports naming it as `from` or `target`.
This is query-time filtering, not a background sweep — no new task, no
persistence changes. `NodeHello` is the heartbeat: a long-lived participant
is expected to re-send it periodically (documented in Crawl's README); this
spec does not add a distinct heartbeat message.

### 3. Library ergonomics in `radii-proto`

Two new public functions, extracted from what `radii-cli`'s `hello` and
`report` subcommands already do inline:

```rust
pub async fn send_hello<A: ToSocketAddrs>(
    addr: A,
    node_id: String,
    roles: Vec<String>,
    listen_addrs: Vec<String>,
) -> Result<RadiiMessage>; // returns the Ack, dials plaintext

pub async fn send_hello_on<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    node_id: String,
    roles: Vec<String>,
    listen_addrs: Vec<String>,
) -> Result<RadiiMessage>; // works over an already-established (e.g. TLS) stream

pub async fn send_report<A: ToSocketAddrs>(
    addr: A,
    from: String,
    target: String,
    protocol: String,
    reachable: bool,
    rtt_ms: Option<u32>,
    observed_addr: Option<String>,
) -> Result<RadiiMessage>;

pub async fn send_report_on<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    from: String,
    target: String,
    protocol: String,
    reachable: bool,
    rtt_ms: Option<u32>,
    observed_addr: Option<String>,
) -> Result<RadiiMessage>;
```

`send_hello`/`send_report` dial plaintext and delegate to the `_on` variants,
exactly mirroring the existing `query_graph`/`query_graph_on` split — TLS
callers dial via `tls::dial` themselves and call the `_on` variant on the
resulting stream. `radii-cli` is refactored to call these instead of
duplicating the dial/write/read sequence — behavior unchanged, verified by
its existing tests.

## Data flow (how a consumer like Wave uses this — no Radii code here)

1. Startup: consumer calls `send_hello(crawl_addr, "wave-device-a", vec!["wave"], vec![my_http_addr])`.
2. Periodically: re-send hello (heartbeat), call `query_graph`, filter
   `NodeInfo` client-side for `roles.contains("wave")`.
3. Periodically: probe each such peer itself, call `send_report` with the
   observed reachability.
4. Whatever the consumer builds on top (catalog fetch, song transfer, cache
   decisions) resolves routes via `radii-core::routing::RoutePlanner` against
   the graph it already pulled in step 2 — no new Radii API needed for that,
   it's the same planner Head and Fetch already use internally.

## Error handling

- Unauthorized role/hello claims: unchanged — the existing mTLS
  peer-identity check (`authorized()` in `crawl/src/server.rs`) already
  covers `node_id` claims in `NodeHello`; roles ride along in the same
  message and get the same protection for free.
- Expired nodes simply don't appear in `GraphQuery` replies — no error, no
  special signaling; a consumer sees a smaller graph.
- `send_hello`/`send_report` surface connection/protocol errors via the
  existing `anyhow::Result` used throughout `radii-proto` — no new error
  type.

## Testing

- `crawl/src/server.rs`: unit-ish tests (extending the existing
  `run_on_with_state` test harness pattern) asserting (a) roles round-trip
  through `NodeHello` → `GraphQuery` → `NodeInfo`, (b) a node past its TTL is
  excluded from a `GraphQuery` reply.
- `proto/src/lib.rs`: unit tests for `send_hello`/`send_report` using the
  existing `tokio::io::duplex` round-trip style already used for
  `write_message`/`read_message`.
- `crates/integration`: one test with two simulated nodes (different roles)
  hello'ing a real `Crawl` instance and asserting `GraphQuery` reflects roles
  and drops an expired node — extending the existing `crawl_protocol.rs` /
  `graph_routing.rs` style tests.
- `radii-cli`: existing tests continue to pass unchanged after the
  hello/report refactor (behavior-preserving).

## Follow-ups (explicitly out of scope now)

- Crawl-to-Crawl gossip, if Wave later needs zero single point of failure
  for discovery itself (not just playback).
- A native opaque per-node "advertise" message, if an app-level payload
  needs to ride the binary Radii protocol instead of a plain HTTP endpoint.
- Everything Wave-side (catalog endpoint, song transfer, universal library
  merge, cache/prefetch hook into `track_transitions`) — a separate plan in
  the Wave repo, consuming what this spec adds.
