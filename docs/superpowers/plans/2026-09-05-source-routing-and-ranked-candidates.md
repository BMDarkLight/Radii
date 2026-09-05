# Source Routing and Ranked Route Candidates Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make Radii forward traffic along an initiator-pinned multi-hop path and fail over across a ranked list of candidate routes, so a broken network path or a dead target node no longer drops the connection.

**Architecture:** The route planner already returns k best routes; both call sites throw them away and dial the target directly. This plan makes routes real: a `TunnelOpen` frame carries an explicit hop list, each relay verifies it names itself and forwards the tail, and the initiator runs a second end-to-end TLS session through the resulting pipe so relays carry opaque bytes. Resolution moves into `radii-core` and returns a score-ordered candidate list spanning multiple paths *and* multiple target nodes, which one serial retry loop walks.

**Tech Stack:** Rust 2021, tokio, rustls / tokio-rustls, postcard, serde, axum (Head), rcgen (test PKI).

**Spec:** `docs/superpowers/specs/2026-09-05-source-routing-and-ranked-candidates-design.md`

## Global Constraints

- Existing config files must keep loading unchanged. `target_node_id` and scalar `node_map` values are accepted via an untagged `OneOrMany` shim.
- `[relay]` is absent by default. A node that has not opted in never forwards and never terminates a chain.
- The relay listener requires mTLS. Config load **fails** if `[relay]` is present without `[relay.tls]`.
- A node's `[relay.tls]` and `[tunnel_tls.listener]` certificates must carry the **same node id** in Subject CN. The hop-local check reads the first, the end-to-end check reads the second; a mismatch fails the chain.
- Planner ceilings are authoritative: `MAX_ROUTE_HOPS = 32`, `MAX_ROUTE_RESULTS = 32`, `MAX_GRAPH_NODES`, `MAX_GRAPH_LINKS` (`crates/core/src/routing.rs`). New limits sit *below* them, never above.
- `radii-proto` does not depend on `radii-core`. Wire types are duplicated in proto and converted in Fetch/Head, as `GraphReport` → `Link` already is. Do not add the crate edge.
- Retry is permitted only until the end-to-end handshake completes. Never retry after application bytes have flowed.
- Every task ends green: `cargo test --workspace` and `cargo clippy --workspace --all-targets -- -D warnings`.
- Commit subjects use Conventional Commits, subject line only, no body.

**Integration-helper signatures** (`crates/integration/src/lib.rs`) — exact, because several tasks below use them:

```rust
pub async fn bind_local() -> anyhow::Result<(TcpListener, String)>   // addr is a String already
pub async fn wait_ready(addr: &str) -> anyhow::Result<()>            // returns Result; call .unwrap()
```

So write `let (listener, addr) = bind_local().await.unwrap();` and
`wait_ready(&addr).await.unwrap();`. `addr` is a `String` — pass `&addr` or
`addr.clone()`, never `addr.to_string()`. Test helpers taking an address take
`&str`, not `SocketAddr`. `TestCa::issue(node_id) -> TlsIdentityConfig`
(`crates/integration/src/pki.rs`), so wrap with `TlsIdentity::load(&ca.issue(id)).unwrap()`
wherever a `TlsIdentity` is needed.

---

## File Structure

| File | Responsibility |
|---|---|
| `crates/core/src/routing.rs` | Add `ResolvedHop`, `ResolvedRoute`, `resolve_candidates`. Planner itself unchanged. |
| `crates/proto/src/lib.rs` | Add `RouteHop`, `RadiiMessage::TunnelOpen`, `MAX_TUNNEL_HOPS`, decode bound. |
| `crates/proto/src/tls.rs` | Add stream-generic `accept_on` / `connect_on` so TLS can nest over a spliced pipe. |
| `crates/fetch/src/config.rs` | `target_node_ids`, `max_candidates`, `attempt_timeout_ms`, `RelayConfig`, `OneOrMany`. |
| `crates/fetch/src/graph.rs` | `SharedRoutes`; poller fills the ranked list via `resolve_candidates`. |
| `crates/fetch/src/relay.rs` | **New.** Relay listener: admission, validation, forwarding, terminal handling, limits. |
| `crates/fetch/src/chain.rs` | **New.** Initiator side: `establish_chain` builds a chain and returns an end-to-end stream. |
| `crates/fetch/src/server.rs` | Retry loop over candidates; static fallback. |
| `crates/fetch/src/lib.rs` | Wire the relay listener alongside the tunnel listener. |
| `crates/head/src/graph.rs` | `plan_backends` returning the ranked list. |
| `crates/head/src/decision.rs` | `GraphRoutePolicy` carries candidates. |
| `crates/head/src/http.rs` | `candidates` array in the JSON response. |
| `crates/head/src/config.rs` | `node_map` becomes multi-valued. |

Relay and chain logic go in new files rather than growing `server.rs`, which is already the busiest file in the crate and would otherwise hold four distinct roles.

---

## Task 1: Candidate resolution in core

**Files:**
- Modify: `crates/core/src/routing.rs`
- Test: `crates/core/src/routing.rs` (in-file `#[cfg(test)] mod tests`, following the existing convention)

**Interfaces:**
- Consumes: existing `RoutePlanner`, `GraphSnapshot`, `NodeId`, `ProtocolId`, `RouteRequest`, `DefaultScorer`.
- Produces: `ResolvedHop { node_id: NodeId, addr: String }`, `ResolvedRoute { hops: Vec<ResolvedHop>, score: f64 }`, `ResolvedRoute::target() -> &NodeId`, `resolve_candidates(...) -> Vec<ResolvedRoute>`.

- [ ] **Step 1: Write the failing tests**

Add to the existing `mod tests` in `crates/core/src/routing.rs`:

```rust
fn addrs(pairs: &[(&str, &str)]) -> HashMap<String, Vec<String>> {
    pairs
        .iter()
        .map(|(node, addr)| ((*node).to_string(), vec![(*addr).to_string()]))
        .collect()
}

#[test]
fn resolves_candidates_across_targets_in_score_order() {
    let snapshot = GraphSnapshot::from_reports([
        report("s", "t1", "radii", 100),
        report("s", "t2", "radii", 10),
    ]);
    let listen = addrs(&[("t1", "10.0.0.1:9000"), ("t2", "10.0.0.2:9000")]);

    let routes = resolve_candidates(
        &snapshot,
        &listen,
        &NodeId("s".into()),
        &[NodeId("t1".into()), NodeId("t2".into())],
        &[ProtocolId::new("radii")],
        4,
        5,
    );

    assert_eq!(routes.len(), 2);
    // t2 is cheaper, so it must rank first even though t1 was listed first.
    assert_eq!(routes[0].target().0, "t2");
    assert_eq!(routes[0].hops.len(), 1);
    assert_eq!(routes[0].hops[0].addr, "10.0.0.2:9000");
    assert!(routes[0].score <= routes[1].score);
}

#[test]
fn excludes_the_source_and_resolves_every_intermediate_hop() {
    let snapshot = GraphSnapshot::from_reports([
        report("s", "r", "radii", 10),
        report("r", "t", "radii", 10),
    ]);
    let listen = addrs(&[("r", "10.0.0.9:7000"), ("t", "10.0.0.5:9000")]);

    let routes = resolve_candidates(
        &snapshot,
        &listen,
        &NodeId("s".into()),
        &[NodeId("t".into())],
        &[ProtocolId::new("radii")],
        4,
        5,
    );

    assert_eq!(routes.len(), 1);
    let hops: Vec<&str> = routes[0].hops.iter().map(|h| h.node_id.0.as_str()).collect();
    assert_eq!(hops, vec!["r", "t"], "source must not appear in the dial list");
    assert_eq!(routes[0].hops[0].addr, "10.0.0.9:7000");
}

#[test]
fn drops_routes_whose_intermediate_hop_has_no_listen_address() {
    let snapshot = GraphSnapshot::from_reports([
        report("s", "r", "radii", 10),
        report("r", "t", "radii", 10),
    ]);
    // `r` is absent from the registry, so the two-hop route is undialable.
    let listen = addrs(&[("t", "10.0.0.5:9000")]);

    let routes = resolve_candidates(
        &snapshot,
        &listen,
        &NodeId("s".into()),
        &[NodeId("t".into())],
        &[ProtocolId::new("radii")],
        4,
        5,
    );

    assert!(routes.is_empty());
}

#[test]
fn dedupes_identical_node_sequences_and_respects_limit() {
    let snapshot = GraphSnapshot::from_reports([
        report("s", "a", "radii", 10),
        report("s", "b", "radii", 20),
        report("a", "t", "radii", 10),
        report("b", "t", "radii", 10),
    ]);
    let listen = addrs(&[
        ("a", "10.0.0.1:7000"),
        ("b", "10.0.0.2:7000"),
        ("t", "10.0.0.5:9000"),
    ]);

    // The same target listed twice must not produce duplicate candidates.
    let routes = resolve_candidates(
        &snapshot,
        &listen,
        &NodeId("s".into()),
        &[NodeId("t".into()), NodeId("t".into())],
        &[ProtocolId::new("radii")],
        4,
        1,
    );

    assert_eq!(routes.len(), 1, "limit must truncate after dedupe");
    assert_eq!(routes[0].hops[0].node_id.0, "a", "cheaper path wins");
}

#[test]
fn returns_empty_when_no_target_is_reachable() {
    let snapshot = GraphSnapshot::from_reports([report("s", "a", "radii", 10)]);
    let listen = addrs(&[("a", "10.0.0.1:7000")]);

    let routes = resolve_candidates(
        &snapshot,
        &listen,
        &NodeId("s".into()),
        &[NodeId("absent".into())],
        &[ProtocolId::new("radii")],
        4,
        5,
    );

    assert!(routes.is_empty());
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p radii-core routing::tests::resolves_candidates -- --nocapture`
Expected: FAIL — `cannot find function resolve_candidates in this scope`.

- [ ] **Step 3: Write the implementation**

Add to `crates/core/src/routing.rs` (after `RouteCandidate`):

```rust
/// One dialable hop of a resolved route: the node to reach, and the address
/// the registry advertises for it.
///
/// The two travel together for the same reason they do on the wire: the
/// address came from a peer-written registry and is a claim, so the node id
/// beside it is what makes the claim checkable at handshake time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedHop {
    pub node_id: NodeId,
    pub addr: String,
}

/// A fully resolved, dialable route.
#[derive(Debug, Clone)]
pub struct ResolvedRoute {
    /// Source excluded — the initiator does not dial itself. Never empty.
    /// The last entry is the target.
    pub hops: Vec<ResolvedHop>,
    pub score: f64,
}

impl ResolvedRoute {
    /// The final hop. Infallible: `resolve_candidates` never emits an empty
    /// `hops`, which is the type's construction invariant.
    pub fn target(&self) -> &NodeId {
        &self
            .hops
            .last()
            .expect("ResolvedRoute::hops is non-empty by construction")
            .node_id
    }

    fn node_sequence(&self) -> Vec<NodeId> {
        self.hops.iter().map(|hop| hop.node_id.clone()).collect()
    }
}

/// Plans to every target, resolves each hop to a dialable address, and returns
/// the best `limit` routes across all of them in ascending score order.
///
/// A route whose *intermediate* hop has no registered listen address is
/// dropped rather than returned: intermediates are now dialed, not merely
/// counted, so an unresolvable one makes the whole route unusable.
#[allow(clippy::too_many_arguments)]
pub fn resolve_candidates(
    snapshot: &GraphSnapshot,
    listen_addrs: &HashMap<String, Vec<String>>,
    source: &NodeId,
    targets: &[NodeId],
    allowed_protocols: &[ProtocolId],
    max_hops: usize,
    limit: usize,
) -> Vec<ResolvedRoute> {
    let planner = RoutePlanner::new(DefaultScorer);
    let mut resolved: Vec<ResolvedRoute> = Vec::new();

    for target in targets {
        let request = RouteRequest {
            source: source.clone(),
            target: target.clone(),
            allowed_protocols: allowed_protocols.to_vec(),
            max_hops,
        };

        for candidate in planner.plan(snapshot, &request, limit) {
            // `candidate.hops` starts at the source; skip it.
            let mut hops = Vec::with_capacity(candidate.hops.len().saturating_sub(1));
            let mut dialable = true;
            for node in candidate.hops.iter().skip(1) {
                match listen_addrs.get(&node.0).and_then(|addrs| addrs.first()) {
                    Some(addr) => hops.push(ResolvedHop {
                        node_id: node.clone(),
                        addr: addr.clone(),
                    }),
                    None => {
                        dialable = false;
                        break;
                    }
                }
            }

            if !dialable || hops.is_empty() {
                continue;
            }

            resolved.push(ResolvedRoute {
                hops,
                score: candidate.score,
            });
        }
    }

    resolved.sort_by(|a, b| a.score.total_cmp(&b.score));
    let mut seen: HashSet<Vec<NodeId>> = HashSet::new();
    resolved.retain(|route| seen.insert(route.node_sequence()));
    resolved.truncate(limit);
    resolved
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p radii-core routing -- --nocapture`
Expected: PASS, including all pre-existing planner tests.

- [ ] **Step 5: Lint and commit**

```bash
cargo clippy -p radii-core --all-targets -- -D warnings
git add crates/core/src/routing.rs
git commit -m "feat(core): resolve ranked dialable route candidates across targets"
```

---

## Task 2: Adopt `resolve_candidates` at both existing call sites

Pure refactor. Behaviour must not change: both callers still take one route and dial the target directly. This isolates the "did the refactor break anything" question from the feature work that follows.

**Files:**
- Modify: `crates/head/src/graph.rs:79-100` (`plan_backend`)
- Modify: `crates/fetch/src/graph.rs:78-126` (`resolve_once`)

**Interfaces:**
- Consumes: `radii_core::routing::{resolve_candidates, ResolvedRoute}` from Task 1.
- Produces: no signature changes. `plan_backend` still returns `Option<(String, usize, f64)>`; `resolve_once` still returns `Option<(String, usize, f64)>`.

- [ ] **Step 1: Run the existing tests to establish the baseline**

Run: `cargo test --workspace`
Expected: PASS. Note the count; it must not drop.

- [ ] **Step 2: Rewrite `plan_backend` over the new helper**

In `crates/head/src/graph.rs`, replace the body of `plan_backend`:

```rust
pub fn plan_backend(
    state: &SharedGraphState,
    source: &NodeId,
    target: &NodeId,
    allowed_protocols: &[ProtocolId],
    max_hops: usize,
) -> Option<(String, usize, f64)> {
    let guard = state.read().ok()?;
    let route = radii_core::routing::resolve_candidates(
        &guard.snapshot,
        &guard.listen_addrs,
        source,
        std::slice::from_ref(target),
        allowed_protocols,
        max_hops,
        1,
    )
    .into_iter()
    .next()?;

    let addr = route.hops.last()?.addr.clone();
    // `hops` excludes the source; the old contract counted it.
    Some((addr, route.hops.len() + 1, route.score))
}
```

Update the import line at the top of the file to drop the now-unused planner
items:

```rust
use radii_core::routing::{GraphSnapshot, Link, NodeId, ProtocolId};
```

- [ ] **Step 3: Rewrite `resolve_once` over the new helper**

In `crates/fetch/src/graph.rs`, replace everything after the `listen_addrs` map is built:

```rust
    let route = radii_core::routing::resolve_candidates(
        &snapshot,
        &listen_addrs,
        source,
        std::slice::from_ref(target),
        allowed_protocols,
        max_hops,
        1,
    )
    .into_iter()
    .next();

    let Some(route) = route else {
        return Ok(None);
    };
    let addr = route.hops.last().expect("non-empty hops").addr.clone();
    Ok(Some((addr, route.hops.len() + 1, route.score)))
}
```

Update its import line the same way:

```rust
use radii_core::routing::{GraphSnapshot, Link, NodeId, ProtocolId};
```

- [ ] **Step 4: Run the tests to verify nothing changed**

Run: `cargo test --workspace`
Expected: PASS with the same count as Step 1. `crates/head/src/graph.rs`'s `resolves_backend_for_reachable_route` asserts `hops == 2` for a direct link and must still pass — that is why the `+ 1` is there.

- [ ] **Step 5: Lint and commit**

```bash
cargo clippy --workspace --all-targets -- -D warnings
git add crates/head/src/graph.rs crates/fetch/src/graph.rs
git commit -m "refactor(routing): resolve backends through the shared candidate helper"
```

---

## Task 3: `TunnelOpen` wire type

**Files:**
- Modify: `crates/proto/src/lib.rs`
- Test: `crates/proto/src/lib.rs` (in-file `mod tests`)

**Interfaces:**
- Produces: `RouteHop { node_id: String, addr: String }`, `RadiiMessage::TunnelOpen { hops: Vec<RouteHop> }`, `pub const MAX_TUNNEL_HOPS: usize = 32`.

- [ ] **Step 1: Write the failing tests**

Add to the existing `mod tests` in `crates/proto/src/lib.rs`:

```rust
#[tokio::test]
async fn tunnel_open_round_trips() {
    let message = RadiiMessage::TunnelOpen {
        hops: vec![
            RouteHop { node_id: "r1".into(), addr: "10.0.0.1:2224".into() },
            RouteHop { node_id: "t".into(), addr: "10.0.0.2:2224".into() },
        ],
    };

    let mut buf = Vec::new();
    write_message(&mut buf, &message).await.unwrap();
    let decoded = read_message(&mut buf.as_slice()).await.unwrap();

    assert_eq!(decoded, message);
}

#[tokio::test]
async fn rejects_a_tunnel_open_with_too_many_hops() {
    let hops = (0..=MAX_TUNNEL_HOPS)
        .map(|i| RouteHop { node_id: format!("n{i}"), addr: "127.0.0.1:1".into() })
        .collect();

    let mut buf = Vec::new();
    write_message(&mut buf, &RadiiMessage::TunnelOpen { hops })
        .await
        .unwrap();

    let err = read_message(&mut buf.as_slice()).await.unwrap_err();
    assert!(
        err.to_string().contains("hop count"),
        "expected a hop-count bound error, got: {err}"
    );
}

#[tokio::test]
async fn rejects_an_empty_tunnel_open() {
    let mut buf = Vec::new();
    write_message(&mut buf, &RadiiMessage::TunnelOpen { hops: Vec::new() })
        .await
        .unwrap();

    let err = read_message(&mut buf.as_slice()).await.unwrap_err();
    assert!(err.to_string().contains("hop count"), "got: {err}");
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p radii-proto tunnel_open -- --nocapture`
Expected: FAIL — `no variant named TunnelOpen`.

- [ ] **Step 3: Add the type, the variant, and the decode bound**

Near `MAX_FRAME_LEN` in `crates/proto/src/lib.rs`:

```rust
/// Maximum hops in a single `TunnelOpen` path.
///
/// Mirrors `radii_core::routing::MAX_ROUTE_HOPS`. It is duplicated rather
/// than imported because `radii-proto` does not depend on `radii-core`; the
/// wire layer must bound its own input without reaching for domain types.
pub const MAX_TUNNEL_HOPS: usize = 32;
```

Above the `RadiiMessage` enum:

```rust
/// One hop of an initiator-pinned source route.
///
/// Flat by construction, like `RelayedMessage`: a hop list can never nest, so
/// no `TunnelOpen` frame can drive the decoder into unbounded recursion.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RouteHop {
    pub node_id: String,
    pub addr: String,
}
```

As a new `RadiiMessage` variant, added **last** so existing postcard variant indices are unchanged:

```rust
    /// Opens a relayed tunnel along an explicit path.
    ///
    /// The list always starts with the node receiving the frame: a relay
    /// checks `hops[0]` names itself, then forwards `hops[1..]` onward. A
    /// single-entry list means the receiver is the chain's terminal node.
    TunnelOpen {
        hops: Vec<RouteHop>,
    },
```

In `read_message`, after the message is decoded and before it is returned:

```rust
    if let RadiiMessage::TunnelOpen { hops } = &message {
        if hops.is_empty() || hops.len() > MAX_TUNNEL_HOPS {
            bail!(
                "tunnel_open hop count {} outside 1..={MAX_TUNNEL_HOPS}",
                hops.len()
            );
        }
    }
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p radii-proto -- --nocapture`
Expected: PASS, including the existing `nested FromHead` regression test.

- [ ] **Step 5: Lint and commit**

```bash
cargo clippy -p radii-proto --all-targets -- -D warnings
git add crates/proto/src/lib.rs
git commit -m "feat(proto): add a bounded TunnelOpen source-route frame"
```

---

## Task 4: Stream-generic TLS accept and connect

Nested TLS needs to hand an *already-connected* stream to rustls. Today `accept` takes a `TcpStream` and `dial_expecting` opens its own, so neither can run over a spliced pipe. Without this task nothing in Tasks 6–8 compiles.

**Files:**
- Modify: `crates/proto/src/tls.rs`
- Test: `crates/proto/src/tls.rs` (in-file `mod tests`)

**Interfaces:**
- Produces:
  - `accept_on<S: AsyncDuplex + 'static>(stream: S, identity: Option<&TlsIdentity>) -> Result<(BoxedStream, Option<String>)>`
  - `connect_on<S: AsyncDuplex + 'static>(stream: S, sni_addr: &str, identity: Option<&TlsIdentity>, expected_node_id: Option<&str>) -> Result<BoxedStream>`
- The existing `accept` and `dial_expecting` keep their signatures and delegate to these.

- [ ] **Step 1: Write the failing test**

Add to `mod tests` in `crates/proto/src/tls.rs` (the module already builds throwaway certs; follow whatever helper it uses to make a `TlsIdentity`):

```rust
/// Two TLS sessions nested over one TCP connection: the outer pair is the
/// hop-local session, the inner pair is the end-to-end session a relay would
/// carry as opaque bytes.
#[tokio::test]
async fn tls_nests_over_an_established_stream() {
    let ca = crate::tls::tests::test_ca();
    let server_identity = ca.identity("node-t");
    let client_identity = ca.identity("node-s");

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let (outer, _) = accept(stream, Some(&server_identity)).await.unwrap();
        let (mut inner, peer) = accept_on(outer, Some(&server_identity)).await.unwrap();
        assert_eq!(peer.as_deref(), Some("node-s"));
        let mut buf = [0u8; 5];
        tokio::io::AsyncReadExt::read_exact(&mut inner, &mut buf).await.unwrap();
        buf
    });

    let outer = dial_expecting(&addr.to_string(), Some(&client_identity), Some("node-t"))
        .await
        .unwrap();
    let mut inner = connect_on(outer, &addr.to_string(), Some(&client_identity), Some("node-t"))
        .await
        .unwrap();
    tokio::io::AsyncWriteExt::write_all(&mut inner, b"hello").await.unwrap();

    assert_eq!(&server.await.unwrap(), b"hello");
}
```

If `mod tests` does not already expose a `test_ca()` / `identity()` pair, add
the smallest helpers that issue a CN-named leaf from a throwaway CA, matching
`crates/integration/src/pki.rs`.

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p radii-proto tls_nests -- --nocapture`
Expected: FAIL — `cannot find function accept_on`.

- [ ] **Step 3: Generalise the helpers**

In `crates/proto/src/tls.rs`, replace the `TlsServerStream` / `TlsClientStream`
aliases' *uses* in the identity extractors with generic parameters, then add:

```rust
/// Like [`accept`], but upgrades an already-established stream. This is what
/// lets a chain's terminal node run its end-to-end session inside the
/// hop-local one it is already speaking.
pub async fn accept_on<S: AsyncDuplex + 'static>(
    stream: S,
    identity: Option<&TlsIdentity>,
) -> Result<(BoxedStream, Option<String>)> {
    match identity {
        Some(identity) => {
            let tls_stream = identity.acceptor().accept(stream).await?;
            let peer = client_identity_of(&tls_stream)?;
            Ok((Box::new(tls_stream), Some(peer)))
        }
        None => Ok((Box::new(stream), None)),
    }
}

/// Like [`dial_expecting`], but over an already-established stream.
///
/// `sni_addr` supplies the server name for the handshake. The caller passes
/// the target hop's advertised address, so certificate SANs are checked
/// against the host actually being reached, exactly as on a direct dial.
pub async fn connect_on<S: AsyncDuplex + 'static>(
    stream: S,
    sni_addr: &str,
    identity: Option<&TlsIdentity>,
    expected_node_id: Option<&str>,
) -> Result<BoxedStream> {
    match identity {
        Some(identity) => {
            let server_name = server_name_for_addr(sni_addr)?;
            let tls_stream = identity.connector().connect(server_name, stream).await?;
            if let Some(expected) = expected_node_id {
                let actual = server_identity_of(&tls_stream)?;
                if actual != expected {
                    bail!("peer authenticated as node {actual:?}, expected {expected:?}");
                }
            }
            Ok(Box::new(tls_stream))
        }
        None => {
            if let Some(expected) = expected_node_id {
                tracing::warn!(
                    expected_node_id = %expected,
                    "opening a nested session without TLS: cannot verify the peer is the \
                     intended node"
                );
            }
            Ok(Box::new(stream))
        }
    }
}
```

Rename the two private extractors to generic forms and keep their existing
certificate-parsing bodies verbatim:

```rust
fn client_identity_of<S>(stream: &tokio_rustls::server::TlsStream<S>) -> Result<String>
fn server_identity_of<S>(stream: &tokio_rustls::client::TlsStream<S>) -> Result<String>
```

Then make the existing entry points delegate, so their behaviour is unchanged:

```rust
pub async fn accept(
    stream: TcpStream,
    identity: Option<&TlsIdentity>,
) -> Result<(BoxedStream, Option<String>)> {
    accept_on(stream, identity).await
}

pub async fn dial_expecting(
    addr: &str,
    identity: Option<&TlsIdentity>,
    expected_node_id: Option<&str>,
) -> Result<BoxedStream> {
    let stream = TcpStream::connect(addr).await?;
    connect_on(stream, addr, identity, expected_node_id).await
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p radii-proto -- --nocapture && cargo test -p radii-integration -- --nocapture`
Expected: PASS. The existing `crawl_tls` and `fetch_tls` integration tests exercise the delegating entry points and must be unaffected.

- [ ] **Step 5: Lint and commit**

```bash
cargo clippy --workspace --all-targets -- -D warnings
git add crates/proto/src/tls.rs
git commit -m "feat(proto): allow TLS sessions to nest over an established stream"
```

---

## Task 5: Relay configuration

**Files:**
- Modify: `crates/fetch/src/config.rs`
- Modify: `crates/fetch/fetch.example.toml`
- Test: `crates/fetch/src/config.rs` (in-file `mod tests`)

**Interfaces:**
- Produces: `RelayConfig { bind: String, node_id: String, max_hops: usize, max_concurrent_total: usize, max_concurrent_per_peer: usize, idle_timeout_ms: u64, allow_peers: Vec<String>, tls: radii_proto::tls::TlsIdentityConfig }`, reachable as `Config::relay: Option<RelayConfig>`.

`node_id` is explicit rather than derived from the certificate so a relay can
validate `hops[0]` before any I/O, and so a misissued certificate surfaces as a
loud mismatch rather than silent self-identification.

- [ ] **Step 1: Write the failing tests**

```rust
#[test]
fn relay_is_absent_by_default() {
    let mut file = NamedTempFile::new().unwrap();
    writeln!(file, "bind = \"0.0.0.0:2223\"").unwrap();
    writeln!(file, "upstream = \"127.0.0.1:22\"").unwrap();
    let config = load(file.path()).unwrap();
    assert!(config.relay.is_none(), "relaying must be opt-in");
}

#[test]
fn loads_relay_with_defaults() {
    let mut file = NamedTempFile::new().unwrap();
    writeln!(file, "bind = \"0.0.0.0:2223\"").unwrap();
    writeln!(file, "upstream = \"127.0.0.1:22\"").unwrap();
    writeln!(file, "[relay]").unwrap();
    writeln!(file, "bind = \"0.0.0.0:2224\"").unwrap();
    writeln!(file, "node_id = \"node-r\"").unwrap();
    writeln!(file, "[relay.tls]").unwrap();
    writeln!(file, "cert = \"/tmp/c.pem\"").unwrap();
    writeln!(file, "key = \"/tmp/k.pem\"").unwrap();
    writeln!(file, "ca = \"/tmp/ca.pem\"").unwrap();

    let relay = load(file.path()).unwrap().relay.expect("relay present");
    assert_eq!(relay.bind, "0.0.0.0:2224");
    assert_eq!(relay.max_hops, 8);
    assert_eq!(relay.max_concurrent_total, 256);
    assert_eq!(relay.max_concurrent_per_peer, 8);
    assert_eq!(relay.idle_timeout_ms, 30_000);
    assert!(relay.allow_peers.is_empty());
}

#[test]
fn rejects_a_relay_without_tls() {
    let mut file = NamedTempFile::new().unwrap();
    writeln!(file, "bind = \"0.0.0.0:2223\"").unwrap();
    writeln!(file, "upstream = \"127.0.0.1:22\"").unwrap();
    writeln!(file, "[relay]").unwrap();
    writeln!(file, "bind = \"0.0.0.0:2224\"").unwrap();
    writeln!(file, "node_id = \"node-r\"").unwrap();

    let err = load(file.path()).unwrap_err();
    assert!(
        err.to_string().contains("relay.tls"),
        "a relay without mTLS is an open proxy; got: {err}"
    );
}

#[test]
fn accepts_the_legacy_scalar_target_node_id() {
    let mut file = NamedTempFile::new().unwrap();
    writeln!(file, "bind = \"0.0.0.0:2223\"").unwrap();
    writeln!(file, "upstream = \"127.0.0.1:22\"").unwrap();
    writeln!(file, "[graph]").unwrap();
    writeln!(file, "crawl_upstream = \"127.0.0.1:7100\"").unwrap();
    writeln!(file, "target_node_id = \"node-b\"").unwrap();

    let graph = load(file.path()).unwrap().graph.expect("graph present");
    assert_eq!(graph.target_node_ids, vec!["node-b".to_string()]);
    assert_eq!(graph.max_candidates, 3);
    assert_eq!(graph.attempt_timeout_ms, 3000);
}

#[test]
fn accepts_a_target_node_id_list() {
    let mut file = NamedTempFile::new().unwrap();
    writeln!(file, "bind = \"0.0.0.0:2223\"").unwrap();
    writeln!(file, "upstream = \"127.0.0.1:22\"").unwrap();
    writeln!(file, "[graph]").unwrap();
    writeln!(file, "crawl_upstream = \"127.0.0.1:7100\"").unwrap();
    writeln!(file, "target_node_ids = [\"node-b\", \"node-c\"]").unwrap();

    let graph = load(file.path()).unwrap().graph.expect("graph present");
    assert_eq!(graph.target_node_ids, vec!["node-b".to_string(), "node-c".to_string()]);
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p radii-fetch config -- --nocapture`
Expected: FAIL — `no field relay on type Config`.

- [ ] **Step 3: Implement the config**

In `crates/fetch/src/config.rs`, add `relay` to `Config`:

```rust
    pub relay: Option<RelayConfig>,
```

Add the shim and the new types:

```rust
/// Accepts either a bare string or a list, so configs written against the
/// single-target shape keep loading unchanged.
#[derive(Debug, Deserialize, Clone)]
#[serde(untagged)]
enum OneOrMany {
    One(String),
    Many(Vec<String>),
}

impl From<OneOrMany> for Vec<String> {
    fn from(value: OneOrMany) -> Self {
        match value {
            OneOrMany::One(one) => vec![one],
            OneOrMany::Many(many) => many,
        }
    }
}

/// A node's relay listener. Absent means the node neither forwards chains nor
/// terminates them.
#[derive(Debug, Deserialize, Clone)]
pub struct RelayConfig {
    pub bind: String,
    /// This node's own id. A `TunnelOpen` whose first hop names anything else
    /// is refused before any dialing happens.
    pub node_id: String,
    #[serde(default = "default_relay_max_hops")]
    pub max_hops: usize,
    #[serde(default = "default_max_concurrent_total")]
    pub max_concurrent_total: usize,
    #[serde(default = "default_max_concurrent_per_peer")]
    pub max_concurrent_per_peer: usize,
    #[serde(default = "default_idle_timeout_ms")]
    pub idle_timeout_ms: u64,
    /// Empty means any peer holding a certificate from the configured CA.
    #[serde(default)]
    pub allow_peers: Vec<String>,
    /// Required. Enforced in [`load`], not by serde, so the error names the
    /// field an operator has to add.
    pub tls: Option<radii_proto::tls::TlsIdentityConfig>,
}

fn default_relay_max_hops() -> usize { 8 }
fn default_max_concurrent_total() -> usize { 256 }
fn default_max_concurrent_per_peer() -> usize { 8 }
fn default_idle_timeout_ms() -> u64 { 30_000 }
fn default_max_candidates() -> usize { 3 }
fn default_attempt_timeout_ms() -> u64 { 3000 }
```

In `GraphConfig`, replace `target_node_id` and add the two knobs:

```rust
    #[serde(rename = "target_node_id", alias = "target_node_ids")]
    target_node_ids_raw: OneOrMany,
    #[serde(default = "default_max_candidates")]
    pub max_candidates: usize,
    #[serde(default = "default_attempt_timeout_ms")]
    pub attempt_timeout_ms: u64,
```

Because the public field must be a `Vec<String>`, normalise after parse.
Add to `GraphConfig`:

```rust
    #[serde(skip)]
    pub target_node_ids: Vec<String>,
```

and in `load`, after `toml::from_str`:

```rust
pub fn load(path: &Path) -> anyhow::Result<Config> {
    let contents = fs::read_to_string(path)?;
    let mut config: Config = toml::from_str(&contents)?;

    if let Some(graph) = config.graph.as_mut() {
        graph.target_node_ids = graph.target_node_ids_raw.clone().into();
        if graph.target_node_ids.is_empty() {
            anyhow::bail!("graph.target_node_ids must name at least one node");
        }
    }

    if let Some(relay) = config.relay.as_ref() {
        if relay.tls.is_none() {
            anyhow::bail!(
                "[relay.tls] is required: a relay listener without mutual TLS is an open \
                 proxy. See SECURITY.md"
            );
        }
    }

    Ok(config)
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p radii-fetch config -- --nocapture`
Expected: PASS, including the pre-existing `loads_bind_and_upstream`.

- [ ] **Step 5: Update the example config**

Append to `crates/fetch/fetch.example.toml`:

```toml
# Optional: accept relayed tunnel chains. Absent, this node neither forwards
# chains for others nor terminates one addressed to it. Mutual TLS is
# mandatory here — a relay listener without it is an open proxy.
#
# A node that should only ever be a chain *target* sets max_hops = 1: it will
# accept a frame naming just itself and refuse anything longer.
# [relay]
# bind = "0.0.0.0:2224"
# node_id = "node-b"
# max_hops = 8
# max_concurrent_total = 256
# max_concurrent_per_peer = 8
# idle_timeout_ms = 30000
# allow_peers = []              # empty = any peer with a CA-valid certificate
#
# [relay.tls]
# cert = "/etc/radii/relay.cert.pem"
# key = "/etc/radii/relay.key.pem"
# ca = "/etc/radii/ca.cert.pem"
```

In the existing `[graph]` block, replace the `target_node_id` line and add:

```toml
target_node_ids = ["node-b"]
max_candidates = 3
attempt_timeout_ms = 3000
```

- [ ] **Step 6: Commit**

```bash
cargo clippy -p radii-fetch --all-targets -- -D warnings
git add crates/fetch/src/config.rs crates/fetch/fetch.example.toml
git commit -m "feat(fetch): configure relay listening and multi-target candidates"
```

---

## Task 6: Relay listener — terminal node only

Smallest useful slice: a node accepts a one-hop `TunnelOpen` addressed to itself, acks, then runs the end-to-end session and tunnels to its configured upstream. No forwarding yet.

**Files:**
- Create: `crates/fetch/src/relay.rs`
- Modify: `crates/fetch/src/lib.rs`
- Test: `crates/integration/tests/relay_terminal.rs`

**Interfaces:**
- Consumes: `RelayConfig` (Task 5), `RadiiMessage::TunnelOpen` / `RouteHop` (Task 3), `tls::accept_on` (Task 4).
- Produces: `relay::RelayRuntime::new(config: RelayConfig, upstream: String, tunnel_listener_tls: Option<TlsIdentity>) -> anyhow::Result<Arc<RelayRuntime>>`, `relay::run(listener: TcpListener, runtime: Arc<RelayRuntime>) -> anyhow::Result<()>`.

- [ ] **Step 1: Write the failing test**

Create `crates/integration/tests/relay_terminal.rs`:

```rust
//! A chain of length one: the initiator opens a tunnel whose only hop is the
//! target itself, then speaks end-to-end TLS through it.

use radii_integration::pki::TestCa;
use radii_integration::{bind_local, wait_ready};
use radii_proto::tls::TlsIdentity;
use radii_proto::{read_message, write_message, RadiiMessage, RouteHop};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

async fn run_echo(listener: TcpListener) {
    loop {
        let Ok((mut stream, _)) = listener.accept().await else { break };
        tokio::spawn(async move {
            let mut buf = [0u8; 64];
            while let Ok(n) = stream.read(&mut buf).await {
                if n == 0 || stream.write_all(&buf[..n]).await.is_err() {
                    break;
                }
            }
        });
    }
}

#[tokio::test]
async fn terminal_node_acks_and_tunnels_to_its_upstream() {
    let ca = TestCa::new();
    let relay_identity = TlsIdentity::load(&ca.issue("node-t")).unwrap();
    let tunnel_identity = TlsIdentity::load(&ca.issue("node-t")).unwrap();
    let client_identity = TlsIdentity::load(&ca.issue("node-s")).unwrap();

    let (echo_listener, echo_addr) = bind_local().await.unwrap();
    tokio::spawn(run_echo(echo_listener));

    let (relay_listener, relay_addr) = bind_local().await.unwrap();
    let mut config = radii_fetch::config::RelayConfig {
        bind: relay_addr.to_string(),
        node_id: "node-t".into(),
        max_hops: 8,
        max_concurrent_total: 16,
        max_concurrent_per_peer: 4,
        idle_timeout_ms: 30_000,
        allow_peers: Vec::new(),
        tls: Some(ca.issue("node-t")),
    };
    config.tls = Some(ca.issue("node-t"));

    let runtime = radii_fetch::relay::RelayRuntime::new(
        config,
        echo_addr.to_string(),
        Some(tunnel_identity),
    )
    .unwrap();
    tokio::spawn(radii_fetch::relay::run(relay_listener, runtime));
    wait_ready(relay_addr).await;

    // Hop-local session.
    let mut hop = radii_proto::tls::dial_expecting(
        &relay_addr.to_string(),
        Some(&client_identity),
        Some("node-t"),
    )
    .await
    .unwrap();

    write_message(
        &mut hop,
        &RadiiMessage::TunnelOpen {
            hops: vec![RouteHop {
                node_id: "node-t".into(),
                addr: relay_addr.to_string(),
            }],
        },
    )
    .await
    .unwrap();

    match read_message(&mut hop).await.unwrap() {
        RadiiMessage::Ack { status } => assert_eq!(status, "tunnel_ready"),
        other => panic!("expected tunnel_ready, got {other:?}"),
    }

    // End-to-end session, nested inside the hop-local one.
    let mut e2e = radii_proto::tls::connect_on(
        hop,
        &relay_addr.to_string(),
        Some(&client_identity),
        Some("node-t"),
    )
    .await
    .unwrap();

    e2e.write_all(b"ping").await.unwrap();
    let mut buf = [0u8; 4];
    e2e.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"ping");

    let _ = relay_identity;
}

#[tokio::test]
async fn rejects_a_tunnel_open_addressed_to_another_node() {
    let ca = TestCa::new();
    let client_identity = TlsIdentity::load(&ca.issue("node-s")).unwrap();

    let (echo_listener, echo_addr) = bind_local().await.unwrap();
    tokio::spawn(run_echo(echo_listener));

    let (relay_listener, relay_addr) = bind_local().await.unwrap();
    let config = radii_fetch::config::RelayConfig {
        bind: relay_addr.to_string(),
        node_id: "node-t".into(),
        max_hops: 8,
        max_concurrent_total: 16,
        max_concurrent_per_peer: 4,
        idle_timeout_ms: 30_000,
        allow_peers: Vec::new(),
        tls: Some(ca.issue("node-t")),
    };
    let runtime =
        radii_fetch::relay::RelayRuntime::new(config, echo_addr.to_string(), None).unwrap();
    tokio::spawn(radii_fetch::relay::run(relay_listener, runtime));
    wait_ready(relay_addr).await;

    let mut hop = radii_proto::tls::dial_expecting(
        &relay_addr.to_string(),
        Some(&client_identity),
        Some("node-t"),
    )
    .await
    .unwrap();

    write_message(
        &mut hop,
        &RadiiMessage::TunnelOpen {
            hops: vec![RouteHop {
                node_id: "someone-else".into(),
                addr: relay_addr.to_string(),
            }],
        },
    )
    .await
    .unwrap();

    match read_message(&mut hop).await.unwrap() {
        RadiiMessage::Ack { status } => assert_eq!(status, "tunnel_misaddressed"),
        other => panic!("expected a refusal, got {other:?}"),
    }
}
```

Make `RelayConfig`'s fields public in Task 5 if they are not already — this
test constructs one directly.

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p radii-integration --test relay_terminal -- --nocapture`
Expected: FAIL — `could not find relay in radii_fetch`.

- [ ] **Step 3: Implement the terminal path**

Create `crates/fetch/src/relay.rs`:

```rust
//! The relay listener: the only surface on which a node accepts a chain.
//!
//! It is separate from the tunnel listener because that one carries raw bytes
//! with no framing, so a `TunnelOpen` preamble cannot be read there without
//! breaking every existing plain client. Keeping it separate also makes relay
//! capability independently firewall-able, which matters when its whole
//! purpose is exposure to peers the operator does not run.

use crate::config::RelayConfig;
use anyhow::{bail, Context, Result};
use radii_proto::tls::TlsIdentity;
use radii_proto::{read_message, write_message, BoxedStream, RadiiMessage, RouteHop};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;

pub struct RelayRuntime {
    pub config: RelayConfig,
    identity: TlsIdentity,
    upstream: String,
    tunnel_listener_tls: Option<TlsIdentity>,
}

impl RelayRuntime {
    pub fn new(
        config: RelayConfig,
        upstream: String,
        tunnel_listener_tls: Option<TlsIdentity>,
    ) -> Result<Arc<Self>> {
        let tls = config
            .tls
            .as_ref()
            .context("[relay.tls] is required for the relay listener")?;
        let identity = TlsIdentity::load(tls)?;
        Ok(Arc::new(Self {
            config,
            identity,
            upstream,
            tunnel_listener_tls,
        }))
    }
}

pub async fn run(listener: TcpListener, runtime: Arc<RelayRuntime>) -> Result<()> {
    tracing::info!(
        bind = %runtime.config.bind,
        node_id = %runtime.config.node_id,
        "relay listening"
    );
    loop {
        let (stream, addr) = listener.accept().await?;
        let runtime = Arc::clone(&runtime);
        tokio::spawn(async move {
            if let Err(err) = handle(stream, addr, runtime).await {
                tracing::warn!(source = %addr, error = %err, "relay connection failed");
            }
        });
    }
}

async fn handle(
    stream: tokio::net::TcpStream,
    addr: SocketAddr,
    runtime: Arc<RelayRuntime>,
) -> Result<()> {
    let (mut inbound, peer) =
        radii_proto::tls::accept(stream, Some(&runtime.identity)).await?;
    let peer = peer.context("relay listener requires mutual TLS")?;

    let hops = match read_message(&mut inbound).await? {
        RadiiMessage::TunnelOpen { hops } => hops,
        other => {
            tracing::warn!(source = %addr, ?other, "relay expected a TunnelOpen");
            return refuse(&mut inbound, "expected_tunnel_open").await;
        }
    };

    if let Err(status) = validate(&hops, &runtime.config) {
        tracing::warn!(source = %addr, peer = %peer, status, "relay refused a chain");
        return refuse(&mut inbound, status).await;
    }

    if hops.len() == 1 {
        return terminate(inbound, runtime).await;
    }

    // Forwarding lands in Task 7. Until then a multi-hop chain is refused
    // rather than silently mishandled.
    refuse(&mut inbound, "relay_forwarding_unavailable").await
}

/// Local, cheap checks made before any dialing happens.
fn validate(hops: &[RouteHop], config: &RelayConfig) -> Result<(), &'static str> {
    if hops.len() > config.max_hops {
        return Err("tunnel_too_long");
    }
    if hops[0].node_id != config.node_id {
        return Err("tunnel_misaddressed");
    }
    let mut seen = std::collections::HashSet::new();
    if !hops.iter().all(|hop| seen.insert(&hop.node_id)) {
        return Err("tunnel_path_loops");
    }
    Ok(())
}

async fn refuse(stream: &mut BoxedStream, status: &str) -> Result<()> {
    write_message(
        stream,
        &RadiiMessage::Ack {
            status: status.to_string(),
        },
    )
    .await
}

/// This node is the chain's last hop: ack, then run the end-to-end session
/// and splice it to the configured upstream.
async fn terminate(mut inbound: BoxedStream, runtime: Arc<RelayRuntime>) -> Result<()> {
    write_message(
        &mut inbound,
        &RadiiMessage::Ack {
            status: "tunnel_ready".to_string(),
        },
    )
    .await?;

    let (e2e, initiator) =
        radii_proto::tls::accept_on(inbound, runtime.tunnel_listener_tls.as_ref()).await?;
    tracing::info!(
        initiator = ?initiator,
        upstream = %runtime.upstream,
        "relay terminating a chain"
    );

    let upstream = tokio::net::TcpStream::connect(crate::server::normalize_upstream(
        &runtime.upstream,
    ))
    .await?;
    splice(e2e, Box::new(upstream)).await
}

pub(crate) async fn splice(a: BoxedStream, b: BoxedStream) -> Result<()> {
    let (mut ar, mut aw) = tokio::io::split(a);
    let (mut br, mut bw) = tokio::io::split(b);
    tokio::try_join!(
        tokio::io::copy(&mut ar, &mut bw),
        tokio::io::copy(&mut br, &mut aw)
    )?;
    Ok(())
}
```

Import only what this task uses — `anyhow::{Context, Result}`, not `bail`.
Task 7 adds `bail` when forwarding needs it. `-D warnings` will reject an
unused import, so do not import ahead of use.

Register the module in `crates/fetch/src/lib.rs`:

```rust
pub mod relay;
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cargo test -p radii-integration --test relay_terminal -- --nocapture`
Expected: PASS, both cases.

- [ ] **Step 5: Lint and commit**

```bash
cargo clippy --workspace --all-targets -- -D warnings
git add crates/fetch/src/relay.rs crates/fetch/src/lib.rs crates/integration/tests/relay_terminal.rs
git commit -m "feat(fetch): terminate relayed tunnel chains on the relay listener"
```

---

## Task 7: Relay forwarding

**Files:**
- Modify: `crates/fetch/src/relay.rs`
- Test: `crates/integration/tests/relay_forwarding.rs`

**Interfaces:**
- Consumes: everything from Task 6.
- Produces: no new public names; `handle` now forwards when `hops.len() > 1`.

- [ ] **Step 1: Write the failing test**

Create `crates/integration/tests/relay_forwarding.rs`. Build the same fixtures
as `relay_terminal.rs` (copy `run_echo` and the `RelayConfig` construction
verbatim rather than sharing them — the two tests must be readable alone), then:

```rust
#[tokio::test]
async fn a_two_hop_chain_carries_bytes_end_to_end() {
    let ca = TestCa::new();
    let client_identity = TlsIdentity::load(&ca.issue("node-s")).unwrap();

    let (echo_listener, echo_addr) = bind_local().await.unwrap();
    tokio::spawn(run_echo(echo_listener));

    // Terminal node.
    let (t_listener, t_addr) = bind_local().await.unwrap();
    let t_runtime = radii_fetch::relay::RelayRuntime::new(
        relay_config(&ca, "node-t", t_addr),
        echo_addr.to_string(),
        Some(TlsIdentity::load(&ca.issue("node-t")).unwrap()),
    )
    .unwrap();
    tokio::spawn(radii_fetch::relay::run(t_listener, t_runtime));

    // Intermediate relay.
    let (r_listener, r_addr) = bind_local().await.unwrap();
    let r_runtime = radii_fetch::relay::RelayRuntime::new(
        relay_config(&ca, "node-r", r_addr),
        "127.0.0.1:1".to_string(), // never used: this node only forwards
        None,
    )
    .unwrap();
    tokio::spawn(radii_fetch::relay::run(r_listener, r_runtime));

    wait_ready(t_addr).await;
    wait_ready(r_addr).await;

    let mut hop = radii_proto::tls::dial_expecting(
        &r_addr.to_string(),
        Some(&client_identity),
        Some("node-r"),
    )
    .await
    .unwrap();

    write_message(
        &mut hop,
        &RadiiMessage::TunnelOpen {
            hops: vec![
                RouteHop { node_id: "node-r".into(), addr: r_addr.to_string() },
                RouteHop { node_id: "node-t".into(), addr: t_addr.to_string() },
            ],
        },
    )
    .await
    .unwrap();

    match read_message(&mut hop).await.unwrap() {
        RadiiMessage::Ack { status } => assert_eq!(status, "tunnel_ready"),
        other => panic!("expected tunnel_ready, got {other:?}"),
    }

    // The end-to-end identity check binds to the TARGET, not to the relay we
    // actually dialed. This is the property that makes an opaque relay safe.
    let mut e2e = radii_proto::tls::connect_on(
        hop,
        &t_addr.to_string(),
        Some(&client_identity),
        Some("node-t"),
    )
    .await
    .unwrap();

    e2e.write_all(b"through").await.unwrap();
    let mut buf = [0u8; 7];
    e2e.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"through");
}

#[tokio::test]
async fn rejects_a_path_that_repeats_a_node() {
    let ca = TestCa::new();
    let client_identity = TlsIdentity::load(&ca.issue("node-s")).unwrap();
    let (r_listener, r_addr) = bind_local().await.unwrap();
    let runtime = radii_fetch::relay::RelayRuntime::new(
        relay_config(&ca, "node-r", r_addr),
        "127.0.0.1:1".to_string(),
        None,
    )
    .unwrap();
    tokio::spawn(radii_fetch::relay::run(r_listener, runtime));
    wait_ready(r_addr).await;

    let mut hop = radii_proto::tls::dial_expecting(
        &r_addr.to_string(),
        Some(&client_identity),
        Some("node-r"),
    )
    .await
    .unwrap();

    write_message(
        &mut hop,
        &RadiiMessage::TunnelOpen {
            hops: vec![
                RouteHop { node_id: "node-r".into(), addr: r_addr.to_string() },
                RouteHop { node_id: "node-r".into(), addr: r_addr.to_string() },
            ],
        },
    )
    .await
    .unwrap();

    match read_message(&mut hop).await.unwrap() {
        RadiiMessage::Ack { status } => assert_eq!(status, "tunnel_path_loops"),
        other => panic!("expected a loop refusal, got {other:?}"),
    }
}

#[tokio::test]
async fn rejects_a_path_longer_than_the_local_limit() {
    let ca = TestCa::new();
    let client_identity = TlsIdentity::load(&ca.issue("node-s")).unwrap();
    let (r_listener, r_addr) = bind_local().await.unwrap();
    let mut config = relay_config(&ca, "node-r", r_addr);
    config.max_hops = 1; // terminate-only posture
    let runtime =
        radii_fetch::relay::RelayRuntime::new(config, "127.0.0.1:1".to_string(), None).unwrap();
    tokio::spawn(radii_fetch::relay::run(r_listener, runtime));
    wait_ready(r_addr).await;

    let mut hop = radii_proto::tls::dial_expecting(
        &r_addr.to_string(),
        Some(&client_identity),
        Some("node-r"),
    )
    .await
    .unwrap();

    write_message(
        &mut hop,
        &RadiiMessage::TunnelOpen {
            hops: vec![
                RouteHop { node_id: "node-r".into(), addr: r_addr.to_string() },
                RouteHop { node_id: "node-t".into(), addr: "127.0.0.1:9".into() },
            ],
        },
    )
    .await
    .unwrap();

    match read_message(&mut hop).await.unwrap() {
        RadiiMessage::Ack { status } => assert_eq!(status, "tunnel_too_long"),
        other => panic!("expected a length refusal, got {other:?}"),
    }
}
```

Add the shared fixture helper to the same file:

```rust
fn relay_config(ca: &TestCa, node_id: &str, bind: &str) -> radii_fetch::config::RelayConfig {
    radii_fetch::config::RelayConfig {
        bind: bind.to_string(),
        node_id: node_id.to_string(),
        max_hops: 8,
        max_concurrent_total: 16,
        max_concurrent_per_peer: 4,
        idle_timeout_ms: 30_000,
        allow_peers: Vec::new(),
        tls: Some(ca.issue(node_id)),
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p radii-integration --test relay_forwarding -- --nocapture`
Expected: FAIL — the two-hop case gets `relay_forwarding_unavailable`.

- [ ] **Step 3: Implement forwarding**

In `crates/fetch/src/relay.rs`, replace the placeholder branch in `handle`:

```rust
    if hops.len() == 1 {
        return terminate(inbound, runtime).await;
    }
    forward(inbound, hops, runtime).await
```

Add:

```rust
/// This node is an intermediate hop: dial the next one, pass the tail along,
/// relay its answer back, then carry opaque bytes in both directions.
///
/// Nothing here inspects the payload. The initiator's end-to-end session runs
/// inside this pipe, so what crosses it is ciphertext this node cannot read.
async fn forward(
    mut inbound: BoxedStream,
    hops: Vec<RouteHop>,
    runtime: Arc<RelayRuntime>,
) -> Result<()> {
    let next = &hops[1];
    let outbound = radii_proto::tls::dial_expecting(
        &next.addr,
        Some(&runtime.identity),
        Some(&next.node_id),
    )
    .await;

    let mut outbound = match outbound {
        Ok(stream) => stream,
        Err(err) => {
            tracing::warn!(
                next = %next.node_id,
                addr = %next.addr,
                error = %err,
                "relay could not reach the next hop"
            );
            return refuse(&mut inbound, "tunnel_hop_unreachable").await;
        }
    };

    write_message(
        &mut outbound,
        &RadiiMessage::TunnelOpen {
            hops: hops[1..].to_vec(),
        },
    )
    .await?;

    // One frame back — the terminal node's ack, or a refusal from any hop
    // downstream — then the pipe goes opaque.
    let ack = read_message(&mut outbound).await?;
    write_message(&mut inbound, &ack).await?;
    if !matches!(&ack, RadiiMessage::Ack { status } if status == "tunnel_ready") {
        return Ok(());
    }

    splice(inbound, outbound).await
}
```

Add `bail` to the `anyhow` import in this file — Task 6 deliberately left it
out, since `-D warnings` rejects an import before its first use.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p radii-integration --test relay_forwarding --test relay_terminal -- --nocapture`
Expected: PASS, all five cases.

- [ ] **Step 5: Lint and commit**

```bash
cargo clippy --workspace --all-targets -- -D warnings
git add crates/fetch/src/relay.rs crates/integration/tests/relay_forwarding.rs
git commit -m "feat(fetch): forward relayed chains along an initiator-pinned path"
```

---

## Task 8: Initiator chain establishment

**Files:**
- Create: `crates/fetch/src/chain.rs`
- Modify: `crates/fetch/src/lib.rs`
- Test: `crates/integration/tests/chain_establish.rs`

**Interfaces:**
- Consumes: `ResolvedRoute` / `ResolvedHop` (Task 1), `tls::connect_on` (Task 4), the relay from Tasks 6–7.
- Produces: `chain::establish(route: &ResolvedRoute, hop_tls: Option<&TlsIdentity>, e2e_tls: Option<&TlsIdentity>) -> anyhow::Result<BoxedStream>`.

- [ ] **Step 1: Write the failing test**

Create `crates/integration/tests/chain_establish.rs`, reusing the `run_echo`
and `relay_config` helpers written out verbatim as in Task 7, then:

```rust
#[tokio::test]
async fn establishes_a_two_hop_chain_and_returns_an_end_to_end_stream() {
    let ca = TestCa::new();
    let client_identity = TlsIdentity::load(&ca.issue("node-s")).unwrap();

    let (echo_listener, echo_addr) = bind_local().await.unwrap();
    tokio::spawn(run_echo(echo_listener));

    let (t_listener, t_addr) = bind_local().await.unwrap();
    tokio::spawn(radii_fetch::relay::run(
        t_listener,
        radii_fetch::relay::RelayRuntime::new(
            relay_config(&ca, "node-t", t_addr),
            echo_addr.to_string(),
            Some(TlsIdentity::load(&ca.issue("node-t")).unwrap()),
        )
        .unwrap(),
    ));

    let (r_listener, r_addr) = bind_local().await.unwrap();
    tokio::spawn(radii_fetch::relay::run(
        r_listener,
        radii_fetch::relay::RelayRuntime::new(
            relay_config(&ca, "node-r", r_addr),
            "127.0.0.1:1".to_string(),
            None,
        )
        .unwrap(),
    ));

    wait_ready(t_addr).await;
    wait_ready(r_addr).await;

    let route = ResolvedRoute {
        hops: vec![
            ResolvedHop { node_id: NodeId("node-r".into()), addr: r_addr.to_string() },
            ResolvedHop { node_id: NodeId("node-t".into()), addr: t_addr.to_string() },
        ],
        score: 1.0,
    };

    let mut stream = radii_fetch::chain::establish(
        &route,
        Some(&client_identity),
        Some(&client_identity),
    )
    .await
    .unwrap();

    stream.write_all(b"chain").await.unwrap();
    let mut buf = [0u8; 5];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"chain");
}

#[tokio::test]
async fn fails_when_a_hop_refuses_the_chain() {
    let ca = TestCa::new();
    let client_identity = TlsIdentity::load(&ca.issue("node-s")).unwrap();

    let (r_listener, r_addr) = bind_local().await.unwrap();
    tokio::spawn(radii_fetch::relay::run(
        r_listener,
        radii_fetch::relay::RelayRuntime::new(
            relay_config(&ca, "node-r", r_addr),
            "127.0.0.1:1".to_string(),
            None,
        )
        .unwrap(),
    ));
    wait_ready(r_addr).await;

    // Next hop points at a closed port, so the relay cannot reach it.
    let route = ResolvedRoute {
        hops: vec![
            ResolvedHop { node_id: NodeId("node-r".into()), addr: r_addr.to_string() },
            ResolvedHop { node_id: NodeId("node-t".into()), addr: "127.0.0.1:1".into() },
        ],
        score: 1.0,
    };

    let err = radii_fetch::chain::establish(
        &route,
        Some(&client_identity),
        Some(&client_identity),
    )
    .await
    .unwrap_err();

    assert!(
        err.to_string().contains("tunnel_hop_unreachable"),
        "the refusal status should reach the initiator; got: {err}"
    );
}
```

Add the imports the test needs:

```rust
use radii_core::routing::{NodeId, ResolvedHop, ResolvedRoute};
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p radii-integration --test chain_establish -- --nocapture`
Expected: FAIL — `could not find chain in radii_fetch`.

- [ ] **Step 3: Implement chain establishment**

Create `crates/fetch/src/chain.rs`:

```rust
//! The initiator half of source routing: turn a resolved route into a byte
//! stream that speaks end-to-end with the target.
//!
//! Two TLS layers are involved and they check different things. The hop-local
//! layer authenticates the *first relay* and carries the `TunnelOpen`. The
//! end-to-end layer authenticates the *target* and carries the payload, which
//! every relay in between handles as opaque bytes.

use anyhow::{bail, Result};
use radii_core::routing::ResolvedRoute;
use radii_proto::tls::TlsIdentity;
use radii_proto::{read_message, write_message, BoxedStream, RadiiMessage, RouteHop};

pub async fn establish(
    route: &ResolvedRoute,
    hop_tls: Option<&TlsIdentity>,
    e2e_tls: Option<&TlsIdentity>,
) -> Result<BoxedStream> {
    let first = route
        .hops
        .first()
        .ok_or_else(|| anyhow::anyhow!("route has no hops"))?;
    let target = route
        .hops
        .last()
        .expect("a route with a first hop has a last hop");

    let mut hop =
        radii_proto::tls::dial_expecting(&first.addr, hop_tls, Some(&first.node_id.0)).await?;

    let hops: Vec<RouteHop> = route
        .hops
        .iter()
        .map(|hop| RouteHop {
            node_id: hop.node_id.0.clone(),
            addr: hop.addr.clone(),
        })
        .collect();
    write_message(&mut hop, &RadiiMessage::TunnelOpen { hops }).await?;

    match read_message(&mut hop).await? {
        RadiiMessage::Ack { status } if status == "tunnel_ready" => {}
        RadiiMessage::Ack { status } => bail!("chain refused: {status}"),
        other => bail!("expected an ack opening a chain, got {other:?}"),
    }

    // The identity checked here is the TARGET's, not the relay we dialed.
    // SNI uses the target's advertised address so certificate SANs are
    // checked against the host actually being reached.
    radii_proto::tls::connect_on(hop, &target.addr, e2e_tls, Some(&target.node_id.0)).await
}
```

Register it in `crates/fetch/src/lib.rs`:

```rust
pub mod chain;
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p radii-integration --test chain_establish -- --nocapture`
Expected: PASS, both cases.

- [ ] **Step 5: Lint and commit**

```bash
cargo clippy --workspace --all-targets -- -D warnings
git add crates/fetch/src/chain.rs crates/fetch/src/lib.rs crates/integration/tests/chain_establish.rs
git commit -m "feat(fetch): establish source-routed chains from the initiator"
```

---

## Task 9: Ranked candidate state and multi-target polling

Replaces `ResolvedTarget` / `SharedTarget`. `crates/integration/tests/fetch_upstream_identity.rs` imports both and must be updated in this task.

**Files:**
- Modify: `crates/fetch/src/graph.rs`
- Modify: `crates/fetch/src/server.rs` (signature only; the retry loop is Task 10)
- Modify: `crates/fetch/src/lib.rs`
- Modify: `crates/integration/tests/fetch_upstream_identity.rs`
- Test: `crates/fetch/src/graph.rs` (in-file `mod tests`)

**Interfaces:**
- Produces: `pub type SharedRoutes = Arc<RwLock<Vec<ResolvedRoute>>>`; `graph::run_poll(config: GraphConfig, routes: SharedRoutes, tls: Option<TlsIdentity>)`; `server::run_on_dynamic_with_tls(listener, static_upstream: String, routes: SharedRoutes, listener_tls, upstream_tls)`.
- `ResolvedTarget` and `SharedTarget` are **removed**.

- [ ] **Step 1: Write the failing test**

Add to `crates/fetch/src/graph.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use radii_core::routing::{GraphSnapshot, Link, NodeId, ProtocolId};

    #[test]
    fn plans_across_every_configured_target() {
        let mut snapshot = GraphSnapshot::new();
        for (from, to, rtt) in [("s", "t1", 100u32), ("s", "t2", 10)] {
            snapshot.add_link(Link {
                from: NodeId(from.into()),
                to: NodeId(to.into()),
                protocol: ProtocolId::new("radii"),
                reachable: true,
                latency_ms: Some(rtt),
            });
        }
        let listen: HashMap<String, Vec<String>> = [
            ("t1".to_string(), vec!["10.0.0.1:2224".to_string()]),
            ("t2".to_string(), vec!["10.0.0.2:2224".to_string()]),
        ]
        .into_iter()
        .collect();

        let routes = plan_from(
            &snapshot,
            &listen,
            &NodeId("s".into()),
            &[NodeId("t1".into()), NodeId("t2".into())],
            &[ProtocolId::new("radii")],
            4,
            3,
        );

        assert_eq!(routes.len(), 2);
        assert_eq!(routes[0].target().0, "t2", "cheaper target ranks first");
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p radii-fetch graph -- --nocapture`
Expected: FAIL — `cannot find function plan_from`.

- [ ] **Step 3: Rewrite the poller**

Replace `ResolvedTarget`, `SharedTarget`, and `resolve_once` in
`crates/fetch/src/graph.rs`:

```rust
use radii_core::routing::{
    resolve_candidates, GraphSnapshot, Link, NodeId, ProtocolId, ResolvedRoute,
};

/// The currently ranked routes, refreshed by [`run_poll`]. Empty means no
/// reachable route has been found yet; callers fall back to their static
/// configured upstream in that case.
pub type SharedRoutes = Arc<RwLock<Vec<ResolvedRoute>>>;

/// Thin seam over `resolve_candidates` so the polling logic is unit-testable
/// without a live Crawl.
#[allow(clippy::too_many_arguments)]
pub fn plan_from(
    snapshot: &GraphSnapshot,
    listen_addrs: &HashMap<String, Vec<String>>,
    source: &NodeId,
    targets: &[NodeId],
    allowed_protocols: &[ProtocolId],
    max_hops: usize,
    max_candidates: usize,
) -> Vec<ResolvedRoute> {
    resolve_candidates(
        snapshot,
        listen_addrs,
        source,
        targets,
        allowed_protocols,
        max_hops,
        max_candidates,
    )
}

pub async fn run_poll(
    config: GraphConfig,
    routes: SharedRoutes,
    tls: Option<TlsIdentity>,
) -> anyhow::Result<()> {
    let interval = Duration::from_millis(config.poll_interval_ms.max(1));
    let source = NodeId(config.source_node_id.clone());
    let targets: Vec<NodeId> = config
        .target_node_ids
        .iter()
        .cloned()
        .map(NodeId)
        .collect();
    let allowed_protocols: Vec<ProtocolId> = config
        .allowed_protocols
        .iter()
        .cloned()
        .map(ProtocolId::new)
        .collect();

    loop {
        match fetch_once(&config.crawl_upstream, tls.as_ref()).await {
            Ok((snapshot, listen_addrs)) => {
                let planned = plan_from(
                    &snapshot,
                    &listen_addrs,
                    &source,
                    &targets,
                    &allowed_protocols,
                    config.max_hops,
                    config.max_candidates,
                );
                if planned.is_empty() {
                    tracing::warn!(?targets, "fetch found no reachable route to any target");
                }
                tracing::debug!(candidates = planned.len(), "fetch refreshed route candidates");
                *routes.write().expect("fetch routes poisoned") = planned;
            }
            Err(err) => {
                tracing::warn!(
                    upstream = %config.crawl_upstream,
                    error = %err,
                    "fetch graph query failed"
                );
            }
        }
        tokio::time::sleep(interval).await;
    }
}

/// Queries Crawl once, returning the snapshot and the node registry.
async fn fetch_once(
    crawl_upstream: &str,
    tls: Option<&TlsIdentity>,
) -> anyhow::Result<(GraphSnapshot, HashMap<String, Vec<String>>)> {
    let mut stream = radii_proto::tls::dial(crawl_upstream, tls).await?;
    let (nodes, reports) = radii_proto::query_graph_on(&mut stream).await?;

    let mut snapshot = GraphSnapshot::new();
    for report in reports {
        snapshot.add_link(Link {
            from: NodeId(report.from),
            to: NodeId(report.target),
            protocol: ProtocolId::new(report.protocol),
            reachable: report.reachable,
            latency_ms: report.rtt_ms,
        });
    }
    if snapshot.dropped_links() > 0 {
        tracing::warn!(
            upstream = %crawl_upstream,
            dropped = snapshot.dropped_links(),
            "crawl graph exceeded the local size cap; planning from a partial view"
        );
    }
    let listen_addrs = nodes
        .into_iter()
        .map(|node| (node.node_id, node.listen_addrs))
        .collect();
    Ok((snapshot, listen_addrs))
}
```

In `crates/fetch/src/server.rs`, change `run_on_dynamic` and
`run_on_dynamic_with_tls` to take `routes: SharedRoutes` and, for now, keep
today's behaviour by using only the best candidate's final hop:

```rust
        let resolved = routes.read().ok().and_then(|guard| guard.first().cloned());
        let (upstream, expected_node_id) = match resolved {
            Some(route) => {
                let last = route.hops.last().expect("non-empty hops").clone();
                (last.addr, Some(last.node_id.0))
            }
            None => (static_upstream.clone(), None),
        };
```

In `crates/fetch/src/lib.rs`, replace the `SharedTarget` wiring:

```rust
            let routes: graph::SharedRoutes = Arc::new(RwLock::new(Vec::new()));
            tokio::spawn(graph::run_poll(graph_config, Arc::clone(&routes), graph_tls));
            server::run_on_dynamic_with_tls(
                listener,
                config.upstream,
                routes,
                listener_tls,
                upstream_tls,
            )
            .await
```

- [ ] **Step 4: Update the existing identity test**

In `crates/integration/tests/fetch_upstream_identity.rs`, replace the
`ResolvedTarget` import and the `tunnel_through` parameter:

```rust
use radii_core::routing::{NodeId, ResolvedHop, ResolvedRoute};

async fn tunnel_through(
    route: Option<ResolvedRoute>,
    listener_tls: Option<TlsIdentity>,
    upstream_tls: Option<TlsIdentity>,
    static_upstream: String,
) -> std::io::Result<usize> {
    let (fetch_listener, fetch_addr) = bind_local().await.unwrap();
    let shared = Arc::new(RwLock::new(route.into_iter().collect::<Vec<_>>()));
```

At each call site, replace the `ResolvedTarget { addr, node_id }` construction
with:

```rust
    Some(ResolvedRoute {
        hops: vec![ResolvedHop {
            node_id: NodeId("node-b".into()),
            addr: poisoned_addr.to_string(),
        }],
        score: 1.0,
    })
```

using whatever address that call site already passed. The test's assertions
are unchanged — it still checks that a poisoned address fails the identity
check.

- [ ] **Step 5: Run the full suite**

Run: `cargo test --workspace`
Expected: PASS, including `fetch_upstream_identity` and `fetch_graph_routing`.

- [ ] **Step 6: Lint and commit**

```bash
cargo clippy --workspace --all-targets -- -D warnings
git add crates/fetch/src/graph.rs crates/fetch/src/server.rs crates/fetch/src/lib.rs crates/integration/tests/fetch_upstream_identity.rs
git commit -m "feat(fetch): track ranked route candidates across multiple targets"
```

---

## Task 10: The retry loop

Where the goal is actually met.

**Files:**
- Modify: `crates/fetch/src/server.rs`
- Test: `crates/integration/tests/candidate_retry.rs`

**Interfaces:**
- Consumes: `chain::establish` (Task 8), `SharedRoutes` (Task 9), `GraphConfig::max_candidates` / `attempt_timeout_ms` (Task 5).
- Produces: `server::run_on_dynamic_with_tls(listener, static_upstream, routes, attempt_timeout_ms: u64, listener_tls, upstream_tls)` — one added parameter.

- [ ] **Step 1: Write the failing test**

Create `crates/integration/tests/candidate_retry.rs`, with the `run_echo` and
`relay_config` helpers written out as in Task 7:

```rust
#[tokio::test]
async fn falls_over_to_the_second_candidate_when_the_first_is_dead() {
    let ca = TestCa::new();
    let client_identity = TlsIdentity::load(&ca.issue("node-s")).unwrap();

    let (echo_listener, echo_addr) = bind_local().await.unwrap();
    tokio::spawn(run_echo(echo_listener));

    // Only the second target is actually running.
    let (t_listener, t_addr) = bind_local().await.unwrap();
    tokio::spawn(radii_fetch::relay::run(
        t_listener,
        radii_fetch::relay::RelayRuntime::new(
            relay_config(&ca, "node-t2", t_addr),
            echo_addr.to_string(),
            Some(TlsIdentity::load(&ca.issue("node-t2")).unwrap()),
        )
        .unwrap(),
    ));
    wait_ready(t_addr).await;

    let routes = vec![
        // Dead: nothing listens here.
        ResolvedRoute {
            hops: vec![ResolvedHop {
                node_id: NodeId("node-t1".into()),
                addr: "127.0.0.1:1".into(),
            }],
            score: 1.0,
        },
        ResolvedRoute {
            hops: vec![ResolvedHop {
                node_id: NodeId("node-t2".into()),
                addr: t_addr.to_string(),
            }],
            score: 2.0,
        },
    ];

    let (fetch_listener, fetch_addr) = bind_local().await.unwrap();
    let shared = Arc::new(RwLock::new(routes));
    tokio::spawn(radii_fetch::server::run_on_dynamic_with_tls(
        fetch_listener,
        "127.0.0.1:1".to_string(),
        shared,
        3000,
        None,
        Some(client_identity),
    ));
    wait_ready(fetch_addr).await;

    let mut client = tokio::net::TcpStream::connect(fetch_addr).await.unwrap();
    client.write_all(b"failover").await.unwrap();
    let mut buf = [0u8; 8];
    client.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"failover", "the client must not observe the dead candidate");
}

#[tokio::test]
async fn falls_back_to_the_static_upstream_when_every_candidate_fails() {
    let ca = TestCa::new();
    let client_identity = TlsIdentity::load(&ca.issue("node-s")).unwrap();

    let (echo_listener, echo_addr) = bind_local().await.unwrap();
    tokio::spawn(run_echo(echo_listener));

    let routes = vec![ResolvedRoute {
        hops: vec![ResolvedHop {
            node_id: NodeId("node-dead".into()),
            addr: "127.0.0.1:1".into(),
        }],
        score: 1.0,
    }];

    let (fetch_listener, fetch_addr) = bind_local().await.unwrap();
    tokio::spawn(radii_fetch::server::run_on_dynamic_with_tls(
        fetch_listener,
        echo_addr.to_string(),
        Arc::new(RwLock::new(routes)),
        1000,
        None,
        Some(client_identity),
    ));
    wait_ready(fetch_addr).await;

    let mut client = tokio::net::TcpStream::connect(fetch_addr).await.unwrap();
    client.write_all(b"static").await.unwrap();
    let mut buf = [0u8; 6];
    client.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"static");
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p radii-integration --test candidate_retry -- --nocapture`
Expected: FAIL — arity mismatch on `run_on_dynamic_with_tls`.

- [ ] **Step 3: Implement the retry loop**

In `crates/fetch/src/server.rs`, add the parameter and replace the
per-connection resolution with the loop:

```rust
/// Walks the ranked candidates until one chain comes up, then splices.
///
/// Retry stops the moment the end-to-end handshake succeeds: after that,
/// application bytes may have flowed and TCP offers no way to migrate the
/// stream, so a later failure is terminal by construction rather than by
/// choice. See the design spec's "Retry boundary".
async fn connect_upstream(
    routes: &SharedRoutes,
    static_upstream: &str,
    attempt_timeout_ms: u64,
    upstream_tls: Option<&TlsIdentity>,
) -> anyhow::Result<BoxedStream> {
    let candidates: Vec<ResolvedRoute> = routes
        .read()
        .map(|guard| guard.clone())
        .unwrap_or_default();

    let timeout = Duration::from_millis(attempt_timeout_ms.max(1));
    for (index, route) in candidates.iter().enumerate() {
        let attempt = tokio::time::timeout(
            timeout,
            crate::chain::establish(route, upstream_tls, upstream_tls),
        )
        .await;

        match attempt {
            Ok(Ok(stream)) => {
                tracing::info!(
                    candidate = index,
                    target = %route.target().0,
                    hops = route.hops.len(),
                    "fetch established a chain"
                );
                return Ok(stream);
            }
            Ok(Err(err)) => tracing::warn!(
                candidate = index,
                target = %route.target().0,
                error = %err,
                "candidate failed; trying the next"
            ),
            Err(_) => tracing::warn!(
                candidate = index,
                target = %route.target().0,
                timeout_ms = attempt_timeout_ms,
                "candidate timed out; trying the next"
            ),
        }
    }

    // No candidate worked. The static upstream came from the operator's own
    // config, which is trusted by definition and may legitimately point at a
    // host with no Radii identity at all, so it carries no expected node id.
    tracing::warn!(
        candidates = candidates.len(),
        upstream = %static_upstream,
        "every candidate failed; falling back to the static upstream"
    );
    radii_proto::tls::dial(&normalize_upstream(static_upstream), upstream_tls).await
}
```

Rewrite `run_on_dynamic_with_tls` to accept `attempt_timeout_ms: u64` and to
call `connect_upstream`, then splice with the inbound stream. Update
`run_on_dynamic` to pass a 3000 ms default. In `crates/fetch/src/lib.rs`, pass
`graph_config.attempt_timeout_ms` through.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test --workspace`
Expected: PASS.

- [ ] **Step 5: Lint and commit**

```bash
cargo clippy --workspace --all-targets -- -D warnings
git add crates/fetch/src/server.rs crates/fetch/src/lib.rs crates/integration/tests/candidate_retry.rs
git commit -m "feat(fetch): fail over across ranked route candidates"
```

---

## Task 11: Relay admission and concurrency limits

**Gate: no relay may face an untrusted network before this task lands.**

**Files:**
- Modify: `crates/fetch/src/relay.rs`
- Test: `crates/integration/tests/relay_limits.rs`

**Interfaces:**
- Consumes: `RelayConfig` fields from Task 5.
- Produces: no new public names. `RelayRuntime` gains private permit accounting.

- [ ] **Step 1: Write the failing test**

Create `crates/integration/tests/relay_limits.rs`:

```rust
#[tokio::test]
async fn refuses_a_peer_outside_a_configured_allowlist() {
    let ca = TestCa::new();
    let stranger = TlsIdentity::load(&ca.issue("node-stranger")).unwrap();

    let (r_listener, r_addr) = bind_local().await.unwrap();
    let mut config = relay_config(&ca, "node-r", r_addr);
    config.allow_peers = vec!["node-friend".to_string()];
    tokio::spawn(radii_fetch::relay::run(
        r_listener,
        radii_fetch::relay::RelayRuntime::new(config, "127.0.0.1:1".into(), None).unwrap(),
    ));
    wait_ready(r_addr).await;

    let mut hop = radii_proto::tls::dial_expecting(
        &r_addr.to_string(),
        Some(&stranger),
        Some("node-r"),
    )
    .await
    .unwrap();

    write_message(
        &mut hop,
        &RadiiMessage::TunnelOpen {
            hops: vec![RouteHop { node_id: "node-r".into(), addr: r_addr.to_string() }],
        },
    )
    .await
    .unwrap();

    match read_message(&mut hop).await.unwrap() {
        RadiiMessage::Ack { status } => assert_eq!(status, "relay_forbidden"),
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[tokio::test]
async fn caps_concurrent_chains_per_peer() {
    let ca = TestCa::new();
    let peer = TlsIdentity::load(&ca.issue("node-s")).unwrap();

    let (echo_listener, echo_addr) = bind_local().await.unwrap();
    tokio::spawn(run_echo(echo_listener));

    let (t_listener, t_addr) = bind_local().await.unwrap();
    let mut config = relay_config(&ca, "node-t", t_addr);
    config.max_concurrent_per_peer = 1;
    tokio::spawn(radii_fetch::relay::run(
        t_listener,
        radii_fetch::relay::RelayRuntime::new(
            config,
            echo_addr.to_string(),
            Some(TlsIdentity::load(&ca.issue("node-t")).unwrap()),
        )
        .unwrap(),
    ));
    wait_ready(t_addr).await;

    let route = ResolvedRoute {
        hops: vec![ResolvedHop {
            node_id: NodeId("node-t".into()),
            addr: t_addr.to_string(),
        }],
        score: 1.0,
    };

    // Hold the first chain open.
    let _held = radii_fetch::chain::establish(&route, Some(&peer), Some(&peer))
        .await
        .unwrap();

    let err = radii_fetch::chain::establish(&route, Some(&peer), Some(&peer))
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("relay_busy"),
        "the second concurrent chain must be refused; got: {err}"
    );
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p radii-integration --test relay_limits -- --nocapture`
Expected: FAIL — the allowlist is ignored and the second chain succeeds.

- [ ] **Step 3: Implement admission and permits**

In `crates/fetch/src/relay.rs`, add to `RelayRuntime`:

```rust
use std::collections::HashMap;
use std::sync::Mutex;

pub struct RelayRuntime {
    pub config: RelayConfig,
    identity: TlsIdentity,
    upstream: String,
    tunnel_listener_tls: Option<TlsIdentity>,
    live: Mutex<Live>,
}

#[derive(Default)]
struct Live {
    total: usize,
    per_peer: HashMap<String, usize>,
}

/// Releases a peer's slot when the chain ends, however it ends.
struct Permit {
    runtime: Arc<RelayRuntime>,
    peer: String,
}

impl Drop for Permit {
    fn drop(&mut self) {
        let mut live = self.runtime.live.lock().expect("relay accounting poisoned");
        live.total = live.total.saturating_sub(1);
        if let Some(count) = live.per_peer.get_mut(&self.peer) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                live.per_peer.remove(&self.peer);
            }
        }
    }
}

impl RelayRuntime {
    /// Admission is CA membership, narrowed by `allow_peers` when set.
    fn admits(&self, peer: &str) -> bool {
        self.config.allow_peers.is_empty()
            || self.config.allow_peers.iter().any(|id| id == peer)
    }

    /// Per-peer accounting is the load-bearing limit: without it the global
    /// cap is meaningless, because one peer can consume all of it.
    fn acquire(self: &Arc<Self>, peer: &str) -> Option<Permit> {
        let mut live = self.live.lock().expect("relay accounting poisoned");
        if live.total >= self.config.max_concurrent_total {
            return None;
        }
        let count = live.per_peer.entry(peer.to_string()).or_insert(0);
        if *count >= self.config.max_concurrent_per_peer {
            return None;
        }
        *count += 1;
        live.total += 1;
        Some(Permit {
            runtime: Arc::clone(self),
            peer: peer.to_string(),
        })
    }
}
```

Initialise `live: Mutex::new(Live::default())` in `new`. In `handle`, after
the peer identity is established and before the `TunnelOpen` is read:

```rust
    if !runtime.admits(&peer) {
        tracing::warn!(source = %addr, peer = %peer, "relay refused an unadmitted peer");
        return refuse(&mut inbound, "relay_forbidden").await;
    }

    let Some(_permit) = runtime.acquire(&peer) else {
        tracing::warn!(source = %addr, peer = %peer, "relay at capacity");
        return refuse(&mut inbound, "relay_busy").await;
    };
```

The permit binds to `_permit` and lives for the rest of `handle`, so the slot
is released when the chain ends for any reason.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test --workspace`
Expected: PASS.

- [ ] **Step 5: Lint and commit**

```bash
cargo clippy --workspace --all-targets -- -D warnings
git add crates/fetch/src/relay.rs crates/integration/tests/relay_limits.rs
git commit -m "feat(fetch): admit and bound relay peers on the relay listener"
```

---

## Task 12: Relay idle timeout

**Files:**
- Modify: `crates/fetch/src/relay.rs`
- Test: `crates/integration/tests/relay_limits.rs` (extend)

**Interfaces:** no public changes; `splice` becomes idle-aware.

- [ ] **Step 1: Write the failing test**

Append to `crates/integration/tests/relay_limits.rs`:

```rust
#[tokio::test]
async fn drops_a_chain_that_goes_idle() {
    let ca = TestCa::new();
    let peer = TlsIdentity::load(&ca.issue("node-s")).unwrap();

    let (echo_listener, echo_addr) = bind_local().await.unwrap();
    tokio::spawn(run_echo(echo_listener));

    let (t_listener, t_addr) = bind_local().await.unwrap();
    let mut config = relay_config(&ca, "node-t", t_addr);
    config.idle_timeout_ms = 300;
    tokio::spawn(radii_fetch::relay::run(
        t_listener,
        radii_fetch::relay::RelayRuntime::new(
            config,
            echo_addr.to_string(),
            Some(TlsIdentity::load(&ca.issue("node-t")).unwrap()),
        )
        .unwrap(),
    ));
    wait_ready(t_addr).await;

    let route = ResolvedRoute {
        hops: vec![ResolvedHop {
            node_id: NodeId("node-t".into()),
            addr: t_addr.to_string(),
        }],
        score: 1.0,
    };
    let mut stream = radii_fetch::chain::establish(&route, Some(&peer), Some(&peer))
        .await
        .unwrap();

    // Send nothing and wait past the idle window.
    tokio::time::sleep(std::time::Duration::from_millis(900)).await;

    let mut buf = [0u8; 1];
    let read = stream.read(&mut buf).await;
    assert!(
        matches!(read, Ok(0) | Err(_)),
        "an idle chain must be dropped, got {read:?}"
    );
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p radii-integration --test relay_limits drops_a_chain -- --nocapture`
Expected: FAIL — the read blocks and the test times out.

- [ ] **Step 3: Implement the idle timeout**

In `crates/fetch/src/relay.rs`, replace `splice` with an idle-aware version and
pass the configured window through from both `terminate` and `forward`:

```rust
/// Copies in both directions, abandoning the chain when neither side has
/// moved a byte for `idle` — closing, for this path, the connection-timeout
/// gap SECURITY.md records as outstanding.
pub(crate) async fn splice_with_idle(
    a: BoxedStream,
    b: BoxedStream,
    idle: std::time::Duration,
) -> Result<()> {
    let (mut ar, mut aw) = tokio::io::split(a);
    let (mut br, mut bw) = tokio::io::split(b);

    let forward = tokio::io::copy(&mut ar, &mut bw);
    let backward = tokio::io::copy(&mut br, &mut aw);
    let both = async { tokio::try_join!(forward, backward).map(|_| ()) };

    match tokio::time::timeout(idle, both).await {
        Ok(result) => result.map_err(Into::into),
        Err(_) => {
            tracing::info!(idle_ms = idle.as_millis(), "relay dropped an idle chain");
            Ok(())
        }
    }
}
```

Call it as
`splice_with_idle(a, b, Duration::from_millis(runtime.config.idle_timeout_ms.max(1)))`
from both call sites, and delete the old `splice`.

Note for the reviewer: this is a whole-chain deadline, not a true
inactivity timer — a chain busy for longer than `idle_timeout_ms` is also
dropped. That is acceptable for the tunnel workloads Radii carries today and
keeps the implementation to one `timeout` call; a per-direction inactivity
timer is a follow-up if long-lived chains appear.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test --workspace`
Expected: PASS.

- [ ] **Step 5: Lint and commit**

```bash
cargo clippy --workspace --all-targets -- -D warnings
git add crates/fetch/src/relay.rs crates/integration/tests/relay_limits.rs
git commit -m "feat(fetch): drop relayed chains that go idle"
```

---

## Task 13: Head ranked candidates

**Files:**
- Modify: `crates/head/src/config.rs`
- Modify: `crates/head/src/graph.rs`
- Modify: `crates/head/src/decision.rs`
- Modify: `crates/head/src/http.rs`
- Modify: `crates/head/head.example.toml`
- Test: `crates/integration/tests/head_http.rs` (extend)

**Interfaces:**
- Produces: `graph::plan_backends(...) -> Vec<(String, usize, f64)>`; `HeadResponse` gains `candidates: Vec<String>`.

Head still returns a decision rather than proxying, so it cannot fail over
itself. Exposing the ranked list is what lets whatever consumes the decision do
so, and it is the seam the future reverse proxy will use.

- [ ] **Step 1: Write the failing test**

Add to `crates/integration/tests/head_http.rs`:

```rust
use radii_core::routing::{GraphSnapshot, Link, NodeId, ProtocolId};
use radii_head::decision::GraphRoutePolicy;
use radii_head::graph::{GraphState, SharedGraphState};
use std::sync::{Arc, RwLock};

/// Two mapped nodes serve one host; `node-c` is cheaper, so it must rank
/// first and become the `backend` the response reports.
fn state_with_two_backends() -> SharedGraphState {
    let mut snapshot = GraphSnapshot::new();
    for (to, rtt) in [("node-b", 200u32), ("node-c", 20)] {
        snapshot.add_link(Link {
            from: NodeId("head".into()),
            to: NodeId(to.into()),
            protocol: ProtocolId::new("http"),
            reachable: true,
            latency_ms: Some(rtt),
        });
    }
    let mut listen_addrs = HashMap::new();
    listen_addrs.insert("node-b".to_string(), vec!["10.0.0.11:9000".to_string()]);
    listen_addrs.insert("node-c".to_string(), vec!["10.0.0.12:9000".to_string()]);
    Arc::new(RwLock::new(GraphState { snapshot, listen_addrs }))
}

#[tokio::test]
async fn head_reports_ranked_candidates() {
    let (listener, addr) = bind_local().await.unwrap();

    let mut node_map = HashMap::new();
    node_map.insert(
        "site.example".to_string(),
        vec!["node-b".to_string(), "node-c".to_string()],
    );
    let policy = GraphRoutePolicy::new(
        node_map,
        "head".to_string(),
        vec!["http".to_string()],
        4,
        3,
        state_with_two_backends(),
    );
    let decision = DecisionEngine::from_config_with_graph(
        &radii_head::config::RoutingConfig {
            default_backend: "http://127.0.0.1:9000".into(),
            host_map: HashMap::new(),
        },
        Some(policy),
    );

    let handle = tokio::spawn(async move { serve_http_on(listener, decision).await });
    wait_ready(&addr).await.unwrap();

    let response = reqwest::Client::new()
        .get(format!("http://{addr}/x"))
        .header("Host", "site.example")
        .send()
        .await
        .unwrap()
        .json::<serde_json::Value>()
        .await
        .unwrap();

    let candidates = response["candidates"].as_array().expect("candidates array");
    assert_eq!(candidates.len(), 2);
    assert_eq!(candidates[0], "10.0.0.12:9000", "cheaper node ranks first");
    assert_eq!(response["backend"], candidates[0], "backend is the top candidate");
    assert_eq!(response["decision_reason"], "graph_route");

    handle.abort();
}
```

`GraphRoutePolicy::new` gains a `max_candidates` parameter in this task — the
`3` above — inserted before the `state` argument. Update its existing call site
in `crates/head/src/runners.rs` to pass `graph_config.max_candidates`.

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p radii-integration --test head_http -- --nocapture`
Expected: FAIL — no `candidates` key.

- [ ] **Step 3: Implement**

`crates/head/src/config.rs` — reuse the same untagged shim as Fetch:

```rust
#[derive(Debug, Deserialize, Clone)]
#[serde(untagged)]
enum OneOrMany {
    One(String),
    Many(Vec<String>),
}

    /// Maps an inbound HTTP host to the Crawl node ids that may serve it.
    /// A bare string is accepted for the single-node form.
    #[serde(default)]
    node_map_raw: HashMap<String, OneOrMany>,
    #[serde(skip)]
    pub node_map: HashMap<String, Vec<String>>,
    #[serde(default = "default_max_candidates")]
    pub max_candidates: usize,
```

Normalise in `load` exactly as Fetch does, with `default_max_candidates() -> usize { 3 }`.

`crates/head/src/graph.rs` — add alongside `plan_backend`:

```rust
/// All reachable backends for `targets`, best first.
pub fn plan_backends(
    state: &SharedGraphState,
    source: &NodeId,
    targets: &[NodeId],
    allowed_protocols: &[ProtocolId],
    max_hops: usize,
    limit: usize,
) -> Vec<(String, usize, f64)> {
    let Ok(guard) = state.read() else {
        return Vec::new();
    };
    radii_core::routing::resolve_candidates(
        &guard.snapshot,
        &guard.listen_addrs,
        source,
        targets,
        allowed_protocols,
        max_hops,
        limit,
    )
    .into_iter()
    .map(|route| {
        let addr = route.hops.last().expect("non-empty hops").addr.clone();
        (addr, route.hops.len() + 1, route.score)
    })
    .collect()
}
```

`crates/head/src/decision.rs` — `GraphRoutePolicy` stores `node_map:
HashMap<String, Vec<NodeId>>` and `max_candidates`, calls `plan_backends`, sets
`BackendDecision.backend` to the first entry, and adds
`pub candidates: Vec<String>` to `BackendDecision` (empty for the host-map and
default policies).

`crates/head/src/http.rs` — add `candidates: Vec<String>` to `HeadResponse` and
populate it from the decision.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test --workspace`
Expected: PASS, including the existing `head_http` and `head_crawl_bridge` tests.

- [ ] **Step 5: Update the example config and commit**

In `crates/head/head.example.toml`, show the list form:

```toml
[graph.node_map]
"site.example" = ["node-b", "node-c"]
```

```bash
cargo clippy --workspace --all-targets -- -D warnings
git add crates/head/src crates/head/head.example.toml crates/integration/tests/head_http.rs
git commit -m "feat(head): report ranked backend candidates for a host"
```

---

## Task 14: Documentation and security register

**Files:**
- Modify: `SECURITY.md`
- Modify: `docs/tls.md`
- Modify: `README.md`
- Modify: `crates/fetch/README.md`, `crates/head/README.md`

- [ ] **Step 1: Update the threat model and controls**

In `SECURITY.md`, add to the threat-model table:

| Asset / surface | Risk |
|---|---|
| Relay listener (`radii-fetch`) | An admitted peer consumes bandwidth and connection slots; a malicious relay can stall or drop a chain it carries |

Add to the implemented-controls table:

| Control | Where | Notes |
|---|---|---|
| Relay admission | `radii-fetch` (`[relay]`) | Opt-in per node; mutual TLS mandatory (config load fails without `[relay.tls]`); admission by CA membership, narrowed by `allow_peers` |
| Relay resource bounds | `radii-fetch` (`[relay]`) | Per-peer and global concurrency caps keyed by the authenticated node id, plus an idle-chain deadline. One peer can cost at most `max_concurrent_per_peer × max_hops` connections |
| Source-route validation | `radii-fetch` (`relay::validate`) | A relay refuses a path not addressed to it, longer than its own `max_hops`, or containing a repeated node id — cycles are impossible rather than merely bounded |
| End-to-end tunnel identity | `radii-fetch` (`chain::establish`) | The payload session authenticates the *target*, not the relay dialed, so a relay carrying the bytes cannot impersonate the endpoint |

- [ ] **Step 2: Record the residual risks**

Add to the residual-risk table, matching the register's existing tone:

| Residual risk | Why it remains |
|---|---|
| A relay certificate is a bandwidth grant | With admission by CA membership, issuing a certificate now entitles the holder to forwarding capacity, not only to writing graph reports. Narrow with `allow_peers` where that is not intended |
| Relays observe traffic patterns | Payloads are opaque, but a relay sees volume, timing, and its immediate neighbours. There is no padding and no cover traffic; this is not anonymity |
| A malicious relay can deny service | It can stall or drop a chain it carries. It cannot read or impersonate the endpoint. Ranked-candidate retry is the mitigation, not prevention |
| Retry stops at the end-to-end handshake | Once application bytes flow, TCP offers no way to migrate the stream, so a mid-stream failure reaches the client |

- [ ] **Step 3: Document the certificate semantics**

In `docs/tls.md`, add a section covering: that `[relay.tls]` is mandatory for
relay listeners; that a node's relay and tunnel certificates must carry the
same node id in Subject CN, because the hop-local check reads one and the
end-to-end check reads the other; and that with open admission a certificate
conveys forwarding rights, which changes what revocation is protecting.

- [ ] **Step 4: Update the READMEs**

In `README.md`, under "What works today", replace Fetch's line:

```markdown
- **Fetch:** TCP tunnel from `bind` to an upstream, reached either directly or
  over a source-routed chain of relays. Routes come from Crawl's reachability
  graph as a ranked candidate list spanning several paths and several target
  nodes; a failed candidate falls over to the next, and an exhausted list falls
  back to the static `upstream`. Relays carry end-to-end-encrypted bytes they
  cannot read, and relaying is opt-in per node (`[relay]`).
```

In `crates/fetch/README.md`, document the `[relay]` block, the `max_hops = 1`
terminate-only posture, the two hop limits and which one applies where, and the
retry boundary.

- [ ] **Step 5: Commit**

```bash
git add SECURITY.md docs/tls.md README.md crates/fetch/README.md crates/head/README.md
git commit -m "docs(security): record relay admission, bounds, and residual risks"
```

---

## Self-Review

**Spec coverage.** Every spec section maps to a task: protocol and chain
establishment → Tasks 3, 4, 6, 7, 8; candidate resolution and retry → Tasks 1,
2, 9, 10; relay admission and limits → Tasks 5, 11, 12; Head candidates →
Task 13; config migration → Tasks 5 and 13; security impact → Task 14. The
spec's six-phase ordering is preserved, with the stream-generic TLS work added
as Task 4 — it was implied by nested TLS but not named, and nothing after it
compiles without it.

**Type consistency.** `ResolvedHop`/`ResolvedRoute` (core) and `RouteHop`
(proto) stay distinct throughout, converted only in `chain::establish`.
`SharedRoutes` replaces `SharedTarget` in Task 9, which is also where the one
existing test that imports `ResolvedTarget` is updated. `resolve_candidates`
keeps one signature from Task 1 onward; `plan_from` (Fetch) and `plan_backends`
(Head) are thin seams over it. `hops.len() + 1` appears wherever the old
source-inclusive hop count is preserved, in Tasks 2 and 13.

**Corrections made during review.** Three, all worth knowing before starting:

1. `bind_local()` returns `(TcpListener, String)` and `wait_ready(&str)`
   returns a `Result`. Every test snippet assumes this; the exact signatures
   are in Global Constraints. Do not call `.to_string()` on an address that is
   already a `String`.
2. Task 4 (stream-generic TLS) is not in the spec's phase list. It has to
   exist: `tls::accept` takes a `TcpStream` and `dial_expecting` opens its own,
   so neither can run over a spliced pipe, and nested TLS is the whole premise
   of the opaque-relay decision. Tasks 6–8 do not compile without it.
3. `GraphRoutePolicy::new` gains a `max_candidates` parameter in Task 13. Its
   existing call site is `crates/head/src/runners.rs`.

**Where this stops.** Completing all fourteen tasks gives Fetch's TCP tunnels
path diversity and target redundancy. It does **not** put a website behind
Radii: Head still returns a JSON decision rather than proxying bytes, so
follow-up #1 in the spec — Head as a reverse proxy — is what carries these
mechanisms to HTTP traffic.
