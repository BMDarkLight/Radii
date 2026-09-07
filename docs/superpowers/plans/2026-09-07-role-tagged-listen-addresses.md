# Role-Tagged Listen Addresses Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make every advertised node address carry the role it serves, so Fetch's "relay listener" reading and Head's "plain backend" reading stop colliding in one field.

**Architecture:** `NodeHello`/`NodeInfo` carry `Vec<ListenAddr>` instead of `Vec<String>`, where `ListenAddr { addr, role }`. Resolution takes two roles — one for intermediate hops, one for the target — because Fetch dials every hop while Head dials none. Task 1 lands the wire change and absorbs the workspace-wide mechanical breakage; Tasks 2–3 add the role semantics on top; Task 4 proves the whole point with one acceptance test.

**Tech Stack:** Rust 2021, tokio, postcard, serde, clap (CLI), rcgen (test PKI).

**Spec:** `docs/superpowers/specs/2026-09-07-role-tagged-listen-addresses-design.md`

## Global Constraints

- Four gates, every task: `cargo test --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo fmt --all -- --check`, plus the task's own covering tests. Run `cargo fmt --all` before committing; the fmt job is required CI (`.github/workflows/ci.yml`).
- Commit subjects: Conventional Commits, **subject line only** — no body, and no trailers of any kind (no `Co-Authored-By`, no `Generated with`). The repo owner has an explicit standing preference.
- `radii-proto` must NOT depend on `radii-core`. Wire types live in proto; `RoleId` lives in core; conversion happens in the consumers, exactly as `GraphReport` → `Link` already does. Do not add the crate edge.
- Decode bounds are authoritative and enforced in `read_message`, not at call sites: `MAX_LISTEN_ADDRS = 16`, `MAX_LISTEN_ADDR_LEN = 256`, `MAX_ROLE_LEN = 64`.
- This is a **deliberate wire break**. Do not add a compat shim, a tolerant decoder, or a default role for untagged addresses — guessing a role is the exact failure this work removes.
- Integration helpers (`crates/integration/src/lib.rs`): `bind_local() -> Result<(TcpListener, String)>` (address is a `String`), `wait_ready(addr: &str) -> Result<()>` (returns a Result — `.unwrap()` it). `TestCa::issue(node_id) -> TlsIdentityConfig`; wrap with `TlsIdentity::load(&ca.issue(id)).unwrap()`.
- `RelayConfig` struct literals in tests need all of: `bind`, `node_id`, `max_hops`, `max_concurrent_total`, `max_concurrent_per_peer`, `idle_timeout_ms`, `handshake_timeout_ms`, `max_pending_total`, `max_pending_per_addr`, `allow_peers`, `tls`.

---

## File Structure

| File | Responsibility |
|---|---|
| `crates/proto/src/lib.rs` | `ListenAddr`, the three bounds, `NodeHello`/`NodeInfo` shape, `send_hello`/`send_hello_on` signatures, decode validation. |
| `crates/core/src/routing.rs` | `RoleId` + its constants; `resolve_candidates` gains `hop_role`/`target_role`. |
| `crates/crawl/src/server.rs` | `NodeEntry.listen_addrs: Vec<ListenAddr>`; store and return them. |
| `crates/fetch/src/graph.rs` | Convert wire → core; resolve with `(Some(RELAY), RELAY)`. |
| `crates/head/src/graph.rs` | Convert wire → core; resolve with `(None, HTTP)`. |
| `crates/cli/src/main.rs` | `--listen-addr role=addr`, repeated. |
| `crates/integration/tests/role_tagged_addrs.rs` | **New.** The acceptance test: one node, both roles, both consumers. |

---

## Task 1: The wire type, its bounds, and the mechanical ripple

The largest task, and mostly mechanical. It changes the shape of `listen_addrs` everywhere and keeps the workspace green **without yet using roles for anything** — resolution still takes the first address regardless of role. Roles become functional in Task 2.

**Files:**
- Modify: `crates/proto/src/lib.rs`
- Modify: `crates/crawl/src/server.rs`, `crates/cli/src/main.rs`, `crates/fetch/src/graph.rs`, `crates/head/src/graph.rs`
- Modify: every test fixture building a `NodeHello` or a `listen_addrs` map (see Step 5)

**Interfaces:**
- Produces: `radii_proto::ListenAddr { pub addr: String, pub role: String }`; `MAX_LISTEN_ADDRS: usize = 16`; `MAX_LISTEN_ADDR_LEN: usize = 256`; `MAX_ROLE_LEN: usize = 64`; `RadiiMessage::NodeHello { node_id: String, roles: Vec<String>, listen_addrs: Vec<ListenAddr> }`; `NodeInfo { node_id: String, listen_addrs: Vec<ListenAddr>, roles: Vec<String> }`; `send_hello_on(stream, node_id: String, roles: Vec<String>, listen_addrs: Vec<ListenAddr>)`.

- [ ] **Step 1: Write the failing proto tests**

Add to the existing `mod tests` in `crates/proto/src/lib.rs`:

```rust
#[tokio::test]
async fn node_hello_round_trips_role_tagged_addresses() {
    let message = RadiiMessage::NodeHello {
        node_id: "node-b".into(),
        roles: vec!["resource".into()],
        listen_addrs: vec![
            ListenAddr { addr: "10.0.0.5:2224".into(), role: "relay".into() },
            ListenAddr { addr: "10.0.0.5:9000".into(), role: "http".into() },
        ],
    };

    let mut buf = Vec::new();
    write_message(&mut buf, &message).await.unwrap();
    assert_eq!(read_message(&mut buf.as_slice()).await.unwrap(), message);
}

#[tokio::test]
async fn rejects_a_hello_with_too_many_listen_addrs() {
    let listen_addrs = (0..=MAX_LISTEN_ADDRS)
        .map(|i| ListenAddr { addr: format!("10.0.0.1:{i}"), role: "relay".into() })
        .collect();
    let mut buf = Vec::new();
    write_message(
        &mut buf,
        &RadiiMessage::NodeHello { node_id: "n".into(), roles: vec![], listen_addrs },
    )
    .await
    .unwrap();

    let err = read_message(&mut buf.as_slice()).await.unwrap_err();
    assert!(err.to_string().contains("listen_addrs"), "got: {err}");
}

#[tokio::test]
async fn rejects_a_hello_with_an_oversized_address() {
    let mut buf = Vec::new();
    write_message(
        &mut buf,
        &RadiiMessage::NodeHello {
            node_id: "n".into(),
            roles: vec![],
            listen_addrs: vec![ListenAddr {
                addr: "a".repeat(MAX_LISTEN_ADDR_LEN + 1),
                role: "relay".into(),
            }],
        },
    )
    .await
    .unwrap();

    let err = read_message(&mut buf.as_slice()).await.unwrap_err();
    assert!(err.to_string().contains("address"), "got: {err}");
}

#[tokio::test]
async fn rejects_a_hello_with_an_oversized_role() {
    let mut buf = Vec::new();
    write_message(
        &mut buf,
        &RadiiMessage::NodeHello {
            node_id: "n".into(),
            roles: vec![],
            listen_addrs: vec![ListenAddr {
                addr: "10.0.0.1:1".into(),
                role: "r".repeat(MAX_ROLE_LEN + 1),
            }],
        },
    )
    .await
    .unwrap();

    let err = read_message(&mut buf.as_slice()).await.unwrap_err();
    assert!(err.to_string().contains("role"), "got: {err}");
}
```

- [ ] **Step 2: Run them to verify they fail**

Run: `cargo test -p radii-proto listen_addr 2>&1 | head -20`
Expected: FAIL — `cannot find type ListenAddr`.

- [ ] **Step 3: Add the type, the bounds, and the decode check**

Near `MAX_FRAME_LEN` in `crates/proto/src/lib.rs`:

```rust
/// Maximum advertised listen addresses per node.
///
/// `listen_addrs` is peer-supplied and was previously unbounded: a hostile
/// `NodeHello` could carry as many addresses as fit in [`MAX_FRAME_LEN`],
/// and Crawl stored every one of them, per node. Bounded here rather than
/// at a call site so the limit applies to anything arriving on the wire.
pub const MAX_LISTEN_ADDRS: usize = 16;
/// Maximum length of one advertised address string.
pub const MAX_LISTEN_ADDR_LEN: usize = 256;
/// Maximum length of one address role string.
pub const MAX_ROLE_LEN: usize = 64;
```

Above the `RadiiMessage` enum:

```rust
/// One advertised listener, and what it speaks.
///
/// The role is what stops a single registry entry meaning two incompatible
/// things: Fetch reaches a node over its `relay` listener, while Head hands
/// a caller the node's `http` address to dial directly. Without the tag,
/// one consumer inevitably reads the other's address.
///
/// Flat by construction, like `RouteHop` and `RelayedMessage`: a
/// listen-address list can never nest, so a hostile frame cannot drive the
/// decoder into recursion.
///
/// `role` is a free string rather than an enum on purpose. Nodes in a mesh
/// upgrade at different times, and a consumer should ignore a role it does
/// not recognise rather than fail the whole `NodeHello`; an enum would make
/// every future role a flag day. Known roles are named by
/// `radii_core::routing::RoleId`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ListenAddr {
    pub addr: String,
    pub role: String,
}
```

Change both `NodeHello` (in `RadiiMessage` and in `RelayedMessage`) and `NodeInfo` to hold `Vec<ListenAddr>`.

In `read_message`, beside the existing `TunnelOpen` check:

```rust
    if let RadiiMessage::NodeHello { listen_addrs, .. } = &message {
        if listen_addrs.len() > MAX_LISTEN_ADDRS {
            bail!(
                "node_hello listen_addrs count {} exceeds {MAX_LISTEN_ADDRS}",
                listen_addrs.len()
            );
        }
        for entry in listen_addrs {
            if entry.addr.len() > MAX_LISTEN_ADDR_LEN {
                bail!(
                    "node_hello listen address length {} exceeds {MAX_LISTEN_ADDR_LEN}",
                    entry.addr.len()
                );
            }
            if entry.role.len() > MAX_ROLE_LEN {
                bail!(
                    "node_hello listen address role length {} exceeds {MAX_ROLE_LEN}",
                    entry.role.len()
                );
            }
        }
    }
```

Update `send_hello` and `send_hello_on` to take `listen_addrs: Vec<ListenAddr>`.

- [ ] **Step 4: Run the proto tests**

Run: `cargo test -p radii-proto`
Expected: PASS, including the pre-existing nested-`FromHead` regression test.

- [ ] **Step 5: Absorb the ripple, keeping behaviour unchanged**

The workspace will not compile. Fix each site mechanically — **do not add role filtering yet**, that is Task 2:

- `crates/crawl/src/server.rs`: `NodeEntry.listen_addrs: Vec<radii_proto::ListenAddr>`. Storage and the `NodeInfo` it returns carry the entries through unchanged.
- `crates/fetch/src/graph.rs` and `crates/head/src/graph.rs`: the `listen_addrs` map becomes `HashMap<String, Vec<radii_proto::ListenAddr>>`. Where each currently builds the map from `NodeInfo`, keep doing so. To keep `resolve_candidates` compiling unchanged, convert at the boundary by taking just the addresses:
  ```rust
  let listen_addrs: HashMap<String, Vec<String>> = nodes
      .into_iter()
      .map(|node| {
          (
              node.node_id,
              node.listen_addrs.into_iter().map(|entry| entry.addr).collect(),
          )
      })
      .collect();
  ```
  This deliberately discards the role for now, preserving today's exact behaviour. Task 2 replaces it.
- `crates/cli/src/main.rs`: keep the existing `--listen-addrs` comma flag for this task and map each value to `ListenAddr { addr, role: String::new() }`. **Add a `// TASK 3` comment** noting the flag and empty role are replaced by `--listen-addr role=addr` in Task 3, so nobody mistakes the placeholder for a decision.
- Every test fixture constructing a `NodeHello`, a `NodeInfo`, or calling `send_hello`/`send_hello_on`. Find them with:
  ```bash
  grep -rln "listen_addrs\|send_hello" crates --include='*.rs'
  ```

- [ ] **Step 6: Run all gates**

```bash
cargo fmt --all
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```
Expected: all green, with the same test count as before plus the four new proto tests.

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "feat(proto): tag advertised listen addresses with the role they serve"
```

---

## Task 2: `RoleId` and two-role resolution

**Files:**
- Modify: `crates/core/src/routing.rs`
- Test: `crates/core/src/routing.rs` (in-file `mod tests`)

**Interfaces:**
- Consumes: `radii_proto::ListenAddr` (Task 1).
- Produces: `RoleId(pub String)` with `RoleId::RELAY` / `RoleId::HTTP` and `RoleId::new<S: Into<String>>(S)`; `resolve_candidates(snapshot, listen_addrs: &HashMap<String, Vec<(String, String)>>, source, targets, allowed_protocols, max_hops, limit, hop_role: Option<&RoleId>, target_role: &RoleId)`.

`listen_addrs` is `HashMap<String, Vec<(String, String)>>` — `(addr, role)` pairs — rather than `Vec<ListenAddr>`, because **`radii-core` must not depend on `radii-proto`**. The consumers convert; the pattern matches how `GraphReport` becomes `Link` today.

- [ ] **Step 1: Write the failing tests**

Add to the existing `mod tests` in `crates/core/src/routing.rs`:

```rust
fn tagged(pairs: &[(&str, &str, &str)]) -> HashMap<String, Vec<(String, String)>> {
    let mut map: HashMap<String, Vec<(String, String)>> = HashMap::new();
    for (node, addr, role) in pairs {
        map.entry((*node).to_string())
            .or_default()
            .push(((*addr).to_string(), (*role).to_string()));
    }
    map
}

#[test]
fn resolves_only_addresses_matching_the_required_role() {
    let snapshot = GraphSnapshot::from_reports([report("s", "t", "radii", 10)]);
    let listen = tagged(&[
        ("t", "10.0.0.5:9000", "http"),
        ("t", "10.0.0.5:2224", "relay"),
    ]);

    let relay = resolve_candidates(
        &snapshot, &listen, &NodeId("s".into()), &[NodeId("t".into())],
        &[ProtocolId::new("radii")], 4, 5,
        Some(&RoleId::new(RoleId::RELAY)), &RoleId::new(RoleId::RELAY),
    );
    assert_eq!(relay[0].hops[0].addr, "10.0.0.5:2224");

    let http = resolve_candidates(
        &snapshot, &listen, &NodeId("s".into()), &[NodeId("t".into())],
        &[ProtocolId::new("radii")], 4, 5,
        None, &RoleId::new(RoleId::HTTP),
    );
    assert_eq!(http[0].hops[0].addr, "10.0.0.5:9000");
}

#[test]
fn drops_a_route_whose_target_lacks_the_required_role() {
    let snapshot = GraphSnapshot::from_reports([report("s", "t", "radii", 10)]);
    let listen = tagged(&[("t", "10.0.0.5:9000", "http")]);

    let routes = resolve_candidates(
        &snapshot, &listen, &NodeId("s".into()), &[NodeId("t".into())],
        &[ProtocolId::new("radii")], 4, 5,
        Some(&RoleId::new(RoleId::RELAY)), &RoleId::new(RoleId::RELAY),
    );
    assert!(routes.is_empty(), "a node with no relay address is not a relay target");
}

#[test]
fn drops_a_route_whose_intermediate_lacks_the_required_role() {
    let snapshot = GraphSnapshot::from_reports([
        report("s", "r", "radii", 10),
        report("r", "t", "radii", 10),
    ]);
    // `r` serves http only, so it cannot carry a relayed chain.
    let listen = tagged(&[
        ("r", "10.0.0.9:9000", "http"),
        ("t", "10.0.0.5:2224", "relay"),
    ]);

    let routes = resolve_candidates(
        &snapshot, &listen, &NodeId("s".into()), &[NodeId("t".into())],
        &[ProtocolId::new("radii")], 4, 5,
        Some(&RoleId::new(RoleId::RELAY)), &RoleId::new(RoleId::RELAY),
    );
    assert!(routes.is_empty());
}

/// With `hop_role: None` the caller dials nothing in between, so an
/// intermediate with no usable address must not disqualify the route — only
/// the target's role matters.
#[test]
fn ignores_intermediate_roles_when_hop_role_is_none() {
    let snapshot = GraphSnapshot::from_reports([
        report("s", "r", "radii", 10),
        report("r", "t", "radii", 10),
    ]);
    let listen = tagged(&[("t", "10.0.0.5:9000", "http")]);

    let routes = resolve_candidates(
        &snapshot, &listen, &NodeId("s".into()), &[NodeId("t".into())],
        &[ProtocolId::new("radii")], 4, 5,
        None, &RoleId::new(RoleId::HTTP),
    );
    assert_eq!(routes.len(), 1);
    assert_eq!(routes[0].hops.len(), 1, "only the target is resolved");
    assert_eq!(routes[0].hops[0].addr, "10.0.0.5:9000");
}
```

- [ ] **Step 2: Run them to verify they fail**

Run: `cargo test -p radii-core resolves_only_addresses -- --nocapture`
Expected: FAIL — `cannot find type RoleId`.

- [ ] **Step 3: Add `RoleId` and rewrite resolution**

In `crates/core/src/routing.rs`, beside `ProtocolId`:

```rust
/// What an advertised address speaks.
///
/// A free string with named constants, like [`ProtocolId`], so an unknown
/// role is something a consumer ignores rather than something that fails a
/// whole `NodeHello`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RoleId(pub String);

impl RoleId {
    /// A relay listener: mutual TLS plus a `TunnelOpen` preamble. What Fetch
    /// reaches a node over, including as a chain's final hop.
    pub const RELAY: &'static str = "relay";
    /// A plain HTTP backend, dialed directly. What Head hands its callers.
    pub const HTTP: &'static str = "http";

    pub fn new<S: Into<String>>(value: S) -> Self {
        Self(value.into())
    }
}
```

Replace `resolve_candidates`'s signature and hop loop:

```rust
#[allow(clippy::too_many_arguments)]
pub fn resolve_candidates(
    snapshot: &GraphSnapshot,
    listen_addrs: &HashMap<String, Vec<(String, String)>>,
    source: &NodeId,
    targets: &[NodeId],
    allowed_protocols: &[ProtocolId],
    max_hops: usize,
    limit: usize,
    hop_role: Option<&RoleId>,
    target_role: &RoleId,
) -> Vec<ResolvedRoute> {
```

with a helper beside it:

```rust
/// The first address `node` advertises in `role`, if any.
fn addr_for_role(
    listen_addrs: &HashMap<String, Vec<(String, String)>>,
    node: &NodeId,
    role: &RoleId,
) -> Option<String> {
    listen_addrs
        .get(&node.0)?
        .iter()
        .find(|(_, advertised)| advertised == &role.0)
        .map(|(addr, _)| addr.clone())
}
```

and this hop loop in place of the current one:

```rust
            // `candidate.hops` starts at the source; skip it.
            let mut hops = Vec::new();
            let mut dialable = true;
            let last_index = candidate.hops.len() - 1;

            for (index, node) in candidate.hops.iter().enumerate().skip(1) {
                let is_target = index == last_index;
                // Intermediates are resolved only when the caller will dial
                // them. Head does not — it hands its caller the target's
                // address and the caller dials that directly — so an
                // intermediate it never touches must not disqualify a route.
                let role = if is_target { Some(target_role) } else { hop_role };
                let Some(role) = role else { continue };

                match addr_for_role(listen_addrs, node, role) {
                    Some(addr) => hops.push(ResolvedHop {
                        node_id: node.clone(),
                        addr,
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
```

- [ ] **Step 4: Run the core tests**

Run: `cargo test -p radii-core routing`
Expected: the four new tests PASS. Pre-existing `resolve_candidates` tests will fail to compile until updated — update them by wrapping each fixture's addresses as `(addr, "relay")` pairs and passing `Some(&RoleId::new(RoleId::RELAY)), &RoleId::new(RoleId::RELAY)`, which preserves exactly what they asserted before.

- [ ] **Step 5: Gates and commit**

```bash
cargo fmt --all
cargo clippy -p radii-core --all-targets -- -D warnings
git add crates/core/src/routing.rs
git commit -m "feat(core): resolve candidate addresses by the role they serve"
```

Note the workspace will not compile until Task 3 updates the two callers — that is expected, and Task 3 is the other half of this change.

---

## Task 3: Wire Fetch and Head to their roles

**Files:**
- Modify: `crates/fetch/src/graph.rs`, `crates/head/src/graph.rs`
- Modify: `crates/cli/src/main.rs`
- Test: `crates/fetch/src/graph.rs` (in-file `mod tests`)

**Interfaces:**
- Consumes: `RoleId`, the new `resolve_candidates` (Task 2); `radii_proto::ListenAddr` (Task 1).

- [ ] **Step 1: Write the failing Fetch test**

In `crates/fetch/src/graph.rs`'s `mod tests`, replace the fixture in `plans_across_every_configured_target` so its listen map is role-tagged, and add:

```rust
    #[test]
    fn plans_only_to_targets_advertising_a_relay_address() {
        let mut snapshot = GraphSnapshot::new();
        for to in ["t-relay", "t-http"] {
            snapshot.add_link(Link {
                from: NodeId("s".into()),
                to: NodeId(to.into()),
                protocol: ProtocolId::new("radii"),
                reachable: true,
                latency_ms: Some(10),
            });
        }
        let mut listen: HashMap<String, Vec<(String, String)>> = HashMap::new();
        listen.insert(
            "t-relay".into(),
            vec![("10.0.0.1:2224".into(), "relay".into())],
        );
        // Advertises only an http backend, so it is not a relay target.
        listen.insert(
            "t-http".into(),
            vec![("10.0.0.2:9000".into(), "http".into())],
        );

        let routes = plan_from(
            &snapshot,
            &listen,
            &NodeId("s".into()),
            &[NodeId("t-relay".into()), NodeId("t-http".into())],
            &[ProtocolId::new("radii")],
            4,
            5,
        );

        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].target().0, "t-relay");
    }
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cargo test -p radii-fetch graph 2>&1 | head -20`
Expected: FAIL to compile — `plan_from` still takes `Vec<String>`.

- [ ] **Step 3: Update both consumers**

In `crates/fetch/src/graph.rs`: change `plan_from`'s `listen_addrs` parameter to `&HashMap<String, Vec<(String, String)>>`, and have it pass `Some(&RoleId::new(RoleId::RELAY)), &RoleId::new(RoleId::RELAY)` to `resolve_candidates`. In `fetch_once`, build the map from `NodeInfo` as `(addr, role)` pairs:

```rust
    let listen_addrs: HashMap<String, Vec<(String, String)>> = nodes
        .into_iter()
        .map(|node| {
            (
                node.node_id,
                node.listen_addrs
                    .into_iter()
                    .map(|entry| (entry.addr, entry.role))
                    .collect(),
            )
        })
        .collect();
```

In `crates/head/src/graph.rs`: build the same map in `fetch_once`, change `GraphState.listen_addrs` to match, and have `plan_backends` and `plan_backend` pass `None, &RoleId::new(RoleId::HTTP)`. Add to `plan_backends`' doc comment, replacing the note about the two incompatible readings:

```rust
/// Head resolves the target's `http` address — the endpoint its caller will
/// dial directly — and passes `None` for the hop role because it dials no
/// intermediate. Fetch resolves `relay` addresses instead, for every hop.
/// The role tag is what lets one registry entry serve both without either
/// consumer reading the other's address.
```

In `crates/cli/src/main.rs`: replace the `--listen-addrs` comma flag (and the `// TASK 3` placeholder from Task 1) with a repeated `--listen-addr role=addr`:

```rust
        #[arg(long = "listen-addr", value_parser = parse_listen_addr)]
        listen_addrs: Vec<radii_proto::ListenAddr>,
```

```rust
/// Parses `role=addr`.
///
/// `role=addr` rather than `addr:role` because a colon already means a port,
/// and doubly so in an IPv6 literal.
fn parse_listen_addr(value: &str) -> Result<radii_proto::ListenAddr, String> {
    let (role, addr) = value
        .split_once('=')
        .ok_or_else(|| format!("expected role=addr, got {value:?}"))?;
    if role.is_empty() || addr.is_empty() {
        return Err(format!("expected role=addr with both parts set, got {value:?}"));
    }
    Ok(radii_proto::ListenAddr {
        addr: addr.to_string(),
        role: role.to_string(),
    })
}
```

- [ ] **Step 4: Add the CLI parser tests**

In `crates/cli/src/main.rs`, add a `#[cfg(test)] mod tests`:

```rust
#[cfg(test)]
mod tests {
    use super::parse_listen_addr;

    #[test]
    fn parses_role_equals_addr() {
        let parsed = parse_listen_addr("relay=10.0.0.5:2224").unwrap();
        assert_eq!(parsed.role, "relay");
        assert_eq!(parsed.addr, "10.0.0.5:2224");
    }

    #[test]
    fn keeps_ipv6_colons_in_the_address() {
        let parsed = parse_listen_addr("http=[::1]:9000").unwrap();
        assert_eq!(parsed.addr, "[::1]:9000");
    }

    #[test]
    fn rejects_a_value_without_a_role() {
        assert!(parse_listen_addr("10.0.0.5:2224").is_err());
        assert!(parse_listen_addr("=10.0.0.5:2224").is_err());
        assert!(parse_listen_addr("relay=").is_err());
    }
}
```

- [ ] **Step 5: Run all gates**

```bash
cargo fmt --all
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```
Expected: all green. Update any remaining fixture that still builds an untagged listen map.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "feat(fetch): resolve relay and http addresses by role"
```

---

## Task 4: The acceptance test, and the docs

**Files:**
- Create: `crates/integration/tests/role_tagged_addrs.rs`
- Modify: `SECURITY.md`, `README.md`, `crates/head/README.md`, `crates/fetch/README.md`, `crates/head/head.example.toml`

- [ ] **Step 1: Write the acceptance test**

Create `crates/integration/tests/role_tagged_addrs.rs`. This is the test the whole design exists for: one node, one `NodeHello`, two consumers, each getting the address meant for it.

```rust
//! The acceptance test for role-tagged addresses.
//!
//! One node advertises both a relay listener and an http backend in a single
//! `NodeHello`. Fetch must resolve the relay address and Head the http one.
//! Before roles, both read the same entry and one of them was always wrong.

use radii_core::routing::{
    resolve_candidates, GraphSnapshot, Link, NodeId, ProtocolId, RoleId,
};
use radii_integration::{bind_local, wait_ready};
use radii_proto::{ListenAddr, RadiiMessage};
use std::collections::HashMap;

#[tokio::test]
async fn one_node_serves_both_consumers_from_one_hello() {
    let (crawl_listener, crawl_addr) = bind_local().await.unwrap();
    tokio::spawn(radii_crawl::server::run_on(
        crawl_listener,
        radii_crawl::config::Config {
            bind: crawl_addr.clone(),
            node_ttl_ms: 60_000,
            relay_peers: Vec::new(),
            tls: None,
        },
    ));
    wait_ready(&crawl_addr).await.unwrap();

    // One hello, two roles.
    let mut stream = radii_proto::tls::dial(&crawl_addr, None).await.unwrap();
    let ack = radii_proto::send_hello_on(
        &mut stream,
        "node-b".to_string(),
        vec!["resource".to_string()],
        vec![
            ListenAddr { addr: "10.0.0.5:2224".into(), role: "relay".into() },
            ListenAddr { addr: "10.0.0.5:9000".into(), role: "http".into() },
        ],
    )
    .await
    .unwrap();
    assert!(matches!(ack, RadiiMessage::Ack { .. }));

    let mut query = radii_proto::tls::dial(&crawl_addr, None).await.unwrap();
    let (nodes, _reports) = radii_proto::query_graph_on(&mut query).await.unwrap();

    let listen_addrs: HashMap<String, Vec<(String, String)>> = nodes
        .into_iter()
        .map(|node| {
            (
                node.node_id,
                node.listen_addrs
                    .into_iter()
                    .map(|entry| (entry.addr, entry.role))
                    .collect(),
            )
        })
        .collect();

    let mut snapshot = GraphSnapshot::new();
    snapshot.add_link(Link {
        from: NodeId("s".into()),
        to: NodeId("node-b".into()),
        protocol: ProtocolId::new("radii"),
        reachable: true,
        latency_ms: Some(10),
    });

    // Fetch's view: every hop over its relay listener.
    let fetch = resolve_candidates(
        &snapshot,
        &listen_addrs,
        &NodeId("s".into()),
        &[NodeId("node-b".into())],
        &[ProtocolId::new("radii")],
        4,
        3,
        Some(&RoleId::new(RoleId::RELAY)),
        &RoleId::new(RoleId::RELAY),
    );
    assert_eq!(fetch.len(), 1);
    assert_eq!(fetch[0].hops.last().unwrap().addr, "10.0.0.5:2224");

    // Head's view: the target's http backend, no intermediates.
    let head = resolve_candidates(
        &snapshot,
        &listen_addrs,
        &NodeId("s".into()),
        &[NodeId("node-b".into())],
        &[ProtocolId::new("radii")],
        4,
        3,
        None,
        &RoleId::new(RoleId::HTTP),
    );
    assert_eq!(head.len(), 1);
    assert_eq!(head[0].hops.last().unwrap().addr, "10.0.0.5:9000");
}
```

Check `radii_crawl::config::Config`'s actual field list before writing that literal and match it; if construction is awkward, build it through `radii_crawl::config::load` with a `NamedTempFile`, as `crates/integration/tests/graph_routing.rs` does for Head.

- [ ] **Step 2: Run it**

Run: `cargo test -p radii-integration --test role_tagged_addrs -- --nocapture`
Expected: PASS.

- [ ] **Step 3: Update the security register**

In `SECURITY.md`:

- **Delete** the residual-risk row beginning `` | `listen_addrs` has two incompatible readings | `` — this work removes it.
- **Add** a residual-risk row:
  ```
  | An address role is a claim, not a credential | A node advertising `role = "relay"` may run nothing there: the chain fails at dial, the candidate is discarded, and retry moves on — bounded by `attempt_timeout_ms`. A false `role = "http"` is weaker, because Head does not dial and so cannot verify; its caller discovers the lie. Not a new exposure — Head hands out unverified addresses today — but a role tag makes a claim more *specific* without making it more *trustworthy* |
  ```
- **Add** an implemented-control row:
  ```
  | Role-tagged listen addresses | `radii-proto` (`ListenAddr`), `radii-core` (`RoleId`) | Each advertised address carries the role it serves, so Fetch resolves `relay` listeners and Head `http` backends from one registry entry without either reading the other's address. Decode bounds the list (`MAX_LISTEN_ADDRS` = 16) and each string (`MAX_LISTEN_ADDR_LEN` = 256, `MAX_ROLE_LEN` = 64), closing a previously unbounded growth path into Crawl's registry |
  ```
- **Rewrite** the "Source routing and `listen_addrs`" section's first bullet. It currently warns that a wrongly-advertised address splices framing bytes into a live backend. Replace with:
  ```
  - [ ] Advertise each listener with its role: `--listen-addr relay=HOST:PORT`
        for a node that carries chains, `--listen-addr http=HOST:PORT` for one
        Head should hand out as a backend. A node advertising no `relay`
        address is simply never selected as a Fetch route target — wrong
        configuration means *not chosen* rather than *chosen and corrupting*.
  ```

- [ ] **Step 4: Update the READMEs and the example config**

- `crates/head/README.md`: delete the "One caveat worth knowing" section describing the dual meaning, and replace with a short note that Head resolves the `http` role while Fetch resolves `relay`.
- `crates/fetch/README.md`: in the deployment-requirement section, replace the `listen_addrs` warning with the role-tagged form.
- `README.md`: in Crawl's "what works today" line, note that node addresses are role-tagged.
- `crates/head/head.example.toml`: no schema change, but add a comment above `[graph.node_map]` noting that mapped nodes must advertise an `http` address.

- [ ] **Step 5: Gates and commit**

```bash
cargo fmt --all
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
git add -A
git commit -m "docs(security): record role-tagged addresses and retire the dual-meaning risk"
```

---

## Self-Review

**Spec coverage.** §1 wire type → Task 1. §2 decode bounds → Task 1 (three tests). §3 two-role resolution → Task 2, consumers in Task 3. §4 clean break → Task 1, stated in Global Constraints as an explicit prohibition on shims. §5 operator surface → Task 3 (CLI) and Task 4 (docs). Security → Task 4's register rows. Testing → the acceptance test in Task 4, plus per-crate tests in Tasks 1–3.

**Type consistency.** `ListenAddr { addr, role }` is the wire type throughout; `radii-core` sees `(String, String)` pairs because it must not depend on `radii-proto`, and both consumers convert at their `fetch_once` boundary. `RoleId::RELAY`/`RoleId::HTTP` are `&'static str` constants wrapped via `RoleId::new`, matching `ProtocolId`'s existing shape. `resolve_candidates`'s two new parameters are last, in the order `hop_role, target_role`, everywhere.

**Known rough edge.** Task 1 leaves the CLI emitting an empty role and both consumers discarding roles, so the workspace is green but roles do nothing until Task 3. That is deliberate — it keeps the wire break and the semantic change in separate, separately-reviewable commits — and Task 1 marks the placeholder with a `// TASK 3` comment so it cannot be mistaken for a decision. Task 2 alone does not compile the workspace; Tasks 2 and 3 land together.
