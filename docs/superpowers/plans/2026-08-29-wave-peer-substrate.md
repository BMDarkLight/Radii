# Wave Peer Substrate (Radii side) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add node-role tagging, node liveness/expiry, and small client library ergonomics to Radii, so a Rust consumer (Wave) can join the mesh and discover role-tagged, live peers without Radii containing any content-specific logic.

**Architecture:** Extend `radii-proto`'s `NodeInfo` with `roles`, change Crawl's in-memory registry from `node_id -> listen_addrs` to `node_id -> NodeEntry { listen_addrs, roles, last_seen_unix_ms }`, and filter expired entries out of `GraphQuery` replies at query time via a small pure function. Separately, promote the hello/report frame-write-then-read sequence currently duplicated in `radii-cli` into reusable `radii-proto` functions.

**Tech Stack:** Rust, tokio, existing `radii-proto`/`radii-core`/`radii-crawl`/`radii-cli` crates. No new dependencies.

**Spec:** [docs/superpowers/specs/2026-08-29-wave-peer-substrate-design.md](../specs/2026-08-29-wave-peer-substrate-design.md)

## Global Constraints

- No catalog/content/song semantics may appear anywhere in Radii — this plan only adds role tags (opaque strings), liveness timestamps, and generic client helpers.
- `GraphQuery` stays a no-argument message; role filtering happens client-side on the returned `NodeInfo.roles`, not as a new query parameter.
- No new `RadiiMessage` variants and no Crawl-to-Crawl gossip — both are explicit non-goals of the spec.
- `CrawlState::default()` must keep `node_ttl_ms == None` (never-expire) so every existing test that constructs `CrawlState::default()` keeps behaving exactly as it does today.
- `node_ttl_ms` config default is `60_000` (ms) when absent from TOML, matching the existing `#[serde(default = "...")]` pattern used elsewhere in this codebase (e.g. `head`'s `GraphConfig::poll_interval_ms`).

---

### Task 1: Node roles and liveness in Crawl's registry

**Files:**
- Modify: `crates/proto/src/lib.rs:56-60` (`NodeInfo` struct), `crates/proto/src/lib.rs:182-195` (existing `round_trips_graph_query_and_snapshot` test)
- Modify: `crates/crawl/src/server.rs` (`CrawlState` struct at lines 9-13, the `NodeHello` arm in `handle_connection` at lines 71-102, the `GraphQuery` arm at lines 174-208, the `NodeHello` arm in `handle_wrapped_message` at lines 224-233)
- Modify: `crates/integration/tests/crawl_protocol.rs:66-72` (assertion broken by the state shape change)
- Test: unit tests added inline in `crates/crawl/src/server.rs` (new `#[cfg(test)] mod tests`)

**Interfaces:**
- Produces: `radii_proto::NodeInfo { node_id: String, listen_addrs: Vec<String>, roles: Vec<String> }` (roles is new).
- Produces: `radii_crawl::server::NodeEntry { listen_addrs: Vec<String>, roles: Vec<String>, last_seen_unix_ms: u64 }` (new, public — required because it's the value type of `CrawlState`'s public `nodes` field).
- Produces: `radii_crawl::server::CrawlState { nodes: HashMap<String, NodeEntry>, reachability: Vec<RadiiMessage>, node_ttl_ms: Option<u64> }` (`nodes`'s value type changes from `Vec<String>`; `node_ttl_ms` is new).
- Consumes: nothing new from outside this task.

- [ ] **Step 1: Add `roles` to `NodeInfo` and update its existing round-trip test**

In `crates/proto/src/lib.rs`, change:

```rust
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodeInfo {
    pub node_id: String,
    pub listen_addrs: Vec<String>,
}
```

to:

```rust
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodeInfo {
    pub node_id: String,
    pub listen_addrs: Vec<String>,
    pub roles: Vec<String>,
}
```

Then update the existing `round_trips_graph_query_and_snapshot` test's `NodeInfo` literal (currently `NodeInfo { node_id: "node-a".into(), listen_addrs: vec!["127.0.0.1:9000".into()] }`) to also set `roles: vec!["crawl".into()]`, so it keeps compiling and now also exercises `roles` round-tripping through postcard.

- [ ] **Step 2: Run proto's tests to confirm the round-trip still passes**

Run: `cargo test -p radii-proto`
Expected: PASS (compiles once the literal is updated; the workspace as a whole will not build yet because `crawl` still references the old `NodeInfo`/`.nodes` shapes — that's fixed in the next steps of this same task, before committing).

- [ ] **Step 3: Introduce `NodeEntry` and change `CrawlState.nodes`'s value type**

In `crates/crawl/src/server.rs`, change:

```rust
#[derive(Default, Debug)]
pub struct CrawlState {
    pub nodes: HashMap<String, Vec<String>>,
    pub reachability: Vec<RadiiMessage>,
}
```

to:

```rust
#[derive(Debug, Clone)]
pub struct NodeEntry {
    pub listen_addrs: Vec<String>,
    pub roles: Vec<String>,
    pub last_seen_unix_ms: u64,
}

#[derive(Default, Debug)]
pub struct CrawlState {
    pub nodes: HashMap<String, NodeEntry>,
    pub reachability: Vec<RadiiMessage>,
    /// `None` means nodes never expire (today's behavior, and the default
    /// via `CrawlState::default()`). `Some(ttl)` drops a node from
    /// `GraphQuery` replies once `now - last_seen_unix_ms > ttl`.
    pub node_ttl_ms: Option<u64>,
}

fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
```

Add `use std::collections::HashSet;` to the top of the file alongside the existing `use std::collections::HashMap;`.

- [ ] **Step 4: Update the direct `NodeHello` handler to store roles and liveness**

In `handle_connection`'s `RadiiMessage::NodeHello { node_id, listen_addrs, .. } => { ... }` arm, change the pattern to bind `roles` too, and change the insert:

```rust
RadiiMessage::NodeHello {
    node_id,
    roles,
    listen_addrs,
} => {
    if !authorized(&peer_identity, &node_id) {
        // ... unchanged ...
    }
    let mut state = state.write().await;
    state.nodes.insert(
        node_id.clone(),
        NodeEntry {
            listen_addrs: listen_addrs.clone(),
            roles: roles.clone(),
            last_seen_unix_ms: now_unix_ms(),
        },
    );
    tracing::info!(source = %addr, node = %node_id, "crawl node hello");
    // ... unchanged ack ...
}
```

- [ ] **Step 5: Update the `FromHead`-wrapped `NodeHello` handler the same way**

In `handle_wrapped_message`, change:

```rust
RadiiMessage::NodeHello {
    node_id,
    listen_addrs,
    ..
} => {
    let mut state = state.write().await;
    state.nodes.insert(node_id.clone(), listen_addrs);
    tracing::info!(via = %source, node = %node_id, "crawl node hello");
}
```

to:

```rust
RadiiMessage::NodeHello {
    node_id,
    roles,
    listen_addrs,
} => {
    let mut state = state.write().await;
    state.nodes.insert(
        node_id.clone(),
        NodeEntry {
            listen_addrs,
            roles,
            last_seen_unix_ms: now_unix_ms(),
        },
    );
    tracing::info!(via = %source, node = %node_id, "crawl node hello");
}
```

- [ ] **Step 6: Add `expired_node_ids` and `graph_snapshot` pure functions, and rewire the `GraphQuery` handler to use them**

Add near the bottom of `crates/crawl/src/server.rs`, above the existing `#[cfg(test)]` boundary (there isn't one yet — this task adds the first one):

```rust
/// Node ids in `nodes` that are registered but haven't been heard from
/// within `node_ttl_ms`. Returns an empty set when `node_ttl_ms` is `None`
/// (liveness disabled) — a node that never sent a hello at all is not in
/// `nodes` in the first place and is therefore never "expired" by this
/// function; it's simply absent, exactly like today.
fn expired_node_ids(
    nodes: &HashMap<String, NodeEntry>,
    node_ttl_ms: Option<u64>,
    now_unix_ms: u64,
) -> HashSet<String> {
    let Some(ttl) = node_ttl_ms else {
        return HashSet::new();
    };
    nodes
        .iter()
        .filter(|(_, entry)| now_unix_ms.saturating_sub(entry.last_seen_unix_ms) > ttl)
        .map(|(node_id, _)| node_id.clone())
        .collect()
}

/// Builds the `(nodes, reports)` pair for a `GraphSnapshot` reply, excluding
/// expired nodes and any reachability report naming an expired node as
/// `from` or `target`. A report naming a node id that never sent a hello at
/// all (and so never appears in `nodes`) is *not* filtered here — that
/// matches today's behavior, where reachability doesn't require prior
/// registration (see `graph_routing.rs` in `crates/integration`, where
/// `head` reports reachability without ever sending its own hello).
fn graph_snapshot(state: &CrawlState, now_unix_ms: u64) -> (Vec<NodeInfo>, Vec<GraphReport>) {
    let expired = expired_node_ids(&state.nodes, state.node_ttl_ms, now_unix_ms);

    let nodes = state
        .nodes
        .iter()
        .filter(|(node_id, _)| !expired.contains(*node_id))
        .map(|(node_id, entry)| NodeInfo {
            node_id: node_id.clone(),
            listen_addrs: entry.listen_addrs.clone(),
            roles: entry.roles.clone(),
        })
        .collect();

    let reports = state
        .reachability
        .iter()
        .filter_map(|message| match message {
            RadiiMessage::ReachabilityReport {
                from,
                target,
                protocol,
                reachable,
                rtt_ms,
                ..
            } => {
                if expired.contains(from) || expired.contains(target) {
                    None
                } else {
                    Some(GraphReport {
                        from: from.clone(),
                        target: target.clone(),
                        protocol: protocol.clone(),
                        reachable: *reachable,
                        rtt_ms: *rtt_ms,
                    })
                }
            }
            _ => None,
        })
        .collect();

    (nodes, reports)
}
```

Then replace the body of the `RadiiMessage::GraphQuery => { ... }` arm in `handle_connection` with:

```rust
RadiiMessage::GraphQuery => {
    let guard = state.read().await;
    let (nodes, reports) = graph_snapshot(&guard, now_unix_ms());
    drop(guard);
    tracing::info!(source = %addr, "crawl graph query");
    write_message(&mut stream, &RadiiMessage::GraphSnapshot { nodes, reports }).await?;
}
```

(This removes the old inline `.map`/`.filter_map` over `guard.nodes`/`guard.reachability` that lived directly in that arm.)

- [ ] **Step 7: Add unit tests for `expired_node_ids` and `graph_snapshot`**

Add to `crates/crawl/src/server.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn entry(roles: Vec<&str>, last_seen_unix_ms: u64) -> NodeEntry {
        NodeEntry {
            listen_addrs: vec!["127.0.0.1:1".to_string()],
            roles: roles.into_iter().map(String::from).collect(),
            last_seen_unix_ms,
        }
    }

    #[test]
    fn no_ttl_means_nothing_expires() {
        let mut nodes = HashMap::new();
        nodes.insert("a".to_string(), entry(vec![], 0));
        assert!(expired_node_ids(&nodes, None, 1_000_000).is_empty());
    }

    #[test]
    fn node_past_ttl_is_expired() {
        let mut nodes = HashMap::new();
        nodes.insert("fresh".to_string(), entry(vec![], 9_000));
        nodes.insert("stale".to_string(), entry(vec![], 0));
        let expired = expired_node_ids(&nodes, Some(5_000), 10_000);
        assert!(expired.contains("stale"));
        assert!(!expired.contains("fresh"));
    }

    #[test]
    fn graph_snapshot_carries_roles() {
        let mut state = CrawlState::default();
        state
            .nodes
            .insert("wave-a".to_string(), entry(vec!["wave"], 0));
        let (nodes, _) = graph_snapshot(&state, 0);
        let node = nodes.iter().find(|n| n.node_id == "wave-a").unwrap();
        assert_eq!(node.roles, vec!["wave".to_string()]);
    }

    #[test]
    fn graph_snapshot_excludes_expired_node_and_its_reports() {
        let mut state = CrawlState {
            node_ttl_ms: Some(5_000),
            ..CrawlState::default()
        };
        state.nodes.insert("fresh".to_string(), entry(vec![], 9_000));
        state.nodes.insert("stale".to_string(), entry(vec![], 0));
        state.reachability.push(RadiiMessage::ReachabilityReport {
            from: "fresh".to_string(),
            target: "stale".to_string(),
            protocol: "http".to_string(),
            reachable: true,
            rtt_ms: Some(10),
            observed_addr: None,
        });

        let (nodes, reports) = graph_snapshot(&state, 10_000);
        assert!(nodes.iter().all(|n| n.node_id != "stale"));
        assert!(nodes.iter().any(|n| n.node_id == "fresh"));
        assert!(
            reports.is_empty(),
            "report naming an expired node must be dropped"
        );
    }

    #[test]
    fn graph_snapshot_keeps_reports_for_unregistered_node_ids() {
        // "head" never sends its own hello (matches crates/integration's
        // graph_routing.rs) — a report naming it must still come through.
        let mut state = CrawlState::default();
        state
            .nodes
            .insert("node-b".to_string(), entry(vec!["resource"], 0));
        state.reachability.push(RadiiMessage::ReachabilityReport {
            from: "head".to_string(),
            target: "node-b".to_string(),
            protocol: "http".to_string(),
            reachable: true,
            rtt_ms: Some(12),
            observed_addr: None,
        });

        let (_, reports) = graph_snapshot(&state, 0);
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].from, "head");
    }
}
```

- [ ] **Step 8: Fix the existing integration test broken by the `NodeEntry` shape change**

In `crates/integration/tests/crawl_protocol.rs`, the assertion at line ~69:

```rust
assert_eq!(
    guard.nodes.get("node-a").unwrap(),
    &vec!["127.0.0.1:1".to_string()]
);
```

becomes:

```rust
assert_eq!(
    guard.nodes.get("node-a").unwrap().listen_addrs,
    vec!["127.0.0.1:1".to_string()]
);
```

- [ ] **Step 9: Run the full workspace test suite**

Run: `cargo test --workspace`
Expected: PASS — this confirms Step 8's fix was sufficient and no other call site (the earlier grep for `NodeInfo`/`CrawlState`/`.nodes` usages found only `crawl_protocol.rs:69` needing a value-shape fix; every other `.nodes.contains_key(...)` call in `crawl_tls.rs` and `head_crawl_bridge.rs` is unaffected by the value type change) was missed.

- [ ] **Step 10: Commit**

```bash
git add crates/proto/src/lib.rs crates/crawl/src/server.rs crates/integration/tests/crawl_protocol.rs
git commit -m "feat(crawl): track node roles and liveness, expose both via GraphQuery"
```

---

### Task 2: Configurable node TTL wired from Crawl's config file

**Files:**
- Modify: `crates/crawl/src/config.rs` (add `node_ttl_ms` field + default fn + tests)
- Modify: `crates/crawl/src/server.rs` (`run` and `run_on` gain a `node_ttl_ms: Option<u64>` parameter)
- Modify: `crates/crawl/src/main.rs` (pass `Some(config.node_ttl_ms)` through)

**Interfaces:**
- Consumes: `radii_crawl::server::CrawlState.node_ttl_ms` (from Task 1).
- Produces: `radii_crawl::config::Config.node_ttl_ms: u64`; `radii_crawl::server::run(bind: &str, tls: Option<TlsIdentity>, node_ttl_ms: Option<u64>)`; `radii_crawl::server::run_on(listener: TcpListener, tls: Option<TlsIdentity>, node_ttl_ms: Option<u64>)`.

- [ ] **Step 1: Add `node_ttl_ms` to Crawl's config with a default, plus tests**

In `crates/crawl/src/config.rs`, change:

```rust
#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    pub bind: String,
    /// Requires mutual TLS on the Crawl listener when present; connections
    /// stay plaintext when absent. See `docs/tls.md`.
    pub tls: Option<radii_proto::tls::TlsIdentityConfig>,
}
```

to:

```rust
#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    pub bind: String,
    /// Requires mutual TLS on the Crawl listener when present; connections
    /// stay plaintext when absent. See `docs/tls.md`.
    pub tls: Option<radii_proto::tls::TlsIdentityConfig>,
    /// How long a node may go without sending a fresh `NodeHello` before it
    /// drops out of `GraphQuery` replies.
    #[serde(default = "default_node_ttl_ms")]
    pub node_ttl_ms: u64,
}

fn default_node_ttl_ms() -> u64 {
    60_000
}
```

Add two tests to the existing `#[cfg(test)] mod tests` block in the same file:

```rust
#[test]
fn defaults_node_ttl_ms_when_absent() {
    let mut file = NamedTempFile::new().unwrap();
    writeln!(file, "bind = \"127.0.0.1:7100\"").unwrap();
    let config = load(file.path()).unwrap();
    assert_eq!(config.node_ttl_ms, 60_000);
}

#[test]
fn loads_explicit_node_ttl_ms() {
    let mut file = NamedTempFile::new().unwrap();
    writeln!(file, "bind = \"127.0.0.1:7100\"\nnode_ttl_ms = 5000").unwrap();
    let config = load(file.path()).unwrap();
    assert_eq!(config.node_ttl_ms, 5000);
}
```

- [ ] **Step 2: Run the config tests**

Run: `cargo test -p radii-crawl config::`
Expected: PASS for all four tests in that module (the two pre-existing ones plus the two new ones).

- [ ] **Step 3: Thread `node_ttl_ms` through `run` and `run_on`**

In `crates/crawl/src/server.rs`, change:

```rust
pub async fn run(bind: &str, tls: Option<TlsIdentity>) -> anyhow::Result<()> {
    let listener = TcpListener::bind(bind).await?;
    tracing::info!(%bind, tls = tls.is_some(), "crawl listening");
    run_on(listener, tls).await
}

pub async fn run_on(listener: TcpListener, tls: Option<TlsIdentity>) -> anyhow::Result<()> {
    let state = Arc::new(RwLock::new(CrawlState::default()));
    run_on_with_state(listener, state, tls).await
}
```

to:

```rust
pub async fn run(
    bind: &str,
    tls: Option<TlsIdentity>,
    node_ttl_ms: Option<u64>,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(bind).await?;
    tracing::info!(%bind, tls = tls.is_some(), "crawl listening");
    run_on(listener, tls, node_ttl_ms).await
}

pub async fn run_on(
    listener: TcpListener,
    tls: Option<TlsIdentity>,
    node_ttl_ms: Option<u64>,
) -> anyhow::Result<()> {
    let state = Arc::new(RwLock::new(CrawlState {
        node_ttl_ms,
        ..CrawlState::default()
    }));
    run_on_with_state(listener, state, tls).await
}
```

(`run_on_with_state`'s signature is unchanged — every existing test calls that function directly, not `run`/`run_on`, so none of them are affected by this step.)

- [ ] **Step 4: Update the one caller**

In `crates/crawl/src/main.rs`, change:

```rust
server::run(&config.bind, tls).await
```

to:

```rust
server::run(&config.bind, tls, Some(config.node_ttl_ms)).await
```

- [ ] **Step 5: Run the full workspace build and test suite**

Run: `cargo build --workspace && cargo test --workspace`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add crates/crawl/src/config.rs crates/crawl/src/server.rs crates/crawl/src/main.rs
git commit -m "feat(crawl): make node liveness TTL configurable"
```

---

### Task 3: End-to-end integration test for roles and TTL over a real connection

**Files:**
- Create: `crates/integration/tests/crawl_roles_and_ttl.rs`

**Interfaces:**
- Consumes: `radii_crawl::server::{run_on_with_state, CrawlState}` (Task 1/2), `radii_proto::{query_graph, read_message, write_message, RadiiMessage}` (existing), `radii_integration::{bind_local, wait_ready}` (existing).

- [ ] **Step 1: Write the test file**

```rust
use radii_crawl::server::{run_on_with_state, CrawlState};
use radii_integration::{bind_local, wait_ready};
use radii_proto::{query_graph, read_message, write_message, RadiiMessage};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::RwLock;

#[tokio::test]
async fn graph_query_reflects_declared_roles() {
    let (listener, addr) = bind_local().await.unwrap();
    let state = Arc::new(RwLock::new(CrawlState::default()));
    let handle = tokio::spawn(async move { run_on_with_state(listener, state, None).await });
    wait_ready(&addr).await.unwrap();

    let mut stream = TcpStream::connect(&addr).await.unwrap();
    write_message(
        &mut stream,
        &RadiiMessage::NodeHello {
            node_id: "wave-a".into(),
            roles: vec!["wave".into()],
            listen_addrs: vec!["127.0.0.1:9500".into()],
        },
    )
    .await
    .unwrap();
    read_message(&mut stream).await.unwrap();

    let (nodes, _reports) = query_graph(&addr).await.unwrap();
    let node = nodes
        .iter()
        .find(|n| n.node_id == "wave-a")
        .expect("node present in graph query reply");
    assert_eq!(node.roles, vec!["wave".to_string()]);

    handle.abort();
}

#[tokio::test]
async fn graph_query_drops_nodes_past_their_ttl() {
    let (listener, addr) = bind_local().await.unwrap();
    let state = Arc::new(RwLock::new(CrawlState {
        node_ttl_ms: Some(50),
        ..CrawlState::default()
    }));
    let handle = tokio::spawn(async move { run_on_with_state(listener, state, None).await });
    wait_ready(&addr).await.unwrap();

    let mut stream = TcpStream::connect(&addr).await.unwrap();
    write_message(
        &mut stream,
        &RadiiMessage::NodeHello {
            node_id: "wave-a".into(),
            roles: vec!["wave".into()],
            listen_addrs: vec!["127.0.0.1:9500".into()],
        },
    )
    .await
    .unwrap();
    read_message(&mut stream).await.unwrap();

    tokio::time::sleep(Duration::from_millis(150)).await;

    let (nodes, _reports) = query_graph(&addr).await.unwrap();
    assert!(
        nodes.iter().all(|n| n.node_id != "wave-a"),
        "node past its TTL must not appear in the graph query reply"
    );

    handle.abort();
}
```

- [ ] **Step 2: Run the new test**

Run: `cargo test -p radii-integration --test crawl_roles_and_ttl`
Expected: PASS (2 tests).

- [ ] **Step 3: Commit**

```bash
git add crates/integration/tests/crawl_roles_and_ttl.rs
git commit -m "test(integration): cover role tagging and TTL expiry over a real connection"
```

---

### Task 4: `send_hello`/`send_report` library helpers in `radii-proto`

**Files:**
- Modify: `crates/proto/src/lib.rs` (add the four new functions and their tests)

**Interfaces:**
- Produces:
  - `pub async fn send_hello<A: ToSocketAddrs>(addr: A, node_id: String, roles: Vec<String>, listen_addrs: Vec<String>) -> Result<RadiiMessage>`
  - `pub async fn send_hello_on<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S, node_id: String, roles: Vec<String>, listen_addrs: Vec<String>) -> Result<RadiiMessage>`
  - `pub async fn send_report<A: ToSocketAddrs>(addr: A, from: String, target: String, protocol: String, reachable: bool, rtt_ms: Option<u32>, observed_addr: Option<String>) -> Result<RadiiMessage>`
  - `pub async fn send_report_on<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S, from: String, target: String, protocol: String, reachable: bool, rtt_ms: Option<u32>, observed_addr: Option<String>) -> Result<RadiiMessage>`
- Consumes: nothing new — uses `write_message`/`read_message`/`RadiiMessage` already defined in this same file.

- [ ] **Step 1: Write the failing tests**

Add to the existing `#[cfg(test)] mod tests` block in `crates/proto/src/lib.rs`:

```rust
#[tokio::test]
async fn send_hello_on_round_trips_ack() {
    let (mut client, mut server): (DuplexStream, DuplexStream) = tokio::io::duplex(64 * 1024);
    let server_task = tokio::spawn(async move {
        let message = read_message(&mut server).await.unwrap();
        assert_eq!(
            message,
            RadiiMessage::NodeHello {
                node_id: "node-a".into(),
                roles: vec!["wave".into()],
                listen_addrs: vec!["127.0.0.1:1".into()],
            }
        );
        write_message(
            &mut server,
            &RadiiMessage::Ack {
                status: "hello_received".into(),
            },
        )
        .await
        .unwrap();
    });

    let reply = send_hello_on(
        &mut client,
        "node-a".into(),
        vec!["wave".into()],
        vec!["127.0.0.1:1".into()],
    )
    .await
    .unwrap();

    assert_eq!(
        reply,
        RadiiMessage::Ack {
            status: "hello_received".into()
        }
    );
    server_task.await.unwrap();
}

#[tokio::test]
async fn send_report_on_round_trips_ack() {
    let (mut client, mut server): (DuplexStream, DuplexStream) = tokio::io::duplex(64 * 1024);
    let server_task = tokio::spawn(async move {
        let message = read_message(&mut server).await.unwrap();
        assert_eq!(
            message,
            RadiiMessage::ReachabilityReport {
                from: "a".into(),
                target: "b".into(),
                protocol: "http".into(),
                reachable: true,
                rtt_ms: Some(12),
                observed_addr: None,
            }
        );
        write_message(
            &mut server,
            &RadiiMessage::Ack {
                status: "report_received".into(),
            },
        )
        .await
        .unwrap();
    });

    let reply = send_report_on(
        &mut client,
        "a".into(),
        "b".into(),
        "http".into(),
        true,
        Some(12),
        None,
    )
    .await
    .unwrap();

    assert_eq!(
        reply,
        RadiiMessage::Ack {
            status: "report_received".into()
        }
    );
    server_task.await.unwrap();
}
```

- [ ] **Step 2: Run the tests to verify they fail to compile (the functions don't exist yet)**

Run: `cargo test -p radii-proto send_hello_on_round_trips_ack`
Expected: FAIL to compile — "cannot find function `send_hello_on` in this scope" (and similarly for `send_report_on`).

- [ ] **Step 3: Implement the four functions**

Add to `crates/proto/src/lib.rs`, near `query_graph`/`query_graph_on`:

```rust
/// Opens a fresh plaintext connection and sends a `NodeHello`, returning
/// whatever the peer replies with (typically an `Ack`). Callers that need a
/// TLS-protected connection should dial via [`tls::dial`] and call
/// [`send_hello_on`] on the resulting stream instead.
pub async fn send_hello<A: ToSocketAddrs>(
    addr: A,
    node_id: String,
    roles: Vec<String>,
    listen_addrs: Vec<String>,
) -> Result<RadiiMessage> {
    let mut stream = TcpStream::connect(addr).await?;
    send_hello_on(&mut stream, node_id, roles, listen_addrs).await
}

/// Sends a `NodeHello` over an already-established connection (plaintext or
/// TLS) and returns whatever the peer replies with.
pub async fn send_hello_on<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    node_id: String,
    roles: Vec<String>,
    listen_addrs: Vec<String>,
) -> Result<RadiiMessage> {
    write_message(
        stream,
        &RadiiMessage::NodeHello {
            node_id,
            roles,
            listen_addrs,
        },
    )
    .await?;
    read_message(stream).await
}

/// Opens a fresh plaintext connection and sends a `ReachabilityReport`,
/// returning whatever the peer replies with. Callers that need a
/// TLS-protected connection should dial via [`tls::dial`] and call
/// [`send_report_on`] on the resulting stream instead.
pub async fn send_report<A: ToSocketAddrs>(
    addr: A,
    from: String,
    target: String,
    protocol: String,
    reachable: bool,
    rtt_ms: Option<u32>,
    observed_addr: Option<String>,
) -> Result<RadiiMessage> {
    let mut stream = TcpStream::connect(addr).await?;
    send_report_on(
        &mut stream,
        from,
        target,
        protocol,
        reachable,
        rtt_ms,
        observed_addr,
    )
    .await
}

/// Sends a `ReachabilityReport` over an already-established connection
/// (plaintext or TLS) and returns whatever the peer replies with.
pub async fn send_report_on<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    from: String,
    target: String,
    protocol: String,
    reachable: bool,
    rtt_ms: Option<u32>,
    observed_addr: Option<String>,
) -> Result<RadiiMessage> {
    write_message(
        stream,
        &RadiiMessage::ReachabilityReport {
            from,
            target,
            protocol,
            reachable,
            rtt_ms,
            observed_addr,
        },
    )
    .await?;
    read_message(stream).await
}
```

Add `use tokio::io::DuplexStream;` is already present in the test module (used by existing tests) — no new imports needed at the top of the file since `AsyncRead`, `AsyncWrite`, `TcpStream`, `ToSocketAddrs` are already imported there.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p radii-proto`
Expected: PASS, including the two new tests and every pre-existing one.

- [ ] **Step 5: Commit**

```bash
git add crates/proto/src/lib.rs
git commit -m "feat(proto): add send_hello/send_report client helpers"
```

---

### Task 5: Refactor `radii-cli` to use the new proto helpers

**Files:**
- Modify: `crates/cli/src/main.rs` (replace the generic `send_message` with thin `send_hello`/`send_report` wrappers around the new proto functions)

**Interfaces:**
- Consumes: `radii_proto::send_hello_on`, `radii_proto::send_report_on` (Task 4).
- Produces: no public interface change — `radii-cli` is a binary; its `Commands::Hello`/`Commands::Report` arms and printed output are unchanged.

- [ ] **Step 1: Replace `send_message` with two thin command-specific functions**

In `crates/cli/src/main.rs`, remove the generic `send_message` function:

```rust
async fn send_message(addr: &str, message: RadiiMessage, tls: TlsArgs) -> Result<()> {
    let tls = tls.load()?;
    let mut stream = radii_proto::tls::dial(addr, tls.as_ref()).await?;
    write_message(&mut stream, &message).await?;
    match read_message(&mut stream).await {
        Ok(RadiiMessage::Ack { status }) => {
            tracing::info!(%status, "received ack");
            println!("ack={status}");
        }
        Ok(other) => {
            tracing::info!(message = ?other, "received reply");
            println!("reply={other:?}");
        }
        Err(err) => {
            tracing::warn!(error = %err, "no ack received");
        }
    }
    Ok(())
}
```

and replace it with:

```rust
async fn send_hello(
    addr: &str,
    node_id: String,
    roles: Vec<String>,
    listen_addrs: Vec<String>,
    tls: TlsArgs,
) -> Result<()> {
    let tls = tls.load()?;
    let mut stream = radii_proto::tls::dial(addr, tls.as_ref()).await?;
    print_reply(radii_proto::send_hello_on(&mut stream, node_id, roles, listen_addrs).await);
    Ok(())
}

async fn send_report(
    addr: &str,
    from: String,
    target: String,
    protocol: String,
    reachable: bool,
    rtt_ms: Option<u32>,
    observed_addr: Option<String>,
    tls: TlsArgs,
) -> Result<()> {
    let tls = tls.load()?;
    let mut stream = radii_proto::tls::dial(addr, tls.as_ref()).await?;
    print_reply(
        radii_proto::send_report_on(
            &mut stream,
            from,
            target,
            protocol,
            reachable,
            rtt_ms,
            observed_addr,
        )
        .await,
    );
    Ok(())
}

fn print_reply(result: Result<RadiiMessage>) {
    match result {
        Ok(RadiiMessage::Ack { status }) => {
            tracing::info!(%status, "received ack");
            println!("ack={status}");
        }
        Ok(other) => {
            tracing::info!(message = ?other, "received reply");
            println!("reply={other:?}");
        }
        Err(err) => {
            // Some early listeners may close without an ack; still treat send as success.
            tracing::warn!(error = %err, "no ack received");
        }
    }
}
```

- [ ] **Step 2: Update the two call sites in `main`**

Change:

```rust
Commands::Hello {
    addr,
    node_id,
    roles,
    listen_addrs,
    tls,
} => {
    send_message(
        &addr,
        RadiiMessage::NodeHello {
            node_id,
            roles,
            listen_addrs,
        },
        tls,
    )
    .await
}
```

to:

```rust
Commands::Hello {
    addr,
    node_id,
    roles,
    listen_addrs,
    tls,
} => send_hello(&addr, node_id, roles, listen_addrs, tls).await,
```

and change:

```rust
Commands::Report {
    addr,
    from,
    target,
    protocol,
    reachable,
    rtt_ms,
    observed_addr,
    tls,
} => {
    send_message(
        &addr,
        RadiiMessage::ReachabilityReport {
            from,
            target,
            protocol,
            reachable,
            rtt_ms,
            observed_addr,
        },
        tls,
    )
    .await
}
```

to:

```rust
Commands::Report {
    addr,
    from,
    target,
    protocol,
    reachable,
    rtt_ms,
    observed_addr,
    tls,
} => {
    send_report(
        &addr,
        from,
        target,
        protocol,
        reachable,
        rtt_ms,
        observed_addr,
        tls,
    )
    .await
}
```

- [ ] **Step 3: Drop now-unused imports**

`write_message` and `read_message` are no longer called directly in this file (only via `send_hello_on`/`send_report_on` inside `radii-proto` itself). Change:

```rust
use radii_proto::{read_message, write_message, RadiiMessage};
```

to:

```rust
use radii_proto::RadiiMessage;
```

(`RadiiMessage` is still needed — `print_reply`'s signature and its `Ok(RadiiMessage::Ack { status })` match arm both use it.)

- [ ] **Step 4: Run the CLI's tests and a full build**

Run: `cargo build --workspace && cargo test -p radii-cli`
Expected: PASS — both existing tests (`tls_args_none_means_plaintext`, `tls_args_reject_partial_configuration`) are unaffected by this refactor since they only exercise `TlsArgs::load`.

- [ ] **Step 5: Commit**

```bash
git add crates/cli/src/main.rs
git commit -m "refactor(cli): delegate hello/report to radii-proto's new helpers"
```

---

### Task 6: Update Crawl's README to reflect roles and liveness

**Files:**
- Modify: `crates/crawl/README.md`

**Interfaces:** none (documentation only).

- [ ] **Step 1: Add a line to the "Today" section**

In `crates/crawl/README.md`, under `## Today`, add a bullet after the existing `In-memory node address map + report list` line:

```markdown
- Nodes carry free-form roles from `NodeHello` (e.g. `["wave"]`), returned via `GraphQuery`'s `NodeInfo.roles` — Crawl doesn't interpret them, just stores and reports them back
- Configurable node liveness (`node_ttl_ms`): a node that stops sending hellos drops out of `GraphQuery` replies once its TTL elapses
```

- [ ] **Step 2: Commit**

```bash
git add crates/crawl/README.md
git commit -m "docs(crawl): document role tagging and node liveness"
```
