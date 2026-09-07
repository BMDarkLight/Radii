# Head Reverse Proxy Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make Head forward requests and stream responses over source-routed relay chains, so a site behind Radii survives a dead path or a dead origin.

**Architecture:** Head keeps its `DecisionEngine` and ranked candidates; only what it does with the winner changes. A decision now carries either chain-reachable routes (graph-resolved, with node ids) or a statically configured address (no node identity, dialed directly). The proxy establishes a chain per candidate, speaks HTTP over it with hyper, and streams both directions. Retry happens only when the chain failed to establish.

**Tech Stack:** Rust 2021, tokio, axum 0.7, hyper 1.x + `hyper-util` + `http-body-util` (already in the lock file via axum), rcgen (test PKI).

**Spec:** `docs/superpowers/specs/2026-09-08-head-reverse-proxy-design.md`

## Global Constraints

- Four gates, every task: `cargo test --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo fmt --all -- --check`, plus the task's covering tests. Run `cargo fmt --all` before committing; the fmt job is required CI.
- Commit subjects: Conventional Commits, **subject line only** — no body, no trailers of any kind (no `Co-Authored-By`, no `Generated with`). The repo owner has an explicit standing preference.
- **Head never buffers request bodies.** Bodies stream client→backend and responses stream back. Buffering exists only to enable replay, and replay is out of scope.
- **Retry only when the chain failed to establish** — the request was never delivered, so replaying it is safe for any method including POST. Once the request is written, a failure is terminal and reaches the client as 502.
- No new external dependencies. hyper 1.x, `hyper-util`, `http-body-util` are already in `Cargo.lock` via axum; promote them to direct deps of `radii-head`.
- **Do not add chain pooling.** A fresh chain per request is a deliberate first-version choice; the latency cost is a documented known limitation.
- Integration helpers: `bind_local() -> Result<(TcpListener, String)>` (address is a `String`), `wait_ready(addr: &str) -> Result<()>` (returns a Result). `TestCa::issue(node_id) -> TlsIdentityConfig`.
- **Do not call `wait_ready` on a listener already returned by `bind_local`** — it is already bound and listening, and the probe consumes a relay pre-admission slot. See the note at the top of `crates/integration/tests/relay_limits.rs`.
- `RelayConfig` struct literals in tests need: `bind`, `node_id`, `max_hops`, `max_concurrent_total`, `max_concurrent_per_peer`, `idle_timeout_ms`, `handshake_timeout_ms`, `max_pending_total`, `max_pending_per_addr`, `allow_peers`, `tls`.

---

## File Structure

| File | Responsibility |
|---|---|
| `crates/head/src/decision.rs` | `BackendTarget` (chain routes vs direct address); policies produce it. |
| `crates/head/src/graph.rs` | `plan_backends` returns `Vec<ResolvedRoute>`; `target_role` becomes `RELAY`. |
| `crates/head/src/proxy.rs` | **New.** Forward one request over one connection; header rules; timeouts. |
| `crates/head/src/http.rs` | Route wiring: `/health`, `/_radii/decision`, proxy fallback; the failover loop. |
| `crates/head/src/config.rs` | `attempt_timeout_ms`, `response_timeout_ms` under `[http]`. |
| `crates/head/Cargo.toml` | Promote hyper/hyper-util/http-body-util; add `radii-fetch`. |
| `crates/integration/tests/head_proxy.rs` | **New.** The acceptance test plus header/streaming coverage. |

---

## Task 1: A decision that knows how to be reached

Refactor only. Head still answers with JSON; nothing proxies yet. This exists so the type change and the behaviour change are separately reviewable.

**Files:**
- Modify: `crates/head/src/decision.rs`, `crates/head/src/graph.rs`, `crates/head/src/http.rs`
- Modify: `crates/head/Cargo.toml` (add `radii-fetch`)
- Test: `crates/head/src/decision.rs` (in-file `mod tests`)

**Interfaces:**
- Produces:
  ```rust
  pub enum BackendTarget {
      /// Graph-resolved, reachable over source-routed chains, best first.
      Chain(Vec<radii_core::routing::ResolvedRoute>),
      /// Statically configured. No node identity, so dialed directly.
      Direct(String),
  }

  pub struct BackendDecision {
      pub target: BackendTarget,
      pub reason: DecisionReason,
  }

  impl BackendDecision {
      /// The address that will be dialed first.
      pub fn backend(&self) -> String;
      /// Every address that could be dialed, best first.
      pub fn candidates(&self) -> Vec<String>;
  }
  ```
- `graph::plan_backends(state, source, targets, allowed_protocols, max_hops, limit) -> Vec<ResolvedRoute>` (was `Vec<(String, usize, f64)>`).

- [ ] **Step 1: Write the failing tests**

Add to `mod tests` in `crates/head/src/decision.rs`:

```rust
    #[test]
    fn a_static_host_map_hit_is_a_direct_target() {
        let mut host_map = HashMap::new();
        host_map.insert("example.com".to_string(), "http://10.0.0.10:9000".to_string());
        let engine = DecisionEngine::from_config(&RoutingConfig {
            default_backend: "http://127.0.0.1:9000".into(),
            host_map,
        });

        let decision = engine.decide(input(Some("example.com")));
        assert!(matches!(decision.target, BackendTarget::Direct(_)));
        assert_eq!(decision.backend(), "http://10.0.0.10:9000");
        assert_eq!(decision.candidates(), vec!["http://10.0.0.10:9000".to_string()]);
    }

    #[test]
    fn a_graph_route_is_a_chain_target_carrying_node_ids() {
        let state = graph_state_with_reachable_route();
        let mut node_map = HashMap::new();
        node_map.insert("example.com".to_string(), vec!["node-b".to_string()]);
        let policy = GraphRoutePolicy::new(
            node_map,
            "head".to_string(),
            vec!["http".to_string()],
            4,
            3,
            state,
        );
        let engine = DecisionEngine::new().with_policy(policy);

        let decision = engine.decide(input(Some("example.com")));
        let BackendTarget::Chain(routes) = &decision.target else {
            panic!("expected a chain target, got a direct one");
        };
        // The node id is what `chain::establish` needs and what a bare
        // address string cannot carry.
        assert_eq!(routes[0].target().0, "node-b");
        assert_eq!(decision.backend(), routes[0].hops.last().unwrap().addr);
    }
```

`graph_state_with_reachable_route()` already exists in that test module — read it and, if its listen map still tags addresses `"http"`, retag to `"relay"` since Head now resolves that role.

- [ ] **Step 2: Run them to verify they fail**

Run: `cargo test -p radii-head decision 2>&1 | head -20`
Expected: FAIL — `cannot find type BackendTarget`.

- [ ] **Step 3: Implement**

In `crates/head/src/decision.rs`, replace `BackendDecision`'s two address fields:

```rust
/// How a decided backend can be reached.
///
/// The two are genuinely different, not two spellings of an address. A
/// graph-resolved backend is a *node*, reached over a source-routed chain
/// that terminates at its relay listener — so it needs the node id, which a
/// bare address cannot carry. A statically configured backend came from the
/// operator's own config, has no node identity at all, and may legitimately
/// point at a host that is not part of the mesh.
pub enum BackendTarget {
    Chain(Vec<radii_core::routing::ResolvedRoute>),
    Direct(String),
}

pub struct BackendDecision {
    pub target: BackendTarget,
    pub reason: DecisionReason,
}

impl BackendDecision {
    /// The address that will be dialed first.
    pub fn backend(&self) -> String {
        match &self.target {
            BackendTarget::Chain(routes) => routes
                .first()
                .and_then(|route| route.hops.last())
                .map(|hop| hop.addr.clone())
                .unwrap_or_else(|| "unreachable".to_string()),
            BackendTarget::Direct(addr) => addr.clone(),
        }
    }

    /// Every address that could be dialed, best first. `backend()` is always
    /// the first, on every path.
    pub fn candidates(&self) -> Vec<String> {
        match &self.target {
            BackendTarget::Chain(routes) => routes
                .iter()
                .filter_map(|route| route.hops.last().map(|hop| hop.addr.clone()))
                .collect(),
            BackendTarget::Direct(addr) => vec![addr.clone()],
        }
    }
}
```

`BackendDecision` derives `Clone`; add `#[derive(Clone)]` to `BackendTarget` too.

`HostMapPolicy` and `DefaultPolicy` return `BackendTarget::Direct(...)`. `decide`'s no-policy sentinel returns `BackendTarget::Direct("unreachable".to_string())`. `GraphRoutePolicy` returns `BackendTarget::Chain(routes)` and returns `None` when `routes` is empty, exactly as it returns `None` today when no route resolves.

In `crates/head/src/graph.rs`, change `plan_backends` to return the routes rather than flattening them:

```rust
pub fn plan_backends(
    state: &SharedGraphState,
    source: &NodeId,
    targets: &[NodeId],
    allowed_protocols: &[ProtocolId],
    max_hops: usize,
    limit: usize,
) -> Vec<radii_core::routing::ResolvedRoute> {
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
        // Head now reaches a backend over a chain, which terminates at the
        // target's RELAY listener and splices to that node's own upstream.
        // It resolves `relay`, not `http`, for the same reason Fetch does.
        None,
        &RoleId::new(RoleId::RELAY),
    )
}
```

Leave `plan_backend` (singular) alone if it still has callers; if it has none after this, delete it rather than leaving it dead.

In `crates/head/src/http.rs`, the JSON handler now calls `decision.backend()` and `decision.candidates()`.

Add to `crates/head/Cargo.toml`:

```toml
radii-fetch = { path = "../fetch" }
```

- [ ] **Step 4: Run the gates**

```bash
cargo fmt --all
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```
Expected: green. `crates/integration/tests/head_http.rs` asserts on the JSON shape and must still pass unchanged — that is the proof this refactor changed no behaviour.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "refactor(head): carry how a backend is reached, not just its address"
```

---

## Task 2: Forward one request

Head proxies to the single best candidate. No failover yet; that is Task 3.

**Files:**
- Create: `crates/head/src/proxy.rs`
- Modify: `crates/head/src/http.rs`, `crates/head/src/lib.rs`, `crates/head/src/config.rs`, `crates/head/Cargo.toml`
- Test: `crates/integration/tests/head_proxy.rs` (new)

**Interfaces:**
- Consumes: `BackendTarget`, `BackendDecision::backend()` (Task 1); `radii_fetch::chain::establish(route, hop_tls, e2e_tls) -> anyhow::Result<BoxedStream>`.
- Produces:
  ```rust
  pub async fn forward(
      stream: radii_proto::BoxedStream,
      request: axum::extract::Request,
      response_timeout: std::time::Duration,
  ) -> anyhow::Result<axum::response::Response>;

  pub fn strip_hop_by_hop(headers: &mut axum::http::HeaderMap);
  ```
- `HttpConfig` gains `attempt_timeout_ms: u64` (default 3000) and `response_timeout_ms: u64` (default 30000).

- [ ] **Step 1: Write the failing tests**

Create `crates/integration/tests/head_proxy.rs`:

```rust
//! Head as a reverse proxy.
//!
//! Before this, Head answered every request with a JSON document describing
//! the backend it *would* pick, so none of the source-routing work reached
//! HTTP traffic at all.

use radii_head::decision::DecisionEngine;
use radii_head::http::serve_http_on;
use radii_integration::{bind_local, wait_ready};
use std::collections::HashMap;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// A minimal HTTP origin that echoes back what it was asked, so a test can
/// assert on the headers Head actually forwarded.
async fn run_origin(listener: TcpListener, body: &'static str) {
    loop {
        let Ok((mut stream, _)) = listener.accept().await else {
            break;
        };
        tokio::spawn(async move {
            let mut buf = vec![0u8; 8192];
            let n = stream.read(&mut buf).await.unwrap_or(0);
            let request = String::from_utf8_lossy(&buf[..n]).to_string();
            // Echo the request head back in a header so assertions can read it.
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nX-Saw-Request: {}\r\n\r\n{}",
                body.len(),
                request.replace('\r', "").replace('\n', "|"),
                body
            );
            let _ = stream.write_all(response.as_bytes()).await;
        });
    }
}

#[tokio::test]
async fn proxies_a_request_to_a_static_backend_and_returns_the_body() {
    let (origin_listener, origin_addr) = bind_local().await.unwrap();
    tokio::spawn(run_origin(origin_listener, "hello from origin"));

    let mut host_map = HashMap::new();
    host_map.insert("example.com".to_string(), origin_addr.clone());
    let decision = DecisionEngine::from_config(&radii_head::config::RoutingConfig {
        default_backend: origin_addr.clone(),
        host_map,
    });

    let (listener, addr) = bind_local().await.unwrap();
    let handle = tokio::spawn(async move { serve_http_on(listener, decision).await });

    let body = reqwest::Client::new()
        .get(format!("http://{addr}/some/path"))
        .header("Host", "example.com")
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();

    assert_eq!(body, "hello from origin");
    handle.abort();
}

#[tokio::test]
async fn health_is_answered_locally_and_not_proxied() {
    let (origin_listener, origin_addr) = bind_local().await.unwrap();
    tokio::spawn(run_origin(origin_listener, "origin"));

    let decision = DecisionEngine::from_config(&radii_head::config::RoutingConfig {
        default_backend: origin_addr,
        host_map: HashMap::new(),
    });
    let (listener, addr) = bind_local().await.unwrap();
    let handle = tokio::spawn(async move { serve_http_on(listener, decision).await });

    let response = reqwest::get(format!("http://{addr}/health")).await.unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.text().await.unwrap(), "", "health must not be proxied");
    handle.abort();
}

#[tokio::test]
async fn forwards_host_and_strips_hop_by_hop_headers() {
    let (origin_listener, origin_addr) = bind_local().await.unwrap();
    tokio::spawn(run_origin(origin_listener, "ok"));

    let mut host_map = HashMap::new();
    host_map.insert("example.com".to_string(), origin_addr.clone());
    let decision = DecisionEngine::from_config(&radii_head::config::RoutingConfig {
        default_backend: origin_addr,
        host_map,
    });
    let (listener, addr) = bind_local().await.unwrap();
    let handle = tokio::spawn(async move { serve_http_on(listener, decision).await });

    let response = reqwest::Client::new()
        .get(format!("http://{addr}/"))
        .header("Host", "example.com")
        .header("X-Custom-Hop", "secret")
        // Naming a header in `Connection` makes it hop-by-hop for this
        // message; forwarding it is request-smuggling surface.
        .header("Connection", "X-Custom-Hop")
        .send()
        .await
        .unwrap();

    let saw = response
        .headers()
        .get("X-Saw-Request")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    assert!(saw.contains("host: example.com"), "Host must reach the origin: {saw}");
    assert!(!saw.to_lowercase().contains("x-custom-hop"), "Connection-named header leaked: {saw}");
    assert!(!saw.to_lowercase().contains("connection:"), "Connection itself leaked: {saw}");
    assert!(saw.to_lowercase().contains("x-forwarded-for"), "XFF should be added: {saw}");
    handle.abort();
}

#[tokio::test]
async fn a_backend_that_cannot_be_reached_is_a_502() {
    let decision = DecisionEngine::from_config(&radii_head::config::RoutingConfig {
        // Nothing listens here.
        default_backend: "127.0.0.1:1".to_string(),
        host_map: HashMap::new(),
    });
    let (listener, addr) = bind_local().await.unwrap();
    let handle = tokio::spawn(async move { serve_http_on(listener, decision).await });

    let response = reqwest::get(format!("http://{addr}/")).await.unwrap();
    assert_eq!(response.status(), 502);
    handle.abort();
}

#[tokio::test]
async fn the_decision_json_moved_to_its_own_path() {
    let (origin_listener, origin_addr) = bind_local().await.unwrap();
    tokio::spawn(run_origin(origin_listener, "origin body"));

    let decision = DecisionEngine::from_config(&radii_head::config::RoutingConfig {
        default_backend: origin_addr,
        host_map: HashMap::new(),
    });
    let (listener, addr) = bind_local().await.unwrap();
    let handle = tokio::spawn(async move { serve_http_on(listener, decision).await });

    let json: serde_json::Value = reqwest::get(format!("http://{addr}/_radii/decision"))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(json.get("backend").is_some(), "decision endpoint should report a backend");

    // Every other path proxies now, so the backend map is no longer disclosed
    // on arbitrary paths.
    let other = reqwest::get(format!("http://{addr}/anything"))
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert_eq!(other, "origin body");
    handle.abort();
}
```

`reqwest` is already a dev-dependency of `radii-integration`. `wait_ready` is imported but the listeners come pre-bound from `bind_local`, so do not call it — remove the import if clippy flags it unused.

- [ ] **Step 2: Run them to verify they fail**

Run: `cargo test -p radii-integration --test head_proxy 2>&1 | head -20`
Expected: FAIL — Head still returns JSON, so the body assertions fail.

- [ ] **Step 3: Add the config knobs**

In `crates/head/src/config.rs`, extend `HttpConfig`:

```rust
#[derive(Debug, Deserialize)]
pub struct HttpConfig {
    pub bind: String,
    /// Bounds one candidate's chain establishment plus HTTP handshake.
    #[serde(default = "default_attempt_timeout_ms")]
    pub attempt_timeout_ms: u64,
    /// Bounds waiting for response headers after the request is sent. Not a
    /// limit on body streaming: a slow large download is legitimate.
    #[serde(default = "default_response_timeout_ms")]
    pub response_timeout_ms: u64,
}

fn default_attempt_timeout_ms() -> u64 {
    3000
}

fn default_response_timeout_ms() -> u64 {
    30_000
}
```

- [ ] **Step 4: Write the proxy**

Add to `crates/head/Cargo.toml`:

```toml
http-body-util = "0.1"
hyper = { version = "1", features = ["client", "http1"] }
hyper-util = { version = "0.1", features = ["tokio"] }
```

Create `crates/head/src/proxy.rs`:

```rust
//! Forwarding one HTTP request over one already-established connection.
//!
//! Deliberately knows nothing about how the connection was obtained — a
//! source-routed chain and a direct TCP dial are the same thing here. That
//! keeps the "how do I reach this backend" decision in one place and makes
//! this file testable against a plain socket.

use anyhow::{Context, Result};
use axum::extract::Request;
use axum::http::header::{HeaderMap, HeaderName};
use axum::response::Response;
use radii_proto::BoxedStream;
use std::time::Duration;

/// Headers that apply to a single transport hop and must never be forwarded.
/// Beyond this fixed list, every header *named in* the message's own
/// `Connection` header is hop-by-hop too — the part implementations most
/// often miss, and a request-smuggling surface when they do.
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

pub fn strip_hop_by_hop(headers: &mut HeaderMap) {
    let mut named: Vec<HeaderName> = Vec::new();
    if let Some(connection) = headers.get("connection") {
        if let Ok(value) = connection.to_str() {
            for token in value.split(',') {
                if let Ok(name) = HeaderName::try_from(token.trim().to_ascii_lowercase()) {
                    named.push(name);
                }
            }
        }
    }
    for name in named {
        headers.remove(name);
    }
    for name in HOP_BY_HOP {
        headers.remove(*name);
    }
}

/// Forwards `request` over `stream` and returns the response with its body
/// still streaming. Neither body is buffered.
pub async fn forward(
    stream: BoxedStream,
    request: Request,
    response_timeout: Duration,
) -> Result<Response> {
    let io = hyper_util::rt::TokioIo::new(stream);
    let (mut sender, connection) = hyper::client::conn::http1::handshake(io)
        .await
        .context("http handshake with the backend failed")?;

    // The connection future drives the socket; dropping it would stall the
    // exchange. It ends on its own when the response completes.
    tokio::spawn(async move {
        if let Err(err) = connection.await {
            tracing::debug!(error = %err, "backend connection closed");
        }
    });

    let (mut parts, body) = request.into_parts();
    strip_hop_by_hop(&mut parts.headers);
    let outbound = hyper::Request::from_parts(parts, body);

    let response = tokio::time::timeout(response_timeout, sender.send_request(outbound))
        .await
        .context("backend did not send response headers in time")?
        .context("backend request failed")?;

    let (mut parts, body) = response.into_parts();
    strip_hop_by_hop(&mut parts.headers);
    Ok(Response::from_parts(parts, axum::body::Body::new(body)))
}
```

Register it in `crates/head/src/lib.rs` with `pub mod proxy;`.

- [ ] **Step 5: Rewire the router**

In `crates/head/src/http.rs`: `AppState` gains `attempt_timeout: Duration` and `response_timeout: Duration`. The router becomes:

```rust
    Router::new()
        .route("/health", get(health))
        .route("/_radii/decision", get(decision_json))
        .fallback(any(proxy_request))
        .with_state(state)
```

`decision_json` is today's `handle_request`, renamed, still returning `HeadResponse`.

`proxy_request` decides, then reaches the backend. For this task, use only the FIRST candidate — the failover loop is Task 3:

```rust
async fn proxy_request(
    State(state): State<AppState>,
    connect: ConnectInfo<SocketAddr>,
    mut request: Request,
) -> Response {
    let host = request
        .headers()
        .get(axum::http::header::HOST)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);

    let decision = state.decision.decide(DecisionInput {
        protocol: state.protocol,
        protocol_label: None,
        host: host.as_deref(),
        source: Some(connect.0),
        destination_port: None,
        attributes: &[],
    });

    add_forwarded_headers(request.headers_mut(), &connect.0, host.as_deref());

    match connect_backend(&state, &decision).await {
        Ok(stream) => match crate::proxy::forward(stream, request, state.response_timeout).await {
            Ok(response) => response,
            Err(err) => {
                tracing::warn!(error = %err, backend = %decision.backend(), "proxy forward failed");
                StatusCode::BAD_GATEWAY.into_response()
            }
        },
        Err(err) => {
            tracing::warn!(error = %err, backend = %decision.backend(), "no backend could be reached");
            StatusCode::BAD_GATEWAY.into_response()
        }
    }
}

/// Records the immediate peer in `X-Forwarded-*`.
///
/// An inbound `X-Forwarded-For` is appended to, never replaced — but it is
/// also never believed: any client can send one. Head makes no
/// access-control decision on these headers, and nothing downstream should
/// treat them as authenticated.
fn add_forwarded_headers(headers: &mut HeaderMap, peer: &SocketAddr, host: Option<&str>) {
    let existing = headers
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    let chain = match existing {
        Some(prior) => format!("{prior}, {}", peer.ip()),
        None => peer.ip().to_string(),
    };
    if let Ok(value) = chain.parse() {
        headers.insert("x-forwarded-for", value);
    }
    if let Ok(value) = "http".parse() {
        headers.insert("x-forwarded-proto", value);
    }
    if let Some(host) = host {
        if let Ok(value) = host.parse() {
            headers.insert("x-forwarded-host", value);
        }
    }
}

/// Opens a connection to the decided backend. Task 3 turns this into a loop.
async fn connect_backend(
    state: &AppState,
    decision: &BackendDecision,
) -> anyhow::Result<radii_proto::BoxedStream> {
    match &decision.target {
        BackendTarget::Direct(addr) => {
            let addr = radii_fetch::server::normalize_upstream(addr);
            let stream = tokio::time::timeout(
                state.attempt_timeout,
                tokio::net::TcpStream::connect(&addr),
            )
            .await
            .context("timed out dialing the configured backend")??;
            Ok(Box::new(stream))
        }
        BackendTarget::Chain(routes) => {
            let route = routes.first().context("no reachable candidate")?;
            tokio::time::timeout(
                state.attempt_timeout,
                radii_fetch::chain::establish(route, state.chain_tls.as_ref(), state.chain_tls.as_ref()),
            )
            .await
            .context("timed out establishing a chain to the backend")?
        }
    }
}
```

`AppState` also gains `chain_tls: Option<radii_proto::tls::TlsIdentity>`, sourced from Head's existing `[tls]` identity in `crates/head/src/lib.rs`. `serve_http_on` keeps its current two-argument signature by defaulting the timeouts and `chain_tls`; add `serve_http_on_with` taking the full state so `lib.rs` can pass the real values, and have `serve_http_on` delegate to it.

- [ ] **Step 6: Run the gates**

```bash
cargo fmt --all
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```
`crates/integration/tests/head_http.rs` asserts the old JSON-on-every-path behaviour and **will now fail**. Update it to request `/_radii/decision`; do not weaken what it asserts about the decision itself.

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "feat(head): forward requests to the decided backend"
```

---

## Task 3: Failover, and the acceptance test

**Files:**
- Modify: `crates/head/src/http.rs`
- Test: `crates/integration/tests/head_proxy.rs` (extend)

**Interfaces:**
- Consumes: everything from Tasks 1–2.

- [ ] **Step 1: Write the acceptance test**

Append to `crates/integration/tests/head_proxy.rs`. This is the test the whole feature exists for.

```rust
/// The feature, end to end: a client makes an ordinary HTTP request, the
/// response comes from an origin reached over a source-routed relay chain,
/// and when the first candidate's node is down the client still gets the
/// response from the second — never observing the failure.
#[tokio::test]
async fn fails_over_to_a_second_node_without_the_client_noticing() {
    use radii_core::routing::{GraphSnapshot, Link, NodeId, ProtocolId};
    use radii_head::decision::GraphRoutePolicy;
    use radii_head::graph::{GraphState, SharedGraphState};
    use radii_integration::pki::TestCa;
    use radii_proto::tls::TlsIdentity;
    use std::sync::{Arc, RwLock};

    let ca = TestCa::new();
    let head_identity = TlsIdentity::load(&ca.issue("head")).unwrap();

    // Only the second node is actually running.
    let (origin_listener, origin_addr) = bind_local().await.unwrap();
    tokio::spawn(run_origin(origin_listener, "served by node-c"));

    let (relay_listener, relay_addr) = bind_local().await.unwrap();
    let runtime = radii_fetch::relay::RelayRuntime::new(
        radii_fetch::config::RelayConfig {
            bind: relay_addr.clone(),
            node_id: "node-c".to_string(),
            max_hops: 8,
            max_concurrent_total: 16,
            max_concurrent_per_peer: 8,
            idle_timeout_ms: 30_000,
            handshake_timeout_ms: 10_000,
            max_pending_total: 256,
            max_pending_per_addr: 64,
            allow_peers: Vec::new(),
            tls: Some(ca.issue("node-c")),
        },
        origin_addr.clone(),
        Some(TlsIdentity::load(&ca.issue("node-c")).unwrap()),
    )
    .unwrap();
    tokio::spawn(radii_fetch::relay::run(relay_listener, runtime));

    let mut snapshot = GraphSnapshot::new();
    for to in ["node-b", "node-c"] {
        snapshot.add_link(Link {
            from: NodeId("head".into()),
            to: NodeId(to.into()),
            protocol: ProtocolId::new("http"),
            reachable: true,
            // node-b looks cheaper, so it is tried first — and it is dead.
            latency_ms: Some(if to == "node-b" { 10 } else { 200 }),
        });
    }
    let mut listen_addrs: HashMap<String, Vec<(String, String)>> = HashMap::new();
    listen_addrs.insert("node-b".into(), vec![("127.0.0.1:1".into(), "relay".into())]);
    listen_addrs.insert("node-c".into(), vec![(relay_addr.clone(), "relay".into())]);
    let state: SharedGraphState = Arc::new(RwLock::new(GraphState { snapshot, listen_addrs }));

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
        state,
    );
    let decision = DecisionEngine::new().with_policy(policy);

    let (listener, addr) = bind_local().await.unwrap();
    let handle = tokio::spawn(async move {
        radii_head::http::serve_http_on_with(
            listener,
            decision,
            std::time::Duration::from_millis(3000),
            std::time::Duration::from_millis(30_000),
            Some(head_identity),
        )
        .await
    });

    let body = reqwest::Client::new()
        .get(format!("http://{addr}/"))
        .header("Host", "site.example")
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();

    assert_eq!(
        body, "served by node-c",
        "the client must get the live node's response without seeing the dead one"
    );
    handle.abort();
}
```

Check `serve_http_on_with`'s real parameter order against what Task 2 produced and match it.

- [ ] **Step 2: Run it to verify it fails**

Run: `cargo test -p radii-integration --test head_proxy fails_over 2>&1 | tail -20`
Expected: FAIL — Task 2 tries only the first candidate, which is dead, so this is a 502.

- [ ] **Step 3: Turn `connect_backend` into a loop**

In `crates/head/src/http.rs`, replace the `BackendTarget::Chain` arm:

```rust
        BackendTarget::Chain(routes) => {
            let mut last: anyhow::Error = anyhow::anyhow!("no reachable candidate");
            for (index, route) in routes.iter().enumerate() {
                // Retry is safe here and only here: a chain that failed to
                // establish never delivered the request, so replaying it is
                // unambiguous for any method, POST included. Once the
                // request is written, a failure is terminal — Head cannot
                // know whether the backend processed it.
                let attempt = tokio::time::timeout(
                    state.attempt_timeout,
                    radii_fetch::chain::establish(
                        route,
                        state.chain_tls.as_ref(),
                        state.chain_tls.as_ref(),
                    ),
                )
                .await;

                match attempt {
                    Ok(Ok(stream)) => {
                        tracing::info!(
                            candidate = index,
                            target = %route.target().0,
                            "head established a chain to a backend"
                        );
                        return Ok(stream);
                    }
                    Ok(Err(err)) => {
                        tracing::warn!(
                            candidate = index,
                            target = %route.target().0,
                            error = %err,
                            "candidate failed; trying the next"
                        );
                        last = err;
                    }
                    Err(_) => {
                        tracing::warn!(
                            candidate = index,
                            target = %route.target().0,
                            timeout_ms = state.attempt_timeout.as_millis(),
                            "candidate timed out; trying the next"
                        );
                        last = anyhow::anyhow!("candidate timed out");
                    }
                }
            }
            Err(last)
        }
```

- [ ] **Step 4: Run the gates**

```bash
cargo fmt --all
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat(head): fail over across ranked candidates when a chain will not open"
```

---

## Task 4: Documentation

**Files:**
- Modify: `SECURITY.md`, `README.md`, `crates/head/README.md`, `crates/head/head.example.toml`
- Modify: `crates/core/src/routing.rs` (the `RoleId::HTTP` doc comment)

- [ ] **Step 1: Mark `RoleId::HTTP` reserved**

In `crates/core/src/routing.rs`, replace `RoleId::HTTP`'s doc comment:

```rust
    /// A plain HTTP backend, dialed directly.
    ///
    /// **Reserved: nothing resolves this today.** Head reaches backends over
    /// source-routed chains, so it resolves [`RoleId::RELAY`] like Fetch
    /// does. This constant is kept because removing it would churn the wire
    /// for no gain, and named explicitly as unused so it does not look
    /// load-bearing — this project already carries one decorative field in
    /// node-level `roles`, and a second should not accumulate silently.
    /// Delete it if no consumer appears, or give it one by adding a
    /// direct-dial mode for backends that are not behind a Radii node.
    pub const HTTP: &'static str = "http";
```

- [ ] **Step 2: Update the security register**

In `SECURITY.md`:

- Add an implemented-control row:
  ```
  | Proxy hop-by-hop header stripping | `radii-head` (`proxy::strip_hop_by_hop`) | Head removes `Connection`, `Keep-Alive`, `Proxy-Authenticate`, `Proxy-Authorization`, `TE`, `Trailer`, `Transfer-Encoding`, `Upgrade`, and every header *named in* the message's own `Connection` header, in both directions. Forwarding a `Connection`-named header to a backend is request-smuggling surface |
  | Proxy timeouts | `radii-head` (`[http]`) | `attempt_timeout_ms` bounds one candidate's chain establishment and HTTP handshake; `response_timeout_ms` bounds waiting for response headers. Body streaming is deliberately unbounded — a slow large download is legitimate |
  ```
- Add residual-risk rows:
  ```
  | `X-Forwarded-For` is recorded, not trusted | Head appends the immediate peer to any inbound value, but any client can send one. Head makes no access-control decision on it and nothing downstream should treat it as authenticated |
  | Head is now a data path | A misrouted request delivers user traffic to the wrong backend rather than printing a wrong address. The end-to-end TLS session inside a chain authenticates the target node, so a relay carrying it cannot read or impersonate the endpoint — but a wrong *decision* is now a wrong *delivery* |
  ```
- Amend the "Head information disclosure" gap: the decision JSON now lives only at `GET /_radii/decision` rather than on every path, so an operator can firewall exactly one route. The lack of authorization on it is unchanged.
- Amend the connection-timeout gap: Head's proxy path is now bounded; its Radii bridge listener still is not.

- [ ] **Step 3: Update the READMEs and example config**

- `README.md`: replace Head's "what works today" line. It currently says other paths return a JSON backend decision. It should say Head proxies HTTP over source-routed chains with failover across ranked candidates, that `/health` and `/_radii/decision` are served locally, and that a fresh chain per request is a known limitation.
- `crates/head/README.md`: document the proxy path, the retry boundary (retry only when the chain failed to establish; once the request is written a failure is terminal and reaches the client as 502), that statically configured backends are dialed directly because they have no node identity, and the header rules.
- `crates/head/head.example.toml`: add `attempt_timeout_ms` and `response_timeout_ms` under `[http]` with the defaults and a one-line explanation each.

- [ ] **Step 4: Gates and commit**

```bash
cargo fmt --all
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
git add -A
git commit -m "docs(head): document the reverse proxy, its retry boundary, and its limits"
```

---

## Self-Review

**Spec coverage.** §1 request path → Tasks 1–2. §2 `relay` role and `RoleId::HTTP` reserved → Task 1 (code) and Task 4 (doc). §3 retry boundary → Task 3, with the reasoning in a comment at the loop. §4 static backends dialed directly → Task 2's `BackendTarget::Direct` arm. §5 headers → Task 2's `proxy.rs` plus `add_forwarded_headers`. §6 timeouts → Task 2's config knobs. §7 decision JSON moves → Task 2's router. Security → Task 4's register rows. Testing → Task 2's five tests and Task 3's acceptance test.

**Type consistency.** `BackendTarget::{Chain,Direct}` and `BackendDecision { target, reason }` with `backend()`/`candidates()` methods are used identically in Tasks 1–3. `plan_backends` returns `Vec<ResolvedRoute>` from Task 1 onward. `proxy::forward(stream, request, response_timeout)` and `proxy::strip_hop_by_hop(&mut HeaderMap)` keep one signature. `serve_http_on_with` is introduced in Task 2 and used by Task 3's test.

**Known rough edge.** Task 2 leaves `connect_backend` using only the first chain candidate, which Task 3 replaces with the loop. That is deliberate — it separates "Head forwards at all" from "Head fails over" into two reviewable commits — and Task 2's own tests exercise only the static-backend path, so nothing depends on the placeholder behaviour.
