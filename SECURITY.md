# Security Policy

Radii is a **network runtime**. Compromises in protocol handling, peer trust, or deployment hygiene can become remote code execution, traffic hijacking, or widespread denial of service. This document defines how we think about security, what is and is not safe today, how to report issues, and how operators should deploy Radii.

> **Status honesty:** Radii is an early foundation. Peer authentication and transport encryption now exist as opt-in mutual TLS (see [`docs/tls.md`](docs/tls.md)), and authorization now covers Head-relayed messages as well as direct ones. Several critical controls are still **not implemented**: TLS is not mandatory by default, and replay protection, connection timeouts, and rate limiting are all still gaps. Do **not** expose Crawl, Head Radii bridges, or Fetch tunnels to untrusted networks without either enabling `[tls]` everywhere it's reachable or additional controls in front of them.

---

## Supported versions

| Version | Supported | Notes |
|---|---|---|
| `0.1.x` (this repository) | Security fixes accepted | Early foundation; expect breaking protocol changes |
| Pre-release / forks / archive ports | Best effort | Report if reproducible on current `main` |

Security fixes are backported only to the latest released minor line once releases exist. Until then, fixes land on `main`.

---

## Reporting a vulnerability

**Please do not open public GitHub issues for security vulnerabilities.**

### Preferred reporting channels

1. **GitHub Security Advisories** (private): use *Security* → *Report a vulnerability* on this repository if enabled.
2. **Email the maintainers** listed in the repository profile / `LICENSE` copyright holder with:
   - A clear description of the issue and impact
   - Affected component (`radii-proto`, `radii-crawl`, `radii-head`, `radii-fetch`, `radii-cli`, docs/CI)
   - Reproduction steps or a minimal proof of concept
   - Whether the issue is already public elsewhere
   - Your preferred credit name / handle

### What to include

- Version / commit SHA
- Environment (OS, how binaries were started, bind addresses)
- Whether exploitation requires local access, same LAN, or remote Internet reachability
- Crash logs, packet captures, or sanitized configs (redact secrets)

### Response expectations

| Stage | Target |
|---|---|
| Initial acknowledgement | within **3 business days** |
| Triage (severity / severity / affected surface) | within **10 business days** |
| Fix or mitigation guidance for confirmed issues | as quickly as practical; critical remote issues prioritized |

We follow coordinated disclosure. We ask reporters to give us a reasonable window (typically **90 days**, adjustable by severity and complexity) before public discussion, unless the issue is already being actively exploited.

### Safe harbor

We will not pursue legal action against researchers who:

- Make a good-faith effort to avoid privacy violations, data destruction, and service disruption
- Do not exploit beyond what is needed to demonstrate the issue
- Do not access data that is not theirs
- Report findings promptly through the channels above

---

## Threat model

### Assets

| Asset | Why it matters |
|---|---|
| Reachability graph / reports | Poisoned topology can steer Fetch toward attacker-controlled relays |
| Head routing decisions | Wrong backends leak or hijack user traffic |
| Fetch tunnels | Bidirectional byte pipes can become open proxies |
| Relay listener (`radii-fetch` `[relay]`) | An admitted peer consumes bandwidth, sockets and connection slots; a relay carrying a chain can stall or drop it |
| Node identity / roles (future) | Spoofed hellos enable Sybil and trust abuse |
| Operator configs & logs | Bind addresses, upstreams, and client IPs are sensitive operational data |

### Trust boundaries

```
 Untrusted clients / Internet
            |
            v
     [ Head HTTP ]  ---- decision metadata ----\
            |                                   \
            v                                    v
   [ Head Radii bridge ] ---- framed msgs ----> [ Crawl ]
            |                                      |
            v                                      v
      [ Fetch tunnel ] <----- path metadata ----- /
            |
            v
     Upstream service
```

Today, **every TCP listener that accepts connections must be treated as an untrusted-input surface**.

### Adversaries considered

1. **Remote network attacker** who can open TCP connections to exposed binds
2. **Malicious or compromised peer** sending crafted Radii frames, hellos, or reports
3. **On-path network attacker** (MITM) on plaintext links — mitigated where mTLS is enabled (see [Cryptography](#cryptography-target-state)), still applicable on any link left plaintext
4. **Local attacker** with filesystem access to configs, logs, or process memory
5. **Operator misconfiguration** (binding `0.0.0.0`, tunneling to internal-only services)

### Out of scope (for now)

- Physical attacks against hosts
- Compromised Rust toolchain / supply-chain attacks beyond dependency auditing in CI
- Application-layer vulnerabilities inside upstream services behind Fetch
- Nation-state traffic-analysis resistance as a guaranteed property of the current code

---

## Current security posture (0.1.x)

### What is implemented

| Control | Location | Behavior |
|---|---|---|
| Frame size limit | `radii-proto` (`MAX_FRAME_LEN` = 1 MiB) | Rejects hostile length prefixes to prevent unbounded allocation |
| Structured logging | `radii-core` | Operational visibility; may contain IPs/hosts — protect log directories |
| Decision isolation | `radii-head` | Routing decision is config-driven; no remote code execution path in decision JSON |
| CI lint/tests/audit | `.github/workflows` | Format, Clippy, tests, `cargo audit`, `cargo deny` |
| Mutual TLS (opt-in) | `radii-proto::tls`, wired into `radii-crawl`, `radii-head`, `radii-fetch`, `radii-cli` | Peer-authenticated, encrypted transport for the Radii control protocol (Crawl's listener, Head↔Crawl bridge, graph queries) and optionally Fetch's tunnel data path, when a `[tls]` / `[tunnel_tls]` section is configured. Private-CA model, not the public Web PKI. See [`docs/tls.md`](docs/tls.md). |
| Route authorization by peer identity | `radii-crawl` | When TLS is enabled, a peer may only submit `NodeHello` / `ReachabilityReport` under its own authenticated node id |
| Relay authorization | `radii-crawl` (`relay_peers`), `radii-head` | `FromHead` envelopes are accepted only from node ids the operator lists in `relay_peers` (default: none), and the inner claim must match the identity Head authenticated for its own bridge client — so a Head cannot launder a spoofed node id, and a peer that is not a configured Head cannot relay at all |
| Non-recursive relay envelope | `radii-proto` (`RelayedMessage`) | `FromHead` carries a flat message type rather than a boxed `RadiiMessage`, so a nested envelope cannot drive the deserializer into a stack overflow (which aborted the process, not just the connection) |
| Relay admission | `radii-fetch` (`[relay]`) | Relaying is opt-in per node — absent `[relay]`, a node neither forwards chains nor terminates one, and no second listener is opened. Mutual TLS is mandatory: config load **fails** if `[relay]` is present without `[relay.tls]`, because a relay listener without client-certificate verification is an open proxy. Admission is CA membership, narrowed to an explicit list when `allow_peers` is set. **`allow_peers` narrows who may hand this node a chain — the inbound mTLS peer on this hop — not who may originate one.** At chain length one those are the same identity; beyond one hop the inbound peer is the previous relay, and a chain's actual originator is authenticated instead by the end-to-end session (see the End-to-end tunnel identity row) |
| Relay resource bounds | `radii-fetch` (`[relay]`) | Per-peer and global concurrency caps keyed by the authenticated node id, a bound on the whole pre-splice handshake (`handshake_timeout_ms`), and an inactivity deadline on a carried chain (`idle_timeout_ms`). The per-peer cap is the load-bearing one: with admission open to any CA-valid peer, a global cap alone lets one identity take every slot. A slot is released on `Drop`, so it returns however the chain ends. Admitted chains and pre-admission handshakes are rationed **separately**, because the identity a chain allowance is keyed by is what the handshake produces — declining to pay for a handshake means declining to learn who is asking. `acquire()` bounds admitted chains per authenticated peer; `acquire_pending()` bounds connections still in the handshake window per **source address** (`max_pending_per_addr`) under a global ceiling (`max_pending_total`), and runs before the TLS handshake begins, so an over-cap connection costs one accept and one close rather than a task and a session held for `handshake_timeout_ms`. A pre-admission slot is handed back on admission, so a long-lived chain does not also occupy a handshake slot. The source-address key is blunt by necessity — peers behind one NAT share an address — so it is set well above a legitimate peer's concurrent-chain allowance rather than tuned tightly |
| Source-route validation | `radii-fetch` (`relay::validate`) | A relay refuses a path not addressed to it (`tunnel_misaddressed`), longer than its own `max_hops` (`tunnel_too_long`), or containing a repeated node id (`tunnel_path_loops`) — so routing cycles are impossible rather than merely bounded. Checks run before any dialing, but **after** the peer is already charged a slot (`acquire()` runs first in `relay::handshake`) |
| Relayed status sanitisation | `radii-fetch` (`relay::KNOWN_ACK_STATUSES`) | A downstream hop's reply is relayed upstream, so only an `Ack` is ever forwarded and only with a status from a closed vocabulary; anything else becomes one fixed local code. Without this a compromised hop could push up to `MAX_FRAME_LEN` of arbitrary text — newlines, escapes — through every upstream node's logs |
| End-to-end tunnel identity | `radii-fetch` (`chain::establish`) | Two nested TLS sessions authenticate different peers: the hop-local one authenticates the first relay dialed, the end-to-end one authenticates the final target. **This holds only when `[tunnel_tls]` identities are actually configured on the originating and terminal nodes.** Without them, `tls::connect_on`/`accept_on` fall back to plaintext and a relay carrying the chain sees cleartext, not ciphertext — Fetch warns at startup when `[graph]` is configured without `[tunnel_tls.upstream]` (`config::graph_without_e2e_tls_warning`) |
| Upstream node verification | `radii-fetch`, `radii-proto` (`tls::dial_expecting`) | When Fetch dials a graph-resolved upstream over mTLS, the peer's certificate CN must match the node id the route was planned to — a poisoned `listen_addrs` cannot silently redirect the tunnel to another CA-issued host |
| Role-tagged listen addresses | `radii-proto` (`ListenAddr`), `radii-core` (`RoleId`) | Each advertised address carries the role it serves, so one registry entry can describe several listeners without a consumer reading the wrong one. Only `relay` is resolved today — by Fetch for every hop it plans, and by Head for the backend it proxies to, since a chain terminates at the target's relay listener either way. Decode bounds the list (`MAX_LISTEN_ADDRS` = 16) and each string (`MAX_LISTEN_ADDR_LEN` = 256, `MAX_ROLE_LEN` = 64), closing a previously unbounded growth path into Crawl's registry |
| Proxy hop-by-hop header stripping | `radii-head` (`proxy::strip_hop_by_hop`) | Head removes `Connection`, `Keep-Alive`, `Proxy-Authenticate`, `Proxy-Authorization`, `TE`, `Trailer`, `Transfer-Encoding`, `Upgrade`, and every header *named in* the message's own `Connection` header, in both directions. The `Connection`-named set is collected before anything is removed, since dropping `Connection` first would lose the list of what else to drop — forwarding such a header to a backend is request-smuggling surface |
| Proxy timeouts | `radii-head` (`[http]`) | `attempt_timeout_ms` bounds one candidate's connection setup (chain establishment plus HTTP handshake); `response_timeout_ms` bounds waiting for response headers. Body streaming is deliberately unbounded — a slow large download is legitimate, and capping it would break the case streaming exists to serve |

### What is NOT implemented (treat as known gaps)

| Gap | Risk if exposed |
|---|---|
| Peer authentication / mutual TLS is opt-in, not mandatory | Any listener without `[tls]` configured stays plaintext and unauthenticated — anyone who can connect can inject Crawl hellos/reports |
| No message signing or anti-replay | An authenticated peer (with or without TLS) can still resend its own old, valid-but-stale reports — mTLS proves who sent a message, not when it was generated |
| A configured relay peer is still trusted to report its clients' identities honestly | Crawl checks that a `FromHead` claim matches the `client_identity` the Head asserts, but that assertion is the Head's word. A *compromised* Head (one whose private key an attacker holds) can still relay any claim it likes for a client it invents. Relay rights are therefore a trust grant: list only Heads you operate |
| No authorization on Head HTTP | The decision JSON now lives only at `GET /_radii/decision` rather than being returned on every path, so an operator can firewall exactly one route instead of all of them. That narrows the disclosure; it does not authenticate it, and the endpoint still reveals the backend map to anyone who can reach it |
| No connection timeouts *outside the relay and proxy paths* | Crawl's listener and Head's Radii bridge still have no deadline on TLS handshakes, idle sessions, or upstream dials — connections that never make progress hold a task and a socket indefinitely. Bounded now: the relay path (`handshake_timeout_ms`, `idle_timeout_ms`), Fetch's candidate dials (`attempt_timeout_ms`), and Head's proxy path (`attempt_timeout_ms`, `response_timeout_ms`) |
| A relay certificate is a bandwidth grant | With admission by CA membership, issuing a certificate entitles the holder to forwarding capacity, not only to writing graph reports. Narrow with `allow_peers` where that is not intended, and see [`docs/tls.md`](docs/tls.md) on what revocation is protecting |
| Relays observe traffic patterns | Payloads are opaque to a relay, but it sees volume, timing, and its immediate neighbours. There is no padding and no cover traffic — **this is not anonymity** and must not be described as such |
| A relay can deny service to a chain it carries | It can stall or drop. It cannot read or impersonate the endpoint. Ranked-candidate retry is the mitigation, not prevention |
| Retry stops at the end-to-end handshake | Once application bytes flow, TCP offers no way to migrate a stream, so a mid-stream failure reaches the client as a closed connection rather than being retried onto another candidate |
| An address role is a claim, not a credential | A node advertising `role = "relay"` may run nothing there: the chain fails at dial, the candidate is discarded, and retry moves on — bounded by `attempt_timeout_ms`. Since both Fetch and Head now dial the role they resolve, a false claim is discovered at handshake rather than by a downstream consumer, and `dial_expecting` additionally checks the peer's certificate CN against the node id the route was planned to. A role tag still makes a claim more *specific* without making it more *trustworthy* — it is verified by connecting, not by being advertised |
| `X-Forwarded-For` is recorded, not trusted | Head appends the immediate peer to any inbound value, but any client can send one. Head makes no access-control decision on it, and nothing downstream should treat it as authenticated — it is provenance for a log, not a credential |
| Head is now a data path | A wrong decision used to print a wrong address; it now delivers user traffic to the wrong backend. The end-to-end TLS session inside a chain authenticates the target node, so a relay carrying it can neither read nor impersonate the endpoint — but the consequence of a routing mistake has changed in kind |
| Head retries only before the request is sent | A candidate is retried only when its chain failed to establish, so the request was never delivered. Once written, a failure reaches the client as 502 — Head cannot know whether the backend processed it, and replaying could duplicate a POST |
| No rate limiting / connection quotas | Easy DoS against Crawl/Head/Fetch, TLS-authenticated or not |
| Graph state is bounded, but the bounds are the only defence | Crawl's reachability table is keyed (a repeat report replaces rather than appends), capped globally (`MAX_REACHABILITY_ENTRIES` = 16384) and per peer (`MAX_REACHABILITY_ENTRIES_PER_PEER` = 1024), and aged out by `node_ttl_ms`; planning is capped by `MAX_GRAPH_NODES` / `MAX_GRAPH_LINKS` / `MAX_ROUTE_HOPS` / `MAX_ROUTE_RESULTS`. So a reporting peer can no longer drive memory or CPU without limit. It can still fill its own per-peer share with invented targets, and a graph truncated at a cap means every planner works from a partial view — `GraphSnapshot::dropped_links()` is non-zero when that happens and Head logs it |
| Fetch is an open TCP tunnel to configured upstream | Misbind + exposure ≈ proxy to internal services |
| No sandboxing of protocol workers | A memory-safety bug would be process-wide (Rust reduces but does not eliminate risk) |
| Logs may include client IPs and hosts | Privacy / compliance exposure |

**Operational rule:** bind Crawl, Head Radii, and Fetch to localhost or a private management network unless you have placed authenticated reverse proxies / firewalls in front, **or** enabled mTLS (see [`docs/tls.md`](docs/tls.md)) on every listener that must be reachable beyond a single trusted host.

---

## Secure deployment checklist

### Network exposure

- [ ] Prefer `127.0.0.1` or a private interface for Crawl and Radii bridges during development
- [ ] Do not publish Fetch on the public Internet with an upstream that can reach internal RFC1918 services
- [ ] Put Head HTTP behind TLS termination and access control if it must be public
- [ ] Use host firewalls / security groups to restrict source IPs for management ports
- [ ] Disable or avoid running unused listeners
- [ ] Leave `[relay]` unset on any node that should not carry other peers' traffic — it is opt-in, and an unset section opens no listener
- [ ] Treat the relay listener as separately firewall-able from the tunnel listener; its whole purpose is exposure to peers you do not run

### Source routing and `listen_addrs`

Graph-resolved traffic is delivered over the relay protocol. **Even a one-hop
route terminates at the target's relay listener**, which then splices to that
node's own configured `upstream` — there is no raw-dial shortcut for short
routes. `listen_addrs` entries are role-tagged so one registry entry can
describe several listeners, but **only the `relay` role is resolved**: Fetch
resolves it for every hop it plans, and Head resolves it for the backend it
proxies to, because a Head-originated chain terminates at that same relay
listener. The `http` role is reserved and unresolved — see the residual-risk
note on role claims below.

Two consequences, and both are operator-visible:

- [ ] Advertise every listener that must be reachable with
      `--listen-addr relay=HOST:PORT` — on every node a path may cross, not
      only on the ones that terminate a chain. A node advertising no `relay`
      address is never selected as a route target *or* as an intermediate
      hop, by Fetch or by Head, and any path crossing it is dropped: wrong
      configuration means *not chosen* rather than *chosen and corrupting*.
      It fails silently, though: an unresolvable route is indistinguishable
      from a node that is down, and Head falls through to its static
      `routing.host_map` / `routing.default_backend`.
- [ ] **A node that terminates chains must configure `[tunnel_tls.listener]`.**
      The end-to-end session is the only thing authenticating an originator
      once chains exceed one hop — at length one the originator is the peer the
      outer session already authenticated, but beyond that it is not the
      previous hop. Without a listener identity the node cannot complete the
      inner handshake at all, and the operator sees an opaque TLS error rather
      than a configuration problem. Fetch emits a startup warning for *this*
      condition (`config::relay_without_tunnel_listener_tls_warning`) — see
      above for the one that has none.
- [ ] **A node that originates chains (has `[graph]`) should configure
      `[tunnel_tls.upstream]`.** Without it the end-to-end layer falls back to
      plaintext, readable by every relay the chain passes through. Fetch
      warns at startup for this condition
      (`config::graph_without_e2e_tls_warning`).

### Peer authentication (mTLS)

- [ ] Enable `[tls]` on Crawl and Head, and `[tunnel_tls]` on Fetch, for any listener reachable beyond a single trusted host — see [`docs/tls.md`](docs/tls.md)
- [ ] Provision certificates from a private CA you control; keep the CA private key offline or in a secrets manager
- [ ] Remember mTLS authenticates the immediate peer on a connection, not the original client behind Head's bridge — see the FromHead limitation above

### Configuration hygiene

- [ ] Treat config files as sensitive (upstreams reveal internal topology)
- [ ] Do not commit real certs, host keys, or production TOML into git — `scripts/gen-dev-certs.sh` output is for local use only
- [ ] Set `RADII_LOG_DIR` to a directory with restricted permissions
- [ ] Rotate any credentials used in front of Radii independently of this project

### Runtime hardening

- [ ] Run services as an unprivileged user
- [ ] Use separate OS users or containers per compartment where practical
- [ ] Apply seccomp/AppArmor/SELinux profiles appropriate to your distro
- [ ] Keep the Rust toolchain and dependencies current (`cargo update` + CI audit)
- [ ] Monitor for unexpected connection volume and upstream errors

### Cryptography (target state)

Radii intends to require, before production claims:

1. **Authenticated peer identity** (e.g. ed25519 / mutual TLS) — implemented, opt-in via `[tls]`. See [`docs/tls.md`](docs/tls.md).
2. **Encrypted transports** for Radii control messages and Fetch data paths — implemented, opt-in via `[tls]` / `[tunnel_tls]`. See [`docs/tls.md`](docs/tls.md).
3. **Explicit route authorization** (which peers may advertise which links) — partially implemented: Crawl checks a direct peer's `NodeHello`/`ReachabilityReport` against its authenticated identity, but does not independently re-verify identities relayed through Head's `FromHead` bridge.
4. **Replay protection and bounded clock skew** for probes/reports — not implemented. mTLS proves who sent a message, not when it was generated; an authenticated peer can still resend its own stale reports.
5. **Documented key lifecycle** (provisioning, rotation, revocation) — implemented. See [`docs/tls.md`](docs/tls.md).

Item 4 has not landed, and item 3 is incomplete, and TLS itself is opt-in rather than mandatory-by-default — so even with `[tls]` configured everywhere, **do not describe Radii as censorship-resistant or confidential in a cryptographic sense**: resilience goals are architectural, not yet fully proven by the wire protocol.

---

## Protocol & DoS considerations

### Framing

- Length-prefixed frames are capped at `MAX_FRAME_LEN` (1 MiB).
- Callers must still apply timeouts; a client can stall after advertising a legal length.
- Future work: per-connection read timeouts, max concurrent connections, and max reports retained in Crawl memory.

### Crawl memory growth

Crawl currently stores reachability reports **in memory without eviction**. A hostile client that passes framing checks can still grow memory via many reports. Operators must restrict who can speak Radii until snapshot TTL/quotas exist.

### Fetch proxy risk

Fetch copies bytes between accepted clients and a configured upstream. If the listener is reachable by an attacker, they may interact with that upstream as if they were Radii. Never point an exposed Fetch at privileged internal admin interfaces.

### Head information disclosure

Proxy mode has shipped: Head’s non-health responses are now the backend’s own, not a decision document. The decision JSON survives at one route, `GET /_radii/decision`, which still reports the selected backend and every ranked candidate address for the requested host — internal hostnames and topology, to anyone who can reach it. It is unauthenticated. Firewall that route, or keep Head off the public internet, until authentication ships.

---

## Dependency & supply-chain security

- CI runs **`cargo audit`** for known RustSec advisories.
- CI runs **`cargo deny`** for license / advisory / ban policies (`deny.toml`).
- Prefer pinned lockfile commits (`Cargo.lock` is tracked).
- Review dependency diffs in pull requests that touch `Cargo.toml` / `Cargo.lock`.
- Do not add `build.rs` network fetches or unchecked `include_bytes!` of untrusted input.

---

## Security-related testing

Security-sensitive automated coverage includes:

- Frame overflow rejection (`radii-proto` + integration framing tests)
- Crawl protocol ingest / ack behavior
- Head host-map decisions (no unintended backend selection)
- Fetch tunnel correctness (so future auth wrappers do not regress data path)
- Head → Crawl Radii bridge wrapping (`FromHead`)
- mTLS handshake success/failure (trusted peer accepted, untrusted-CA peer rejected, plaintext-only fallback) and peer-identity authorization (`radii-proto::tls`, `crawl_tls`, `fetch_tls` integration tests)

CI must remain green on these tests for merges to `main`.

---

## Incident response (operators)

If you suspect abuse or compromise:

1. **Contain:** firewall or stop public binds for Crawl / Head Radii / Fetch
2. **Preserve:** rotate log directory copies; capture `ss`/`netstat` and process lists
3. **Rotate:** any credentials used at reverse proxies or upstreams
4. **Rebuild:** from a known-good commit; verify `Cargo.lock` integrity
5. **Report:** if the root cause is a Radii defect, follow the vulnerability reporting process above

---

## Coordinated disclosure & credits

We appreciate responsible research. With consent, we will credit reporters in release notes or advisories. We may delay credit until a fix is available for high-severity issues.

---

## Policy changes

This policy will evolve as authentication, encryption, and authorization land. When a security control moves from “gap” to “implemented,” this file and the root README status line should be updated in the same change set.

Questions about this policy (non-vulnerability) can be filed as ordinary GitHub issues labeled `security-policy`.
