# Security Policy

Radii is a **network runtime**. Compromises in protocol handling, peer trust, or deployment hygiene can become remote code execution, traffic hijacking, or widespread denial of service. This document defines how we think about security, what is and is not safe today, how to report issues, and how operators should deploy Radii.

> **Status honesty:** Radii is an early foundation. Peer authentication and transport encryption now exist as opt-in mutual TLS (see [`docs/tls.md`](docs/tls.md)), but several critical controls are still **not implemented**: TLS is not mandatory by default, replay protection, full authorization (Head-relayed messages), and rate limiting are all still gaps. Do **not** expose Crawl, Head Radii bridges, or Fetch tunnels to untrusted networks without either enabling `[tls]` everywhere it's reachable or additional controls in front of them.

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
| Route authorization by peer identity | `radii-crawl` | When TLS is enabled, a peer may only submit `NodeHello` / `ReachabilityReport` under its own authenticated node id — direct connections only, see limitation below |

### What is NOT implemented (treat as known gaps)

| Gap | Risk if exposed |
|---|---|
| Peer authentication / mutual TLS is opt-in, not mandatory | Any listener without `[tls]` configured stays plaintext and unauthenticated — anyone who can connect can inject Crawl hellos/reports |
| No message signing or anti-replay | An authenticated peer (with or without TLS) can still resend its own old, valid-but-stale reports — mTLS proves who sent a message, not when it was generated |
| Route authorization doesn't cover Head-relayed messages | Crawl authorizes the direct peer on a connection, not the original client behind Head's `FromHead` bridge — a compromised Head can inject reports under any node id |
| No authorization on Head HTTP | Information disclosure of backend maps via decision JSON |
| No rate limiting / connection quotas | Easy DoS against Crawl/Head/Fetch, TLS-authenticated or not |
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

Head’s non-health HTTP responses currently return JSON describing the selected backend. That can leak internal hostnames and topology. Disable public exposure or front with auth until proxy mode + auth ship.

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
