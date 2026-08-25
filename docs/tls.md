# Mutual TLS for Radii

Radii nodes speak a private wire protocol (`RadiiMessage`, framed by `radii-proto`) to each other — Crawl's listener, Head's Radii bridge, and the graph queries Head/Fetch make against Crawl. Optionally, Fetch's tunnel *data path* (the bytes it relays between an inbound client and the configured upstream) can be TLS-wrapped too. This document covers how that TLS support works, how to provision certificates for it, and its current limitations.

## Model

Radii nodes form a private mesh, not a public web service, so peer authentication uses **a private CA**, not the public Web PKI:

- Every node presents one leaf certificate as its identity.
- Every node trusts one CA bundle to verify whoever it connects to.
- Every TLS connection is **mutual**: both sides present and verify a certificate. There is no server-only TLS mode.

TLS is **opt-in per compartment, per connection role**, controlled by a `[tls]` (or, for Fetch's tunnel, `[tunnel_tls]`) section in that compartment's config file:

| Compartment | Config section | Protects |
|---|---|---|
| Crawl | `[tls]` | The Crawl listener (accepts Head's bridge, `radii-cli`, and any other Radii-speaking peer) |
| Head | `[tls]` | The Radii bridge listener *and* every outbound connection Head makes to Crawl (the bridge relay, the graph poller) |
| Fetch | `[tls]` | The graph poller's connection to Crawl only |
| Fetch | `[tunnel_tls.listener]` | The Fetch bind socket — requires inbound tunnel clients to authenticate |
| Fetch | `[tunnel_tls.upstream]` | Fetch's outbound connection to the tunnel's upstream |
| `radii-cli` | `--tls-cert` / `--tls-key` / `--tls-ca` | `hello` / `report` connections to a TLS-enabled Crawl or Head bridge |

When a section is absent, that connection stays plaintext — today's default, unchanged. See each crate's example TOML (`crates/*/*.example.toml`) for commented-out `[tls]` blocks.

## Provisioning certificates

### Quick start (development / testing)

```bash
scripts/gen-dev-certs.sh ./certs crawl head fetch
```

This generates a throwaway CA (`./certs/ca.cert.pem` + `ca.key.pem`) and one Ed25519 leaf certificate per node id you pass, each signed by that CA with `DNS:localhost`, `DNS:<node-id>`, and `IP:127.0.0.1` as Subject Alternative Names (SANs). Point each compartment's `[tls]` section at the resulting files:

```toml
[tls]
cert = "./certs/crawl.cert.pem"
key = "./certs/crawl.key.pem"
ca = "./certs/ca.cert.pem"
```

**This script is for local development and CI, not production.** It writes the CA private key to disk unencrypted next to everything else. Treat every file it produces as disposable.

### Production provisioning

For a real deployment, run an equivalent process on infrastructure you control:

1. Generate a CA key and self-signed CA certificate. Keep the CA private key offline (or in an HSM/secrets manager) — anyone who has it can mint a certificate for any node id and be trusted by your whole mesh.
2. For each node, generate a key pair and a certificate signing request (CSR) with `CN=<node-id>` and a SAN covering however that node will be dialed (its IP and/or hostname — must match what peers put in their config's address fields, since rustls verifies the SAN against the address used to connect).
3. Sign each CSR with the CA to produce that node's leaf certificate.
4. Distribute each node's own `cert` + `key` to it over a secure, authenticated channel (e.g. your existing secrets management, not email/Slack/shared drives). Distribute the CA certificate (never the CA key) to every node.
5. Set restrictive filesystem permissions on every private key (`chmod 600`), and run Radii as an unprivileged user per `SECURITY.md`'s runtime hardening checklist.

Any standard CA tooling works — `openssl`, `step-ca`, `cfssl`, your organization's internal PKI, etc. `scripts/gen-dev-certs.sh` is a thin `openssl` wrapper you can adapt if you don't already have a preferred tool.

## Peer identity and authorization

The Subject CN of a peer's leaf certificate is its **authenticated node identity**. Crawl uses this identity to authorize `NodeHello` and `ReachabilityReport` messages: when TLS is enabled, a peer may only advertise a `node_id` / `from` matching its own certificate's CN. A peer authenticated as `node-a` claiming to be `node-b` gets an `unauthorized_node_id` Ack and the claim is dropped — this stops one authenticated peer from impersonating another and poisoning the graph with claims it isn't entitled to make.

**Known limitation:** this check only applies to direct connections. Messages relayed through Head's bridge (`RadiiMessage::FromHead`) are trusted at the connection level — Crawl verifies that *Head* is an authenticated peer, but does not independently re-verify the identity of whichever client originally sent the wrapped message to Head. Head is a trust boundary in the current design; do not run an untrusted Head in front of a Crawl instance you don't want poisoned.

## Rotation

There is no automated rotation yet. To rotate a node's certificate:

1. Issue a new leaf certificate for that node (same CA, same node id).
2. Replace the `cert`/`key` files at the paths its config points to.
3. Restart the process — certificates are loaded once at startup, not watched for changes.

To rotate the CA itself (e.g. on a schedule, or because you suspect the CA key is compromised — see revocation below): issue a new CA and new leaf certificates for every node, then roll out the new `ca` + `cert` + `key` to every node together. There is no cross-signing or overlap period support today, so a CA rotation is a coordinated, all-at-once change — plan for brief unavailability of the Radii mesh during the rollover, or stage it compartment-by-compartment accepting temporary connectivity loss between not-yet-rotated peers.

## Revocation

There is no CRL or OCSP support. If a node's key is compromised, the only way to revoke its trust today is to **rotate the CA** (see above) and exclude that node from the new leaf certificates you issue — every other node's `ca` bundle no longer includes a CA that would validate the compromised node's old certificate. This is heavyweight; track it as a known gap when planning a deployment where compromise response time matters.

## Related gaps (not covered by TLS alone)

Enabling TLS gives you peer authentication, transport encryption, and the route-authorization check above. It does **not** give you:

- **Replay protection.** An authenticated peer can still resend its own old, valid, but now-stale `ReachabilityReport`s — mTLS proves who sent a message, not when it was generated. See `SECURITY.md`'s cryptography target state for this gap.
- **Rate limiting.** A TLS-authenticated peer can still open unbounded connections or send unbounded reports.
- **HTTPS on Head's public HTTP surface.** `[tls]` here only covers the Radii mesh protocol; front Head's HTTP listener with your own TLS-terminating reverse proxy if it's public, per `SECURITY.md`'s deployment checklist.

Track these in `SECURITY.md` rather than assuming TLS alone makes a deployment production-ready.
