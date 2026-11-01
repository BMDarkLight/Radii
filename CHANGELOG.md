# Changelog

All notable changes to Radii are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/) — which, before 1.0, means a minor
version may break the API or the wire protocol.

## [0.1.0] — 2026-11-01

The first tagged pre-release: a reference build for applications that embed
Radii, Wave first among them. Radii is an early foundation and is **not
production-ready**; read [`SECURITY.md`](SECURITY.md) before exposing any
listener.

### Crates

| Crate | What it is |
|---|---|
| `radii-proto` | The framed wire protocol, its bounds, and opt-in mutual TLS |
| `radii-core` | Routing: the graph snapshot, ranked route planning, role-aware address resolution |
| `radii-beacon` | LAN discovery by UDP broadcast, with no Crawl to ask |
| `radii-crawl` | Crawl: the node registry and reachability graph |
| `radii-head` | Head: the HTTP front door, backend decisions and the Radii bridge |
| `radii-fetch` | Fetch: tunnels, and relays for source-routed chains |
| `radii-cli` | The `radii` command-line tool |

None are published to crates.io. Depend on them by git tag:

```toml
radii-proto = { git = "https://github.com/BMDarkLight/Radii", tag = "v0.1.0" }
radii-beacon = { git = "https://github.com/BMDarkLight/Radii", tag = "v0.1.0" }
```

### Added

- **Wire protocol** — length-framed postcard messages capped at 1 MiB, with
  every peer-supplied string and list bounded, and message shapes that cannot
  nest, so a hostile frame cannot drive the decoder into recursion.
- **Mutual TLS**, opt-in per listener, from a private CA: both directions
  verified, peer identity taken from the certificate CN, and an optional CRL
  checked in both directions.
- **Crawl** — node registry with roles and a configurable liveness TTL, and a
  reachability graph capped globally, per peer, and by size, so a graph reply
  is always sendable.
- **Head** — host-to-backend decisions from a static map or from the graph,
  ranked candidates with failover, request forwarding, a Radii bridge that
  relays hellos and reports to Crawl under the client's authenticated
  identity, and a `/health` that reports graph staleness.
- **Fetch** — plain tunnels, and source-routed relay chains pinned by the
  initiator, with end-to-end TLS to the target, per-peer and global admission
  caps, and handshake and idle deadlines.
- **Beacon** — nodes on one local network find each other by broadcast; an
  announcement is answered directly, so hearing in one direction is enough.
- **CLI** — `radii hello`, `report`, `graph`, `plan`, `health` and
  `decision`, with plain, pretty and JSON output.

### Security

- The beacon answers only senders on loopback, private and link-local
  networks, rate-limits answers per host rather than per host and port, and
  caps answers overall without resetting the cap when it fills. Before this,
  a forged source address could make any node send its hello at an arbitrary
  host, and rotating the source port bypassed the per-sender limit.
- The CLI escapes control characters in peer-supplied names before printing
  them, so a node id cannot carry terminal escape sequences.
- Dependencies updated for RUSTSEC-2026-0346, -0347, -0348 and -0349
  (`rustls`), -0382 (`rustls-webpki`), -0381 (`webpki-roots`) and -0386
  (`tokio`).

### Known gaps

TLS is opt-in rather than mandatory; Crawl, the Head bridge and Fetch's front
listener have no connection timeouts or quotas; Crawl's node registry is
unbounded on a plaintext listener; there is no replay protection; and beacon
sightings are unauthenticated by design. [`SECURITY.md`](SECURITY.md) lists
each with its risk.

[0.1.0]: https://github.com/BMDarkLight/Radii/releases/tag/v0.1.0
