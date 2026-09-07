# Role-Tagged Listen Addresses

**Status:** design, approved 2026-09-07
**Supersedes:** the `listen_addrs` residual-risk row added by the source-routing work
**Related:** `docs/superpowers/specs/2026-09-05-source-routing-and-ranked-candidates-design.md`

## The problem

Crawl's node registry stores one list of addresses per node, and two consumers
read it meaning different things:

- **Fetch** treats an advertised address as a **relay listener** — one that
  requires mutual TLS and a `TunnelOpen` preamble before it will carry
  anything. This became true when source routing landed: every graph-resolved
  route, even a one-hop one, terminates at the target's relay listener.
- **Head** reads the same entry and hands it to a caller as a **plain backend**
  to dial directly.

One field, two incompatible readings. A node advertising a relay listener is
given to Head's callers as though it were an HTTP backend, and the failure
looks like a backend outage. In the other direction, a node still advertising a
plain tunnel port completes the hop-local handshake and then has `TunnelOpen`
framing bytes spliced straight into a live backend, after which every candidate
fails and traffic degrades silently to the static `upstream`.

### Root cause

The registry never held what Head needs. `listen_addrs` are *Radii listener*
addresses. Head's "backend" is an HTTP endpoint serving a host — for a Radii
node that is its `upstream`, which Crawl does not record at all. Head has been
reading Radii listener addresses and handing them out as HTTP backends. Source
routing did not create that; it made it visible.

### What already exists and is not the answer

`NodeHello` and `NodeInfo` already carry `roles: Vec<String>`, Crawl already
stores it, and **nothing reads it for any decision** — it is decorative. Giving
it teeth would disambiguate per *node*, which forecloses a node that both
relays for the mesh and serves its own content. The README's stated goal is
heterogeneous nodes including donated public ones, so that foreclosure is real.
The ambiguity is per *address*, and that is where the fix belongs.

## Design

### 1. The wire type

`NodeHello.listen_addrs` and `NodeInfo.listen_addrs` become role-tagged:

```rust
pub struct ListenAddr {
    pub addr: String,
    pub role: String,
}
```

Flat by construction, like `RouteHop` and `RelayedMessage`: a listen-address
list can never nest, so a hostile frame cannot drive the decoder into
recursion.

**Role is a free string, not an enum.** This mirrors the existing
`ProtocolId(pub String)` with its associated constants, and it matters for a
mesh whose nodes upgrade at different times: a consumer ignores a role it does
not want rather than failing the whole `NodeHello`. A strict enum would make
every future role a flag day.

Known roles get constants in `radii-core`:

```rust
pub struct RoleId(pub String);

impl RoleId {
    pub const RELAY: &'static str = "relay";
    pub const HTTP: &'static str = "http";
}
```

**Node-level `roles` is left alone.** It stays the decorative node-description
field it is today. Merging the two would conflate "what this node is" with
"what this port speaks", and those genuinely differ — a node that is a relay
still has non-relay ports.

### 2. Decode bounds

`listen_addrs` is peer-supplied and currently **unbounded**: a hostile
`NodeHello` can carry `MAX_FRAME_LEN` worth of addresses and Crawl stores every
one. This change is the right moment to close that, following the
`MAX_TUNNEL_HOPS` precedent — enforced at decode in `read_message`, so the
bound applies to anything arriving on the wire rather than to one call site:

```rust
pub const MAX_LISTEN_ADDRS: usize = 16;
pub const MAX_LISTEN_ADDR_LEN: usize = 256;
pub const MAX_ROLE_LEN: usize = 64;
```

A `NodeHello` exceeding any of these is rejected as a decode error.

### 3. Resolution takes two roles

Fetch and Head need different things from a route, which the shared
`resolve_candidates` currently obscures by giving both the same thing:

- **Fetch dials every hop**, so intermediates and target alike need a `relay`
  address. A hop lacking one makes the route undialable.
- **Head dials nothing.** It hands its caller the target's address and the
  caller dials it. Head needs the target's `http` address and never touches an
  intermediate.

So:

```rust
pub fn resolve_candidates(
    snapshot: &GraphSnapshot,
    listen_addrs: &HashMap<String, Vec<ListenAddr>>,
    source: &NodeId,
    targets: &[NodeId],
    allowed_protocols: &[ProtocolId],
    max_hops: usize,
    limit: usize,
    hop_role: Option<&RoleId>,   // None = do not resolve intermediates
    target_role: &RoleId,
) -> Vec<ResolvedRoute>
```

Fetch passes `(Some(RELAY), RELAY)`. Head passes `(None, HTTP)`.

The existing undialable-hop filter extends naturally: a hop advertising no
address *in the required role* drops the route, exactly as a hop with no
address at all does today. Within a role, selection stays `.first()`;
multi-address expansion remains a documented follow-up, unchanged by this.

`ResolvedHop` and `ResolvedRoute` do not change. The role is an input to
resolution, not part of its output — an already-resolved route is just
addresses.

**Known oddity, deliberately out of scope.** With `hop_role: None`, Head plans
a multi-hop path and then hands out a *direct* address; the caller never
traverses that path, so those intermediate edges act purely as a
reachability-and-score heuristic. This is existing behaviour and the design
does not worsen it. Changing Head to score by direct reachability is a separate
question.

### 4. A clean break

Postcard is positional, so an old node and a new one fail to decode each other.
That is the intended outcome. A tolerant decoder would have to *guess* a role
for an untagged address, and guessing wrong is exactly the failure this design
exists to eliminate — fail loudly at the handshake, not silently at the splice.

The break is free now: pre-release, CD is `workflow_dispatch`-only, and the
README states the project is not at a release stage. It will not be free later.

### 5. The operator surface

`radii-cli hello` takes one repeated flag instead of a comma list:

```
radii-cli hello --node-id node-b \
  --listen-addr relay=10.0.0.5:2224 \
  --listen-addr http=10.0.0.5:9000
```

`role=addr`, not `addr:role`: colons already mean ports, and doubly so for IPv6
literals. A value with no `=`, an empty role, or an empty address is a usage
error.

**The failure mode is the payoff.** Today an operator must hand-type the right
port into `listen_addrs` with nothing validating it, and getting it wrong
corrupts a live backend. With roles, a node that advertises no `relay` address
simply never gets selected as a Fetch route target. Wrong config becomes *not
chosen* rather than *chosen and corrupting*. That is what justifies the wire
break, more than the tidiness does.

`SECURITY.md`'s source-routing deployment section correspondingly shrinks from
a warning-with-consequences to a plain statement of what to advertise.

## Security

**Roles are claims, not credentials.** This makes a self-asserted field
load-bearing for routing. Per false claim:

- **A false `relay` claim** — the node says relay and runs nothing there. The
  chain fails at dial, the candidate is discarded, retry moves on. Cost is one
  wasted attempt, bounded by `attempt_timeout_ms`. The existing
  identity-check-plus-retry pattern covers it unchanged.
- **A false `http` claim** is the weaker side. Head does not dial, so no
  dial-time verification catches it; the caller discovers the lie. This is not
  a new exposure — Head hands out unverified addresses today — but a role tag
  makes a claim more *specific* without making it more *trustworthy*, and that
  gap must be stated in the residual-risk table rather than left looking like
  verification.

Claiming another node's address under a role is the same poisoning
`listen_addrs` already permits, mitigated the same way: the certificate CN
check at dial.

The decode bounds in §2 additionally close an existing unbounded-growth path
into Crawl's registry.

## Testing

The acceptance test for the whole design is one case: **a single node, one
`NodeHello`, advertising both a `relay` and an `http` address — Fetch resolves
the relay one, Head resolves the http one.** If that passes, the dual meaning
is genuinely resolved rather than relabelled.

Around it:

- **proto** — `ListenAddr` round-trips; decode rejects an over-cap address
  list, an over-long address, and an over-long role.
- **core** — a hop advertising only `http` is undialable for a relay route;
  `(None, HTTP)` resolves the target only; a target with no matching role drops
  the route.
- **crawl** — roles survive storage and the graph-query round trip.
- **cli** — `role=addr` parses; a malformed value is a usage error.

## Migration cost

Every fixture that builds a `NodeHello` or a `listen_addrs` map changes:
crawl's tests, `fetch_graph_routing`, `graph_routing`, the head tests,
`chain_establish`, and the relay suite. Mechanical but broad, and it is most of
the work.

## Follow-ups, not in scope

- **Fetch self-advertising its `[relay] bind`** rather than relying on
  hand-typed hellos. Roles are the missing half of this, and it becomes much
  cheaper afterwards.
- **Head scoring by direct reachability** instead of by a path its callers
  never walk (§3).
- **Multi-address expansion** within a role.
