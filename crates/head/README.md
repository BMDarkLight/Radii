# radii-head

Head is the public access plane. It accepts inbound HTTP, decides a backend from Crawl's live reachability graph (falling back to a static host map, then a default), and can bridge Radii protocol traffic to Crawl.

## Run

```bash
cargo run -p radii-head -- --config crates/head/head.example.toml
```

## Today

- HTTP listener with `GET /health`
- Catch-all handler returns JSON: source IP, host, chosen backend, decision reason
- Decision engine, in priority order:
  1. **Graph route** (optional, `[graph]` config) — polls Crawl for its reachability graph on an interval and plans a route from Head's `source_node_id` to the node mapped to the request host in `node_map`; resolves to that node's registered listen address. Falls through if the host isn't mapped or no reachable route exists.
  2. **Host map** — static `routing.host_map` lookup.
  3. **Default** — `routing.default_backend`.
- Optional Radii TCP bridge that wraps inbound messages as `FromHead` and forwards to Crawl over a single persistent upstream session per client connection (opened lazily on the first message, reconnected transparently if Crawl drops it) rather than dialing Crawl anew for every message

## Next

- Reverse-proxy HTTP to the selected backend
- Authenticated control-plane surface
- Live config reload
- HTTPS / SSH / DNS surfaces (deferred until the HTTP path is solid)
