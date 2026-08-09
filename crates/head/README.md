# radii-head

Head is the public access plane. It accepts inbound HTTP, decides a backend from a host map (or default), and can bridge Radii protocol traffic to Crawl.

## Run

```bash
cargo run -p radii-head -- --config crates/head/head.example.toml
```

## Today

- HTTP listener with `GET /health`
- Catch-all handler returns JSON: source IP, host, chosen backend, decision reason
- Host-map + default decision engine
- Optional Radii TCP bridge that wraps inbound messages as `FromHead` and forwards to Crawl

## Next

- Reverse-proxy HTTP to the selected backend
- Authenticated control-plane surface
- Live config reload
- HTTPS / SSH / DNS surfaces (deferred until the HTTP path is solid)
