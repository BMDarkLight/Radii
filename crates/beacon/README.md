# radii-beacon

The LAN beacon: how nodes on one local network find each other before any of them knows where a Crawl is.

## How it works

- A node broadcasts its `NodeHello` on UDP port 7101 (`DEFAULT_PORT`), to the limited broadcast address and to any directed broadcast or host addresses it is given.
- A node that hears an announcement answers it with its own hello, sent straight back. Answers are never answered, and each address gets at most one answer a second, so nothing loops.
- Because of the answer, hearing in one direction is enough. A phone's hotspot or a firewall that drops broadcasts one way still lets both sides find each other.
- Broadcast, not multicast: access points and hotspots filter multicast far more often, while broadcast has to work for DHCP.
- A listener advertised as `0.0.0.0:PORT` means "the address you heard me from"; a `Sighting` fills it in.
- Every datagram is held to the same bounds as a framed `NodeHello`, and fits in 1200 bytes.

## Use

```rust
use radii_beacon::{Beacon, BeaconConfig, DEFAULT_PORT};
use radii_proto::ListenAddr;

let mut beacon = Beacon::bind(BeaconConfig {
    node_id: "node-a".into(),
    roles: vec!["wave".into()],
    listen_addrs: vec![ListenAddr { addr: "0.0.0.0:50800".into(), role: "wave".into() }],
    port: DEFAULT_PORT,
})?;
beacon.announce(&[])?;
while let Some(seen) = beacon.recv(std::time::Duration::from_millis(250))? {
    println!("{} at {:?}", seen.node_id, seen.listener("wave"));
}
```

The socket is blocking and runs on whatever thread calls it; it needs no async runtime.

## Limits

- Beacons are not authenticated. Treat a sighting as a hint and confirm the node over a channel that is.
- Nodes on one host share the port, but unicast answers reach only one of them on some systems.
