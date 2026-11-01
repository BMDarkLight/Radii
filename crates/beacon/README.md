# radii-beacon

The LAN beacon: how nodes on one local network find each other before any of them knows where a Crawl is.

## How it works

- A node broadcasts its `NodeHello` on UDP port 7101 (`DEFAULT_PORT`), to the limited broadcast address and to any directed broadcast or host addresses it is given.
- A node that hears an announcement answers it with its own hello, sent straight back. Answers are never answered, and each host gets at most one answer a second, so nothing loops.
- Only beacons from the local network are heard or answered: loopback, private (RFC 1918) and link-local addresses. Anything else is dropped unread.
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

- Beacons are not authenticated. Anyone on the network can send one, under any node id, advertising any listener address. Treat a sighting as a hint and confirm the node over a channel that is authenticated — never update a known peer's address, or send it a credential, on the strength of a sighting alone.
- A beacon broadcasts its node id to the whole network. Don't use an id that is meant to stay private, and don't treat knowing one as proof of anything.
- An answer goes to the datagram's source address, which the sender chooses. Answers are capped at one per host per second and 64 hosts per second in all, so a forged source on the local network gets a node to send at most that.
- Nodes on one host share the port, but unicast answers reach only one of them on some systems.
