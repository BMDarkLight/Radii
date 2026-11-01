// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 BMDarkLight
//
// This file is part of Radii.
//
// Radii is free software: you can redistribute it and/or modify it under
// the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. See the LICENSE file for the full text and
// additional terms.

//! The LAN beacon: how nodes on one local network find each other before
//! any of them knows where a Crawl is.
//!
//! A node broadcasts its `NodeHello` now and then, and answers a hello it
//! hears with its own, sent straight back to where it came from. So a
//! network that carries broadcasts only one way, like a phone's hotspot or
//! a host whose firewall drops them, still lets both sides find each other.
//!
//! Broadcast rather than multicast: access points and hotspots filter
//! multicast far more often, while broadcast has to work for DHCP.
//!
//! A listener advertised on an unspecified host (`0.0.0.0:PORT`) means "the
//! address you heard me from". [`Sighting`] fills it in, since a node on
//! several networks can't know which of its addresses another node reaches.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::time::{Duration, Instant};

use radii_proto::{ListenAddr, RadiiMessage};
use socket2::{Domain, Protocol, Socket, Type};

/// The port beacons are sent to and heard on unless a node picks another.
pub const DEFAULT_PORT: u16 = 7101;

/// The largest beacon sent or read: under a typical path MTU, so a hello is
/// never fragmented.
pub const MAX_DATAGRAM: usize = 1200;

const MAGIC: &[u8; 4] = b"RDB1";

/// One answer per host in this window, so two nodes can't keep answering
/// each other.
const ANSWER_GAP: Duration = Duration::from_secs(1);

/// The most hosts answered in one window, which is also the most answers
/// sent in one. A whole LAN fits well inside it; a stream of announcements
/// with forged sources does not get past it.
const ANSWERED_CAP: usize = 64;

/// Whether a beacon was sent unasked or in answer to one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Sent unasked. Whoever hears it answers.
    Announce,
    /// Sent back to an announcement. Never answered, so nothing loops.
    Answer,
}

/// Whether a beacon from `ip` is one this node listens to: loopback, a
/// private network, or link-local. A beacon finds nodes on the local
/// network, and a datagram from anywhere else is either misrouted or forged.
///
/// Forged is the case that matters. A UDP source address is whatever the
/// sender wrote, and an announcement is answered at it — so a node that
/// answered anyone would send its hello at any host on the internet that a
/// stranger named, several times larger than what asked for it.
pub fn on_local_network(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_private() || v4.is_link_local(),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => on_local_network(IpAddr::V4(v4)),
            None => false,
        },
    }
}

/// Who has been answered lately, which holds answers to one per host per
/// [`ANSWER_GAP`] and to [`ANSWERED_CAP`] in all.
///
/// Keyed by host, not host and port: the port is as freely forged as the
/// address, and a key that includes it gives a new allowance per port.
/// When the table is full of hosts still inside their window, nobody new is
/// answered until one ages out. Making room by forgetting them instead would
/// hand every one of them a fresh answer, which is the flood the cap exists
/// to stop.
#[derive(Debug, Default)]
struct Answered {
    at: HashMap<IpAddr, Instant>,
}

impl Answered {
    /// Whether `ip` may be answered at `now`, recording it if so.
    fn allow(&mut self, ip: IpAddr, now: Instant) -> bool {
        self.at
            .retain(|_, at| now.saturating_duration_since(*at) < ANSWER_GAP);
        if self.at.contains_key(&ip) || self.at.len() >= ANSWERED_CAP {
            return false;
        }
        self.at.insert(ip, now);
        true
    }
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

/// One beacon datagram carrying `hello`, which must be a `NodeHello` within
/// the protocol's bounds.
pub fn encode(kind: Kind, hello: &RadiiMessage) -> io::Result<Vec<u8>> {
    if !matches!(hello, RadiiMessage::NodeHello { .. }) {
        return Err(invalid("a beacon carries only a NodeHello"));
    }
    radii_proto::validate_message(hello).map_err(|e| invalid(e.to_string()))?;
    let mut out = MAGIC.to_vec();
    out.push(match kind {
        Kind::Announce => 0,
        Kind::Answer => 1,
    });
    out.extend(postcard::to_allocvec(hello).map_err(|e| invalid(e.to_string()))?);
    if out.len() > MAX_DATAGRAM {
        return Err(invalid(format!(
            "beacon of {} bytes exceeds {MAX_DATAGRAM}",
            out.len()
        )));
    }
    Ok(out)
}

/// Reads a beacon datagram, holding its hello to the same bounds as one
/// that arrives framed over a stream.
pub fn decode(bytes: &[u8]) -> io::Result<(Kind, RadiiMessage)> {
    let rest = bytes
        .strip_prefix(MAGIC.as_slice())
        .ok_or_else(|| invalid("not a Radii beacon"))?;
    let (&kind, body) = rest
        .split_first()
        .ok_or_else(|| invalid("beacon has no body"))?;
    let kind = match kind {
        0 => Kind::Announce,
        1 => Kind::Answer,
        other => return Err(invalid(format!("unknown beacon kind {other}"))),
    };
    let hello: RadiiMessage = postcard::from_bytes(body).map_err(|e| invalid(e.to_string()))?;
    if !matches!(hello, RadiiMessage::NodeHello { .. }) {
        return Err(invalid("a beacon carries only a NodeHello"));
    }
    radii_proto::validate_message(&hello).map_err(|e| invalid(e.to_string()))?;
    Ok((kind, hello))
}

/// A node heard on the network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sighting {
    pub node_id: String,
    pub roles: Vec<String>,
    /// Its listeners, with an unspecified host replaced by the address the
    /// beacon came from.
    pub listen_addrs: Vec<ListenAddr>,
    /// Where the beacon came from.
    pub from: SocketAddr,
    pub kind: Kind,
}

impl Sighting {
    /// Whether the node said it plays `role`.
    pub fn has_role(&self, role: &str) -> bool {
        self.roles.iter().any(|r| r == role)
    }

    /// The first listener for `role` that is a socket address.
    pub fn listener(&self, role: &str) -> Option<SocketAddr> {
        self.listen_addrs
            .iter()
            .filter(|l| l.role == role)
            .find_map(|l| l.addr.parse().ok())
    }
}

/// `addr` with an unspecified host replaced by `from`'s. Anything that is
/// not a socket address is left as it is.
fn resolve(addr: &str, from: IpAddr) -> String {
    match addr.parse::<SocketAddr>() {
        Ok(at) if at.ip().is_unspecified() => SocketAddr::new(from, at.port()).to_string(),
        _ => addr.to_string(),
    }
}

/// Who a beacon says this node is.
#[derive(Debug, Clone)]
pub struct BeaconConfig {
    pub node_id: String,
    pub roles: Vec<String>,
    pub listen_addrs: Vec<ListenAddr>,
    /// The port beacons are heard on and sent to. 0 takes any free port,
    /// which only suits tests, since no other node knows to send there.
    pub port: u16,
}

/// A bound beacon socket. Sends this node's hello and hears others'.
pub struct Beacon {
    socket: UdpSocket,
    node_id: String,
    port: u16,
    announce: Vec<u8>,
    answer: Vec<u8>,
    answered: Answered,
}

impl Beacon {
    /// Binds the beacon port on every interface. The port is shared, so
    /// several nodes on one host can each hear broadcasts.
    pub fn bind(config: BeaconConfig) -> io::Result<Self> {
        let hello = RadiiMessage::NodeHello {
            node_id: config.node_id.clone(),
            roles: config.roles,
            listen_addrs: config.listen_addrs,
        };
        let announce = encode(Kind::Announce, &hello)?;
        let answer = encode(Kind::Answer, &hello)?;

        let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
        socket.set_reuse_address(true)?;
        #[cfg(all(unix, not(target_os = "solaris"), not(target_os = "illumos")))]
        socket.set_reuse_port(true)?;
        socket.set_broadcast(true)?;
        socket.bind(&SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, config.port).into())?;
        let socket: UdpSocket = socket.into();
        let port = socket.local_addr()?.port();
        Ok(Self {
            socket,
            node_id: config.node_id,
            port,
            announce,
            answer,
            answered: Answered::default(),
        })
    }

    /// The port the beacon is bound to.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Announces on the limited broadcast address and at each of `to` on
    /// the beacon port. A directed broadcast address per interface reaches
    /// networks the default route doesn't; a host's own address reaches a
    /// node that broadcasts don't. Fails only if nothing could be sent.
    pub fn announce(&self, to: &[Ipv4Addr]) -> io::Result<()> {
        let mut failed = None;
        let mut sent = false;
        for ip in std::iter::once(Ipv4Addr::BROADCAST).chain(to.iter().copied()) {
            match self
                .socket
                .send_to(&self.announce, SocketAddrV4::new(ip, self.port))
            {
                Ok(_) => sent = true,
                Err(e) => failed = Some(e),
            }
        }
        match failed {
            Some(e) if !sent => Err(e),
            _ => Ok(()),
        }
    }

    /// Announces to one exact address, port included.
    pub fn announce_at(&self, to: SocketAddr) -> io::Result<()> {
        self.socket.send_to(&self.announce, to).map(|_| ())
    }

    /// Waits up to `timeout` for a beacon from another node and returns who
    /// sent it, answering it if it was an announcement. `None` when nothing
    /// came, or what came was this node's own beacon, not a beacon, or from
    /// off the local network (see [`on_local_network`]).
    pub fn recv(&mut self, timeout: Duration) -> io::Result<Option<Sighting>> {
        self.socket
            .set_read_timeout(Some(timeout.max(Duration::from_millis(1))))?;
        let mut buf = [0u8; MAX_DATAGRAM];
        let (n, from) = match self.socket.recv_from(&mut buf) {
            Ok(got) => got,
            // A timeout, or on Windows the echo of an earlier send that
            // found no listener.
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::Interrupted
                        | io::ErrorKind::ConnectionReset
                ) =>
            {
                return Ok(None)
            }
            Err(e) => return Err(e),
        };
        if !on_local_network(from.ip()) {
            return Ok(None);
        }
        let Ok((kind, hello)) = decode(&buf[..n]) else {
            return Ok(None);
        };
        let RadiiMessage::NodeHello {
            node_id,
            roles,
            listen_addrs,
        } = hello
        else {
            return Ok(None);
        };
        if node_id == self.node_id {
            return Ok(None);
        }
        if kind == Kind::Announce {
            self.answer_to(from);
        }
        Ok(Some(Sighting {
            node_id,
            roles,
            listen_addrs: listen_addrs
                .into_iter()
                .map(|l| ListenAddr {
                    addr: resolve(&l.addr, from.ip()),
                    role: l.role,
                })
                .collect(),
            from,
            kind,
        }))
    }

    fn answer_to(&mut self, to: SocketAddr) {
        if self.answered.allow(to.ip(), Instant::now()) {
            let _ = self.socket.send_to(&self.answer, to);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const WAIT: Duration = Duration::from_secs(2);
    const BRIEF: Duration = Duration::from_millis(200);

    fn hello(node_id: &str) -> RadiiMessage {
        RadiiMessage::NodeHello {
            node_id: node_id.into(),
            roles: vec!["wave".into()],
            listen_addrs: vec![ListenAddr {
                addr: "0.0.0.0:50800".into(),
                role: "wave".into(),
            }],
        }
    }

    fn beacon(node_id: &str) -> Beacon {
        let RadiiMessage::NodeHello {
            roles,
            listen_addrs,
            ..
        } = hello(node_id)
        else {
            unreachable!()
        };
        Beacon::bind(BeaconConfig {
            node_id: node_id.into(),
            roles,
            listen_addrs,
            port: 0,
        })
        .unwrap()
    }

    fn at(beacon: &Beacon) -> SocketAddr {
        SocketAddr::from((Ipv4Addr::LOCALHOST, beacon.port()))
    }

    #[test]
    fn a_hello_survives_the_round_trip() {
        for kind in [Kind::Announce, Kind::Answer] {
            let bytes = encode(kind, &hello("node-a")).unwrap();
            assert_eq!(decode(&bytes).unwrap(), (kind, hello("node-a")));
        }
    }

    #[test]
    fn only_a_bounded_node_hello_is_carried() {
        assert!(encode(Kind::Announce, &RadiiMessage::GraphQuery).is_err());

        let mut bytes = MAGIC.to_vec();
        bytes.push(0);
        bytes.extend(postcard::to_allocvec(&RadiiMessage::GraphQuery).unwrap());
        assert!(decode(&bytes).is_err());

        // Built by hand, past encode's check, to see decode hold the bound.
        let mut bytes = MAGIC.to_vec();
        bytes.push(0);
        let oversized = RadiiMessage::NodeHello {
            node_id: "node-a".into(),
            roles: vec!["r".repeat(radii_proto::MAX_ROLE_LEN + 1)],
            listen_addrs: Vec::new(),
        };
        bytes.extend(postcard::to_allocvec(&oversized).unwrap());
        assert!(decode(&bytes).is_err());
    }

    #[test]
    fn foreign_and_damaged_datagrams_are_refused() {
        let good = encode(Kind::Announce, &hello("node-a")).unwrap();
        assert!(decode(b"M-SEARCH * HTTP/1.1\r\n").is_err());
        assert!(decode(MAGIC).is_err());
        let mut unknown = good.clone();
        unknown[MAGIC.len()] = 7;
        assert!(decode(&unknown).is_err());
        assert!(decode(&good[..good.len() - 3]).is_err());
    }

    #[test]
    fn a_hello_too_big_for_one_datagram_is_refused() {
        let hello = RadiiMessage::NodeHello {
            node_id: "node-a".into(),
            roles: (0..radii_proto::MAX_NODE_ROLES)
                .map(|i| format!("{i:0>width$}", width = radii_proto::MAX_ROLE_LEN))
                .collect(),
            listen_addrs: (0..radii_proto::MAX_LISTEN_ADDRS)
                .map(|i| ListenAddr {
                    addr: format!("node-{i}.example:7000"),
                    role: "relay".into(),
                })
                .collect(),
        };
        assert!(encode(Kind::Announce, &hello).is_err());
    }

    #[test]
    fn an_announcement_is_heard_and_answered() {
        let a = beacon("node-a");
        let mut b = beacon("node-b");
        a.announce_at(at(&b)).unwrap();

        let heard = b.recv(WAIT).unwrap().expect("b hears a");
        assert_eq!(heard.node_id, "node-a");
        assert_eq!(heard.kind, Kind::Announce);
        assert!(heard.has_role("wave"));
        assert_eq!(
            heard.listener("wave"),
            Some(SocketAddr::from((Ipv4Addr::LOCALHOST, 50800)))
        );

        let mut a = a;
        let answer = a.recv(WAIT).unwrap().expect("a hears b answer");
        assert_eq!(answer.node_id, "node-b");
        assert_eq!(answer.kind, Kind::Answer);
        assert_eq!(answer.from, at(&b));

        // An answer is never answered.
        assert!(b.recv(BRIEF).unwrap().is_none());
    }

    #[test]
    fn a_node_answers_each_address_once_in_a_while() {
        let mut a = beacon("node-a");
        let mut b = beacon("node-b");
        a.announce_at(at(&b)).unwrap();
        a.announce_at(at(&b)).unwrap();
        assert!(b.recv(WAIT).unwrap().is_some());
        assert!(b.recv(WAIT).unwrap().is_some());

        assert!(a.recv(WAIT).unwrap().is_some());
        assert!(a.recv(BRIEF).unwrap().is_none());
    }

    #[test]
    fn a_new_source_port_is_not_a_new_allowance() {
        let mut b = beacon("node-b");
        let mut first = beacon("node-a");
        let mut second = beacon("node-c");
        first.announce_at(at(&b)).unwrap();
        second.announce_at(at(&b)).unwrap();
        assert!(b.recv(WAIT).unwrap().is_some());
        assert!(b.recv(WAIT).unwrap().is_some());

        // Both came from 127.0.0.1, so only the first is answered.
        assert!(first.recv(WAIT).unwrap().is_some());
        assert!(second.recv(BRIEF).unwrap().is_none());
    }

    #[test]
    fn a_full_table_refuses_rather_than_forgets() {
        let mut answered = Answered::default();
        let start = Instant::now();
        let host = |i: usize| IpAddr::V4(Ipv4Addr::new(10, 0, (i / 256) as u8, (i % 256) as u8));
        for i in 0..ANSWERED_CAP {
            assert!(answered.allow(host(i), start));
        }
        assert!(!answered.allow(host(ANSWERED_CAP), start));
        // Nobody already answered gets another one for being crowded out.
        assert!(!answered.allow(host(0), start));

        let later = start + ANSWER_GAP;
        assert!(answered.allow(host(ANSWERED_CAP), later));
        assert!(answered.allow(host(0), later));
    }

    #[test]
    fn only_the_local_network_is_heard() {
        for local in [
            "127.0.0.1",
            "10.1.2.3",
            "172.20.10.2",
            "192.168.1.20",
            "169.254.7.7",
        ] {
            assert!(on_local_network(local.parse().unwrap()), "{local}");
        }
        for remote in ["8.8.8.8", "100.64.0.1", "203.0.113.9", "2001:db8::1"] {
            assert!(!on_local_network(remote.parse().unwrap()), "{remote}");
        }
    }

    #[test]
    fn a_node_ignores_its_own_beacon() {
        let mut a = beacon("node-a");
        a.announce_at(at(&a)).unwrap();
        assert!(a.recv(BRIEF).unwrap().is_none());
    }

    #[test]
    fn named_listeners_are_kept_as_they_are() {
        let from: IpAddr = Ipv4Addr::new(10, 0, 0, 9).into();
        assert_eq!(resolve("0.0.0.0:7000", from), "10.0.0.9:7000");
        assert_eq!(resolve("192.168.1.4:7000", from), "192.168.1.4:7000");
        assert_eq!(resolve("relay.example:7000", from), "relay.example:7000");
    }
}
