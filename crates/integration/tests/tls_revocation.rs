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

//! Withdrawing a node's access without rotating the whole CA.
//!
//! Relay admission is CA membership: absent an `allow_peers` list, holding a
//! certificate this relay's CA signed entitles the holder to forwarding
//! capacity. Before revocation the only way to take that back was reissuing
//! every certificate in the mesh, so a single leaked key was a standing
//! bandwidth grant. A CRL is the narrow lever — one file, no reissue.

use radii_crawl::server::{run_on_with_state, CrawlState};
use radii_integration::pki::TestCa;
use radii_integration::{bind_local, wait_ready};
use radii_proto::tls::{TlsIdentity, TlsIdentityConfig};
use radii_proto::{read_message, write_message, ListenAddr, RadiiMessage};
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::RwLock;

fn with_crl(mut config: TlsIdentityConfig, crl: std::path::PathBuf) -> TlsIdentityConfig {
    config.crl = Some(crl);
    config
}

async fn start_crawl(identity: TlsIdentity) -> String {
    let (listener, addr) = bind_local().await.unwrap();
    let state = Arc::new(RwLock::new(CrawlState {
        relay_peers: HashSet::new(),
        ..CrawlState::default()
    }));
    tokio::spawn(async move {
        let _ = run_on_with_state(listener, state, Some(identity)).await;
    });
    wait_ready(&addr).await.unwrap();
    addr
}

fn hello(node_id: &str) -> RadiiMessage {
    RadiiMessage::NodeHello {
        node_id: node_id.to_string(),
        roles: vec!["resource".into()],
        listen_addrs: vec![ListenAddr {
            addr: "127.0.0.1:2224".into(),
            role: "relay".into(),
        }],
    }
}

/// A revoked peer cannot reach a listener that carries the CRL, while an
/// unrevoked one is unaffected. Both halves matter: revocation that also
/// breaks healthy peers is not a usable lever.
#[tokio::test]
async fn a_revoked_peer_is_refused_while_others_still_connect() {
    let ca = TestCa::new();
    let crawl_config = ca.issue("crawl");
    let good_config = ca.issue("node-good");
    let compromised_config = ca.issue("node-compromised");

    // The operator revokes exactly one node and restarts Crawl with the CRL.
    let crl = ca.revoke(&["node-compromised"]);
    let crawl = TlsIdentity::load(&with_crl(crawl_config, crl.clone())).unwrap();
    let addr = start_crawl(crawl).await;

    // The revoked node still holds a CA-signed certificate, and it is still
    // inside its validity window — revocation is the only thing refusing it.
    let compromised = TlsIdentity::load(&compromised_config).unwrap();
    let refused = async {
        let mut stream = radii_proto::tls::dial(&addr, Some(&compromised)).await?;
        write_message(&mut stream, &hello("node-compromised")).await?;
        read_message(&mut stream).await
    }
    .await;
    assert!(
        refused.is_err(),
        "a revoked certificate must not be able to write to the graph"
    );

    // An unrevoked peer is untouched.
    let good = TlsIdentity::load(&good_config).unwrap();
    let mut stream = radii_proto::tls::dial(&addr, Some(&good)).await.unwrap();
    write_message(&mut stream, &hello("node-good"))
        .await
        .unwrap();
    match read_message(&mut stream).await.unwrap() {
        RadiiMessage::Ack { status } => assert_eq!(status, "hello_received"),
        other => panic!("unexpected reply: {other:?}"),
    }
}

/// Revocation also has to cut the other direction: a client carrying the CRL
/// must refuse a revoked *server*, or traffic would keep flowing to a node
/// whose key is known compromised.
#[tokio::test]
async fn a_client_carrying_the_crl_refuses_a_revoked_server() {
    let ca = TestCa::new();
    let compromised_server = ca.issue("node-compromised");
    let client_config = ca.issue("node-good");

    let crl = ca.revoke(&["node-compromised"]);

    let server = TlsIdentity::load(&compromised_server).unwrap();
    let addr = start_crawl(server).await;

    let client = TlsIdentity::load(&with_crl(client_config, crl)).unwrap();
    assert!(
        radii_proto::tls::dial(&addr, Some(&client)).await.is_err(),
        "a client holding the CRL must refuse a revoked server"
    );
}
