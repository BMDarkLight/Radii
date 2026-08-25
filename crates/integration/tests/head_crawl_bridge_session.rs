use radii_head::radii::run_radii_on;
use radii_integration::{bind_local, wait_ready};
use radii_proto::{read_message, write_message, RadiiMessage};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};

/// A Crawl stand-in that counts how many separate TCP connections it accepts
/// and, on each one, keeps reading/acking messages until the peer closes.
async fn run_counting_crawl_stub(listener: TcpListener, connections: Arc<AtomicUsize>) {
    loop {
        let Ok((mut stream, _)) = listener.accept().await else {
            break;
        };
        connections.fetch_add(1, Ordering::SeqCst);
        tokio::spawn(async move {
            loop {
                let Ok(_message) = read_message(&mut stream).await else {
                    break;
                };
                let ack = RadiiMessage::Ack {
                    status: "stub_ack".to_string(),
                };
                if write_message(&mut stream, &ack).await.is_err() {
                    break;
                }
            }
        });
    }
}

/// Sending several messages over one client connection to Head's radii
/// bridge must open exactly one upstream connection to Crawl, not one per
/// message.
#[tokio::test]
async fn bridge_reuses_one_upstream_session_across_messages() {
    let (crawl_listener, crawl_addr) = bind_local().await.unwrap();
    let connections = Arc::new(AtomicUsize::new(0));
    let crawl_connections = Arc::clone(&connections);
    let crawl_handle =
        tokio::spawn(
            async move { run_counting_crawl_stub(crawl_listener, crawl_connections).await },
        );
    // `crawl_listener` is already bound (and thus already accepting SYNs at
    // the OS level) via `bind_local`, so no readiness probe is needed here —
    // and probing would itself count as a connection against `connections`.

    let (head_listener, head_addr) = bind_local().await.unwrap();
    let crawl_upstream = crawl_addr.clone();
    let head_handle =
        tokio::spawn(async move { run_radii_on(head_listener, crawl_upstream, None).await });
    wait_ready(&head_addr).await.unwrap();

    let mut stream = TcpStream::connect(&head_addr).await.unwrap();
    for i in 0..5 {
        write_message(
            &mut stream,
            &RadiiMessage::NodeHello {
                node_id: format!("node-{i}"),
                roles: vec!["access".into()],
                listen_addrs: vec![],
            },
        )
        .await
        .unwrap();
        match read_message(&mut stream).await.unwrap() {
            RadiiMessage::Ack { status } => assert_eq!(status, "stub_ack"),
            other => panic!("unexpected: {other:?}"),
        }
    }

    assert_eq!(
        connections.load(Ordering::SeqCst),
        1,
        "expected a single reused upstream session, not one dial per message"
    );

    head_handle.abort();
    crawl_handle.abort();
}

/// If the upstream session to Crawl drops mid-stream, the bridge should
/// transparently reconnect rather than failing the client connection.
#[tokio::test]
async fn bridge_reconnects_after_upstream_drop() {
    let (crawl_listener, crawl_addr) = bind_local().await.unwrap();
    let connections = Arc::new(AtomicUsize::new(0));
    let crawl_connections = Arc::clone(&connections);
    let crawl_handle = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = crawl_listener.accept().await else {
                break;
            };
            crawl_connections.fetch_add(1, Ordering::SeqCst);
            // Reply to exactly one message, then drop the connection to
            // simulate Crawl restarting mid-session.
            if read_message(&mut stream).await.is_ok() {
                let ack = RadiiMessage::Ack {
                    status: "stub_ack".to_string(),
                };
                let _ = write_message(&mut stream, &ack).await;
            }
        }
    });
    // `crawl_listener` is already bound (and thus already accepting SYNs at
    // the OS level) via `bind_local`, so no readiness probe is needed here —
    // and probing would itself count as a connection against `connections`.

    let (head_listener, head_addr) = bind_local().await.unwrap();
    let crawl_upstream = crawl_addr.clone();
    let head_handle =
        tokio::spawn(async move { run_radii_on(head_listener, crawl_upstream, None).await });
    wait_ready(&head_addr).await.unwrap();

    let mut stream = TcpStream::connect(&head_addr).await.unwrap();
    for _ in 0..2 {
        write_message(
            &mut stream,
            &RadiiMessage::NodeHello {
                node_id: "node-a".into(),
                roles: vec!["access".into()],
                listen_addrs: vec![],
            },
        )
        .await
        .unwrap();
        match read_message(&mut stream).await.unwrap() {
            RadiiMessage::Ack { status } => assert_eq!(status, "stub_ack"),
            other => panic!("unexpected: {other:?}"),
        }
    }

    assert_eq!(
        connections.load(Ordering::SeqCst),
        2,
        "expected exactly one reconnect after the upstream dropped the session"
    );

    head_handle.abort();
    crawl_handle.abort();
}
