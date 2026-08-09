use radii_fetch::server::run_on;
use radii_integration::{bind_local, wait_ready};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[tokio::test]
async fn tunnels_bytes_bidirectionally() {
    let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo.local_addr().unwrap().to_string();
    // Accept loop: wait_ready() also opens a Fetch connection that reaches upstream.
    let echo_handle = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = echo.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 64];
                if let Ok(n) = stream.read(&mut buf).await {
                    if n > 0 {
                        let _ = stream.write_all(&buf[..n]).await;
                    }
                }
            });
        }
    });

    let (listener, fetch_addr) = bind_local().await.unwrap();
    let upstream = echo_addr.clone();
    let fetch_handle = tokio::spawn(async move { run_on(listener, &upstream).await });
    wait_ready(&fetch_addr).await.unwrap();

    let mut client = TcpStream::connect(&fetch_addr).await.unwrap();
    client.write_all(b"ping-radii").await.unwrap();
    let mut buf = [0u8; 64];
    let n = tokio::time::timeout(std::time::Duration::from_secs(2), client.read(&mut buf))
        .await
        .expect("timed out reading tunnel echo")
        .unwrap();
    assert_eq!(&buf[..n], b"ping-radii");

    fetch_handle.abort();
    echo_handle.abort();
}
