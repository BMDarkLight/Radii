//! Cross-crate integration helpers for Radii smoke and protocol tests.

pub mod pki;

use std::time::Duration;
use tokio::net::TcpListener;
use tokio::time::timeout;

pub async fn bind_local() -> anyhow::Result<(TcpListener, String)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    Ok((listener, addr.to_string()))
}

pub async fn wait_ready(addr: &str) -> anyhow::Result<()> {
    let deadline = Duration::from_secs(2);
    timeout(deadline, async {
        loop {
            if tokio::net::TcpStream::connect(addr).await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .map_err(|_| anyhow::anyhow!("timed out waiting for {addr}"))?;
    Ok(())
}
