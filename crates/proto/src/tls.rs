//! Mutual TLS for Radii's wire protocol.
//!
//! Radii nodes form a private mesh, not a public web service, so peer
//! authentication uses a private CA rather than the public Web PKI: every
//! node presents one leaf certificate (its identity) and trusts one CA
//! bundle to verify whoever it connects to. TLS is opt-in per compartment —
//! when a `[tls]` section is configured, that listener/connection requires a
//! valid client *and* server certificate from the trusted CA; when it's
//! absent, the connection stays plaintext (today's default).
//!
//! See `docs/tls.md` for how to provision a CA and per-node certificates.

use crate::BoxedStream;
use anyhow::{bail, Context, Result};
use rustls::server::WebPkiClientVerifier;
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use serde::Deserialize;
use std::fs::File;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Once};
use tokio::net::TcpStream;
use x509_parser::prelude::FromDer;

pub use tokio_rustls::{TlsAcceptor, TlsConnector};

pub type TlsServerStream = tokio_rustls::server::TlsStream<TcpStream>;
pub type TlsClientStream = tokio_rustls::client::TlsStream<TcpStream>;

/// Certificate/key paths for one Radii node's mTLS identity: its own leaf
/// certificate and private key, plus the CA bundle used to verify peers.
#[derive(Debug, Clone, Deserialize)]
pub struct TlsIdentityConfig {
    pub cert: PathBuf,
    pub key: PathBuf,
    pub ca: PathBuf,
}

/// Loaded server and client TLS configurations sharing one node identity.
/// Cheap to clone (both fields are `Arc`s), so it can be handed to every
/// spawned connection task.
#[derive(Clone)]
pub struct TlsIdentity {
    server: Arc<ServerConfig>,
    client: Arc<ClientConfig>,
}

impl TlsIdentity {
    pub fn load(config: &TlsIdentityConfig) -> Result<Self> {
        ensure_crypto_provider();

        let certs = load_certs(&config.cert)?;
        let ca_certs = load_certs(&config.ca)?;

        let client_verifier = WebPkiClientVerifier::builder(Arc::new(build_root_store(&ca_certs)?))
            .build()
            .context("building mTLS client verifier")?;

        let server = ServerConfig::builder()
            .with_client_cert_verifier(client_verifier)
            .with_single_cert(certs.clone(), load_key(&config.key)?)
            .context("building TLS server config")?;

        let client = ClientConfig::builder()
            .with_root_certificates(build_root_store(&ca_certs)?)
            .with_client_auth_cert(certs, load_key(&config.key)?)
            .context("building TLS client config")?;

        Ok(Self {
            server: Arc::new(server),
            client: Arc::new(client),
        })
    }

    pub fn acceptor(&self) -> TlsAcceptor {
        TlsAcceptor::from(Arc::clone(&self.server))
    }

    pub fn connector(&self) -> TlsConnector {
        TlsConnector::from(Arc::clone(&self.client))
    }
}

fn ensure_crypto_provider() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        // Ignore the error: it only fails if a provider (e.g. installed by
        // another dependency such as reqwest) is already in place, which is
        // exactly as good for our purposes.
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

fn build_root_store(ca_certs: &[CertificateDer<'static>]) -> Result<RootCertStore> {
    let mut roots = RootCertStore::empty();
    for cert in ca_certs {
        roots
            .add(cert.clone())
            .context("adding CA certificate to trust store")?;
    }
    Ok(roots)
}

fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let mut reader = BufReader::new(
        File::open(path).with_context(|| format!("opening cert file {}", path.display()))?,
    );
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| format!("parsing cert file {}", path.display()))?;
    if certs.is_empty() {
        bail!("no certificates found in {}", path.display());
    }
    Ok(certs)
}

fn load_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    let mut reader = BufReader::new(
        File::open(path).with_context(|| format!("opening key file {}", path.display()))?,
    );
    rustls_pemfile::private_key(&mut reader)
        .with_context(|| format!("parsing key file {}", path.display()))?
        .ok_or_else(|| anyhow::anyhow!("no private key found in {}", path.display()))
}

/// Builds the TLS `ServerName` rustls needs to verify a peer's certificate
/// from a `host:port` (or bare host/IP) address string. Certificates for
/// IP-addressed nodes must carry a matching IP SAN.
fn server_name_for_addr(addr: &str) -> Result<ServerName<'static>> {
    let host = addr.rsplit_once(':').map(|(host, _)| host).unwrap_or(addr);
    ServerName::try_from(host.to_string()).context("invalid TLS server name")
}

/// Extracts the Subject Common Name from a peer's leaf certificate, used as
/// its authenticated node identity for route/message authorization.
fn peer_common_name(cert: &CertificateDer<'_>) -> Result<String> {
    let (_, parsed) = x509_parser::certificate::X509Certificate::from_der(cert.as_ref())
        .context("parsing peer certificate")?;
    let common_name = parsed
        .subject()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .map(|cn| cn.to_string());
    common_name.ok_or_else(|| anyhow::anyhow!("peer certificate has no Subject CN"))
}

/// Accepts a connection, upgrading to mTLS when `identity` is configured.
/// Returns the (possibly boxed-TLS) stream and, for TLS connections, the
/// authenticated peer identity taken from its client certificate's Subject
/// CN — `None` for plaintext connections, since there is no peer identity to
/// authenticate without TLS.
pub async fn accept(
    stream: TcpStream,
    identity: Option<&TlsIdentity>,
) -> Result<(BoxedStream, Option<String>)> {
    match identity {
        Some(identity) => {
            let tls_stream = identity.acceptor().accept(stream).await?;
            let peer = client_identity(&tls_stream)?;
            Ok((Box::new(tls_stream), Some(peer)))
        }
        None => Ok((Box::new(stream), None)),
    }
}

/// Dials `addr`, upgrading to mTLS when `identity` is configured.
pub async fn dial(addr: &str, identity: Option<&TlsIdentity>) -> Result<BoxedStream> {
    let stream = TcpStream::connect(addr).await?;
    match identity {
        Some(identity) => {
            let server_name = server_name_for_addr(addr)?;
            let tls_stream = identity.connector().connect(server_name, stream).await?;
            Ok(Box::new(tls_stream))
        }
        None => Ok(Box::new(stream)),
    }
}

fn client_identity(stream: &TlsServerStream) -> Result<String> {
    let certs = stream
        .get_ref()
        .1
        .peer_certificates()
        .ok_or_else(|| anyhow::anyhow!("no client certificate presented"))?;
    let leaf = certs
        .first()
        .ok_or_else(|| anyhow::anyhow!("empty client certificate chain"))?;
    peer_common_name(leaf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{CertificateParams, DistinguishedName, DnType, Ia5String, KeyPair, SanType};
    use std::io::Write;
    use tempfile::TempDir;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    struct TestPki {
        _dir: TempDir,
        node_a: TlsIdentityConfig,
        node_b: TlsIdentityConfig,
        outsider: TlsIdentityConfig,
    }

    fn write_pem(dir: &Path, name: &str, pem: &str) -> PathBuf {
        let path = dir.join(name);
        let mut file = File::create(&path).unwrap();
        file.write_all(pem.as_bytes()).unwrap();
        path
    }

    fn issue_leaf(
        dir: &Path,
        prefix: &str,
        common_name: &str,
        ca_cert: &rcgen::Certificate,
        ca_key: &KeyPair,
        ca_path: &Path,
    ) -> TlsIdentityConfig {
        let mut params = CertificateParams::new(vec![]).unwrap();
        params.distinguished_name = DistinguishedName::new();
        params
            .distinguished_name
            .push(DnType::CommonName, common_name);
        params.subject_alt_names = vec![
            SanType::IpAddress("127.0.0.1".parse().unwrap()),
            SanType::DnsName(Ia5String::try_from("localhost").unwrap()),
        ];
        let key = KeyPair::generate().unwrap();
        let cert = params.signed_by(&key, ca_cert, ca_key).unwrap();

        let cert_path = write_pem(dir, &format!("{prefix}.cert.pem"), &cert.pem());
        let key_path = write_pem(dir, &format!("{prefix}.key.pem"), &key.serialize_pem());

        TlsIdentityConfig {
            cert: cert_path,
            key: key_path,
            ca: ca_path.to_path_buf(),
        }
    }

    fn test_pki() -> TestPki {
        let dir = TempDir::new().unwrap();

        let mut ca_params = CertificateParams::new(vec![]).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params.distinguished_name = DistinguishedName::new();
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "Radii Test CA");
        let ca_key = KeyPair::generate().unwrap();
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();
        let ca_path = write_pem(dir.path(), "ca.cert.pem", &ca_cert.pem());

        let node_a = issue_leaf(dir.path(), "node-a", "node-a", &ca_cert, &ca_key, &ca_path);
        let node_b = issue_leaf(dir.path(), "node-b", "node-b", &ca_cert, &ca_key, &ca_path);

        // A cert from a *different*, untrusted CA — used to prove the
        // handshake rejects peers outside the configured trust store.
        let mut rogue_ca_params = CertificateParams::new(vec![]).unwrap();
        rogue_ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        rogue_ca_params.distinguished_name = DistinguishedName::new();
        rogue_ca_params
            .distinguished_name
            .push(DnType::CommonName, "Rogue CA");
        let rogue_ca_key = KeyPair::generate().unwrap();
        let rogue_ca_cert = rogue_ca_params.self_signed(&rogue_ca_key).unwrap();
        let rogue_ca_path = write_pem(dir.path(), "rogue-ca.cert.pem", &rogue_ca_cert.pem());
        let mut outsider = issue_leaf(
            dir.path(),
            "outsider",
            "outsider",
            &rogue_ca_cert,
            &rogue_ca_key,
            &rogue_ca_path,
        );
        // The outsider must still be told to trust the *real* CA so it can
        // verify the server it connects to; only its own leaf cert is rogue.
        outsider.ca = node_a.ca.clone();

        TestPki {
            _dir: dir,
            node_a,
            node_b,
            outsider,
        }
    }

    #[tokio::test]
    async fn accepts_and_authenticates_trusted_peer() {
        let pki = test_pki();
        let server_identity = TlsIdentity::load(&pki.node_a).unwrap();
        let client_identity_cfg = TlsIdentity::load(&pki.node_b).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (mut tls_stream, peer) = accept(stream, Some(&server_identity)).await.unwrap();
            let mut buf = [0u8; 5];
            tls_stream.read_exact(&mut buf).await.unwrap();
            (peer, buf)
        });

        let mut client = dial(&addr, Some(&client_identity_cfg)).await.unwrap();
        client.write_all(b"hello").await.unwrap();

        let (peer, buf) = server.await.unwrap();
        assert_eq!(peer.as_deref(), Some("node-b"));
        assert_eq!(&buf, b"hello");
    }

    #[tokio::test]
    async fn rejects_peer_from_untrusted_ca() {
        let pki = test_pki();
        let server_identity = TlsIdentity::load(&pki.node_a).unwrap();
        let outsider_identity = TlsIdentity::load(&pki.outsider).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            accept(stream, Some(&server_identity)).await
        });

        let dial_result = dial(&addr, Some(&outsider_identity)).await;
        let server_result = server.await.unwrap();

        assert!(
            dial_result.is_err() || server_result.is_err(),
            "expected the handshake to fail for a peer signed by an untrusted CA"
        );
    }

    #[tokio::test]
    async fn plaintext_when_no_identity_configured() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (mut stream, peer) = accept(stream, None).await.unwrap();
            let mut buf = [0u8; 5];
            stream.read_exact(&mut buf).await.unwrap();
            (peer, buf)
        });

        let mut client = dial(&addr, None).await.unwrap();
        client.write_all(b"hello").await.unwrap();

        let (peer, buf) = server.await.unwrap();
        assert!(peer.is_none());
        assert_eq!(&buf, b"hello");
    }
}
