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

use crate::{AsyncDuplex, BoxedStream};
use anyhow::{bail, Context, Result};
use rustls::client::WebPkiServerVerifier;
use rustls::server::WebPkiClientVerifier;
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, CertificateRevocationListDer, PrivateKeyDer, ServerName};
use serde::Deserialize;
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
    /// PEM certificate revocation list, checked against every peer
    /// certificate in both directions. Optional: absent means no revocation
    /// checking, which is where this project started.
    ///
    /// Without it the only way to withdraw a compromised node's access is
    /// rotating the CA and reissuing every certificate in the mesh — and
    /// because relay admission is CA membership, a leaked key is a standing
    /// grant of forwarding capacity until that happens. See `docs/tls.md`.
    ///
    /// Read once at load, like `cert`/`key`/`ca`: a CRL that changes on disk
    /// takes effect at restart, not before.
    #[serde(default)]
    pub crl: Option<PathBuf>,
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
        let crls = match &config.crl {
            Some(path) => load_crls(path)?,
            None => Vec::new(),
        };

        // Revocation is applied to BOTH directions. Checking only inbound
        // client certificates would leave a revoked node able to keep
        // answering as a server, which is exactly how traffic would continue
        // to reach it.
        let mut client_verifier =
            WebPkiClientVerifier::builder(Arc::new(build_root_store(&ca_certs)?));
        let mut server_verifier =
            WebPkiServerVerifier::builder(Arc::new(build_root_store(&ca_certs)?));
        if !crls.is_empty() {
            // End-entity only: the leaf is the node identity being withdrawn,
            // and a private mesh CA has no issuer above it to publish its own
            // revocation status. Checking the full chain would make every
            // handshake fail on the CA's unknown status instead.
            client_verifier = client_verifier
                .with_crls(crls.clone())
                .only_check_end_entity_revocation();
            server_verifier = server_verifier
                .with_crls(crls)
                .only_check_end_entity_revocation();
        }

        let server = ServerConfig::builder()
            .with_client_cert_verifier(
                client_verifier
                    .build()
                    .context("building mTLS client verifier")?,
            )
            .with_single_cert(certs.clone(), load_key(&config.key)?)
            .context("building TLS server config")?;

        let client = ClientConfig::builder()
            .with_webpki_verifier(
                server_verifier
                    .build()
                    .context("building mTLS server verifier")?,
            )
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
    let certs = CertificateDer::pem_file_iter(path)
        .with_context(|| format!("opening cert file {}", path.display()))?
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| format!("parsing cert file {}", path.display()))?;
    if certs.is_empty() {
        bail!("no certificates found in {}", path.display());
    }
    Ok(certs)
}

/// Loads a PEM certificate revocation list.
///
/// A configured-but-unreadable CRL is an error rather than an empty list:
/// silently falling back to "revoke nothing" would leave an operator
/// believing revocation is enforced when it is not.
fn load_crls(path: &Path) -> Result<Vec<CertificateRevocationListDer<'static>>> {
    let crls = CertificateRevocationListDer::pem_file_iter(path)
        .with_context(|| format!("opening crl file {}", path.display()))?
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| format!("parsing crl file {}", path.display()))?;
    if crls.is_empty() {
        bail!("no certificate revocation list found in {}", path.display());
    }
    Ok(crls)
}

fn load_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    PrivateKeyDer::from_pem_file(path)
        .with_context(|| format!("parsing key file {}", path.display()))
}

/// Builds the TLS `ServerName` rustls needs to verify a peer's certificate
/// from a `host:port` (or bare host/IP) address string. Certificates for
/// IP-addressed nodes must carry a matching IP SAN.
fn server_name_for_addr(addr: &str) -> Result<ServerName<'static>> {
    ServerName::try_from(host_of(addr).to_string())
        .with_context(|| format!("invalid TLS server name in address {addr:?}"))
}

/// The host part of an address, in every spelling a node can advertise.
///
/// Splitting on the last colon is only correct for IPv4 and DNS names. An
/// IPv6 address is *made of* colons, so the naive split turned
/// `[::1]:7100` into `[::1]` and a bare `::1` into `:` — neither of which
/// is a server name, so every mTLS dial to a v6-addressed node failed with
/// "invalid TLS server name". Plaintext was unaffected, because
/// `TcpStream::connect` parses the bracketed form itself: the *secure*
/// configuration was the broken one, which is the wrong way round for a
/// runtime whose whole premise is reaching nodes across churning networks.
///
/// Three shapes, checked in the order that makes each unambiguous:
///
/// - Bracketed (`[::1]`, `[::1]:7100`) — the brackets exist precisely to
///   mark where the address ends, so trust them and ignore any port.
/// - Unbracketed with more than one colon (`::1`, `2001:db8::1`) — a bare
///   v6 literal. There is no port to strip: `::1:7100` is a valid address
///   in its own right, so guessing otherwise would silently rewrite it.
/// - Anything else (`127.0.0.1:7100`, `node-b.example:7100`, `host`) — at
///   most one colon, which can only be a port separator.
///
/// A malformed address is returned unchanged rather than repaired, so
/// `ServerName::try_from` rejects it with the original text in the error.
/// Zone-scoped literals (`fe80::1%eth0`) are not supported: the zone is
/// local to the sending host and cannot appear in a peer's certificate.
fn host_of(addr: &str) -> &str {
    if let Some(rest) = addr.strip_prefix('[') {
        return match rest.split_once(']') {
            Some((host, _)) => host,
            None => addr,
        };
    }
    if addr.matches(':').count() > 1 {
        return addr;
    }
    addr.rsplit_once(':').map(|(host, _)| host).unwrap_or(addr)
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
    accept_on(stream, identity).await
}

/// Like [`accept`], but upgrades an already-established stream. This is what
/// lets a chain's terminal node run its end-to-end session inside the
/// hop-local one it is already speaking.
pub async fn accept_on<S: AsyncDuplex + 'static>(
    stream: S,
    identity: Option<&TlsIdentity>,
) -> Result<(BoxedStream, Option<String>)> {
    match identity {
        Some(identity) => {
            let tls_stream = identity.acceptor().accept(stream).await?;
            let peer = client_identity_of(&tls_stream)?;
            Ok((Box::new(tls_stream), Some(peer)))
        }
        None => Ok((Box::new(stream), None)),
    }
}

/// Dials `addr`, upgrading to mTLS when `identity` is configured.
pub async fn dial(addr: &str, identity: Option<&TlsIdentity>) -> Result<BoxedStream> {
    dial_expecting(addr, identity, None).await
}

/// Dials `addr` like [`dial`], but additionally requires the peer that
/// answers to be the node named by `expected_node_id`.
///
/// A valid CA-issued certificate only proves the peer belongs to the mesh; it
/// does not prove it is the peer you meant to reach. That distinction matters
/// wherever the address itself came from untrusted data — Crawl's node
/// registry is written by peers, so an address learned from the graph is a
/// claim, not a fact. Checking the Subject CN against the node id turns the
/// handshake into an assertion about *which* node answered.
///
/// The check applies only when TLS is actually in use: on a plaintext
/// connection there is no certificate to check, and callers get today's
/// unauthenticated behavior (see `SECURITY.md` — plaintext listeners are
/// documented as untrusted-network-unsafe).
pub async fn dial_expecting(
    addr: &str,
    identity: Option<&TlsIdentity>,
    expected_node_id: Option<&str>,
) -> Result<BoxedStream> {
    let stream = TcpStream::connect(addr).await?;
    connect_on(stream, addr, identity, expected_node_id).await
}

/// Like [`dial_expecting`], but over an already-established stream.
///
/// `sni_addr` supplies the server name for the handshake. A nested session
/// has no socket address of its own to derive one from, so the caller passes
/// the address of the host it believes it is reaching — the target hop's
/// advertised address — and certificate SANs are checked against that real
/// host, exactly as on a direct dial.
///
/// The `expected_node_id` check applies only when TLS is actually in use: on
/// a plaintext stream there is no certificate to check, and callers get
/// today's unauthenticated behavior (see `SECURITY.md` — plaintext listeners
/// are documented as untrusted-network-unsafe).
pub async fn connect_on<S: AsyncDuplex + 'static>(
    stream: S,
    sni_addr: &str,
    identity: Option<&TlsIdentity>,
    expected_node_id: Option<&str>,
) -> Result<BoxedStream> {
    match identity {
        Some(identity) => {
            let server_name = server_name_for_addr(sni_addr)?;
            let tls_stream = identity.connector().connect(server_name, stream).await?;
            if let Some(expected) = expected_node_id {
                let actual = server_identity_of(&tls_stream)?;
                if actual != expected {
                    bail!(
                        "upstream {sni_addr} authenticated as node {actual:?}, expected \
                         {expected:?}"
                    );
                }
            }
            Ok(Box::new(tls_stream))
        }
        None => {
            if let Some(expected) = expected_node_id {
                tracing::warn!(
                    sni_addr = %sni_addr,
                    expected_node_id = %expected,
                    "opening a connection without TLS: cannot verify the peer is the \
                     intended node"
                );
            }
            Ok(Box::new(stream))
        }
    }
}

fn client_identity_of<S>(stream: &tokio_rustls::server::TlsStream<S>) -> Result<String> {
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

/// The authenticated node identity of the *server* on an outbound TLS
/// connection, taken from its leaf certificate's Subject CN.
fn server_identity_of<S>(stream: &tokio_rustls::client::TlsStream<S>) -> Result<String> {
    let certs = stream
        .get_ref()
        .1
        .peer_certificates()
        .ok_or_else(|| anyhow::anyhow!("no server certificate presented"))?;
    let leaf = certs
        .first()
        .ok_or_else(|| anyhow::anyhow!("empty server certificate chain"))?;
    peer_common_name(leaf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{CertificateParams, DistinguishedName, DnType, Ia5String, KeyPair, SanType};
    use std::fs::File;
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
            // The v6 loopback, so a test can dial `[::1]:port` and have the
            // certificate actually match. rustls verifies an IP-addressed
            // peer against its IP SANs (it sends no SNI for one), so without
            // this the v6 handshake would fail on the certificate rather
            // than on the name parsing the test is there to exercise.
            SanType::IpAddress("::1".parse().unwrap()),
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
            crl: None,
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

    struct CrlPki {
        _dir: TempDir,
        /// `node-a`, serving with the CRL configured.
        server_with_crl: TlsIdentityConfig,
        /// `node-b`, dialing with the CRL configured. Not revoked.
        client_with_crl: TlsIdentityConfig,
        /// `node-r`, named by the CRL. Also carries the CRL itself, so it
        /// can be used from either end of a handshake.
        revoked: TlsIdentityConfig,
    }

    /// Issues a leaf with an explicit serial, so a CRL can name it. rcgen
    /// picks a random serial when none is set, and a CRL entry has to match
    /// one exactly.
    fn issue_leaf_with_serial(
        dir: &Path,
        prefix: &str,
        common_name: &str,
        serial: u64,
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
        params.serial_number = Some(rcgen::SerialNumber::from(serial));
        let key = KeyPair::generate().unwrap();
        let cert = params.signed_by(&key, ca_cert, ca_key).unwrap();

        let cert_path = write_pem(dir, &format!("{prefix}.cert.pem"), &cert.pem());
        let key_path = write_pem(dir, &format!("{prefix}.key.pem"), &key.serialize_pem());

        TlsIdentityConfig {
            cert: cert_path,
            key: key_path,
            ca: ca_path.to_path_buf(),
            crl: None,
        }
    }

    /// A CA with three leaves, one of them revoked by a CRL the other two
    /// (and the revoked leaf itself) are configured with.
    fn test_pki_with_crl() -> CrlPki {
        use rcgen::{
            date_time_ymd, CertificateRevocationListParams, RevocationReason, RevokedCertParams,
            SerialNumber,
        };

        let dir = TempDir::new().unwrap();

        let mut ca_params = CertificateParams::new(vec![]).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params.distinguished_name = DistinguishedName::new();
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "Radii Test CA");
        ca_params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            // Required for the CA to be a valid CRL issuer.
            rcgen::KeyUsagePurpose::CrlSign,
            rcgen::KeyUsagePurpose::DigitalSignature,
        ];
        let ca_key = KeyPair::generate().unwrap();
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();
        let ca_path = write_pem(dir.path(), "ca.cert.pem", &ca_cert.pem());

        const REVOKED_SERIAL: u64 = 0xBAD;

        let crl_params = CertificateRevocationListParams {
            this_update: date_time_ymd(2026, 1, 1),
            next_update: date_time_ymd(2099, 1, 1),
            crl_number: SerialNumber::from(1u64),
            issuing_distribution_point: None,
            revoked_certs: vec![RevokedCertParams {
                serial_number: SerialNumber::from(REVOKED_SERIAL),
                revocation_time: date_time_ymd(2026, 1, 1),
                reason_code: Some(RevocationReason::KeyCompromise),
                invalidity_date: None,
            }],
            key_identifier_method: rcgen::KeyIdMethod::Sha256,
        };
        let crl = crl_params.signed_by(&ca_cert, &ca_key).unwrap();
        let crl_path = write_pem(dir.path(), "revoked.crl.pem", &crl.pem().unwrap());

        let mut server_with_crl = issue_leaf_with_serial(
            dir.path(),
            "node-a",
            "node-a",
            1,
            &ca_cert,
            &ca_key,
            &ca_path,
        );
        let mut client_with_crl = issue_leaf_with_serial(
            dir.path(),
            "node-b",
            "node-b",
            2,
            &ca_cert,
            &ca_key,
            &ca_path,
        );
        let mut revoked = issue_leaf_with_serial(
            dir.path(),
            "node-r",
            "node-r",
            REVOKED_SERIAL,
            &ca_cert,
            &ca_key,
            &ca_path,
        );
        server_with_crl.crl = Some(crl_path.clone());
        client_with_crl.crl = Some(crl_path.clone());
        revoked.crl = Some(crl_path);

        CrlPki {
            _dir: dir,
            server_with_crl,
            client_with_crl,
            revoked,
        }
    }

    /// A revoked node must not be able to authenticate as a CLIENT.
    ///
    /// Without this, the only remedy for a compromised node is rotating the
    /// whole CA — and since admission to a relay is CA membership, that cert
    /// is a standing grant of forwarding capacity. See SECURITY.md.
    #[tokio::test]
    async fn a_revoked_client_certificate_is_refused() {
        let pki = test_pki_with_crl();

        let server_identity = TlsIdentity::load(&pki.server_with_crl).unwrap();
        let revoked_client = TlsIdentity::load(&pki.revoked).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            accept(stream, Some(&server_identity)).await.map(|_| ())
        });

        let dialed = dial(&addr, Some(&revoked_client)).await;
        let accepted = server.await.unwrap();

        assert!(
            dialed.is_err() || accepted.is_err(),
            "a revoked client certificate must not complete a handshake"
        );
    }

    /// The same list must apply to the SERVER side of a dial. A revoked node
    /// that can still answer as a server could keep receiving traffic
    /// routed to it, which is the half a client-only check would miss.
    #[tokio::test]
    async fn a_revoked_server_certificate_is_refused() {
        let pki = test_pki_with_crl();

        let revoked_server = TlsIdentity::load(&pki.revoked).unwrap();
        let client_identity = TlsIdentity::load(&pki.client_with_crl).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let _ = accept(stream, Some(&revoked_server)).await;
        });

        assert!(
            dial(&addr, Some(&client_identity)).await.is_err(),
            "a revoked server certificate must not complete a handshake"
        );
    }

    /// Revocation must not break the healthy path: a node the CRL does not
    /// name still authenticates normally.
    #[tokio::test]
    async fn a_current_certificate_still_authenticates_when_a_crl_is_configured() {
        let pki = test_pki_with_crl();

        let server_identity = TlsIdentity::load(&pki.server_with_crl).unwrap();
        let client_identity = TlsIdentity::load(&pki.client_with_crl).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (_, peer) = accept(stream, Some(&server_identity)).await.unwrap();
            peer
        });

        dial(&addr, Some(&client_identity))
            .await
            .expect("an unrevoked peer must still authenticate");
        assert_eq!(server.await.unwrap().as_deref(), Some("node-b"));
    }

    /// A `crl` path that does not exist is a configuration error, surfaced
    /// at load rather than silently leaving revocation unenforced.
    #[test]
    fn a_missing_crl_file_fails_to_load() {
        let pki = test_pki();
        let mut config = pki.node_a.clone();
        config.crl = Some(PathBuf::from("/nonexistent/revoked.crl.pem"));
        let err = TlsIdentity::load(&config)
            .map(|_| ())
            .expect_err("a missing CRL must not load as an empty one");
        assert!(
            err.to_string().contains("crl") || err.to_string().contains("revocation"),
            "the error must name the CRL, got: {err}"
        );
    }

    /// Every spelling a node can advertise in `listen_addrs`, and the host a
    /// certificate must therefore be checked against.
    ///
    /// The IPv6 rows are the regression. Splitting on the last colon made
    /// `[::1]:7100` into `[::1]` and a bare `::1` into `:`, so
    /// `ServerName::try_from` rejected both and every mTLS dial to a
    /// v6-addressed node failed with "invalid TLS server name" — while the
    /// same mesh worked in plaintext, because `TcpStream::connect` parses
    /// the bracketed form itself.
    #[test]
    fn resolves_the_server_name_for_every_address_shape() {
        for (addr, expected) in [
            ("127.0.0.1:7100", "127.0.0.1"),
            ("node-b.example:7100", "node-b.example"),
            ("node-b.example", "node-b.example"),
            ("[::1]:7100", "::1"),
            ("[2001:db8::1]:443", "2001:db8::1"),
            ("[::1]", "::1"),
            ("::1", "::1"),
            ("2001:db8::1", "2001:db8::1"),
        ] {
            assert_eq!(host_of(addr), expected, "host_of({addr:?})");
            server_name_for_addr(addr)
                .unwrap_or_else(|err| panic!("{addr:?} must resolve to a server name: {err}"));
        }
    }

    /// A malformed address is rejected, not silently repaired into a name
    /// that would be checked against the wrong certificate. The error names
    /// the original text so an operator can find it in their registry.
    #[test]
    fn rejects_a_malformed_address_rather_than_guessing() {
        for addr in ["[::1", "[", "fe80::1%eth0"] {
            let err = server_name_for_addr(addr)
                .expect_err("a malformed address must not produce a server name");
            assert!(
                err.to_string().contains(addr),
                "the error must quote the offending address, got: {err}"
            );
        }
    }

    /// The end of the fix that the string test cannot reach: a real mutual
    /// TLS handshake to a v6 literal, verified against the certificate's
    /// `::1` IP SAN.
    ///
    /// Skipped where the host has no v6 loopback to bind. The test above is
    /// the unconditional guard for the regression itself; this one proves
    /// the whole dial path works, so losing it on a v4-only host costs
    /// coverage of the integration, not of the bug.
    #[tokio::test]
    async fn authenticates_a_peer_reached_at_an_ipv6_literal() {
        let Ok(listener) = TcpListener::bind("[::1]:0").await else {
            eprintln!("skipping: no IPv6 loopback on this host");
            return;
        };
        let addr = listener.local_addr().unwrap().to_string();
        assert!(
            addr.starts_with('['),
            "expected a bracketed v6 addr: {addr}"
        );

        let pki = test_pki();
        let server_identity = TlsIdentity::load(&pki.node_a).unwrap();
        let client_identity_cfg = TlsIdentity::load(&pki.node_b).unwrap();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (mut tls_stream, peer) = accept(stream, Some(&server_identity)).await.unwrap();
            let mut buf = [0u8; 5];
            tls_stream.read_exact(&mut buf).await.unwrap();
            (peer, buf)
        });

        // `dial_expecting` rather than `dial`: the node-id check is the
        // reason the server name has to be right in the first place.
        let mut client = dial_expecting(&addr, Some(&client_identity_cfg), Some("node-a"))
            .await
            .expect("an mTLS dial to a v6 literal must succeed");
        client.write_all(b"hello").await.unwrap();

        let (peer, buf) = server.await.unwrap();
        assert_eq!(peer.as_deref(), Some("node-b"));
        assert_eq!(&buf, b"hello");
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

    /// Two TLS sessions nested over one TCP connection: the outer pair is the
    /// hop-local session, the inner pair is the end-to-end session a relay
    /// would carry as opaque bytes.
    #[tokio::test]
    async fn tls_nests_over_an_established_stream() {
        let pki = test_pki();
        let server_identity = TlsIdentity::load(&pki.node_a).unwrap();
        let client_identity = TlsIdentity::load(&pki.node_b).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server_identity_for_inner = server_identity.clone();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (outer, _) = accept(stream, Some(&server_identity)).await.unwrap();
            let (mut inner, peer) = accept_on(outer, Some(&server_identity_for_inner))
                .await
                .unwrap();
            assert_eq!(peer.as_deref(), Some("node-b"));
            let mut buf = [0u8; 5];
            inner.read_exact(&mut buf).await.unwrap();
            buf
        });

        let outer = dial_expecting(&addr.to_string(), Some(&client_identity), Some("node-a"))
            .await
            .unwrap();
        let mut inner = connect_on(
            outer,
            &addr.to_string(),
            Some(&client_identity),
            Some("node-a"),
        )
        .await
        .unwrap();
        inner.write_all(b"hello").await.unwrap();

        assert_eq!(&server.await.unwrap(), b"hello");
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
