//! A throwaway certificate authority for TLS integration tests. Every cert
//! is generated fresh per test process and lives only in a temp directory —
//! never commit real key material, per `SECURITY.md`.

use radii_proto::tls::TlsIdentityConfig;
use rcgen::{CertificateParams, DistinguishedName, DnType, Ia5String, KeyPair, SanType};
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use tempfile::TempDir;

pub struct TestCa {
    dir: TempDir,
    cert: rcgen::Certificate,
    key: KeyPair,
    ca_path: PathBuf,
    counter: AtomicU32,
}

impl TestCa {
    pub fn new() -> Self {
        let dir = TempDir::new().expect("create temp dir for test CA");
        let mut params = CertificateParams::new(vec![]).expect("empty SAN list");
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.distinguished_name = DistinguishedName::new();
        params
            .distinguished_name
            .push(DnType::CommonName, "Radii Test CA");
        let key = KeyPair::generate().expect("generate CA key");
        let cert = params.self_signed(&key).expect("self-sign CA cert");
        let ca_path = write_pem(dir.path(), "ca.cert.pem", &cert.pem());

        Self {
            dir,
            cert,
            key,
            ca_path,
            counter: AtomicU32::new(0),
        }
    }

    /// Issues a leaf certificate with the given node id as its Subject CN,
    /// signed by this CA and trusting this CA. IP/DNS SANs cover
    /// `127.0.0.1` and `localhost`, which is all `bind_local` addresses need.
    pub fn issue(&self, node_id: &str) -> TlsIdentityConfig {
        let n = self.counter.fetch_add(1, Ordering::SeqCst);

        let mut params = CertificateParams::new(vec![]).expect("empty SAN list");
        params.distinguished_name = DistinguishedName::new();
        params.distinguished_name.push(DnType::CommonName, node_id);
        params.subject_alt_names = vec![
            SanType::IpAddress("127.0.0.1".parse().unwrap()),
            SanType::DnsName(Ia5String::try_from("localhost").unwrap()),
        ];
        let key = KeyPair::generate().expect("generate leaf key");
        let cert = params
            .signed_by(&key, &self.cert, &self.key)
            .expect("sign leaf cert");

        let cert_path = write_pem(self.dir.path(), &format!("{n}.cert.pem"), &cert.pem());
        let key_path = write_pem(
            self.dir.path(),
            &format!("{n}.key.pem"),
            &key.serialize_pem(),
        );

        TlsIdentityConfig {
            cert: cert_path,
            key: key_path,
            ca: self.ca_path.clone(),
        }
    }

    /// The path to this CA's own certificate, for constructing an identity
    /// (e.g. an "outsider") that trusts this CA without being issued by it.
    pub fn ca_path(&self) -> PathBuf {
        self.ca_path.clone()
    }
}

impl Default for TestCa {
    fn default() -> Self {
        Self::new()
    }
}

fn write_pem(dir: &Path, name: &str, pem: &str) -> PathBuf {
    let path = dir.join(name);
    let mut file = File::create(&path).expect("create pem file");
    file.write_all(pem.as_bytes()).expect("write pem file");
    path
}
