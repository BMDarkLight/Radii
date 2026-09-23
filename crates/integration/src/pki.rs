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

//! A throwaway certificate authority for TLS integration tests. Every cert
//! is generated fresh per test process and lives only in a temp directory —
//! never commit real key material, per `SECURITY.md`.

use radii_proto::tls::TlsIdentityConfig;
use rcgen::{
    date_time_ymd, CertificateParams, CertificateRevocationListParams, DistinguishedName, DnType,
    Ia5String, KeyPair, RevocationReason, RevokedCertParams, SanType, SerialNumber,
};
use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Mutex;
use tempfile::TempDir;

pub struct TestCa {
    dir: TempDir,
    cert: rcgen::Certificate,
    key: KeyPair,
    ca_path: PathBuf,
    counter: AtomicU32,
    /// Serial per issued node id, so [`Self::revoke`] can name them.
    serials: Mutex<HashMap<String, u64>>,
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
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            // Required for this CA to be a valid CRL issuer.
            rcgen::KeyUsagePurpose::CrlSign,
            rcgen::KeyUsagePurpose::DigitalSignature,
        ];
        let key = KeyPair::generate().expect("generate CA key");
        let cert = params.self_signed(&key).expect("self-sign CA cert");
        let ca_path = write_pem(dir.path(), "ca.cert.pem", &cert.pem());

        Self {
            dir,
            cert,
            key,
            ca_path,
            counter: AtomicU32::new(0),
            serials: Mutex::new(HashMap::new()),
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
        // Explicit, so `revoke` can name this certificate in a CRL. rcgen
        // otherwise picks a random serial, and a CRL entry must match one
        // exactly.
        let serial = u64::from(n) + 1;
        params.serial_number = Some(SerialNumber::from(serial));
        let key = KeyPair::generate().expect("generate leaf key");
        let cert = params
            .signed_by(&key, &self.cert, &self.key)
            .expect("sign leaf cert");
        self.serials
            .lock()
            .expect("serial table poisoned")
            .insert(node_id.to_string(), serial);

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
            crl: None,
        }
    }

    /// Writes a CRL revoking the named nodes and returns its path, for
    /// setting as `TlsIdentityConfig::crl`. Each node must already have been
    /// issued by [`Self::issue`].
    pub fn revoke(&self, node_ids: &[&str]) -> PathBuf {
        let serials = self.serials.lock().expect("serial table poisoned");
        let revoked_certs = node_ids
            .iter()
            .map(|node_id| {
                let serial = *serials
                    .get(*node_id)
                    .unwrap_or_else(|| panic!("{node_id} was never issued a certificate"));
                RevokedCertParams {
                    serial_number: SerialNumber::from(serial),
                    revocation_time: date_time_ymd(2026, 1, 1),
                    reason_code: Some(RevocationReason::KeyCompromise),
                    invalidity_date: None,
                }
            })
            .collect();

        let params = CertificateRevocationListParams {
            this_update: date_time_ymd(2026, 1, 1),
            next_update: date_time_ymd(2099, 1, 1),
            crl_number: SerialNumber::from(1u64),
            issuing_distribution_point: None,
            revoked_certs,
            key_identifier_method: rcgen::KeyIdMethod::Sha256,
        };
        let crl = params
            .signed_by(&self.cert, &self.key)
            .expect("sign test CRL");
        write_pem(
            self.dir.path(),
            "revoked.crl.pem",
            &crl.pem().expect("CRL to PEM"),
        )
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
