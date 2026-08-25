#!/usr/bin/env bash
# Generates a throwaway private CA and per-node leaf certificates for local
# development and testing of Radii's mutual TLS support.
#
# NOT for production use: the CA key is written to disk unencrypted, and
# nothing here handles rotation, revocation, or secure distribution. For a
# real deployment, run an equivalent process (or a proper internal CA) on a
# host you control, keep the CA key offline, and distribute leaf certs and
# keys to each node over a secure channel. See docs/tls.md.
#
# Usage:
#   scripts/gen-dev-certs.sh [output-dir] [node-id ...]
#
# Example:
#   scripts/gen-dev-certs.sh ./certs crawl head fetch
#
# For each node id, writes <output-dir>/<node-id>.cert.pem and
# <output-dir>/<node-id>.key.pem, signed by <output-dir>/ca.cert.pem (with
# CA key at <output-dir>/ca.key.pem). All nodes share the same CA bundle.

set -euo pipefail

if ! command -v openssl >/dev/null 2>&1; then
  echo "error: openssl is required but was not found on PATH" >&2
  exit 1
fi

out_dir="${1:-./certs}"
shift || true
node_ids=("$@")

if [ ${#node_ids[@]} -eq 0 ]; then
  node_ids=(crawl head fetch)
fi

mkdir -p "$out_dir"

ca_key="$out_dir/ca.key.pem"
ca_cert="$out_dir/ca.cert.pem"

if [ -f "$ca_key" ] || [ -f "$ca_cert" ]; then
  echo "error: $ca_key or $ca_cert already exists — refusing to overwrite an existing CA" >&2
  exit 1
fi

echo "Generating CA at $ca_cert"
openssl req -x509 -newkey ed25519 -noenc \
  -keyout "$ca_key" -out "$ca_cert" \
  -days 3650 -subj "/CN=Radii Dev CA"
chmod 600 "$ca_key"

for node_id in "${node_ids[@]}"; do
  key="$out_dir/$node_id.key.pem"
  cert="$out_dir/$node_id.cert.pem"
  csr="$out_dir/$node_id.csr.pem"
  ext="$out_dir/$node_id.ext.cnf"

  if [ -f "$key" ] || [ -f "$cert" ]; then
    echo "warning: $key or $cert already exists — skipping $node_id" >&2
    continue
  fi

  echo "Generating leaf certificate for '$node_id'"
  cat > "$ext" <<EOF
subjectAltName = DNS:localhost, DNS:$node_id, IP:127.0.0.1
EOF

  openssl req -newkey ed25519 -noenc \
    -keyout "$key" -out "$csr" \
    -subj "/CN=$node_id"

  openssl x509 -req -in "$csr" \
    -CA "$ca_cert" -CAkey "$ca_key" -CAcreateserial \
    -out "$cert" -days 825 -extfile "$ext"

  chmod 600 "$key"
  rm -f "$csr" "$ext"
done

echo
echo "Done. Point each compartment's [tls] section at:"
echo "  ca   = \"$out_dir/ca.cert.pem\""
echo "  cert = \"$out_dir/<node-id>.cert.pem\""
echo "  key  = \"$out_dir/<node-id>.key.pem\""
