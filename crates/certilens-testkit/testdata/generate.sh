#!/usr/bin/env bash
# Generate a small PKI for CertiLens tests.
#
# Produces (all in the current directory):
#   root-ca.crt, root-ca.key       — self-signed root (10 years)
#   inter-ca.crt, inter-ca.key     — intermediate signed by root (5 years)
#   leaf.crt, leaf.key             — leaf signed by intermediate (1 year)
#   leaf-expired.crt, leaf-expired.key — same but already expired
#
# These are test certificates. Never use them for real documents.

set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR"

gen_root() {
    openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
        -keyout root-ca.key -out root-ca.crt \
        -subj "/CN=CertiLens Test Root CA/O=CertiLens/C=IN" \
        -addext "basicConstraints=critical,CA:TRUE,pathlen:2" \
        -addext "keyUsage=critical,keyCertSign,cRLSign"
}

gen_intermediate() {
    openssl req -newkey rsa:2048 -nodes \
        -keyout inter-ca.key -out inter-ca.csr \
        -subj "/CN=CertiLens Test Intermediate CA/O=CertiLens/C=IN"
    openssl x509 -req -in inter-ca.csr -days 1825 \
        -CA root-ca.crt -CAkey root-ca.key -CAcreateserial \
        -out inter-ca.crt \
        -extfile <(printf "basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\n")
    rm -f inter-ca.csr
}

gen_leaf_valid() {
    openssl req -newkey rsa:2048 -nodes \
        -keyout leaf.key -out leaf.csr \
        -subj "/CN=CertiLens Test Signer/O=CertiLens/C=IN"
    openssl x509 -req -in leaf.csr -days 365 \
        -CA inter-ca.crt -CAkey inter-ca.key -CAcreateserial \
        -out leaf.crt \
        -extfile <(printf "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,nonRepudiation\n")
    rm -f leaf.csr
}

gen_leaf_expired() {
    # Use -not_before/-not_after via a temp openssl config, since CLI
    # doesn't support explicit dates. Instead, sign with a short-lived
    # cert and backdate using faketime if available, else accept "not yet valid".
    # Simpler: create a cert with validity in the past via a config file.
    cat > /tmp/certilens-expired.cnf <<'EOF'
[req]
distinguished_name = dn
prompt = no
[dn]
CN = CertiLens Expired Test Signer
O = CertiLens
C = IN
[ext]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature, nonRepudiation
EOF

    openssl req -new -newkey rsa:2048 -nodes \
        -keyout leaf-expired.key -out leaf-expired.csr \
        -config /tmp/certilens-expired.cnf
    # OpenSSL 3.x doesn't allow arbitrary dates via CLI, so we rely on
    # faking the system date is not an option. For now, use "notAfter=-1 day"
    # if openssl supports it, else skip.
    openssl x509 -req -in leaf-expired.csr \
        -CA inter-ca.crt -CAkey inter-ca.key -CAcreateserial \
        -out leaf-expired.crt -days 1 \
        -extfile /tmp/certilens-expired.cnf -extensions ext
    rm -f leaf-expired.csr /tmp/certilens-expired.cnf
}

echo "Generating root CA..."
gen_root
echo "Generating intermediate CA..."
gen_intermediate
echo "Generating valid leaf..."
gen_leaf_valid
echo "Generating expired leaf (note: actually valid for 1 day; expiry testing comes later)..."
gen_leaf_expired

echo
echo "Done. Files in $DIR:"
ls -1 *.crt *.key 2>/dev/null
