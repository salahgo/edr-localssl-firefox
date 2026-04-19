#!/bin/sh
set -eu

apk add --no-cache openssl >/dev/null

out_dir=/work/certs
mkdir -p "$out_dir"

if [ -f "$out_dir/rootCA.pem" ] && [ -f "$out_dir/site.key" ] && [ -f "$out_dir/site.fullchain.crt" ]; then
  echo "Using existing certificates in $out_dir"
  openssl x509 -in "$out_dir/rootCA.pem" -noout -fingerprint -sha256
  exit 0
fi

tmp_dir=$(mktemp -d)
trap 'rm -rf "$tmp_dir"' EXIT

cat >"$tmp_dir/site.cnf" <<'EOF'
[req]
default_bits = 2048
prompt = no
distinguished_name = dn
req_extensions = req_ext

[dn]
CN = localhost

[req_ext]
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
EOF

cat >"$tmp_dir/site.ext" <<'EOF'
authorityKeyIdentifier = keyid,issuer
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
EOF

openssl genrsa -out "$out_dir/rootCA.key" 4096
openssl req -x509 -new -nodes -key "$out_dir/rootCA.key" -sha256 -days 3650 -subj "/CN=Aegis Nginx Lab Root CA" -out "$out_dir/rootCA.pem"
openssl genrsa -out "$out_dir/site.key" 2048
openssl req -new -key "$out_dir/site.key" -out "$tmp_dir/site.csr" -config "$tmp_dir/site.cnf"
openssl x509 -req -in "$tmp_dir/site.csr" -CA "$out_dir/rootCA.pem" -CAkey "$out_dir/rootCA.key" -CAcreateserial -out "$out_dir/site.crt" -days 825 -sha256 -extfile "$tmp_dir/site.ext"
cat "$out_dir/site.crt" "$out_dir/rootCA.pem" > "$out_dir/site.fullchain.crt"
chmod 600 "$out_dir/rootCA.key" "$out_dir/site.key"

echo "Created certificates in $out_dir"
openssl x509 -in "$out_dir/rootCA.pem" -noout -fingerprint -sha256
