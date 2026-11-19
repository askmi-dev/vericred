#!/usr/bin/env sh
# Regenerates the TEST-ONLY X.509 fixtures for x5c.test.ts.
# root (self-signed trust anchor) -> intermediate CA -> issuer leaf.
# These keys are public test material. Never use them for a real issuer.
set -eu
cd "$(dirname "$0")"

curve="-newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes"

openssl req -x509 $curve -keyout root.key -out root.pem -days 36500 \
  -subj "/CN=VeriCred Test Root" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign"

openssl req $curve -keyout intermediate.key -out intermediate.csr -subj "/CN=VeriCred Test Intermediate"
printf 'basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\n' > ca.ext
openssl x509 -req -in intermediate.csr -CA root.pem -CAkey root.key -CAcreateserial \
  -out intermediate.pem -days 36500 -extfile ca.ext

openssl req $curve -keyout leaf.key -out leaf.csr -subj "/CN=issuer.example.test"
printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nsubjectAltName=URI:https://issuer.example.test,DNS:issuer.example.test\n' > leaf.ext
openssl x509 -req -in leaf.csr -CA intermediate.pem -CAkey intermediate.key -CAcreateserial \
  -out leaf.pem -days 36500 -extfile leaf.ext

cat leaf.pem intermediate.pem > chain.pem
rm -f ./*.csr ./*.ext ./*.srl root.key intermediate.key
