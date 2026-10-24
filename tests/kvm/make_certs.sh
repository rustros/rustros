#!/bin/bash
# Throwaway TLS material for the tests that serve HTTPS (sites_test.py,
# hot_test.py, curl_test.py): a test CA and a certificate for site.test,
# www.site.test, api.test and 10.0.2.2 (the host as QEMU's user network
# shows it to the VM), ECDSA P-256, valid 30 days, with the extensions strict X.509
# verification (Python 3.13's default) requires. Made fresh for every run, so no
# private key lives in the repository and none expires under the suite.
#
#   make_certs.sh DIR    -> DIR/panelmock/{ca.pem,ca.key,site.pem,site.key}
set -e
D=${1:?usage: make_certs.sh DIR}/panelmock
mkdir -p $D && cd $D
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out ca.key
openssl req -x509 -new -key ca.key -sha256 -days 30 -subj /CN=TestCA -out ca.pem \
    -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out site.key
openssl req -new -key site.key -subj /CN=site.test -out site.csr
printf "basicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:site.test,DNS:www.site.test,DNS:api.test,IP:10.0.2.2\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n" > site.ext
openssl x509 -req -in site.csr -CA ca.pem -CAkey ca.key -CAcreateserial -sha256 -days 30 -extfile site.ext -out site.pem 2>/dev/null
rm -f site.csr site.ext ca.srl
