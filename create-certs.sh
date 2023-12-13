#!/bin/bash

mkdir -p certs/

# Create private root key
openssl genrsa -out certs/rootCAKey.pem 2048

# Create a root certificate
openssl req -x509 -sha256 -new -nodes -key certs/rootCAKey.pem -days 3650 -out certs/rootCACert.pem \
    -subj "/C=US/ST=Massachusetts/L=Cambridge/O=MIT/CN=sigmaos"

# Print certificate
# openssl x509 -in rootCACert.pem -text


# Generate sigmaos key and certificate
openssl genrsa -out certs/sigmaos.key 2048
openssl req -new -key certs/sigmaos.key \
    -subj "/C=US/ST=Massachusetts/L=Cambridge/O=MIT/CN=sigmaos" \
    -out certs/sigmaos.csr \

CONFIG="
[ v3_ca ]
subjectAltName=DNS:localhost,IP:127.0.0.1,IP:$(hostname -I | cut -d' ' -f1)
basicConstraints = critical,CA:TRUE,pathlen:1
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer:always"

openssl x509 -req -extensions v3_ca -in certs/sigmaos.csr -CA certs/rootCACert.pem -CAkey certs/rootCAKey.pem -CAcreatserial -out certs/sigmaos.crt -days 825 -sha256  -extfile <(printf "$CONFIG")

CERTS="$(cat certs/rootCACert.pem certs/sigmaos.crt)"

export SIGMAROOTCA=`base64 -w 0 <<< $CERTS`

