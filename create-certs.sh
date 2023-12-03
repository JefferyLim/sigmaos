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
openssl req -new -key certs/sigmaos.key -out certs/sigmaos.csr \
    -subj "/C=US/ST=Massachusetts/L=Cambridge/O=MIT/CN=sigmaos"
    
openssl x509 -req -in certs/sigmaos.csr -CA certs/rootCACert.pem -CAkey certs/rootCAKey.pem -CAcreatserial -out certs/sigmaos.crt -days 825 -sha256 -extfile <(printf "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:$(hostname -I | cut -d' ' -f1)")

export SIGMAROOTCA=`base64 -w 0 certs/rootCACert.pem`

