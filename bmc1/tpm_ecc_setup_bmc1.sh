#!/bin/bash

# TPM ECC key + certificate setup for BMC1

# Device cleanup
tpm2_evictcontrol -C o -c 0x81000011
tpm2_evictcontrol -C o -c 0x81000021

cd /etc/tpm-demo/certs || mkdir -p /etc/tpm-demo/certs && cd /etc/tpm-demo/certs

# Create primary key
tpm2_createprimary -C o -G ecc -g sha256 -c primary_bmc1.ctx
tpm2_evictcontrol -C o -c primary_bmc1.ctx 0x81000011 || true

# Create ECC signing key
tpm2_create -G ecc -g sha256 \
  -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|sign" \
  -C primary_bmc1.ctx -u bmc1.pub -r bmc1.priv

# Load and persist
tpm2_load -C primary_bmc1.ctx -u bmc1.pub -r bmc1.priv -c bmc1_sign.ctx
tpm2_evictcontrol -C o -c bmc1_sign.ctx 0x81000021 || true

# Copy CA cert and key from BMC0 if not present
if [[ ! -f cacert.pem ]]; then
  echo "Missing CA cert, please copy cacert.pem and cacert.key from BMC0"
  exit 1
fi

# Create CSR
openssl req -new \
  -provider tpm2 -provider default -propquery '?provider=tpm2' \
  -key "handle:0x81000021" \
  -subj "/C=IN/ST=KA/L=City/O=ExampleOrg/OU=TLS/CN=bmc1/emailAddress=abc@bmc.com" \
  -out bmc1.csr

# Sign cert
openssl x509 -req -in bmc1.csr -CA cacert.pem -CAkey cacert.key \
  -CAcreateserial -out bmc1.crt -days 730 -sha256

echo "BMC1 setup complete"
echo "Primary Handle: 0x81000011"
echo "Sign Handle   : 0x81000021"