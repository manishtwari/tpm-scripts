#!/bin/bash

# TPM ECC key + certificate setup for BMC0

# Device cleanup
tpm2_evictcontrol -C o -c 0x81000010
tpm2_evictcontrol -C o -c 0x81000020

cd /etc/tpm-demo/certs || mkdir -p /etc/tpm-demo/certs && cd /etc/tpm-demo/certs

# Create primary key
tpm2_createprimary -C o -G ecc -g sha256 -c primary_bmc0.ctx
tpm2_evictcontrol -C o -c primary_bmc0.ctx 0x81000010 || true

# Create ECC signing key
tpm2_create -G ecc -g sha256 \
  -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|sign" \
  -C primary_bmc0.ctx -u bmc0.pub -r bmc0.priv

# Load and persist
tpm2_load -C primary_bmc0.ctx -u bmc0.pub -r bmc0.priv -c bmc0_sign.ctx
tpm2_evictcontrol -C o -c bmc0_sign.ctx 0x81000020 || true

# Create CA if not present
if [[ ! -f cacert.pem ]]; then
  openssl ecparam -name prime256v1 -genkey -noout -out cacert.key
  openssl req -x509 -new -nodes -key cacert.key \
    -subj "/C=IN/ST=KA/L=City/O=ExampleOrg/OU=Security/CN=rootca/emailAddress=abc@bmc.com" \
    -days 1825 -sha256 -out cacert.pem
fi

# Create CSR
openssl req -new \
  -provider tpm2 -provider default -propquery '?provider=tpm2' \
  -key "handle:0x81000020" \
  -subj "/C=IN/ST=KA/L=City/O=ExampleOrg/OU=TLS/CN=bmc0/emailAddress=abc@bmc.com" \
  -out bmc0.csr

# Sign cert
openssl x509 -req -in bmc0.csr -CA cacert.pem -CAkey cacert.key \
  -CAcreateserial -out bmc0.crt -days 730 -sha256

echo "BMC0 setup complete"
echo "Primary Handle: 0x81000010"
echo "Sign Handle   : 0x81000020"