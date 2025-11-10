#!/bin/bash
set -e

# TPM ECC key + certificate setup for BMC0

# Handles
PRIMARY_HANDLE=0x81000010
SIGN_HANDLE=0x81000020

# NV index to store ONLY the  certificate (DER)
BMC0_CERT_NV_INDEX=0x1500022

# Device cleanup (make idempotent)
tpm2_evictcontrol -C o -c $PRIMARY_HANDLE 
tpm2_evictcontrol -C o -c $SIGN_HANDLE 

mkdir -p /etc/tpm-demo/certs
cd /etc/tpm-demo/certs

# Create primary key (and persist it)
tpm2_createprimary -C o -G ecc -g sha256 -c primary_bmc0.ctx
tpm2_evictcontrol -C o -c primary_bmc0.ctx $PRIMARY_HANDLE 

# Create ECC signing key (child under primary)
tpm2_create -G ecc -g sha256 \
  -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|sign" \
  -C primary_bmc0.ctx -u bmc0.pub -r bmc0.priv

# Load and persist signing key
tpm2_load -C primary_bmc0.ctx -u bmc0.pub -r bmc0.priv -c bmc0_sign.ctx
tpm2_evictcontrol -C o -c bmc0_sign.ctx $SIGN_HANDLE 

# Create CA if not present (kept on filesystem, NOT stored in TPM)
if [[ ! -f cacert.pem ]]; then
  openssl ecparam -name prime256v1 -genkey -noout -out cacert.key
  openssl req -x509 -new -nodes -key cacert.key \
    -subj "/C=IN/ST=KA/L=City/O=ExampleOrg/OU=Security/CN=rootca/emailAddress=abc@bmc.com" \
    -days 1825 -sha256 -out cacert.pem
fi

# Create CSR using TPM key handle
openssl req -new \
  -provider tpm2 -provider default -propquery '?provider=tpm2' \
  -key "handle:$SIGN_HANDLE" \
  -subj "/C=IN/ST=KA/L=City/O=ExampleOrg/OU=TLS/CN=bmc0/emailAddress=abc@bmc.com" \
  -out bmc0.csr

# Sign cert ( cert on filesystem first)
openssl x509 -req -in bmc0.csr -CA cacert.pem -CAkey cacert.key \
  -CAcreateserial -out bmc0.crt -days 730 -sha256

# =========================================================
# Store ONLY the  certificate inside TPM NV RAM
# =========================================================
echo "Storing bmc0 certificate into TPM NV index $BMC0_CERT_NV_INDEX ..."

# Convert to DER (recommended for NV storage)
openssl x509 -in bmc0.crt -outform der -out bmc0.crt.der

CERT_SIZE=$(stat -c%s bmc0.crt.der)

# Remove NV index if it already exists (idempotent)
tpm2_nvreadpublic $BMC0_CERT_NV_INDEX >/dev/null 2>&1 && \
  tpm2_nvundefine $BMC0_CERT_NV_INDEX -C o 

# Define NV space exactly sized for the cert and write it
tpm2_nvdefine $BMC0_CERT_NV_INDEX -C o -s $CERT_SIZE -a "ownerread|ownerwrite|authread|authwrite"
tpm2_nvwrite  $BMC0_CERT_NV_INDEX -C o -i bmc0.crt.der

# (Optional) quick verification: read back and print subject
tpm2_nvread $BMC0_CERT_NV_INDEX -C o -s $CERT_SIZE \
  | openssl x509 -inform der -noout -subject

echo "BMC0 setup complete"
echo "Primary Handle  : $PRIMARY_HANDLE"
echo "Sign Handle     : $SIGN_HANDLE"
echo "Cert NV Index   : $BMC0_CERT_NV_INDEX"
