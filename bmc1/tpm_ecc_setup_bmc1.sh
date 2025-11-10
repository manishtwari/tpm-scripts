#!/bin/bash
set -e

# TPM ECC key + certificate setup for BMC1

# Handles
PRIMARY_HANDLE=0x81000011
SIGN_HANDLE=0x81000021

# NV index to store ONLY the  certificate (DER)
BMC1_CERT_NV_INDEX=0x1500032   # pick a different index than BMC0

# Device cleanup
tpm2_evictcontrol -C o -c $PRIMARY_HANDLE 
tpm2_evictcontrol -C o -c $SIGN_HANDLE   

mkdir -p /etc/tpm-demo/certs
cd /etc/tpm-demo/certs

# Create primary key (and persist it)
tpm2_createprimary -C o -G ecc -g sha256 -c primary_bmc1.ctx
tpm2_evictcontrol -C o -c primary_bmc1.ctx $PRIMARY_HANDLE 

# Create ECC signing key
tpm2_create -G ecc -g sha256 \
  -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|sign" \
  -C primary_bmc1.ctx -u bmc1.pub -r bmc1.priv

# Load and persist signing key
tpm2_load -C primary_bmc1.ctx -u bmc1.pub -r bmc1.priv -c bmc1_sign.ctx
tpm2_evictcontrol -C o -c bmc1_sign.ctx $SIGN_HANDLE 

# CA cert/key should be copied from BMC0 (kept on filesystem, NOT stored in TPM)
if [[ ! -f cacert.pem || ! -f cacert.key ]]; then
  echo "Missing CA cert/key. Please copy cacert.pem and cacert.key from BMC0 to /etc/tpm-demo/certs"
  exit 1
fi

# Create CSR using TPM key handle
openssl req -new \
  -provider tpm2 -provider default -propquery '?provider=tpm2' \
  -key "handle:$SIGN_HANDLE" \
  -subj "/C=IN/ST=KA/L=City/O=ExampleOrg/OU=TLS/CN=bmc1/emailAddress=abc@bmc.com" \
  -out bmc1.csr

# Sign  cert (on filesystem first)
openssl x509 -req -in bmc1.csr -CA cacert.pem -CAkey cacert.key \
  -CAcreateserial -out bmc1.crt -days 730 -sha256

# =========================================================
# Store ONLY the  certificate inside TPM NV RAM
# =========================================================
echo "Storing bmc1 certificate into TPM NV index $BMC1_CERT_NV_INDEX ..."

# Convert to DER for NV storage
openssl x509 -in bmc1.crt -outform der -out bmc1.crt.der
CERT_SIZE=$(stat -c%s bmc1.crt.der)

# Remove NV index if it already exists (idempotent)
tpm2_nvreadpublic $BMC1_CERT_NV_INDEX >/dev/null 2>&1 && \
  tpm2_nvundefine $BMC1_CERT_NV_INDEX -C o 

# Define NV space exactly sized for the cert and write it
tpm2_nvdefine $BMC1_CERT_NV_INDEX -C o -s $CERT_SIZE -a "ownerread|ownerwrite|authread|authwrite"
tpm2_nvwrite  $BMC1_CERT_NV_INDEX -C o -i bmc1.crt.der

# Optional verification: read back and print subject
tpm2_nvread $BMC1_CERT_NV_INDEX -C o -s $CERT_SIZE \
  | openssl x509 -inform der -noout -subject

echo "BMC1 setup complete"
echo "Primary Handle  : $PRIMARY_HANDLE"
echo "Sign Handle     : $SIGN_HANDLE"
echo "Cert NV Index   : $BMC1_CERT_NV_INDEX"
