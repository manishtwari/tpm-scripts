# TPM-based ECC mTLS Setup (BMC0 - BMC1)
This setup enables secure **mutual TLS (mTLS)** communication between two BMCs using **TPM-backed ECC keys** for certificate storage and signing.

All private keys remain protected inside the TPM.

- **BMC0** → acts as **Client**  
- **BMC1** → acts as **Server**


## Software Versions Used

tpm2-tss: 4.1.3
tpm2-tools: 5.7
tpm2-openssl: 1.3.0
stunnel: 5.75

To include these packages in your **Yocto build**, add the following line to your image recipe:
```
IMAGE_INSTALL:append = " tpm2-tools tpm2-openssl tpm2-tss libtss2-tcti-device stunnel"
```



# On BMC0
sudo bash setup_bmc0_ecc.sh

# Copy CA to BMC1
scp /etc/tpm-demo/certs/cacert.* root@<bmc1_ip>:/etc/tpm-demo/certs/

# On BMC1
sudo bash setup_bmc1_ecc.sh
