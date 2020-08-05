# generate key
docker trust key generate fariha

# add public key to Notary server
docker trust signer add --key cert.pem fariha [IMAGE]

# sign with private key and push specific tag to registry
docker trust sign [IMAGE]:[TAG]
