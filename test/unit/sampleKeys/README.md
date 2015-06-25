Key generation
=================

### Private Key:

```sh
openssl genrsa -out privateKey.pem 512
```

### Public Key:

```sh
openssl rsa -in privateKey.pem -pubout > publicKey.pem
```
