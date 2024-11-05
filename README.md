---

<p align="center">
  <a href="https://github.com/liatrio/go-template/actions/workflows/build.yml?query=branch%3Amain">
    <img alt="Build Status" src="https://img.shields.io/github/actions/workflow/status/liatrio/go-template/build.yml?branch=main&style=for-the-badge">
  </a>
  <a href="https://goreportcard.com/report/github.com/liatrio/go-template">
    <img alt="Go Report Card" src="https://goreportcard.com/badge/github.com/liatrio/go-template?style=for-the-badge">
  </a>
  <a href="https://codecov.io/gh/liatrio/go-template/branch/main" >
    <img alt="Codecov Status" src="https://img.shields.io/codecov/c/github/liatrio/go-template?style=for-the-badge"/>
  </a>
  <a href="https://github.com/liatrio/go-template/releases">
    <img alt="GitHub release" src="https://img.shields.io/github/v/release/liatrio/go-template?include_prereleases&style=for-the-badge">
  </a>
  <a href="https://api.securityscorecards.dev/projects/github.com/liatrio/go-template/badge">
    <img alt="OpenSSF Scorecard" src="https://img.shields.io/ossf-scorecard/github.com/liatrio/go-template?label=openssf%20scorecard&style=for-the-badge">
  </a>
</p>

---

# go-template

## Quick Start Guide

Here are the steps to quickly get started with this project:

### MacOS

Presuming you have [homebrew](https://brew.sh) installed:

1. Run `brew bundle` to install `go` and `taskfile`
2. Run `make` to run core build requirements
4. Run `make check` to run core build requirements
5. Run `pre-commit install` to install the pre-commits
6. #ShipIt

```
❯ openssl x509 -in root.pem -text -noout

Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 1 (0x1)
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: O=Liatrio, CN=Root CA
        Validity
            Not Before: Nov  8 20:57:40 2024 GMT
            Not After : Nov  8 20:57:40 2124 GMT
        Subject: O=Liatrio, CN=Root CA
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:29:7c:ff:0b:4d:d2:bc:d1:38:ac:3c:13:ce:44:
                    be:ef:6e:55:6c:8b:c3:96:82:e5:93:69:02:6f:99:
                    71:dd:f7:77:35:9e:be:ed:f7:0d:50:78:b8:73:d2:
                    2d:27:c5:ed:00:7c:c2:9f:8e:b2:0e:ae:6f:b4:f0:
                    93:93:40:82:cc
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Basic Constraints: critical
                CA:TRUE, pathlen:1
            X509v3 Subject Key Identifier:
                C7:C6:B6:50:D8:DD:25:9E:3E:E8:E6:69:B6:A6:4F:E9:8B:CD:EE:AB
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:45:02:20:76:3d:59:0b:c4:9d:22:7b:62:65:ad:11:21:01:
        57:d1:c2:93:6f:f5:c0:cc:8f:3d:e1:c3:6d:56:73:f9:68:bd:
        02:21:00:f8:4a:ee:6a:c6:8e:67:8e:99:99:a4:03:2f:fb:86:
        56:a7:22:d0:55:b5:02:80:1c:55:51:48:01:13:eb:2a:37
❯ openssl x509 -in intermediate.pem -text -noout

Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 2 (0x2)
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: O=Liatrio, CN=Root CA
        Validity
            Not Before: Nov  8 20:57:40 2024 GMT
            Not After : Nov  8 20:57:40 2124 GMT
        Subject: O=Liatrio, CN=Intermediate CA
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:e4:62:14:b0:04:ba:96:0d:67:ef:d8:e8:ff:89:
                    14:14:61:25:4f:24:e4:89:fc:e0:a9:a4:05:78:45:
                    c9:df:9c:be:82:55:b1:7d:45:3d:c7:e0:2c:e2:cc:
                    30:bb:f3:27:f4:8b:5a:d0:f4:28:48:03:9e:04:b9:
                    98:50:4d:6e:c7
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Basic Constraints: critical
                CA:TRUE
            X509v3 Subject Key Identifier:
                47:AC:5E:38:57:F3:4E:A2:BC:BC:CB:4C:D0:9C:DB:F0:A5:F8:40:53
            X509v3 Authority Key Identifier:
                C7:C6:B6:50:D8:DD:25:9E:3E:E8:E6:69:B6:A6:4F:E9:8B:CD:EE:AB
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:45:02:20:5d:9c:ec:be:c6:04:79:e5:54:3c:2a:23:10:78:
        d3:31:b3:3a:7e:db:e1:09:6a:c6:e4:b7:63:7a:dd:8e:96:4d:
        02:21:00:81:c2:3c:d3:ae:77:dd:f5:c0:9a:72:e4:1d:04:ff:
        7d:51:a7:21:2d:6e:24:79:b6:d5:19:4e:73:13:51:eb:6f
```
