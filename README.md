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

```shell
❯ openssl x509 -in intermediate.pem -text -noout

Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 2 (0x2)
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: CN=https://blah.com
        Validity
            Not Before: Nov  9 03:01:34 2024 GMT
            Not After : Nov  9 03:01:34 2124 GMT
        Subject: O=Liatrio, CN=Intermediate CA
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:58:3f:a0:c8:73:8f:d5:a2:12:4e:07:27:79:f2:
                    af:9f:98:ca:b2:ef:82:11:6a:2a:06:f5:42:29:cd:
                    7b:ef:58:a5:f5:70:b7:bf:aa:f3:82:28:86:58:11:
                    c8:31:e6:b9:85:3c:81:37:ff:68:5c:9d:a8:8a:64:
                    ea:30:04:3c:a3
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Basic Constraints: critical
                CA:FALSE
            X509v3 Subject Key Identifier:
                8C:64:41:D0:37:8D:E2:A2:40:4E:06:B0:12:1E:89:11:B0:0D:6C:A4
            X509v3 Authority Key Identifier:
                26:BE:D6:32:0C:AA:AC:28:CE:71:6B:F7:6A:F7:8B:06:E4:D7:DD:E3
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:46:02:21:00:b1:2a:35:9c:4f:87:70:30:66:14:27:78:19:
        b3:54:ca:8f:b6:4a:13:a2:3d:b8:ce:73:98:16:02:79:7f:2e:
        d9:02:21:00:e5:92:2f:c1:95:fb:2d:1c:f0:e8:18:41:c1:b8:
        bf:bb:9d:e6:a4:e8:39:b3:7b:7a:ad:98:34:93:ce:7d:e4:23
❯ openssl x509 -in root.pem -text -noout

Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 1 (0x1)
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: CN=https://blah.com
        Validity
            Not Before: Nov  9 03:01:34 2024 GMT
            Not After : Nov  9 03:01:34 2124 GMT
        Subject: CN=https://blah.com
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:39:d4:66:e5:d2:dd:44:93:38:c9:02:9e:96:84:
                    28:c9:48:bb:20:12:35:4b:23:ed:66:97:76:49:0f:
                    d2:83:5a:63:90:f7:88:a7:90:ab:d0:90:fd:fa:62:
                    83:16:5a:3b:d2:17:7a:20:6f:e6:d8:35:79:af:88:
                    b0:83:51:dc:b0
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Basic Constraints: critical
                CA:TRUE
            X509v3 Subject Key Identifier:
                26:BE:D6:32:0C:AA:AC:28:CE:71:6B:F7:6A:F7:8B:06:E4:D7:DD:E3
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:45:02:20:6b:54:22:d1:b2:2c:35:6f:09:0e:6c:4e:d1:e2:
        c7:c5:bf:93:e4:4b:b9:88:1c:f9:36:ee:85:ab:48:ce:e7:17:
        02:21:00:d3:de:5f:96:19:ba:cd:4a:59:93:31:e9:f8:84:66:
        c2:57:e4:34:78:89:d2:f1:1a:89:61:c9:a6:e1:f4:9a:9c
```
