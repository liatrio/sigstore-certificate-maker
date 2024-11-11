# Sigstore Certificate Maker

A tool for creating certificate chains for Sigstore services (Fulcio and Timestamp Authority).

## Overview

This tool creates root and intermediate certificates for:

- Fulcio (Code Signing Certificate Authority)
- Timestamp Authority (RFC 3161 compliant)

## Requirements

- AWS KMS access
- Go 1.21 or higher

## Usage

### Environment Variables

- `AWS_REGION`: AWS region (default: us-east-1)
- `AWS_KMS_KEY_ALIAS`: KMS key alias (default: alias/fulcio-key)

### Templates

The tool uses JSON templates to define certificate properties:

#### Fulcio Intermediate Template

```json
{
    "subject": {
        "commonName": "fulcio.example.com"
    },
    "issuer": {
        "commonName": "fulcio.example.com"
    },
    "keyUsage": ["certSign", "crlSign"],
    "extKeyUsage": ["codeSign"],
    "basicConstraints": {
        "isCA": true,
        "maxPathLen": 0
    }
}
```

#### Root CA Template

```json
{
    "subject": {
        "commonName": "https://blah.com"
    },
    "issuer": {
        "commonName": "https://blah.com"
    },
    "keyUsage": ["certSign", "crlSign"],
    "basicConstraints": {
        "isCA": true,
        "maxPathLen": 0
    }
}
```

#### TSA Intermediate Template

```json
{
    "subject": {
        "commonName": "tsa.example.com"
    },
    "issuer": {
        "commonName": "tsa.example.com"
    },
    "keyUsage": ["certSign", "crlSign"],
    "basicConstraints": {
        "isCA": false
    },
    "extensions": [
        {
            "id": "2.5.29.37",
            "critical": true,
            "value": "asn1Seq (asn1Enc oid:1.3.6.1.5.5.7.3.8) | toJson"
        }
    ]
}
```

### Example Certificate Outputs

#### Root CA Certificate

```text
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 1 (0x1)
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: CN=https://blah.com
        Subject: CN=https://blah.com
        X509v3 extensions:
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Basic Constraints: critical
                CA:TRUE
```

#### TSA Intermediate Certificate

```text
Certificate:
    Data:
        Version: 3 (0x2)
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: CN=https://blah.com
        Subject: O=Liatrio, CN=Intermediate CA
        X509v3 extensions:
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Basic Constraints: critical
                CA:FALSE
```

#### Fulcio Intermediate Certificate

```text
Certificate:
    Data:
        Version: 3 (0x2)
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: CN=https://blah.com
        Subject: CN=fulcio.example.com
        X509v3 extensions:
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Basic Constraints: critical
                CA:TRUE, pathlen:0
            X509v3 Extended Key Usage:
                Code Signing
```

## Running the Tool

```shell
# Using default template paths
go run main.go

# Using custom template paths
go run main.go path/to/root.json path/to/intermediate.json
```

## References

- [Fulcio Issue #1178](https://github.com/sigstore/fulcio/issues/1178)
- [Scaffolding Issue #1334](https://github.com/sigstore/scaffolding/issues/1334)
- [Helm Charts Issue #863](https://github.com/sigstore/helm-charts/issues/863)
