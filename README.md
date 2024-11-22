# Sigstore Certificate Maker

A tool for creating certificate chains for Sigstore services (Fulcio and Timestamp Authority).

## Overview

This tool creates root and intermediate certificates for:

- Fulcio (Code Signing Certificate Authority)
- Timestamp Authority (RFC 3161 compliant)

## Requirements

- Access to one of the supported KMS providers (AWS, Google Cloud, Azure)
- Pre-existing KMS keys (the tool uses existing keys and does not create new ones)
- Go 1.21 or higher

## Local Development

Clone and build the project locally:

```bash
# Clone the repository
git clone https://github.com/liatrio/sigstore-certificate-maker.git

# Change to project directory
cd sigstore-certificate-maker

# Build the binary
go build -o sigstore-certificate-maker
```

## Usage

The tool can be configured using either command-line flags or environment variables.

### Command-Line Interface

Available flags:

- `--kms-type`: KMS provider type (awskms, cloudkms, azurekms)
- `--kms-region`: KMS region (required for AWS KMS)
- `--root-key-id`: KMS key identifier for root certificate
- `--intermediate-key-id`: KMS key identifier for intermediate certificate
- `--kms-vault-name`: Azure KMS vault name
- `--kms-tenant-id`: Azure KMS tenant ID
- `--kms-credentials-file`: Path to credentials file (for Google Cloud KMS)
- `--root-template`: Path to root certificate template
- `--intermediate-template`: Path to intermediate certificate template
- `--root-cert`: Output path for root certificate (default: root.pem)
- `--intermediate-cert`: Output path for intermediate certificate (default: intermediate.pem)

### Environment Variables

- `KMS_TYPE`: KMS provider type ("awskms", "cloudkms", "azurekms")
- `KMS_REGION`: Region (required for AWS KMS, defaults to us-east-1)
- `ROOT_KEY_ID`: Key identifier for root certificate
- `INTERMEDIATE_KEY_ID`: Key identifier for intermediate certificate
- `KMS_VAULT_NAME`: Azure Key Vault name
- `KMS_TENANT_ID`: Azure tenant ID
- `KMS_CREDENTIALS_FILE`: Path to credentials file (for Google Cloud KMS)

### Provider-Specific Configuration Examples

#### AWS KMS

```shell
export KMS_TYPE=awskms
export KMS_REGION=us-east-1
export ROOT_KEY_ID=alias/fulcio-root
export INTERMEDIATE_KEY_ID=alias/fulcio-intermediate
```

#### Google Cloud KMS

```shell
export KMS_TYPE=cloudkms
export ROOT_KEY_ID=projects/my-project/locations/global/keyRings/my-ring/cryptoKeys/root-key
export INTERMEDIATE_KEY_ID=projects/my-project/locations/global/keyRings/my-ring/cryptoKeys/intermediate-key
export KMS_CREDENTIALS_FILE=/path/to/credentials.json
```

#### Azure KMS

```shell
export KMS_TYPE=azurekms
export ROOT_KEY_ID=root-key
export INTERMEDIATE_KEY_ID=intermediate-key
export KMS_VAULT_NAME=my-vault
export KMS_TENANT_ID=tenant-id
```

### Example Templates

#### Fulcio Root Template

```json
{
  "subject": {
    "country": ["US"],
    "organization": ["Sigstore"],
    "organizationalUnit": ["Fulcio Root CA"],
    "commonName": "https://fulcio.com"
  },
  "issuer": {
    "commonName": "https://fulcio.com"
  },
  "notBefore": "2024-01-01T00:00:00Z",
  "notAfter": "2034-01-01T00:00:00Z",
  "basicConstraints": {
    "isCA": true,
    "maxPathLen": 1
  },
  "keyUsage": [
    "certSign",
    "crlSign"
  ],
  "extKeyUsage": [
    "CodeSigning"
  ]
}
```

#### Fulcio Intermediate Template

```json
{
  "subject": {
    "country": ["US"],
    "organization": ["Sigstore"],
    "organizationalUnit": ["Fulcio Intermediate CA"],
    "commonName": "https://fulcio.com"
  },
  "issuer": {
    "commonName": "https://fulcio.com"
  },
  "notBefore": "2024-01-01T00:00:00Z",
  "notAfter": "2034-01-01T00:00:00Z",
  "serialNumber": 2,
  "basicConstraints": {
    "isCA": true,
    "maxPathLen": 0
  },
  "keyUsage": [
    "certSign",
    "crlSign",
    "digitalSignature"
  ],
  "extKeyUsage": [
    "CodeSigning"
  ]
}
```

#### TSA Root Template

```json
{
  "subject": {
    "country": ["US"],
    "organization": ["Sigstore"],
    "organizationalUnit": ["Timestamp Authority Root CA"],
    "commonName": "https://tsa.com"
  },
  "issuer": {
    "commonName": "https://tsa.com"
  },
  "notBefore": "2024-01-01T00:00:00Z",
  "notAfter": "2034-01-01T00:00:00Z",
  "basicConstraints": {
    "isCA": true,
    "maxPathLen": 1
  },
  "keyUsage": [
    "certSign",
    "crlSign"
  ]
}
```

#### TSA Intermediate Template

```json
{
  "subject": {
    "country": ["US"],
    "organization": ["Sigstore"],
    "organizationalUnit": ["Timestamp Authority Intermediate CA"],
    "commonName": "https://tsa.com"
  },
  "issuer": {
    "commonName": "https://tsa.com"
  },
  "notBefore": "2024-01-01T00:00:00Z",
  "notAfter": "2034-01-01T00:00:00Z",
  "serialNumber": 2,
  "basicConstraints": {
    "isCA": false,
    "maxPathLen": 0
  },
  "keyUsage": [
    "digitalSignature"
  ],
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
        Issuer: C=US, O=Sigstore, OU=Fulcio Root CA, CN=https://fulcio.com
        Subject: C=US, O=Sigstore, OU=Fulcio Root CA, CN=https://fulcio.com
        X509v3 extensions:
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Basic Constraints: critical
                CA:TRUE, pathlen:1
            X509v3 Extended Key Usage:
                Code Signing
```

#### TSA Intermediate Certificate

```text
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 2 (0x2)
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: C=US, O=Sigstore, OU=Timestamp Authority Root CA, CN=https://tsa.com
        Subject: C=US, O=Sigstore, OU=Timestamp Authority Intermediate CA, CN=https://tsa.com
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature
            X509v3 Basic Constraints: critical
                CA:FALSE
            X509v3 Extended Key Usage: critical
                Time Stamping
```

#### Fulcio Intermediate Certificate

```text
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 2 (0x2)
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: C=US, O=Sigstore, OU=Fulcio Root CA, CN=https://fulcio.com
        Subject: C=US, O=Sigstore, OU=Fulcio Intermediate CA, CN=https://fulcio.com
        X509v3 extensions:
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign, Digital Signature
            X509v3 Basic Constraints: critical
                CA:TRUE, pathlen:0
            X509v3 Extended Key Usage:
                Code Signing
```

## Running the Tool

Example for Fulcio with AWS KMS:

```bash
sigstore-certificate-maker create \
  --kms-type awskms \
  --kms-region us-east-1 \
  --root-key-id alias/fulcio-root \
  --intermediate-key-id alias/fulcio-intermediate \
  --root-template fulcio-root-template.json \
  --intermediate-template fulcio-intermediate-template.json
```

Example for TSA with Azure KMS:

```bash
sigstore-certificate-maker create \
  --kms-type azurekms \
  --kms-vault-name my-vault \
  --kms-tenant-id tenant-id \
  --root-key-id tsa-root \
  --intermediate-key-id tsa-intermediate \
  --root-template tsa-root-template.json \
  --intermediate-template tsa-intermediate-template.json
```

[![Build and Test](https://github.com/{owner}/{repo}/actions/workflows/build.yml/badge.svg)](https://github.com/{owner}/{repo}/actions/workflows/build.yml)
