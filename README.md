# Sigstore Certificate Maker

A tool for creating certificate chains for Sigstore services (Fulcio and Timestamp Authority).

## Overview

This tool creates root and intermediate certificates for:

- Fulcio (Code Signing Certificate Authority)
- Timestamp Authority (RFC 3161 compliant)

## Requirements

- Access to one of the supported KMS providers (AWS, Google Cloud, Azure)
- Go 1.21 or higher

## Installation

```bash
go install github.com/liatrio/sigstore-certificate-maker@latest
```

## Local Development

Clone and build the project locally:

```bash
# Clone the repository
git clone https://github.com/liatrio/sigstore-certificate-maker.git

# Change to project directory
cd sigstore-certificate-maker

# Build the binary
go build -o sigstore-certificate-maker

# Run locally
./sigstore-certificate-maker create
```

For development, you can also use:

```bash
# Run directly with Go
go run main.go create

# Run tests
go test ./...
```

## Usage

The tool can be configured using either command-line flags or environment variables.

### Command-Line Interface

```shell
# Create certificates using default settings
sigstore-certificate-maker create

# Specify KMS provider and settings
sigstore-certificate-maker create \
  --kms-type cloudkms \
  --kms-key-id projects/my-project/locations/global/keyRings/my-ring/cryptoKeys/my-key \
  --kms-credentials-file /path/to/credentials.json

# Specify custom template paths
sigstore-certificate-maker create \
  --root-template path/to/root.json \
  --intermediate-template path/to/intermediate.json
```

Available flags:

- `--kms-type`: KMS provider type (awskms, cloudkms, azurekms)
- `--kms-region`: KMS region (required for AWS KMS)
- `--kms-key-id`: Key identifier
- `--kms-vault-name`: Azure KMS vault name
- `--kms-tenant-id`: Azure KMS tenant ID
- `--kms-credentials-file`: Path to credentials file (for Google Cloud KMS)
- `--root-template`: Path to root certificate template
- `--intermediate-template`: Path to intermediate certificate template

### Environment Variables

- `KMS_TYPE`: KMS provider type ("awskms", "cloudkms", "azurekms")
- `KMS_REGION`: Region (required for AWS KMS, defaults to us-east-1)
- `KMS_KEY_ID`: Key identifier
  - AWS: Key alias (default: alias/fulcio-key)
  - Google Cloud: Full resource name (projects/_/locations/_/keyRings/_/cryptoKeys/_)
  - Azure: Key name
- `KMS_OPTIONS`: Provider-specific options
  - Google Cloud: credentials-file
  - Azure: vault-name, tenant-id

### Provider-Specific Configuration Examples

#### AWS KMS

```shell
export KMS_TYPE=awskms
export KMS_REGION=us-east-1
export KMS_KEY_ID=alias/fulcio-key
```

#### Google Cloud KMS

```shell
export KMS_TYPE=cloudkms
export KMS_KEY_ID=projects/my-project/locations/global/keyRings/my-ring/cryptoKeys/my-key
export KMS_OPTIONS_CREDENTIALS_FILE=/path/to/credentials.json
```

#### Azure KMS

```shell
export KMS_TYPE=azurekms
export KMS_KEY_ID=my-key
export KMS_OPTIONS_VAULT_NAME=my-vault
export KMS_OPTIONS_TENANT_ID=tenant-id
```

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

```bash
# Basic usage with default settings
sigstore-certificate-maker create

# Using AWS KMS with custom templates
sigstore-certificate-maker create \
  --kms-type awskms \
  --kms-region us-east-1 \
  --kms-key-id alias/fulcio-key \
  --root-template path/to/root.json \
  --intermediate-template path/to/intermediate.json
```

### Configuration Precedence

The tool uses the following precedence order for configuration:

1. Command-line flags (highest priority)
2. Environment variables
3. Default values (lowest priority)
