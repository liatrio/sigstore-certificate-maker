package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.step.sm/crypto/kms/apiv1"
	"go.step.sm/crypto/x509util"
)

// mockKMS provides an in-memory KMS for testing
type mockKMS struct {
	keys    map[string]*ecdsa.PrivateKey
	signers map[string]crypto.Signer
}

func newMockKMS() *mockKMS {
	m := &mockKMS{
		keys:    make(map[string]*ecdsa.PrivateKey),
		signers: make(map[string]crypto.Signer),
	}

	// Pre-create test keys
	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	intermediateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	m.keys["root-key"] = rootKey
	m.keys["intermediate-key"] = intermediateKey

	return m
}

func (m *mockKMS) CreateSigner(req *apiv1.CreateSignerRequest) (crypto.Signer, error) {
	key, ok := m.keys[req.SigningKey]
	if !ok {
		return nil, fmt.Errorf("key not found: %s", req.SigningKey)
	}
	m.signers[req.SigningKey] = key
	return key, nil
}

func (m *mockKMS) GetPublicKey(req *apiv1.GetPublicKeyRequest) (crypto.PublicKey, error) {
	key, ok := m.keys[req.Name]
	if !ok {
		return nil, fmt.Errorf("key not found: %s", req.Name)
	}
	return key.Public(), nil
}

func (m *mockKMS) Close() error {
	return nil
}

func (m *mockKMS) CreateKey(req *apiv1.CreateKeyRequest) (*apiv1.CreateKeyResponse, error) {
	return nil, fmt.Errorf("CreateKey is not supported in mockKMS")
}

// TestParseTemplate tests JSON template parsing
func TestParseTemplate(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "cert-template-*.json")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())

	templateContent := `{
		"subject": {
			"commonName": "Test CA"
		},
		"issuer": {
			"commonName": "Test CA"
		},
		"keyUsage": [
			"certSign",
			"crlSign"
		],
		"basicConstraints": {
			"isCA": true,
			"maxPathLen": 0
		},
		"notBefore": "2024-01-01T00:00:00Z",
		"notAfter": "2025-01-01T00:00:00Z"
	}`

	err = os.WriteFile(tmpFile.Name(), []byte(templateContent), 0600)
	require.NoError(t, err)

	tmpl, err := ParseTemplate(tmpFile.Name(), nil)
	require.NoError(t, err)
	assert.Equal(t, "Test CA", tmpl.Subject.CommonName)
	assert.True(t, tmpl.IsCA)
	assert.Equal(t, 0, tmpl.MaxPathLen)
}

// TestCreateCertificates tests certificate chain creation
func TestCreateCertificates(t *testing.T) {
	t.Run("Fulcio", func(t *testing.T) {
		tmpDir, err := os.MkdirTemp("", "cert-test-fulcio-*")
		require.NoError(t, err)
		t.Cleanup(func() { os.RemoveAll(tmpDir) })

		// Root template (same for both)
		rootContent := `{
			"subject": {
				"commonName": "https://blah.com"
			},
			"issuer": {
				"commonName": "https://blah.com"
			},
			"keyUsage": [
				"certSign",
				"crlSign"
			],
			"extKeyUsage": [
				"CodeSigning"
			],
			"basicConstraints": {
				"isCA": true,
				"maxPathLen": 0
			},
			"notBefore": "2024-01-01T00:00:00Z",
			"notAfter": "2025-01-01T00:00:00Z"
		}`

		// Fulcio intermediate template
		intermediateContent := `{
			"subject": {
				"commonName": "https://blah.com"
			},
			"issuer": {
				"commonName": "https://blah.com"
			},
			"keyUsage": [
				"certSign",
				"crlSign"
			],
			"extKeyUsage": [
				"CodeSigning"
			],
			"basicConstraints": {
				"isCA": true,
				"maxPathLen": 0
			},
			"notBefore": "2024-01-01T00:00:00Z",
			"notAfter": "2025-01-01T00:00:00Z"
		}`

		testCertificateCreation(t, tmpDir, rootContent, intermediateContent)
	})

	t.Run("TSA", func(t *testing.T) {
		tmpDir, err := os.MkdirTemp("", "cert-test-tsa-*")
		require.NoError(t, err)
		t.Cleanup(func() { os.RemoveAll(tmpDir) })

		// Root template (same for both)
		rootContent := `{
			"subject": {
				"commonName": "https://blah.com"
			},
			"issuer": {
				"commonName": "https://blah.com"
			},
			"keyUsage": [
				"certSign",
				"crlSign"
			],
			"extKeyUsage": [
				"CodeSigning"
			],
			"basicConstraints": {
				"isCA": true,
				"maxPathLen": 0
			},
			"notBefore": "2024-01-01T00:00:00Z",
			"notAfter": "2025-01-01T00:00:00Z"
		}`

		// TSA intermediate template
		intermediateContent := `{
			"subject": {
				"commonName": "https://blah.com"
			},
			"issuer": {
				"commonName": "https://blah.com"
			},
			"keyUsage": [
				"certSign",
				"crlSign"
			],
			"basicConstraints": {
				"isCA": false
			},
			"extensions": [
				{
					"id": "2.5.29.37",
					"critical": true,
					"value": "asn1Seq (asn1Enc oid:1.3.6.1.5.5.7.3.8) | toJson"
				}
			],
			"notBefore": "2024-01-01T00:00:00Z",
			"notAfter": "2025-01-01T00:00:00Z"
		}`

		testCertificateCreation(t, tmpDir, rootContent, intermediateContent)
	})
}

// TestWriteCertificateToFile tests PEM file writing
func TestWriteCertificateToFile(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "cert-write-test-*")
	require.NoError(t, err)
	t.Cleanup(func() { os.RemoveAll(tmpDir) })

	km := newMockKMS()
	signer, err := km.CreateSigner(&apiv1.CreateSignerRequest{
		SigningKey: "root-key",
	})
	require.NoError(t, err)

	template := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "Test Cert",
		},
	}

	cert, err := x509util.CreateCertificate(template, template, signer.Public(), signer)
	require.NoError(t, err)

	testFile := filepath.Join(tmpDir, "test-cert.pem")
	err = writeCertificateToFile(cert, testFile)
	require.NoError(t, err)

	content, err := os.ReadFile(testFile)
	require.NoError(t, err)

	block, _ := pem.Decode(content)
	require.NotNil(t, block)
	assert.Equal(t, "CERTIFICATE", block.Type)

	parsedCert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	assert.Equal(t, "Test Cert", parsedCert.Subject.CommonName)
}

// testCertificateCreation creates and verifies certificate chains
func testCertificateCreation(t *testing.T, tmpDir, rootContent, intermediateContent string) {
	rootTmplPath := filepath.Join(tmpDir, "root-template.json")
	intermediateTmplPath := filepath.Join(tmpDir, "intermediate-template.json")
	rootCertPath := filepath.Join(tmpDir, "root.pem")
	intermediateCertPath := filepath.Join(tmpDir, "intermediate.pem")

	err := os.WriteFile(rootTmplPath, []byte(rootContent), 0600)
	require.NoError(t, err)

	err = os.WriteFile(intermediateTmplPath, []byte(intermediateContent), 0600)
	require.NoError(t, err)

	km := newMockKMS()
	config := KMSConfig{
		Type:              "mockkms",
		RootKeyID:         "root-key",
		IntermediateKeyID: "intermediate-key",
		Options:           make(map[string]string),
	}

	err = createCertificates(km, config, rootTmplPath, intermediateTmplPath, rootCertPath, intermediateCertPath)
	require.NoError(t, err)
}

func TestValidateKMSConfig(t *testing.T) {
	tests := []struct {
		name    string
		config  KMSConfig
		wantErr bool
	}{
		{
			name: "valid azure config",
			config: KMSConfig{
				Type:              "azurekms",
				RootKeyID:         "root-key",
				IntermediateKeyID: "intermediate-key",
				Options: map[string]string{
					"vault-name": "test-vault",
					"tenant-id":  "test-tenant",
				},
			},
			wantErr: false,
		},
		{
			name: "missing key IDs",
			config: KMSConfig{
				Type: "azurekms",
				Options: map[string]string{
					"vault-name": "test-vault",
					"tenant-id":  "test-tenant",
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateKMSConfig(tt.config)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
