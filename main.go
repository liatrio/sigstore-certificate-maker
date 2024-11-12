// Package main provides certificate creation utilities for Sigstore services
package main

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"

	"go.step.sm/crypto/kms/apiv1"
	"go.step.sm/crypto/kms/awskms"
	"go.step.sm/crypto/x509util"
	"go.uber.org/zap"
)

var (
	logger *zap.Logger
)

func init() {
	rawJSON := []byte(`{
		"level": "debug",
		"encoding": "json",
		"outputPaths": ["stdout"],
		"errorOutputPaths": ["stderr"],
		"initialFields": {"service": "sigstore-certificate-maker"},
		"encoderConfig": {
			"messageKey": "message",
			"levelKey": "level",
			"levelEncoder": "lowercase",
			"timeKey": "timestamp",
			"timeEncoder": "iso8601"
		}
	}`)

	var cfg zap.Config
	if err := json.Unmarshal(rawJSON, &cfg); err != nil {
		panic(err)
	}

	logger = zap.Must(cfg.Build())
}

func initKMS(ctx context.Context, region, keyID string) (apiv1.KeyManager, error) {
	opts := apiv1.Options{
		Type: "awskms",
		URI:  fmt.Sprintf("awskms:///%s?region=%s", keyID, region),
	}
	return awskms.New(ctx, opts)
}

// createCertificates generates a certificate chain using AWS KMS
func createCertificates(km apiv1.KeyManager, rootTemplatePath, intermediateTemplatePath string) error {
	// Parse templates
	rootTmpl, err := parseTemplate(rootTemplatePath, nil)
	if err != nil {
		return fmt.Errorf("error parsing root template: %w", err)
	}

	// Generate root key pair
	rootKey, err := km.CreateKey(&apiv1.CreateKeyRequest{
		Name:               "root-key",
		SignatureAlgorithm: apiv1.ECDSAWithSHA256,
	})
	if err != nil {
		return fmt.Errorf("error creating root key: %w", err)
	}

	rootSigner, err := km.CreateSigner(&apiv1.CreateSignerRequest{
		SigningKey: rootKey.Name,
	})
	if err != nil {
		return fmt.Errorf("error creating root signer: %w", err)
	}

	// Create root certificate
	rootCert, err := x509util.CreateCertificate(rootTmpl, rootTmpl, rootSigner.Public(), rootSigner)
	if err != nil {
		return fmt.Errorf("error creating root certificate: %w", err)
	}

	// Parse intermediate template
	intermediateTmpl, err := parseTemplate(intermediateTemplatePath, rootCert)
	if err != nil {
		return fmt.Errorf("error parsing intermediate template: %w", err)
	}

	intermediateKey, err := km.CreateKey(&apiv1.CreateKeyRequest{
		Name:               "intermediate-key",
		SignatureAlgorithm: apiv1.ECDSAWithSHA256,
	})
	if err != nil {
		return fmt.Errorf("error creating intermediate key: %w", err)
	}

	intermediateSigner, err := km.CreateSigner(&apiv1.CreateSignerRequest{
		SigningKey: intermediateKey.Name,
	})
	if err != nil {
		return fmt.Errorf("error creating intermediate signer: %w", err)
	}

	// Create intermediate certificate
	intermediateCert, err := x509util.CreateCertificate(intermediateTmpl, rootCert, intermediateSigner.Public(), rootSigner)
	if err != nil {
		return fmt.Errorf("error creating intermediate certificate: %w", err)
	}

	if err := writeCertificateToFile(rootCert, "root.pem"); err != nil {
		return fmt.Errorf("error writing root certificate: %w", err)
	}

	if err := writeCertificateToFile(intermediateCert, "intermediate.pem"); err != nil {
		return fmt.Errorf("error writing intermediate certificate: %w", err)
	}

	// Verify certificate chain
	pool := x509.NewCertPool()
	pool.AddCert(rootCert)
	if _, err := intermediateCert.Verify(x509.VerifyOptions{
		Roots: pool,
	}); err != nil {
		return fmt.Errorf("CA.Intermediate.Verify() error = %v", err)
	}

	logger.Info("Certificates created successfully",
		zap.String("root_cert", rootCert.Subject.CommonName),
		zap.String("intermediate_cert", intermediateCert.Subject.CommonName),
		zap.Bool("root_is_ca", rootCert.IsCA),
		zap.Bool("intermediate_is_ca", intermediateCert.IsCA),
		zap.Int("root_path_len", rootCert.MaxPathLen),
		zap.String("key_usage", fmt.Sprintf("%v", rootCert.KeyUsage)),
		zap.String("ext_key_usage", fmt.Sprintf("%v", rootCert.ExtKeyUsage)))

	return nil
}

func writeCertificateToFile(cert *x509.Certificate, filename string) error {
	certPEM := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}

	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create file %s: %w", filename, err)
	}
	defer file.Close()

	if err := pem.Encode(file, certPEM); err != nil {
		return fmt.Errorf("failed to write certificate to file %s: %w", filename, err)
	}

	return nil
}

type CertificateTemplate struct {
	Subject struct {
		CommonName string `json:"commonName"`
	} `json:"subject"`
	Issuer struct {
		CommonName string `json:"commonName"`
	} `json:"issuer"`
	KeyUsage         []string `json:"keyUsage"`
	ExtKeyUsage      []string `json:"extKeyUsage,omitempty"`
	BasicConstraints struct {
		IsCA       bool `json:"isCA"`
		MaxPathLen int  `json:"maxPathLen"`
	} `json:"basicConstraints"`
	Extensions []struct {
		ID       string `json:"id"`
		Critical bool   `json:"critical"`
		Value    string `json:"value"`
	} `json:"extensions,omitempty"`
}

// parseTemplate creates an x509 certificate from JSON template
func parseTemplate(filename string, parent *x509.Certificate) (*x509.Certificate, error) {
	content, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("error reading template file: %w", err)
	}

	var tmpl CertificateTemplate
	if err := json.Unmarshal(content, &tmpl); err != nil {
		return nil, fmt.Errorf("error parsing template JSON: %w", err)
	}

	cert := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: tmpl.Subject.CommonName,
		},
		Issuer: func() pkix.Name {
			if parent != nil {
				return parent.Subject
			}
			return pkix.Name{CommonName: tmpl.Issuer.CommonName}
		}(),
		SerialNumber:          big.NewInt(time.Now().Unix()),
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		BasicConstraintsValid: true,
		IsCA:                  tmpl.BasicConstraints.IsCA,
	}

	// Only set MaxPathLen for CA certificates
	if tmpl.BasicConstraints.IsCA {
		cert.MaxPathLen = tmpl.BasicConstraints.MaxPathLen
		cert.MaxPathLenZero = tmpl.BasicConstraints.MaxPathLen == 0
	}

	// Set key usages from template
	for _, usage := range tmpl.KeyUsage {
		switch usage {
		case "certSign":
			cert.KeyUsage |= x509.KeyUsageCertSign
		case "crlSign":
			cert.KeyUsage |= x509.KeyUsageCRLSign
		case "digitalSignature":
			cert.KeyUsage |= x509.KeyUsageDigitalSignature
		}
	}

	// Set extended key usages from template
	for _, usage := range tmpl.ExtKeyUsage {
		switch usage {
		case "timeStamping":
			cert.ExtKeyUsage = append(cert.ExtKeyUsage, x509.ExtKeyUsageTimeStamping)
		case "codeSign":
			cert.ExtKeyUsage = append(cert.ExtKeyUsage, x509.ExtKeyUsageCodeSigning)
		}
	}

	return cert, nil
}

type Config struct {
	KMS struct {
		Region   string `json:"region"`
		KeyAlias string `json:"keyAlias"`
	} `json:"kms"`
	Certificates struct {
		ValidityYears int    `json:"validityYears"`
		RootPath      string `json:"rootPath"`
		IntermPath    string `json:"intermediatePath"`
	} `json:"certificates"`
}

func main() {
	rootTemplate := "root-template.json"
	intermediateTemplate := "intermediate-template.json"

	if len(os.Args) > 1 {
		rootTemplate = os.Args[1]
	}
	if len(os.Args) > 2 {
		intermediateTemplate = os.Args[2]
	}

	region := os.Getenv("AWS_REGION")
	if region == "" {
		region = "us-east-1"
	}
	keyAlias := os.Getenv("AWS_KMS_KEY_ALIAS")
	if keyAlias == "" {
		keyAlias = "alias/fulcio-key"
	}

	ctx := context.Background()
	km, err := initKMS(ctx, region, keyAlias)
	if err != nil {
		logger.Fatal("Failed to initialize KMS", zap.Error(err))
	}

	logger.Info("Creating certificates using templates",
		zap.String("root_template", rootTemplate),
		zap.String("intermediate_template", intermediateTemplate))

	if err := createCertificates(km, rootTemplate, intermediateTemplate); err != nil {
		logger.Fatal("Failed to create certificates", zap.Error(err))
	}
}
