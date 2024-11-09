package main

import (
	"context"
	"fmt"
	"math/big"
	"time"

	"crypto/x509"
	"crypto/x509/pkix"

	"encoding/json"
	"encoding/pem"
	"os"

	"bytes"
	"text/template"

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

type CertificateTemplate struct {
	Subject          pkix.Name              `json:"subject"`
	Issuer           pkix.Name              `json:"issuer"`
	KeyUsage         []string               `json:"keyUsage"`
	ExtKeyUsage      []string               `json:"extKeyUsage,omitempty"`
	BasicConstraints *BasicConstraints      `json:"basicConstraints"`
	Extensions       []CertificateExtension `json:"extensions,omitempty"`
}

type BasicConstraints struct {
	IsCA       bool `json:"isCA"`
	MaxPathLen int  `json:"maxPathLen"`
}

type CertificateExtension struct {
	ID       string `json:"id"`
	Critical bool   `json:"critical"`
	Value    string `json:"value"`
}

func parseTemplate(templatePath string, data interface{}) (*CertificateTemplate, error) {
	tmpl, err := template.ParseFiles(templatePath)
	if err != nil {
		return nil, fmt.Errorf("error parsing template: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return nil, fmt.Errorf("error executing template: %w", err)
	}

	var certTemplate CertificateTemplate
	if err := json.Unmarshal(buf.Bytes(), &certTemplate); err != nil {
		return nil, fmt.Errorf("error unmarshaling template: %w", err)
	}

	return &certTemplate, nil
}

func createCertificates(km apiv1.KeyManager, rootTemplatePath, intermediateTemplatePath string) error {
	// Parse root template
	rootTmpl, err := parseTemplate(rootTemplatePath, nil)
	if err != nil {
		return fmt.Errorf("error parsing root template: %w", err)
	}

	// Create root key and signer
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

	// Create root certificate template
	rootTemplate := &x509.Certificate{
		Subject:               rootTmpl.Subject,
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(100, 0, 0),
		BasicConstraintsValid: true,
		IsCA:                  rootTmpl.BasicConstraints.IsCA,
		MaxPathLen:            rootTmpl.BasicConstraints.MaxPathLen,
	}

	// Set key usage
	for _, usage := range rootTmpl.KeyUsage {
		switch usage {
		case "certSign":
			rootTemplate.KeyUsage |= x509.KeyUsageCertSign
		case "crlSign":
			rootTemplate.KeyUsage |= x509.KeyUsageCRLSign
		}
	}

	// Create root certificate
	rootCert, err := x509util.CreateCertificate(rootTemplate, rootTemplate, rootSigner.Public(), rootSigner)
	if err != nil {
		return fmt.Errorf("error creating root certificate: %w", err)
	}

	intermediateSubject := &pkix.Name{
		CommonName:   "Intermediate CA",
		Organization: []string{"Liatrio"},
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

	// Parse intermediate template
	intermediateTmpl, err := parseTemplate(intermediateTemplatePath, nil)
	if err != nil {
		return fmt.Errorf("error parsing intermediate template: %w", err)
	}

	// Create intermediate certificate template
	intermediateTemplate := &x509.Certificate{
		Subject:               *intermediateSubject,
		SerialNumber:          big.NewInt(2),
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(100, 0, 0),
		BasicConstraintsValid: true,
		IsCA:                  intermediateTmpl.BasicConstraints.IsCA,
		MaxPathLen:            intermediateTmpl.BasicConstraints.MaxPathLen,
	}

	// Set key usage
	for _, usage := range intermediateTmpl.KeyUsage {
		switch usage {
		case "certSign":
			intermediateTemplate.KeyUsage |= x509.KeyUsageCertSign
		case "crlSign":
			intermediateTemplate.KeyUsage |= x509.KeyUsageCRLSign
		}
	}

	// Create intermediate certificate
	intermediateCert, err := x509util.CreateCertificate(intermediateTemplate, rootTemplate, intermediateSigner.Public(), rootSigner)
	if err != nil {
		return fmt.Errorf("error creating intermediate certificate: %w", err)
	}

	if err := writeCertificateToFile(rootCert, "root.pem"); err != nil {
		return fmt.Errorf("error writing root certificate: %w", err)
	}

	if err := writeCertificateToFile(intermediateCert, "intermediate.pem"); err != nil {
		return fmt.Errorf("error writing intermediate certificate: %w", err)
	}

	logger.Info("Certificates created successfully",
		zap.String("root_cert", rootCert.Subject.CommonName),
		zap.String("intermediate_cert", intermediateCert.Subject.CommonName))

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

func main() {
	ctx := context.Background()
	km, err := initKMS(ctx, "us-east-1", "alias/fulcio-key")
	if err != nil {
		logger.Fatal("Failed to initialize KMS", zap.Error(err))
	}

	if err := createCertificates(km, "root-template.json", "intermediate-template.json"); err != nil {
		logger.Fatal("Failed to create certificates", zap.Error(err))
	}
}
