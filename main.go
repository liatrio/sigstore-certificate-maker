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
	"strings"
	"time"

	"github.com/spf13/cobra"
	"go.step.sm/crypto/kms/apiv1"
	"go.step.sm/crypto/kms/awskms"
	"go.step.sm/crypto/kms/azurekms"
	"go.step.sm/crypto/kms/cloudkms"
	"go.step.sm/crypto/x509util"
	"go.uber.org/zap"
)

var (
	logger *zap.Logger

	rootCmd = &cobra.Command{
		Use:   "sigstore-certificate-maker",
		Short: "Create certificate chains for Sigstore services",
		Long: `A tool for creating root and intermediate certificates 
			   for Sigstore services (Fulcio and Timestamp Authority)`,
	}

	createCmd = &cobra.Command{
		Use:   "create",
		Short: "Create certificate chain",
		RunE:  runCreate,
	}

	// Flag variables
	kmsType            string
	kmsRegion          string
	kmsKeyID           string
	kmsVaultName       string
	kmsTenantID        string
	kmsCredsFile       string
	rootTemplatePath   string
	intermTemplatePath string

	rawJSON = []byte(`{
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
)

func init() {
	var cfg zap.Config
	if err := json.Unmarshal(rawJSON, &cfg); err != nil {
		panic(err)
	}
	logger = zap.Must(cfg.Build())

	// Add create command
	rootCmd.AddCommand(createCmd)

	// Add flags to create command
	createCmd.Flags().StringVar(&kmsType, "kms-type", "awskms", "KMS provider type (awskms, cloudkms, azurekms)")
	createCmd.Flags().StringVar(&kmsRegion, "kms-region", "us-east-1", "KMS region")
	createCmd.Flags().StringVar(&kmsKeyID, "kms-key-id", "alias/fulcio-key", "KMS key identifier")
	createCmd.Flags().StringVar(&kmsVaultName, "kms-vault-name", "", "Azure KMS vault name")
	createCmd.Flags().StringVar(&kmsTenantID, "kms-tenant-id", "", "Azure KMS tenant ID")
	createCmd.Flags().StringVar(&kmsCredsFile, "kms-credentials-file", "", "Path to credentials file (for Google Cloud KMS)")
	createCmd.Flags().StringVar(&rootTemplatePath, "root-template", "root-template.json", "Path to root certificate template")
	createCmd.Flags().StringVar(&intermTemplatePath, "intermediate-template", "intermediate-template.json", "Path to intermediate certificate template")
}

func runCreate(cmd *cobra.Command, args []string) error {
	// Build KMS config from flags and environment
	kmsConfig := KMSConfig{
		Type:    getConfigValue(kmsType, "KMS_TYPE", "awskms"),
		Region:  getConfigValue(kmsRegion, "KMS_REGION", "us-east-1"),
		KeyID:   getConfigValue(kmsKeyID, "KMS_KEY_ID", "alias/fulcio-key"),
		Options: make(map[string]string),
	}

	// Handle provider-specific options
	switch kmsConfig.Type {
	case "cloudkms":
		if credsFile := getConfigValue(kmsCredsFile, "KMS_CREDENTIALS_FILE", ""); credsFile != "" {
			kmsConfig.Options["credentials-file"] = credsFile
		}
	case "azurekms":
		if vaultName := getConfigValue(kmsVaultName, "KMS_VAULT_NAME", ""); vaultName != "" {
			kmsConfig.Options["vault-name"] = vaultName
		}
		if tenantID := getConfigValue(kmsTenantID, "KMS_TENANT_ID", ""); tenantID != "" {
			kmsConfig.Options["tenant-id"] = tenantID
		}
	}

	ctx := context.Background()
	km, err := initKMS(ctx, kmsConfig)
	if err != nil {
		return fmt.Errorf("failed to initialize KMS: %w", err)
	}

	// Validate template paths
	if _, err := os.Stat(rootTemplatePath); err != nil {
		return fmt.Errorf("root template not found at %s: %w", rootTemplatePath, err)
	}
	if _, err := os.Stat(intermTemplatePath); err != nil {
		return fmt.Errorf("intermediate template not found at %s: %w", intermTemplatePath, err)
	}

	return createCertificates(km, rootTemplatePath, intermTemplatePath)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		logger.Fatal("Command failed", zap.Error(err))
	}
}

func initKMS(ctx context.Context, config KMSConfig) (apiv1.KeyManager, error) {
	if err := validateKMSConfig(config); err != nil {
		return nil, fmt.Errorf("invalid KMS configuration: %w", err)
	}

	opts := apiv1.Options{
		Type: apiv1.Type(config.Type),
		URI:  "",
	}

	switch config.Type {
	case "awskms":
		opts.URI = fmt.Sprintf("awskms:///%s?region=%s", config.KeyID, config.Region)
		return awskms.New(ctx, opts)
	case "cloudkms":
		opts.URI = fmt.Sprintf("cloudkms:%s", config.KeyID)
		if credFile, ok := config.Options["credentials-file"]; ok {
			opts.URI += fmt.Sprintf("?credentials-file=%s", credFile)
		}
		return cloudkms.New(ctx, opts)
	case "azurekms":
		opts.URI = fmt.Sprintf("azurekms:///%s?vault-name=%s&tenant-id=%s",
			config.KeyID,
			config.Options["vault-name"],
			config.Options["tenant-id"])
		return azurekms.New(ctx, opts)
	default:
		return nil, fmt.Errorf("unsupported KMS type: %s", config.Type)
	}
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

	// Validate template content
	if tmpl.Subject.CommonName == "" {
		return nil, fmt.Errorf("template subject.commonName cannot be empty")
	}

	if parent == nil && tmpl.Issuer.CommonName == "" {
		return nil, fmt.Errorf("template issuer.commonName cannot be empty for root certificate")
	}

	if tmpl.BasicConstraints.IsCA && len(tmpl.KeyUsage) == 0 {
		return nil, fmt.Errorf("CA certificate must specify at least one key usage")
	}

	// Validate key usage combinations
	if tmpl.BasicConstraints.IsCA {
		hasKeyUsageCertSign := false
		for _, usage := range tmpl.KeyUsage {
			if usage == "certSign" {
				hasKeyUsageCertSign = true
				break
			}
		}
		if !hasKeyUsageCertSign {
			return nil, fmt.Errorf("CA certificate must have certSign key usage")
		}
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
		Type    string            `json:"type"`
		Region  string            `json:"region"`
		KeyID   string            `json:"keyId"`
		Options map[string]string `json:"options,omitempty"`
	} `json:"kms"`
	Certificates struct {
		ValidityYears int    `json:"validityYears"`
		RootPath      string `json:"rootPath"`
		IntermPath    string `json:"intermediatePath"`
	} `json:"certificates"`
}

type KMSConfig struct {
	Type    string            // "awskms", "cloudkms", "azurekms"
	Region  string            // AWS region or Cloud location
	KeyID   string            // Key identifier
	Options map[string]string // Provider-specific options
}

func validateKMSConfig(config KMSConfig) error {
	if config.Type == "" {
		return fmt.Errorf("KMS type cannot be empty")
	}
	if config.KeyID == "" {
		return fmt.Errorf("KeyID cannot be empty")
	}

	switch config.Type {
	case "awskms":
		if config.Region == "" {
			return fmt.Errorf("region is required for AWS KMS")
		}
	case "cloudkms":
		if !strings.HasPrefix(config.KeyID, "projects/") {
			return fmt.Errorf("cloudkms KeyID must start with 'projects/'")
		}
	case "azurekms":
		if config.Options["vault-name"] == "" {
			return fmt.Errorf("vault-name is required for Azure KMS")
		}
		if config.Options["tenant-id"] == "" {
			return fmt.Errorf("tenant-id is required for Azure KMS")
		}
	}

	return nil
}

func getConfigValue(flagValue, envVar, defaultValue string) string {
	if flagValue != "" {
		return flagValue
	}
	if envValue := os.Getenv(envVar); envValue != "" {
		return envValue
	}
	return defaultValue
}
