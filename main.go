// Copyright 2024 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

// Package main provides certificate creation utilities for Fulcio and Timestamp Authority
package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"strings"

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

	version = "dev"

	rootCmd = &cobra.Command{
		Use:     "sigstore-certificate-maker",
		Short:   "Create certificate chains for Sigstore services",
		Long:    `A tool for creating root and intermediate certificates for Fulcio and Timestamp Authority`,
		Version: version,
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
	rootKeyID          string
	intermediateKeyID  string
	rootCertPath       string
	intermCertPath     string

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
	logger = initLogger()

	// Add create command
	rootCmd.AddCommand(createCmd)

	// Add flags to create command
	createCmd.Flags().StringVar(&kmsType, "kms-type", "", "KMS provider type (awskms, cloudkms, azurekms)")
	createCmd.Flags().StringVar(&kmsRegion, "kms-region", "", "KMS region")
	createCmd.Flags().StringVar(&kmsKeyID, "kms-key-id", "", "KMS key identifier")
	createCmd.Flags().StringVar(&kmsVaultName, "kms-vault-name", "", "Azure KMS vault name")
	createCmd.Flags().StringVar(&kmsTenantID, "kms-tenant-id", "", "Azure KMS tenant ID")
	createCmd.Flags().StringVar(&kmsCredsFile, "kms-credentials-file", "", "Path to credentials file (for Google Cloud KMS)")
	createCmd.Flags().StringVar(&rootTemplatePath, "root-template", "root-template.json", "Path to root certificate template")
	createCmd.Flags().StringVar(&intermTemplatePath, "intermediate-template", "intermediate-template.json", "Path to intermediate certificate template")
	createCmd.Flags().StringVar(&rootKeyID, "root-key-id", "", "KMS key identifier for root certificate")
	createCmd.Flags().StringVar(&intermediateKeyID, "intermediate-key-id", "", "KMS key identifier for intermediate certificate")
	createCmd.Flags().StringVar(&rootCertPath, "root-cert", "root.pem", "Output path for root certificate")
	createCmd.Flags().StringVar(&intermCertPath, "intermediate-cert", "intermediate.pem", "Output path for intermediate certificate")
}

func runCreate(cmd *cobra.Command, args []string) error {
	// Build KMS config from flags and environment
	kmsConfig := KMSConfig{
		Type:              getConfigValue(kmsType, "KMS_TYPE"),
		Region:            getConfigValue(kmsRegion, "KMS_REGION"),
		RootKeyID:         getConfigValue(rootKeyID, "KMS_ROOT_KEY_ID"),
		IntermediateKeyID: getConfigValue(intermediateKeyID, "KMS_INTERMEDIATE_KEY_ID"),
		Options:           make(map[string]string),
	}

	// Handle provider-specific options
	switch kmsConfig.Type {
	case "cloudkms":
		if credsFile := getConfigValue(kmsCredsFile, "KMS_CREDENTIALS_FILE"); credsFile != "" {
			kmsConfig.Options["credentials-file"] = credsFile
		}
	case "azurekms":
		if vaultName := getConfigValue(kmsVaultName, "KMS_VAULT_NAME"); vaultName != "" {
			kmsConfig.Options["vault-name"] = vaultName
		}
		if tenantID := getConfigValue(kmsTenantID, "KMS_TENANT_ID"); tenantID != "" {
			kmsConfig.Options["tenant-id"] = tenantID
		}
	}

	ctx := context.Background()
	km, err := initKMS(ctx, kmsConfig)
	if err != nil {
		return fmt.Errorf("failed to initialize KMS: %w", err)
	}

	// Validate template paths
	if err := validateTemplatePath(rootTemplatePath); err != nil {
		return fmt.Errorf("root template error: %w", err)
	}
	if err := validateTemplatePath(intermTemplatePath); err != nil {
		return fmt.Errorf("intermediate template error: %w", err)
	}

	return createCertificates(km, kmsConfig, rootTemplatePath, intermTemplatePath, rootCertPath, intermCertPath)
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

	// Use RootKeyID as the primary key ID, fall back to IntermediateKeyID if root is not set
	keyID := config.RootKeyID
	if keyID == "" {
		keyID = config.IntermediateKeyID
	}

	switch config.Type {
	case "awskms":
		opts.URI = fmt.Sprintf("awskms:///%s?region=%s", keyID, config.Region)
		return awskms.New(ctx, opts)
	case "cloudkms":
		opts.URI = fmt.Sprintf("cloudkms:%s", keyID)
		if credFile, ok := config.Options["credentials-file"]; ok {
			opts.URI += fmt.Sprintf("?credentials-file=%s", credFile)
		}
		return cloudkms.New(ctx, opts)
	case "azurekms":
		opts.URI = fmt.Sprintf("azurekms://%s.vault.azure.net/keys/%s",
			config.Options["vault-name"], keyID)
		if config.Options["tenant-id"] != "" {
			opts.URI += fmt.Sprintf("?tenant-id=%s", config.Options["tenant-id"])
		}
		return azurekms.New(ctx, opts)
	default:
		return nil, fmt.Errorf("unsupported KMS type: %s", config.Type)
	}
}

// createCertificates generates a certificate chain using the configured KMS provider
func createCertificates(km apiv1.KeyManager, config KMSConfig, rootTemplatePath, intermediateTemplatePath, rootCertPath, intermediateCertPath string) error {
	// Parse templates
	rootTmpl, err := ParseTemplate(rootTemplatePath, nil)
	if err != nil {
		return fmt.Errorf("error parsing root template: %w", err)
	}

	rootKeyName := config.RootKeyID
	if config.Type == "azurekms" {
		rootKeyName = fmt.Sprintf("azurekms:vault=%s;name=%s",
			config.Options["vault-name"], config.RootKeyID)
	}

	rootSigner, err := km.CreateSigner(&apiv1.CreateSignerRequest{
		SigningKey: rootKeyName,
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
	intermediateTmpl, err := ParseTemplate(intermediateTemplatePath, rootCert)
	if err != nil {
		return fmt.Errorf("error parsing intermediate template: %w", err)
	}

	intermediateKeyName := config.IntermediateKeyID
	if config.Type == "azurekms" {
		intermediateKeyName = fmt.Sprintf("azurekms:vault=%s;name=%s",
			config.Options["vault-name"], config.IntermediateKeyID)
	}

	intermediateSigner, err := km.CreateSigner(&apiv1.CreateSignerRequest{
		SigningKey: intermediateKeyName,
	})
	if err != nil {
		return fmt.Errorf("error creating intermediate signer: %w", err)
	}

	// Create intermediate certificate
	intermediateCert, err := x509util.CreateCertificate(intermediateTmpl, rootCert, intermediateSigner.Public(), rootSigner)
	if err != nil {
		return fmt.Errorf("error creating intermediate certificate: %w", err)
	}

	if err := writeCertificateToFile(rootCert, rootCertPath); err != nil {
		return fmt.Errorf("error writing root certificate: %w", err)
	}

	if err := writeCertificateToFile(intermediateCert, intermCertPath); err != nil {
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

type KMSConfig struct {
	Type              string            // "awskms", "cloudkms", "azurekms"
	Region            string            // AWS region or Cloud location
	RootKeyID         string            // Root CA key identifier
	IntermediateKeyID string            // Intermediate CA key identifier
	Options           map[string]string // Provider-specific options
}

func validateKMSConfig(config KMSConfig) error {
	if config.Type == "" {
		return fmt.Errorf("KMS type cannot be empty")
	}
	if config.RootKeyID == "" && config.IntermediateKeyID == "" {
		return fmt.Errorf("at least one of RootKeyID or IntermediateKeyID must be specified")
	}

	switch config.Type {
	case "awskms":
		if config.Region == "" {
			return fmt.Errorf("region is required for AWS KMS")
		}
	case "cloudkms":
		if config.RootKeyID != "" && !strings.HasPrefix(config.RootKeyID, "projects/") {
			return fmt.Errorf("cloudkms RootKeyID must start with 'projects/'")
		}
		if config.IntermediateKeyID != "" && !strings.HasPrefix(config.IntermediateKeyID, "projects/") {
			return fmt.Errorf("cloudkms IntermediateKeyID must start with 'projects/'")
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

func getConfigValue(flagValue, envVar string) string {
	if flagValue != "" {
		return flagValue
	}
	return os.Getenv(envVar)
}

func initLogger() *zap.Logger {
	var cfg zap.Config
	if err := json.Unmarshal(rawJSON, &cfg); err != nil {
		panic(err)
	}
	return zap.Must(cfg.Build())
}

func validateTemplatePath(path string) error {
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("template not found at %s: %w", path, err)
	}

	if !strings.HasSuffix(path, ".json") {
		return fmt.Errorf("template file must have .json extension: %s", path)
	}

	content, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("error reading template file: %w", err)
	}

	var js json.RawMessage
	if err := json.Unmarshal(content, &js); err != nil {
		return fmt.Errorf("invalid JSON in template file: %w", err)
	}

	return nil
}
