// Package main provides template parsing and certificate generation functionality
// for creating X.509 certificates from JSON templates
package main

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"time"
)

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

	if err := validateTemplate(&tmpl, parent); err != nil {
		return nil, err
	}

	return createCertificateFromTemplate(&tmpl, parent)
}

func validateTemplate(tmpl *CertificateTemplate, parent *x509.Certificate) error {
	if tmpl.Subject.CommonName == "" {
		return fmt.Errorf("template subject.commonName cannot be empty")
	}

	if parent == nil && tmpl.Issuer.CommonName == "" {
		return fmt.Errorf("template issuer.commonName cannot be empty for root certificate")
	}

	if tmpl.BasicConstraints.IsCA && len(tmpl.KeyUsage) == 0 {
		return fmt.Errorf("CA certificate must specify at least one key usage")
	}

	if tmpl.BasicConstraints.IsCA {
		hasKeyUsageCertSign := false
		for _, usage := range tmpl.KeyUsage {
			if usage == "certSign" {
				hasKeyUsageCertSign = true
				break
			}
		}
		if !hasKeyUsageCertSign {
			return fmt.Errorf("CA certificate must have certSign key usage")
		}
	}

	return nil
}

func createCertificateFromTemplate(tmpl *CertificateTemplate, parent *x509.Certificate) (*x509.Certificate, error) {
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

	if tmpl.BasicConstraints.IsCA {
		cert.MaxPathLen = tmpl.BasicConstraints.MaxPathLen
		cert.MaxPathLenZero = tmpl.BasicConstraints.MaxPathLen == 0
	}

	setKeyUsages(cert, tmpl.KeyUsage)
	setExtKeyUsages(cert, tmpl.ExtKeyUsage)

	return cert, nil
}

func setKeyUsages(cert *x509.Certificate, usages []string) {
	for _, usage := range usages {
		switch usage {
		case "certSign":
			cert.KeyUsage |= x509.KeyUsageCertSign
		case "crlSign":
			cert.KeyUsage |= x509.KeyUsageCRLSign
		case "digitalSignature":
			cert.KeyUsage |= x509.KeyUsageDigitalSignature
		}
	}
}

func setExtKeyUsages(cert *x509.Certificate, usages []string) {
	for _, usage := range usages {
		switch usage {
		case "timeStamping":
			cert.ExtKeyUsage = append(cert.ExtKeyUsage, x509.ExtKeyUsageTimeStamping)
		case "codeSign":
			cert.ExtKeyUsage = append(cert.ExtKeyUsage, x509.ExtKeyUsageCodeSigning)
		}
	}
}
