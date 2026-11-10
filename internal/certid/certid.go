// Package certid computes Kubernetes x509 credential IDs and parses certificates.
//
// kube-apiserver's x509 authenticator sets the user extra
// "authentication.kubernetes.io/credential-id" to "X509SHA256=" followed by the
// lowercase hex SHA-256 of the leaf certificate's DER encoding
// (staging/src/k8s.io/apiserver/pkg/authentication/request/x509/x509.go).
// This package reproduces that value so we can match certificates we have seen
// issued against requests the authorization webhook sees.
package certid

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"sigs.k8s.io/yaml"
)

// ExtraKey is the user extra key kube-apiserver uses for credential IDs.
const ExtraKey = "authentication.kubernetes.io/credential-id"

// Prefix is the credential ID prefix for x509 client certificates.
const Prefix = "X509SHA256="

var idPattern = regexp.MustCompile(`^X509SHA256=[0-9a-f]{64}$`)

// FromCert returns the credential ID kube-apiserver assigns to cert.
func FromCert(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return Prefix + hex.EncodeToString(sum[:])
}

// Valid reports whether id is a well-formed x509 credential ID.
func Valid(id string) bool { return idPattern.MatchString(id) }

// Normalize trims whitespace and lowercases the hex part of an ID, accepting
// either the full "X509SHA256=<hex>" form or just the 64-char hex digest.
func Normalize(id string) (string, error) {
	id = strings.TrimSpace(id)
	if strings.HasPrefix(id, Prefix) {
		id = Prefix + strings.ToLower(strings.TrimPrefix(id, Prefix))
	} else {
		id = Prefix + strings.ToLower(id)
	}
	if !Valid(id) {
		return "", fmt.Errorf("not a valid x509 credential ID (want %s<64 hex chars>)", Prefix)
	}
	return id, nil
}

// ObjectName returns the Kubernetes object name used for both the
// IssuedCertificate and CertificateRevocation of a credential ID. Using a
// deterministic name gives one object per credential and makes lookups O(1).
func ObjectName(id string) string {
	return "sha256-" + strings.TrimPrefix(id, Prefix)
}

// Info is a summary of a client certificate.
type Info struct {
	CredentialID  string
	CommonName    string
	Organizations []string
	SerialNumber  string
	Issuer        string
	NotBefore     time.Time
	NotAfter      time.Time
	ClientAuth    bool
	PEM           string
}

// Summarize extracts the fields we record about a certificate.
func Summarize(cert *x509.Certificate) Info {
	clientAuth := len(cert.ExtKeyUsage) == 0 // no EKU means any usage
	for _, u := range cert.ExtKeyUsage {
		if u == x509.ExtKeyUsageClientAuth || u == x509.ExtKeyUsageAny {
			clientAuth = true
		}
	}
	return Info{
		CredentialID:  FromCert(cert),
		CommonName:    cert.Subject.CommonName,
		Organizations: append([]string(nil), cert.Subject.Organization...),
		SerialNumber:  strings.ToUpper(cert.SerialNumber.Text(16)),
		Issuer:        cert.Issuer.String(),
		NotBefore:     cert.NotBefore.UTC(),
		NotAfter:      cert.NotAfter.UTC(),
		ClientAuth:    clientAuth,
		PEM:           string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})),
	}
}

// FirstCertFromPEM returns the first CERTIFICATE block in data (the leaf, by
// convention for CSR status.certificate and kubeconfig client certs).
func FirstCertFromPEM(data []byte) (*x509.Certificate, error) {
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			return nil, errors.New("no PEM CERTIFICATE block found")
		}
		if block.Type == "CERTIFICATE" {
			return x509.ParseCertificate(block.Bytes)
		}
	}
}

// kubeconfig is the subset of a kubeconfig needed to find embedded client certs.
type kubeconfig struct {
	Users []struct {
		Name string `json:"name"`
		User struct {
			ClientCertificateData string `json:"client-certificate-data"`
		} `json:"user"`
	} `json:"users"`
}

// ParseUserInput accepts either PEM certificate text or a kubeconfig with
// embedded client-certificate-data, and returns the client certificates in it.
// It never touches private keys: only CERTIFICATE PEM blocks and
// client-certificate-data fields are read.
func ParseUserInput(input string) ([]*x509.Certificate, error) {
	input = strings.TrimSpace(input)
	if input == "" {
		return nil, errors.New("empty input")
	}
	if strings.Contains(input, "-----BEGIN CERTIFICATE-----") {
		var certs []*x509.Certificate
		data := []byte(input)
		for {
			var block *pem.Block
			block, data = pem.Decode(data)
			if block == nil {
				break
			}
			if block.Type != "CERTIFICATE" {
				continue
			}
			c, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("parsing certificate: %w", err)
			}
			certs = append(certs, c)
		}
		if len(certs) == 0 {
			return nil, errors.New("no certificates found in PEM input")
		}
		// For pasted chains, only the leaf identifies the credential.
		return certs[:1], nil
	}
	var kc kubeconfig
	if err := yaml.Unmarshal([]byte(input), &kc); err != nil {
		return nil, fmt.Errorf("input is neither PEM nor a kubeconfig: %w", err)
	}
	var certs []*x509.Certificate
	for _, u := range kc.Users {
		if u.User.ClientCertificateData == "" {
			continue
		}
		der, err := base64.StdEncoding.DecodeString(u.User.ClientCertificateData)
		if err != nil {
			return nil, fmt.Errorf("user %q: decoding client-certificate-data: %w", u.Name, err)
		}
		c, err := FirstCertFromPEM(der)
		if err != nil {
			return nil, fmt.Errorf("user %q: %w", u.Name, err)
		}
		certs = append(certs, c)
	}
	if len(certs) == 0 {
		return nil, errors.New("kubeconfig contains no embedded client-certificate-data")
	}
	return certs, nil
}
