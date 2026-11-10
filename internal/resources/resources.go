// Package resources defines the PoC's custom resources and conversions to and
// from unstructured objects, so we can use the dynamic client without code
// generation.
package resources

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

const (
	Group   = "certrevoker.example.com"
	Version = "v1alpha1"
)

var (
	IssuedCertificatesGVR     = schema.GroupVersionResource{Group: Group, Version: Version, Resource: "issuedcertificates"}
	CertificateRevocationsGVR = schema.GroupVersionResource{Group: Group, Version: Version, Resource: "certificaterevocations"}
)

// Sources of an IssuedCertificate record.
const (
	// SourceCSR: seen in a CertificateSigningRequest's status.certificate.
	SourceCSR = "CSR"
	// SourceObserved: seen only as a credential ID on requests reaching the
	// authorization webhook (e.g. kubeadm-signed kubeconfigs). The certificate
	// itself, and so its validity period, is unknown.
	SourceObserved = "Observed"
)

// IssuedCertificate is one client certificate we know about.
type IssuedCertificate struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              IssuedCertificateSpec   `json:"spec"`
	Status            IssuedCertificateStatus `json:"status,omitempty"`
}

type IssuedCertificateSpec struct {
	CredentialID   string       `json:"credentialID"`
	Source         string       `json:"source"`
	CommonName     string       `json:"commonName,omitempty"`
	Organizations  []string     `json:"organizations,omitempty"`
	SerialNumber   string       `json:"serialNumber,omitempty"`
	Issuer         string       `json:"issuer,omitempty"`
	NotBefore      *metav1.Time `json:"notBefore,omitempty"`
	NotAfter       *metav1.Time `json:"notAfter,omitempty"`
	SignerName     string       `json:"signerName,omitempty"`
	CSRName        string       `json:"csrName,omitempty"`
	CSRUID         string       `json:"csrUID,omitempty"`
	Requestor      string       `json:"requestor,omitempty"`
	CertificatePEM string       `json:"certificatePEM,omitempty"`
}

type IssuedCertificateStatus struct {
	FirstSeen  *metav1.Time `json:"firstSeen,omitempty"`
	LastSeen   *metav1.Time `json:"lastSeen,omitempty"`
	SeenAsUser string       `json:"seenAsUser,omitempty"`
	SeenGroups []string     `json:"seenGroups,omitempty"`
}

// CertificateRevocation marks one credential ID as revoked.
type CertificateRevocation struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              CertificateRevocationSpec   `json:"spec"`
	Status            CertificateRevocationStatus `json:"status,omitempty"`
}

type CertificateRevocationSpec struct {
	CredentialID string `json:"credentialID"`
	Reason       string `json:"reason,omitempty"`
	// RevokedBy is informational and set by the portal. The audit log entry
	// for the create request is the authoritative record of who revoked.
	RevokedBy  string `json:"revokedBy,omitempty"`
	CommonName string `json:"commonName,omitempty"`
	// NotAfter, when known, lets the revocation be garbage collected once the
	// certificate has expired and kube-apiserver would reject it anyway.
	NotAfter *metav1.Time `json:"notAfter,omitempty"`
}

type CertificateRevocationStatus struct {
	DeniedRequests int64        `json:"deniedRequests,omitempty"`
	LastDenied     *metav1.Time `json:"lastDenied,omitempty"`
	LastDeniedUser string       `json:"lastDeniedUser,omitempty"`
}

// FromUnstructured converts u into out (a pointer to one of the types above).
func FromUnstructured(u *unstructured.Unstructured, out any) error {
	return runtime.DefaultUnstructuredConverter.FromUnstructured(u.Object, out)
}

// ToUnstructured converts obj into an unstructured object with apiVersion/kind set.
func ToUnstructured(obj any, kind string) (*unstructured.Unstructured, error) {
	m, err := runtime.DefaultUnstructuredConverter.ToUnstructured(obj)
	if err != nil {
		return nil, err
	}
	u := &unstructured.Unstructured{Object: m}
	u.SetAPIVersion(Group + "/" + Version)
	u.SetKind(kind)
	return u, nil
}
