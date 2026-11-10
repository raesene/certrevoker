package certid

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

func testCert(t *testing.T, cn string, orgs ...string) (*x509.Certificate, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: cn, Organization: orgs},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// FromCert must match kube-apiserver's x509 authenticator:
// "X509SHA256=" + hex(sha256(chain[0].Raw)).
func TestFromCertMatchesAPIServerFormula(t *testing.T) {
	c, _ := testCert(t, "alice")
	sum := sha256.Sum256(c.Raw)
	want := "X509SHA256=" + hex.EncodeToString(sum[:])
	if got := FromCert(c); got != want {
		t.Fatalf("FromCert = %q, want %q", got, want)
	}
	if !Valid(want) {
		t.Fatalf("Valid(%q) = false", want)
	}
}

func TestNormalize(t *testing.T) {
	hexPart := strings.Repeat("ab", 32)
	for _, in := range []string{"X509SHA256=" + hexPart, strings.ToUpper(hexPart), "  " + hexPart + "\n", "X509SHA256=" + strings.ToUpper(hexPart)} {
		got, err := Normalize(in)
		if err != nil || got != "X509SHA256="+hexPart {
			t.Errorf("Normalize(%q) = %q, %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "JTI=abc", "X509SHA256=xyz", hexPart[:10]} {
		if _, err := Normalize(bad); err == nil {
			t.Errorf("Normalize(%q) succeeded, want error", bad)
		}
	}
}

func TestObjectNameIsValidDNSSubdomain(t *testing.T) {
	c, _ := testCert(t, "alice")
	name := ObjectName(FromCert(c))
	if len(name) > 253 || strings.ToLower(name) != name || !strings.HasPrefix(name, "sha256-") {
		t.Fatalf("bad object name %q", name)
	}
}

func TestParseUserInputPEMAndKubeconfig(t *testing.T) {
	c, pemBytes := testCert(t, "bob", "devs")
	want := FromCert(c)

	certs, err := ParseUserInput(string(pemBytes) + "\n-----BEGIN EC PRIVATE KEY-----\nAAAA\n-----END EC PRIVATE KEY-----\n")
	if err != nil || len(certs) != 1 || FromCert(certs[0]) != want {
		t.Fatalf("PEM input: got %v, %v", certs, err)
	}

	kc := `apiVersion: v1
kind: Config
users:
- name: bob
  user:
    client-certificate-data: ` + base64.StdEncoding.EncodeToString(pemBytes) + `
    client-key-data: c2VjcmV0
- name: token-user
  user:
    token: abc
`
	certs, err = ParseUserInput(kc)
	if err != nil || len(certs) != 1 || FromCert(certs[0]) != want {
		t.Fatalf("kubeconfig input: got %v, %v", certs, err)
	}

	if _, err := ParseUserInput("users: []"); err == nil {
		t.Fatal("expected error for kubeconfig without client certs")
	}
}

func TestSummarize(t *testing.T) {
	c, _ := testCert(t, "carol", "system:masters")
	info := Summarize(c)
	if info.CommonName != "carol" || len(info.Organizations) != 1 || !info.ClientAuth || info.SerialNumber != "2A" {
		t.Fatalf("unexpected summary %+v", info)
	}
}
