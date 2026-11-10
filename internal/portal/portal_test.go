package portal

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	authnv1 "k8s.io/api/authentication/v1"
	authzv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	dynfake "k8s.io/client-go/dynamic/fake"
	kubefake "k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
	k8stesting "k8s.io/client-go/testing"

	"github.com/raesene/certrevoker/internal/certid"
	"github.com/raesene/certrevoker/internal/resources"
)

var (
	aliceID   = certid.Prefix + strings.Repeat("a1", 32)
	mastersID = certid.Prefix + strings.Repeat("c3", 32)
)

func newTestServer(t *testing.T, allow bool) (*Server, *dynfake.FakeDynamicClient) {
	t.Helper()
	kube := kubefake.NewClientset()
	kube.PrependReactor("create", "tokenreviews", func(a k8stesting.Action) (bool, runtime.Object, error) {
		tr := a.(k8stesting.CreateAction).GetObject().(*authnv1.TokenReview)
		tr.Status = authnv1.TokenReviewStatus{Authenticated: tr.Spec.Token == "good-token",
			User: authnv1.UserInfo{Username: "admin@example.com", Groups: []string{"secops"}}}
		return true, tr, nil
	})
	kube.PrependReactor("create", "subjectaccessreviews", func(a k8stesting.Action) (bool, runtime.Object, error) {
		sar := a.(k8stesting.CreateAction).GetObject().(*authzv1.SubjectAccessReview)
		sar.Status.Allowed = allow
		return true, sar, nil
	})

	notAfter := metav1.NewTime(time.Now().Add(24 * time.Hour))
	alice := &resources.IssuedCertificate{Spec: resources.IssuedCertificateSpec{
		CredentialID: aliceID, Source: resources.SourceCSR, CommonName: "alice",
		Organizations: []string{"devs"}, NotAfter: &notAfter, SignerName: "kubernetes.io/kube-apiserver-client",
	}}
	alice.Name = certid.ObjectName(aliceID)
	masters := &resources.IssuedCertificate{Spec: resources.IssuedCertificateSpec{
		CredentialID: mastersID, Source: resources.SourceObserved,
	}, Status: resources.IssuedCertificateStatus{SeenAsUser: "kubernetes-super-admin", SeenGroups: []string{"system:masters", "system:authenticated"}}}
	masters.Name = certid.ObjectName(mastersID)
	ua, _ := resources.ToUnstructured(alice, "IssuedCertificate")
	um, _ := resources.ToUnstructured(masters, "IssuedCertificate")

	dyn := dynfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(),
		map[schema.GroupVersionResource]string{
			resources.IssuedCertificatesGVR:     "IssuedCertificateList",
			resources.CertificateRevocationsGVR: "CertificateRevocationList",
		}, ua, um)

	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	s, err := New(kube, &rest.Config{Host: "https://example.invalid"}, slog.New(slog.NewTextHandler(io.Discard, nil)), stop)
	if err != nil {
		t.Fatal(err)
	}
	s.newClient = func(token string) (dynamic.Interface, error) { return dyn, nil }
	return s, dyn
}

// client is a tiny cookie-carrying test client.
type client struct {
	t      *testing.T
	s      http.Handler
	cookie *http.Cookie
}

func (c *client) do(method, path string, form url.Values) *httptest.ResponseRecorder {
	c.t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req := httptest.NewRequest(method, path, body)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if c.cookie != nil {
		req.AddCookie(c.cookie)
	}
	rec := httptest.NewRecorder()
	c.s.ServeHTTP(rec, req)
	for _, ck := range rec.Result().Cookies() {
		if ck.Name == cookieName {
			c.cookie = ck
		}
	}
	return rec
}

var csrfRe = regexp.MustCompile(`name="csrf" value="([^"]+)"`)

func csrfFrom(t *testing.T, html string) string {
	t.Helper()
	m := csrfRe.FindStringSubmatch(html)
	if m == nil {
		t.Fatalf("no csrf token in page:\n%s", html)
	}
	return m[1]
}

func TestUnauthenticatedRedirectsToLogin(t *testing.T) {
	s, _ := newTestServer(t, true)
	c := &client{t: t, s: s}
	rec := c.do(http.MethodGet, "/", nil)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/login" {
		t.Fatalf("got %d %q", rec.Code, rec.Header().Get("Location"))
	}
	if !strings.Contains(c.do(http.MethodGet, "/login", nil).Body.String(), "Log in") {
		t.Fatal("login page did not render")
	}
}

func TestBadTokenAndUnauthorizedUserAreRejected(t *testing.T) {
	s, _ := newTestServer(t, true)
	c := &client{t: t, s: s}
	rec := c.do(http.MethodPost, "/login", url.Values{"token": {"bad-token"}})
	if !strings.Contains(rec.Body.String(), "not accepted") || c.cookie != nil {
		t.Fatalf("bad token: %d %s", rec.Code, rec.Body.String())
	}

	s2, _ := newTestServer(t, false)
	c2 := &client{t: t, s: s2}
	rec = c2.do(http.MethodPost, "/login", url.Values{"token": {"good-token"}})
	if !strings.Contains(rec.Body.String(), "is not allowed") || c2.cookie != nil {
		t.Fatalf("unauthorized user: %d %s", rec.Code, rec.Body.String())
	}
}

func TestLoginInventoryRevokeUnrevoke(t *testing.T) {
	s, dyn := newTestServer(t, true)
	c := &client{t: t, s: s}

	rec := c.do(http.MethodPost, "/login", url.Values{"token": {"good-token"}})
	if rec.Code != http.StatusSeeOther || c.cookie == nil {
		t.Fatalf("login: %d %s", rec.Code, rec.Body.String())
	}
	if !c.cookie.HttpOnly || !c.cookie.Secure || c.cookie.SameSite != http.SameSiteStrictMode {
		t.Fatalf("insecure session cookie: %+v", c.cookie)
	}

	page := c.do(http.MethodGet, "/", nil).Body.String()
	for _, want := range []string{"admin@example.com", "alice", "devs", "kubernetes-super-admin", "not enforceable", `<span class="what">Active</span><span class="num">2</span>`} {
		if !strings.Contains(page, want) {
			t.Errorf("inventory page missing %q", want)
		}
	}
	if strings.Contains(page, ">system:authenticated<") {
		t.Error("implicit system:authenticated group should be hidden")
	}
	csrf := csrfFrom(t, page)

	// Missing CSRF token is refused.
	if rec := c.do(http.MethodPost, "/revoke", url.Values{"id": {aliceID}}); rec.Code != http.StatusForbidden {
		t.Fatalf("revoke without csrf: %d", rec.Code)
	}

	rec = c.do(http.MethodPost, "/revoke", url.Values{"csrf": {csrf}, "id": {aliceID}, "reason": {"laptop stolen"}})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("revoke: %d %s", rec.Code, rec.Body.String())
	}
	u, err := dyn.Resource(resources.CertificateRevocationsGVR).Get(context.Background(), certid.ObjectName(aliceID), metav1.GetOptions{})
	if err != nil {
		t.Fatalf("revocation not created: %v", err)
	}
	var rv resources.CertificateRevocation
	if err := resources.FromUnstructured(u, &rv); err != nil {
		t.Fatal(err)
	}
	if rv.Spec.CredentialID != aliceID || rv.Spec.Reason != "laptop stolen" || rv.Spec.RevokedBy != "admin@example.com" ||
		rv.Spec.CommonName != "alice" || rv.Spec.NotAfter == nil {
		t.Fatalf("unexpected revocation %+v", rv.Spec)
	}

	page = c.do(http.MethodGet, "/?view=revoked", nil).Body.String()
	if !strings.Contains(page, "Revoked alice") && !strings.Contains(page, "Revoked X509SHA256=") {
		t.Errorf("missing flash message")
	}
	if !strings.Contains(page, `<span class="what">Revoked</span><span class="num">1</span>`) || !strings.Contains(page, "Remove revocation") {
		t.Errorf("revoked view wrong:\n%s", page)
	}

	detail := c.do(http.MethodGet, "/cert?id="+aliceID, nil).Body.String()
	if !strings.Contains(detail, "laptop stolen") || !strings.Contains(detail, "kubernetes.io/kube-apiserver-client") {
		t.Errorf("detail page missing revocation/inventory info")
	}

	rec = c.do(http.MethodPost, "/unrevoke", url.Values{"csrf": {csrf}, "id": {aliceID}})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("unrevoke: %d", rec.Code)
	}
	if _, err := dyn.Resource(resources.CertificateRevocationsGVR).Get(context.Background(), certid.ObjectName(aliceID), metav1.GetOptions{}); err == nil {
		t.Fatal("revocation still present after unrevoke")
	}

	// Revoke by raw ID (not in inventory) shows up as Manual.
	other := certid.Prefix + strings.Repeat("d4", 32)
	c.do(http.MethodPost, "/revoke", url.Values{"csrf": {csrf}, "id": {strings.TrimPrefix(other, certid.Prefix)}})
	page = c.do(http.MethodGet, "/?view=revoked", nil).Body.String()
	if !strings.Contains(page, "Manual") {
		t.Errorf("manual revocation not listed:\n%s", page)
	}

	// Inspect page renders and parses a kubeconfig-less garbage input gracefully.
	page = c.do(http.MethodPost, "/inspect", url.Values{"csrf": {csrf}, "input": {"hello"}}).Body.String()
	if !strings.Contains(page, "neither PEM nor a kubeconfig") {
		t.Errorf("inspect error not shown:\n%s", page)
	}

	// Logout ends the session.
	c.do(http.MethodPost, "/logout", url.Values{"csrf": {csrf}})
	if rec := c.do(http.MethodGet, "/", nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("still logged in after logout: %d", rec.Code)
	}
}

func TestFmtTimeHandlesAllTimeForms(t *testing.T) {
	ts := time.Date(2026, 11, 10, 11, 26, 0, 0, time.UTC)
	mt := metav1.NewTime(ts)
	want := "2026-11-10 11:26 UTC"
	for _, in := range []any{ts, &ts, mt, &mt} {
		if got := fmtTime(in); got != want {
			t.Errorf("fmtTime(%T) = %q, want %q", in, got, want)
		}
	}
	var nilT *time.Time
	var nilM *metav1.Time
	for _, in := range []any{nilT, nilM, metav1.Time{}} {
		if got := fmtTime(in); got != "" {
			t.Errorf("fmtTime(%T zero) = %q, want empty", in, got)
		}
	}
}
