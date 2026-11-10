package webhook

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	authzv1 "k8s.io/api/authorization/v1"

	"github.com/raesene/certrevoker/internal/certid"
	"github.com/raesene/certrevoker/internal/resources"
)

type fakeLookup map[string]*resources.CertificateRevocation

func (f fakeLookup) Revocation(id string) (*resources.CertificateRevocation, bool) {
	r, ok := f[id]
	return r, ok
}

type fakeRecorder struct{ seen, denied []string }

func (f *fakeRecorder) RecordSeen(id, _ string, _ []string) { f.seen = append(f.seen, id) }
func (f *fakeRecorder) RecordDenied(id, _ string)           { f.denied = append(f.denied, id) }

var (
	revokedID = certid.Prefix + strings.Repeat("aa", 32)
	activeID  = certid.Prefix + strings.Repeat("bb", 32)
)

func call(t *testing.T, h http.Handler, spec authzv1.SubjectAccessReviewSpec) authzv1.SubjectAccessReviewStatus {
	t.Helper()
	sar := authzv1.SubjectAccessReview{Spec: spec}
	sar.APIVersion, sar.Kind = "authorization.k8s.io/v1", "SubjectAccessReview"
	body, _ := json.Marshal(sar)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/authorize", bytes.NewReader(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var resp authzv1.SubjectAccessReview
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.APIVersion != "authorization.k8s.io/v1" || resp.Kind != "SubjectAccessReview" {
		t.Fatalf("response missing apiVersion/kind: %+v", resp.TypeMeta)
	}
	return resp.Status
}

func newHandler() (*Handler, *fakeRecorder) {
	rec := &fakeRecorder{}
	rev := &resources.CertificateRevocation{Spec: resources.CertificateRevocationSpec{CredentialID: revokedID, Reason: "laptop stolen"}}
	return &Handler{
		Revocations: fakeLookup{revokedID: rev},
		Recorder:    rec,
		Log:         slog.New(slog.NewTextHandler(io.Discard, nil)),
	}, rec
}

func TestRevokedCertificateIsExplicitlyDenied(t *testing.T) {
	h, rec := newHandler()
	st := call(t, h, authzv1.SubjectAccessReviewSpec{
		User:               "bob",
		Groups:             []string{"devs", "system:authenticated"},
		Extra:              map[string]authzv1.ExtraValue{certid.ExtraKey: {revokedID}},
		ResourceAttributes: &authzv1.ResourceAttributes{Verb: "list", Resource: "pods", Namespace: "default"},
	})
	if st.Allowed || !st.Denied {
		t.Fatalf("want explicit deny, got %+v", st)
	}
	if !strings.Contains(st.Reason, "revoked") || !strings.Contains(st.Reason, "laptop stolen") {
		t.Fatalf("reason %q", st.Reason)
	}
	if len(rec.denied) != 1 || len(rec.seen) != 0 {
		t.Fatalf("recorder: %+v", rec)
	}
}

func TestActiveCertificateGetsNoOpinionAndIsRecorded(t *testing.T) {
	h, rec := newHandler()
	st := call(t, h, authzv1.SubjectAccessReviewSpec{
		User:                  "alice",
		Extra:                 map[string]authzv1.ExtraValue{certid.ExtraKey: {activeID}},
		NonResourceAttributes: &authzv1.NonResourceAttributes{Verb: "get", Path: "/version"},
	})
	if st.Allowed || st.Denied {
		t.Fatalf("want NoOpinion, got %+v", st)
	}
	if len(rec.seen) != 1 || rec.seen[0] != activeID {
		t.Fatalf("recorder: %+v", rec)
	}
}

func TestNonX509CredentialsAreIgnored(t *testing.T) {
	h, rec := newHandler()
	st := call(t, h, authzv1.SubjectAccessReviewSpec{
		User:  "system:serviceaccount:default:foo",
		Extra: map[string]authzv1.ExtraValue{certid.ExtraKey: {"JTI=" + strings.TrimPrefix(revokedID, certid.Prefix)}},
	})
	if st.Allowed || st.Denied || len(rec.seen)+len(rec.denied) != 0 {
		t.Fatalf("want ignored NoOpinion, got %+v %+v", st, rec)
	}
}

func TestRejectsNonPOSTAndGarbage(t *testing.T) {
	h, _ := newHandler()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/authorize", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET: %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/authorize", strings.NewReader("{not json")))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("garbage: %d", rec.Code)
	}
}
