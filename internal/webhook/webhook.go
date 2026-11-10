// Package webhook implements a kube-apiserver authorization webhook that
// explicitly denies requests made with revoked x509 client certificates.
//
// It must be placed before Node and RBAC in the AuthorizationConfiguration.
// Its decisions are:
//   - Deny (allowed=false, denied=true) if any x509 credential ID on the
//     request is revoked. Explicit Deny stops the authorizer chain, so RBAC
//     grants, including ones to system:authenticated, never apply.
//   - NoOpinion (allowed=false, denied=false) otherwise, so later authorizers
//     decide as usual.
//
// Limitation: kube-apiserver authorizes system:masters before any configured
// authorizer, so certificates with O=system:masters never reach this webhook
// and can't be revoked this way.
package webhook

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"

	authzv1 "k8s.io/api/authorization/v1"

	"github.com/raesene/certrevoker/internal/certid"
	"github.com/raesene/certrevoker/internal/resources"
)

// RevocationLookup is satisfied by state.Store.
type RevocationLookup interface {
	Revocation(id string) (*resources.CertificateRevocation, bool)
}

// Recorder is satisfied by inventory.Observer.
type Recorder interface {
	RecordSeen(id, user string, groups []string)
	RecordDenied(id, user string)
}

type Handler struct {
	Revocations RevocationLookup
	Recorder    Recorder
	Log         *slog.Logger
}

const maxBody = 1 << 20

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBody))
	if err != nil {
		http.Error(w, "reading body", http.StatusBadRequest)
		return
	}
	var sar authzv1.SubjectAccessReview
	if err := json.Unmarshal(body, &sar); err != nil {
		http.Error(w, "invalid SubjectAccessReview", http.StatusBadRequest)
		return
	}

	status := h.decide(&sar.Spec)

	resp := authzv1.SubjectAccessReview{Status: status}
	resp.APIVersion = "authorization.k8s.io/v1"
	resp.Kind = "SubjectAccessReview"
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(&resp)
}

func (h *Handler) decide(spec *authzv1.SubjectAccessReviewSpec) authzv1.SubjectAccessReviewStatus {
	for _, id := range spec.Extra[certid.ExtraKey] {
		if !strings.HasPrefix(id, certid.Prefix) {
			continue
		}
		if rev, revoked := h.Revocations.Revocation(id); revoked {
			h.Recorder.RecordDenied(id, spec.User)
			reason := fmt.Sprintf("client certificate %s has been revoked", id)
			if rev.Spec.Reason != "" {
				reason += ": " + rev.Spec.Reason
			}
			h.Log.Info("denied request with revoked certificate",
				"credentialID", id, "user", spec.User, "groups", spec.Groups,
				"request", describe(spec))
			return authzv1.SubjectAccessReviewStatus{Allowed: false, Denied: true, Reason: reason}
		}
		h.Recorder.RecordSeen(id, spec.User, spec.Groups)
	}
	return authzv1.SubjectAccessReviewStatus{Allowed: false, Denied: false}
}

func describe(spec *authzv1.SubjectAccessReviewSpec) string {
	if ra := spec.ResourceAttributes; ra != nil {
		res := ra.Resource
		if ra.Subresource != "" {
			res += "/" + ra.Subresource
		}
		if ra.Group != "" {
			res += "." + ra.Group
		}
		if ra.Namespace != "" {
			return fmt.Sprintf("%s %s in namespace %s", ra.Verb, res, ra.Namespace)
		}
		return fmt.Sprintf("%s %s", ra.Verb, res)
	}
	if na := spec.NonResourceAttributes; na != nil {
		return fmt.Sprintf("%s %s", na.Verb, na.Path)
	}
	return "unknown"
}
