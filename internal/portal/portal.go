// Package portal is a small web UI for viewing known client certificates and
// revoking them by credential ID.
//
// Administrators log in with a Kubernetes bearer token. The portal validates it
// with a TokenReview, then makes every read and write with that token, so
// access is governed by RBAC on the custom resources and the audit log records
// the real administrator.
package portal

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"slices"
	"sort"
	"strings"
	"time"

	authnv1 "k8s.io/api/authentication/v1"
	authzv1 "k8s.io/api/authorization/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/raesene/certrevoker/internal/certid"
	"github.com/raesene/certrevoker/internal/resources"
)

//go:embed templates/*.html static/*
var assets embed.FS

// Server is the portal HTTP handler.
type Server struct {
	kube     kubernetes.Interface // the portal's own identity: TokenReview / SubjectAccessReview only
	baseCfg  *rest.Config         // API server address and CA, with no credentials
	sessions *sessionStore
	tmpl     *template.Template
	log      *slog.Logger
	mux      *http.ServeMux
	// newClient builds an API client that authenticates as the logged-in
	// administrator. Replaceable in tests.
	newClient func(token string) (dynamic.Interface, error)
}

func New(kube kubernetes.Interface, cfg *rest.Config, log *slog.Logger, stop <-chan struct{}) (*Server, error) {
	tmpl, err := template.New("").Funcs(template.FuncMap{
		"fmtTime":     fmtTime,
		"shortID":     shortID,
		"join":        strings.Join,
		"relative":    relative,
		"rfc3339":     func(t time.Time) string { return t.UTC().Format(time.RFC3339) },
		"dict":        dict,
		"fmtDate":     func(t *time.Time) string { return t.UTC().Format("2006-01-02") },
		"shortSigner": shortSigner,
		"hexPrefix": func(id string) string {
			h := strings.TrimPrefix(id, certid.Prefix)
			if len(h) > 12 {
				return h[:12] + "…"
			}
			return h
		},
		"fmtClock": func(t *time.Time) string { return t.UTC().Format("15:04 UTC") },
	}).ParseFS(assets, "templates/*.html")
	if err != nil {
		return nil, err
	}
	s := &Server{
		kube:     kube,
		baseCfg:  rest.AnonymousClientConfig(cfg),
		sessions: newSessionStore(30 * time.Minute),
		tmpl:     tmpl,
		log:      log.With("component", "portal"),
		mux:      http.NewServeMux(),
	}
	s.newClient = func(token string) (dynamic.Interface, error) {
		c := rest.CopyConfig(s.baseCfg)
		c.BearerToken = token
		return dynamic.NewForConfig(c)
	}
	go s.sessions.gc(stop)

	static, _ := fs.Sub(assets, "static")
	s.mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.FS(static))))
	s.mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })
	s.mux.HandleFunc("GET /login", s.loginPage)
	s.mux.HandleFunc("POST /login", s.login)
	s.mux.HandleFunc("POST /logout", s.authed(s.logout))
	s.mux.HandleFunc("GET /{$}", s.authed(s.inventory))
	s.mux.HandleFunc("GET /cert", s.authed(s.certDetail))
	s.mux.HandleFunc("GET /inspect", s.authed(s.inspectPage))
	s.mux.HandleFunc("POST /inspect", s.authed(s.inspect))
	s.mux.HandleFunc("POST /revoke", s.authed(s.revoke))
	s.mux.HandleFunc("POST /unrevoke", s.authed(s.unrevoke))
	return s, nil
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'; form-action 'self'")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cache-Control", "no-store")
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	s.mux.ServeHTTP(w, r)
}

type authedHandler func(w http.ResponseWriter, r *http.Request, sess *session)

func (s *Server) authed(h authedHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess := s.sessions.get(r)
		if sess == nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		if r.Method == http.MethodPost && !validCSRF(sess, r) {
			http.Error(w, "invalid CSRF token", http.StatusForbidden)
			return
		}
		h(w, r, sess)
	}
}

// ---- login / logout ----

func (s *Server) loginPage(w http.ResponseWriter, r *http.Request) {
	s.render(w, "login.html", map[string]any{"Error": ""})
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimSpace(r.PostFormValue("token"))
	if token == "" {
		s.render(w, "login.html", map[string]any{"Error": "Enter a Kubernetes bearer token."})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	tr, err := s.kube.AuthenticationV1().TokenReviews().Create(ctx,
		&authnv1.TokenReview{Spec: authnv1.TokenReviewSpec{Token: token}}, metav1.CreateOptions{})
	if err != nil {
		s.log.Error("TokenReview failed", "err", err)
		s.render(w, "login.html", map[string]any{"Error": "Could not validate the token (TokenReview failed)."})
		return
	}
	if !tr.Status.Authenticated {
		s.log.Info("login rejected: token not authenticated", "remote", r.RemoteAddr)
		s.render(w, "login.html", map[string]any{"Error": "Token was not accepted by the Kubernetes API server."})
		return
	}
	u := tr.Status.User
	canView, err := s.can(ctx, u, "list", resources.IssuedCertificatesGVR.Resource)
	if err != nil {
		s.render(w, "login.html", map[string]any{"Error": "Authorization check failed."})
		return
	}
	if !canView {
		s.log.Info("login rejected: not authorized", "user", u.Username)
		s.render(w, "login.html", map[string]any{"Error": fmt.Sprintf(
			"%s is not allowed to list issuedcertificates.%s.", u.Username, resources.Group)})
		return
	}
	canRevoke, _ := s.can(ctx, u, "create", resources.CertificateRevocationsGVR.Resource)

	client, err := s.newClient(token)
	if err != nil {
		s.render(w, "login.html", map[string]any{"Error": "Could not create API client."})
		return
	}
	sess := s.sessions.create(&session{
		token: token, user: u.Username, groups: u.Groups, canRevoke: canRevoke, client: client,
	})
	setSessionCookie(w, sess)
	s.log.Info("login", "user", u.Username, "groups", u.Groups, "canRevoke", canRevoke)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// can asks kube-apiserver whether the token's user may perform verb on one of
// our resources. Used only to shape the UI; the API enforces RBAC regardless.
func (s *Server) can(ctx context.Context, u authnv1.UserInfo, verb, resource string) (bool, error) {
	extra := map[string]authzv1.ExtraValue{}
	for k, v := range u.Extra {
		extra[k] = authzv1.ExtraValue(v)
	}
	sar, err := s.kube.AuthorizationV1().SubjectAccessReviews().Create(ctx, &authzv1.SubjectAccessReview{
		Spec: authzv1.SubjectAccessReviewSpec{
			User: u.Username, UID: u.UID, Groups: u.Groups, Extra: extra,
			ResourceAttributes: &authzv1.ResourceAttributes{
				Group: resources.Group, Version: resources.Version, Resource: resource, Verb: verb,
			},
		},
	}, metav1.CreateOptions{})
	if err != nil {
		s.log.Error("SubjectAccessReview failed", "err", err)
		return false, err
	}
	return sar.Status.Allowed, nil
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request, sess *session) {
	s.sessions.delete(sess.id)
	clearSessionCookie(w)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// ---- inventory ----

// row is one credential in the inventory table.
type row struct {
	ID          string
	Identity    string
	Groups      []string
	Source      string
	Signer      string
	Requestor   string
	NotBefore   *time.Time
	NotAfter    *time.Time
	LastSeen    *time.Time
	Expired     bool
	Revoked     bool
	Revocation  *resources.CertificateRevocation
	Masters     bool
	InInventory bool
}

func (s *Server) loadRows(ctx context.Context, sess *session) ([]row, error) {
	icList, err := sess.client.Resource(resources.IssuedCertificatesGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	revList, err := sess.client.Resource(resources.CertificateRevocationsGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	revs := map[string]*resources.CertificateRevocation{}
	for i := range revList.Items {
		var rv resources.CertificateRevocation
		if err := resources.FromUnstructured(&revList.Items[i], &rv); err == nil {
			revs[rv.Spec.CredentialID] = &rv
		}
	}
	now := time.Now()
	var rows []row
	for i := range icList.Items {
		var ic resources.IssuedCertificate
		if err := resources.FromUnstructured(&icList.Items[i], &ic); err != nil {
			continue
		}
		rw := row{
			ID: ic.Spec.CredentialID, Source: ic.Spec.Source, Signer: ic.Spec.SignerName,
			Requestor: ic.Spec.Requestor, InInventory: true,
			Identity: ic.Spec.CommonName, Groups: ic.Spec.Organizations,
		}
		if rw.Identity == "" {
			rw.Identity = ic.Status.SeenAsUser
		}
		if len(rw.Groups) == 0 {
			rw.Groups = withoutImplicitGroups(ic.Status.SeenGroups)
		}
		if ic.Spec.NotBefore != nil {
			t := ic.Spec.NotBefore.Time
			rw.NotBefore = &t
		}
		if ic.Spec.NotAfter != nil {
			t := ic.Spec.NotAfter.Time
			rw.NotAfter = &t
			rw.Expired = now.After(t)
		}
		if ic.Status.LastSeen != nil {
			t := ic.Status.LastSeen.Time
			rw.LastSeen = &t
		}
		if rv, ok := revs[rw.ID]; ok {
			rw.Revoked, rw.Revocation = true, rv
			delete(revs, rw.ID)
		}
		rw.Masters = slices.Contains(rw.Groups, "system:masters")
		rows = append(rows, rw)
	}
	// Revocations for credentials not in the inventory (revoked by ID).
	for id, rv := range revs {
		rw := row{ID: id, Identity: rv.Spec.CommonName, Source: "Manual", Revoked: true, Revocation: rv}
		if rv.Spec.NotAfter != nil {
			t := rv.Spec.NotAfter.Time
			rw.NotAfter = &t
			rw.Expired = now.After(t)
		}
		rows = append(rows, rw)
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Identity != rows[j].Identity {
			return rows[i].Identity < rows[j].Identity
		}
		return rows[i].ID < rows[j].ID
	})
	return rows, nil
}

// withoutImplicitGroups hides groups kube-apiserver adds to every
// authenticated user, which aren't part of the certificate.
func withoutImplicitGroups(groups []string) []string {
	var out []string
	for _, g := range groups {
		if g != "system:authenticated" {
			out = append(out, g)
		}
	}
	return out
}

func (s *Server) inventory(w http.ResponseWriter, r *http.Request, sess *session) {
	rows, err := s.loadRows(r.Context(), sess)
	if s.handleAPIError(w, r, sess, err) {
		return
	}
	view := r.URL.Query().Get("view")
	if view == "" {
		view = "active"
	}
	q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	var shown []row
	counts := map[string]int{}
	for _, rw := range rows {
		counts["all"]++
		if rw.Revoked {
			counts["revoked"]++
		} else if rw.Expired {
			counts["expired"]++
		} else {
			counts["active"]++
		}
		switch view {
		case "active":
			if rw.Revoked || rw.Expired {
				continue
			}
		case "revoked":
			if !rw.Revoked {
				continue
			}
		case "expired":
			if !rw.Expired {
				continue
			}
		}
		if q != "" && !matches(rw, q) {
			continue
		}
		shown = append(shown, rw)
	}
	s.render(w, "inventory.html", map[string]any{
		"Session": sess.view(), "Flash": s.sessions.popFlash(sess),
		"Rows": shown, "View": view, "Q": q, "Counts": counts, "Foot": footFor(shown),
	})
}

// foot is the ledger's foot row: totals for the rows in view, each saying
// how it was reached.
type foot struct {
	Total, CSR, Observed, Manual        int
	Active, Revoked, Expired, Masters   int
	SeenHour, NeverSeen, UnknownExpiry  int
	EarliestIssued, NextExpiry, LastSee *time.Time
}

func footFor(rows []row) foot {
	var f foot
	now := time.Now()
	earlier := func(cur, t *time.Time) *time.Time {
		if t != nil && (cur == nil || t.Before(*cur)) {
			return t
		}
		return cur
	}
	for _, rw := range rows {
		f.Total++
		switch rw.Source {
		case "CSR":
			f.CSR++
		case "Observed":
			f.Observed++
		default:
			f.Manual++
		}
		switch {
		case rw.Revoked:
			f.Revoked++
		case rw.Expired:
			f.Expired++
		default:
			f.Active++
		}
		if rw.Masters {
			f.Masters++
		}
		f.EarliestIssued = earlier(f.EarliestIssued, rw.NotBefore)
		if rw.NotAfter == nil {
			f.UnknownExpiry++
		} else if rw.NotAfter.After(now) {
			f.NextExpiry = earlier(f.NextExpiry, rw.NotAfter)
		}
		switch {
		case rw.LastSeen == nil:
			f.NeverSeen++
		default:
			if now.Sub(*rw.LastSeen) < time.Hour {
				f.SeenHour++
			}
			if f.LastSee == nil || rw.LastSeen.After(*f.LastSee) {
				f.LastSee = rw.LastSeen
			}
		}
	}
	return f
}

func matches(rw row, q string) bool {
	hay := strings.ToLower(strings.Join(append([]string{rw.ID, rw.Identity, rw.Signer, rw.Requestor, rw.Source}, rw.Groups...), " "))
	return strings.Contains(hay, q)
}

func (s *Server) certDetail(w http.ResponseWriter, r *http.Request, sess *session) {
	id, err := certid.Normalize(r.URL.Query().Get("id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	ctx := r.Context()
	name := certid.ObjectName(id)
	var ic *resources.IssuedCertificate
	if u, err := sess.client.Resource(resources.IssuedCertificatesGVR).Get(ctx, name, metav1.GetOptions{}); err == nil {
		ic = &resources.IssuedCertificate{}
		_ = resources.FromUnstructured(u, ic)
	} else if !apierrors.IsNotFound(err) && s.handleAPIError(w, r, sess, err) {
		return
	}
	var rv *resources.CertificateRevocation
	if u, err := sess.client.Resource(resources.CertificateRevocationsGVR).Get(ctx, name, metav1.GetOptions{}); err == nil {
		rv = &resources.CertificateRevocation{}
		_ = resources.FromUnstructured(u, rv)
	} else if !apierrors.IsNotFound(err) && s.handleAPIError(w, r, sess, err) {
		return
	}
	masters := false
	if ic != nil {
		masters = slices.Contains(ic.Spec.Organizations, "system:masters") || slices.Contains(ic.Status.SeenGroups, "system:masters")
	}
	s.render(w, "cert.html", map[string]any{
		"Session": sess.view(), "Flash": s.sessions.popFlash(sess),
		"ID": id, "Issued": ic, "Revocation": rv, "Masters": masters,
	})
}

// ---- inspect ----

type inspected struct {
	Info        certid.Info
	Expired     bool
	Masters     bool
	InInventory bool
	Revoked     bool
}

func (s *Server) inspectPage(w http.ResponseWriter, r *http.Request, sess *session) {
	s.render(w, "inspect.html", map[string]any{"Session": sess.view(), "Flash": s.sessions.popFlash(sess)})
}

func (s *Server) inspect(w http.ResponseWriter, r *http.Request, sess *session) {
	input := r.PostFormValue("input")
	certs, err := certid.ParseUserInput(input)
	if err != nil {
		s.render(w, "inspect.html", map[string]any{"Session": sess.view(), "Error": err.Error()})
		return
	}
	ctx := r.Context()
	var results []inspected
	for _, c := range certs {
		info := certid.Summarize(c)
		info.PEM = "" // don't echo back
		res := inspected{Info: info, Expired: time.Now().After(info.NotAfter),
			Masters: slices.Contains(info.Organizations, "system:masters")}
		name := certid.ObjectName(info.CredentialID)
		if _, err := sess.client.Resource(resources.IssuedCertificatesGVR).Get(ctx, name, metav1.GetOptions{}); err == nil {
			res.InInventory = true
		}
		if _, err := sess.client.Resource(resources.CertificateRevocationsGVR).Get(ctx, name, metav1.GetOptions{}); err == nil {
			res.Revoked = true
		}
		results = append(results, res)
	}
	s.render(w, "inspect.html", map[string]any{"Session": sess.view(), "Results": results})
}

// ---- revoke / unrevoke ----

func (s *Server) revoke(w http.ResponseWriter, r *http.Request, sess *session) {
	id, err := certid.Normalize(r.PostFormValue("id"))
	if err != nil {
		s.sessions.setFlash(sess, "Error: "+err.Error())
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	reason := strings.TrimSpace(r.PostFormValue("reason"))
	if len(reason) > 256 {
		reason = reason[:256]
	}
	ctx := r.Context()
	name := certid.ObjectName(id)
	rv := resources.CertificateRevocation{Spec: resources.CertificateRevocationSpec{
		CredentialID: id, Reason: reason, RevokedBy: sess.user,
	}}
	rv.Name = name
	// Snapshot identity and expiry from the inventory, if known, so the
	// revocation can be displayed and garbage-collected on its own.
	if u, err := sess.client.Resource(resources.IssuedCertificatesGVR).Get(ctx, name, metav1.GetOptions{}); err == nil {
		var ic resources.IssuedCertificate
		if resources.FromUnstructured(u, &ic) == nil {
			rv.Spec.CommonName = ic.Spec.CommonName
			if rv.Spec.CommonName == "" {
				rv.Spec.CommonName = ic.Status.SeenAsUser
			}
			rv.Spec.NotAfter = ic.Spec.NotAfter
		}
	}
	// Certificates pasted on the inspect page carry their own details.
	if cn := strings.TrimSpace(r.PostFormValue("cn")); cn != "" && rv.Spec.CommonName == "" {
		rv.Spec.CommonName = cn
	}
	if na := r.PostFormValue("notAfter"); na != "" && rv.Spec.NotAfter == nil {
		if t, err := time.Parse(time.RFC3339, na); err == nil {
			rv.Spec.NotAfter = &metav1.Time{Time: t}
		}
	}
	u, err := resources.ToUnstructured(&rv, "CertificateRevocation")
	if err == nil {
		_, err = sess.client.Resource(resources.CertificateRevocationsGVR).Create(ctx, u, metav1.CreateOptions{})
	}
	switch {
	case err == nil:
		s.log.Info("certificate revoked", "credentialID", id, "by", sess.user, "reason", reason)
		s.sessions.setFlash(sess, fmt.Sprintf("Revoked %s. Requests using it will be denied within the API server's cache TTL.", shortID(id)))
	case apierrors.IsAlreadyExists(err):
		s.sessions.setFlash(sess, fmt.Sprintf("%s is already revoked.", shortID(id)))
	case apierrors.IsUnauthorized(err):
		s.expire(w, r, sess)
		return
	default:
		s.sessions.setFlash(sess, "Revocation failed: "+err.Error())
	}
	s.redirectBack(w, r, id)
}

func (s *Server) unrevoke(w http.ResponseWriter, r *http.Request, sess *session) {
	id, err := certid.Normalize(r.PostFormValue("id"))
	if err != nil {
		s.sessions.setFlash(sess, "Error: "+err.Error())
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	err = sess.client.Resource(resources.CertificateRevocationsGVR).Delete(r.Context(), certid.ObjectName(id), metav1.DeleteOptions{})
	switch {
	case err == nil:
		s.log.Info("revocation removed", "credentialID", id, "by", sess.user)
		s.sessions.setFlash(sess, fmt.Sprintf("Removed revocation for %s.", shortID(id)))
	case apierrors.IsNotFound(err):
		s.sessions.setFlash(sess, fmt.Sprintf("%s was not revoked.", shortID(id)))
	case apierrors.IsUnauthorized(err):
		s.expire(w, r, sess)
		return
	default:
		s.sessions.setFlash(sess, "Removing revocation failed: "+err.Error())
	}
	s.redirectBack(w, r, id)
}

func (s *Server) redirectBack(w http.ResponseWriter, r *http.Request, id string) {
	if r.PostFormValue("from") == "cert" {
		http.Redirect(w, r, "/cert?id="+id, http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// ---- helpers ----

// handleAPIError renders API errors. It returns true if it wrote a response.
func (s *Server) handleAPIError(w http.ResponseWriter, r *http.Request, sess *session, err error) bool {
	if err == nil {
		return false
	}
	if apierrors.IsUnauthorized(err) {
		s.expire(w, r, sess)
		return true
	}
	status := http.StatusBadGateway
	msg := "Kubernetes API error: " + err.Error()
	if apierrors.IsForbidden(err) {
		status = http.StatusForbidden
	}
	var se *apierrors.StatusError
	if errors.As(err, &se) {
		msg = "Kubernetes API error: " + se.ErrStatus.Message
	}
	w.WriteHeader(status)
	s.render(w, "error.html", map[string]any{"Session": sess.view(), "Error": msg})
	return true
}

// expire ends a session whose token the API server no longer accepts.
func (s *Server) expire(w http.ResponseWriter, r *http.Request, sess *session) {
	s.sessions.delete(sess.id)
	clearSessionCookie(w)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *Server) render(w http.ResponseWriter, name string, data map[string]any) {
	if _, ok := data["Page"]; !ok {
		data["Page"] = strings.TrimSuffix(name, ".html") // masthead marks the current page
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.ExecuteTemplate(w, name, data); err != nil {
		s.log.Error("template error", "template", name, "err", err)
	}
}

func fmtTime(t any) string {
	switch v := t.(type) {
	case *time.Time:
		if v == nil {
			return ""
		}
		return v.UTC().Format("2006-01-02 15:04 UTC")
	case time.Time:
		return v.UTC().Format("2006-01-02 15:04 UTC")
	case *metav1.Time:
		if v == nil {
			return ""
		}
		return v.UTC().Format("2006-01-02 15:04 UTC")
	case metav1.Time:
		if v.IsZero() {
			return ""
		}
		return v.UTC().Format("2006-01-02 15:04 UTC")
	}
	return ""
}

func relative(t *time.Time) string {
	if t == nil {
		return ""
	}
	d := time.Since(*t)
	switch {
	case d < 0:
		return "in the future"
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	}
	return fmt.Sprintf("%dd ago", int(d.Hours()/24))
}

// shortSigner abbreviates the built-in signer names for the ledger; the
// full name stays in the cell's title.
func shortSigner(name string) string {
	switch name {
	case "kubernetes.io/kube-apiserver-client":
		return "apiserver-client"
	case "kubernetes.io/kube-apiserver-client-kubelet":
		return "kubelet"
	}
	return strings.TrimPrefix(name, "kubernetes.io/")
}

// dict builds a map from alternating keys and values, for passing several
// values to a sub-template.
func dict(kv ...any) (map[string]any, error) {
	if len(kv)%2 != 0 {
		return nil, errors.New("dict: odd number of arguments")
	}
	m := make(map[string]any, len(kv)/2)
	for i := 0; i < len(kv); i += 2 {
		k, ok := kv[i].(string)
		if !ok {
			return nil, errors.New("dict: keys must be strings")
		}
		m[k] = kv[i+1]
	}
	return m, nil
}

func shortID(id string) string {
	hexPart := strings.TrimPrefix(id, certid.Prefix)
	if len(hexPart) > 16 {
		return certid.Prefix + hexPart[:16] + "…"
	}
	return id
}
