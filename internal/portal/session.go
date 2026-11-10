package portal

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"net/http"
	"sync"
	"time"

	"k8s.io/client-go/dynamic"
)

const cookieName = "certrevoker_session"

// session holds a logged-in administrator's Kubernetes token server-side.
// The browser only gets an opaque random session ID. All reads and writes to
// the API are made with the admin's own token, so RBAC is enforced by
// kube-apiserver and the audit log records the real user.
type session struct {
	id        string
	csrf      string
	token     string
	user      string
	groups    []string
	canRevoke bool
	expires   time.Time
	client    dynamic.Interface
	flash     string
}

type sessionStore struct {
	mu       sync.Mutex
	sessions map[string]*session
	ttl      time.Duration
}

func newSessionStore(ttl time.Duration) *sessionStore {
	return &sessionStore{sessions: map[string]*session{}, ttl: ttl}
}

func randomString() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func (s *sessionStore) create(sess *session) *session {
	sess.id = randomString()
	sess.csrf = randomString()
	sess.expires = time.Now().Add(s.ttl)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[sess.id] = sess
	return sess
}

func (s *sessionStore) get(r *http.Request) *session {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[c.Value]
	if !ok {
		return nil
	}
	if time.Now().After(sess.expires) {
		delete(s.sessions, c.Value)
		return nil
	}
	return sess
}

func (s *sessionStore) delete(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, id)
}

func (s *sessionStore) setFlash(sess *session, msg string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess.flash = msg
}

func (s *sessionStore) popFlash(sess *session) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	msg := sess.flash
	sess.flash = ""
	return msg
}

// gc drops expired sessions periodically.
func (s *sessionStore) gc(stop <-chan struct{}) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			now := time.Now()
			s.mu.Lock()
			for id, sess := range s.sessions {
				if now.After(sess.expires) {
					delete(s.sessions, id)
				}
			}
			s.mu.Unlock()
		}
	}
}

func setSessionCookie(w http.ResponseWriter, sess *session) {
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    sess.id,
		Path:     "/",
		Expires:  sess.expires,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
}

func clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: cookieName, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode,
	})
}

func validCSRF(sess *session, r *http.Request) bool {
	return subtle.ConstantTimeCompare([]byte(sess.csrf), []byte(r.PostFormValue("csrf"))) == 1
}

// sessView is the template-visible part of a session.
type sessView struct {
	User      string
	Groups    []string
	CanRevoke bool
	CSRF      string
}

func (s *session) view() sessView {
	return sessView{User: s.user, Groups: s.groups, CanRevoke: s.canRevoke, CSRF: s.csrf}
}
