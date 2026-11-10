package inventory

import (
	"context"
	"log/slog"
	"slices"
	"sync"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/dynamic"

	"github.com/raesene/certrevoker/internal/certid"
	"github.com/raesene/certrevoker/internal/resources"
	"github.com/raesene/certrevoker/internal/state"
)

// Observer batches what the authorization webhook sees and writes it to the
// custom resources periodically, so the webhook's hot path never calls the API.
//
// Counts are approximate: kube-apiserver caches webhook decisions
// (unauthorizedTTL), so repeated identical requests don't all reach us.
type Observer struct {
	dyn   dynamic.Interface
	store *state.Store
	log   *slog.Logger

	mu     sync.Mutex
	seen   map[string]*seenEntry   // credential ID -> latest observation
	denied map[string]*deniedEntry // credential ID -> denials since last flush
}

type seenEntry struct {
	user   string
	groups []string
	first  time.Time
	last   time.Time
}

type deniedEntry struct {
	count int64
	last  time.Time
	user  string
}

func NewObserver(dyn dynamic.Interface, store *state.Store, log *slog.Logger) *Observer {
	return &Observer{
		dyn:    dyn,
		store:  store,
		log:    log.With("component", "observer"),
		seen:   map[string]*seenEntry{},
		denied: map[string]*deniedEntry{},
	}
}

// RecordSeen notes that a credential ID was used by user/groups.
func (o *Observer) RecordSeen(id, user string, groups []string) {
	now := time.Now().UTC()
	o.mu.Lock()
	defer o.mu.Unlock()
	if e, ok := o.seen[id]; ok {
		e.last, e.user, e.groups = now, user, groups
		return
	}
	o.seen[id] = &seenEntry{user: user, groups: groups, first: now, last: now}
}

// RecordDenied notes that a request with a revoked credential ID was denied.
func (o *Observer) RecordDenied(id, user string) {
	now := time.Now().UTC()
	o.mu.Lock()
	defer o.mu.Unlock()
	e, ok := o.denied[id]
	if !ok {
		e = &deniedEntry{}
		o.denied[id] = e
	}
	e.count++
	e.last, e.user = now, user
}

// Run flushes observations every interval until ctx is cancelled.
func (o *Observer) Run(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			o.flush(ctx)
		}
	}
}

func (o *Observer) flush(ctx context.Context) {
	o.mu.Lock()
	seen, denied := o.seen, o.denied
	o.seen, o.denied = map[string]*seenEntry{}, map[string]*deniedEntry{}
	o.mu.Unlock()

	for id, e := range seen {
		if err := o.flushSeen(ctx, id, e); err != nil {
			o.log.Warn("failed to record observation; will retry", "credentialID", id, "err", err)
			o.requeueSeen(id, e)
		}
	}
	for id, e := range denied {
		if err := o.flushDenied(ctx, id, e); err != nil {
			o.log.Warn("failed to record denial; will retry", "credentialID", id, "err", err)
			o.requeueDenied(id, e)
		}
	}
}

func (o *Observer) requeueSeen(id string, e *seenEntry) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if cur, ok := o.seen[id]; ok {
		cur.first = minTime(cur.first, e.first)
		return
	}
	o.seen[id] = e
}

func (o *Observer) requeueDenied(id string, e *deniedEntry) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if cur, ok := o.denied[id]; ok {
		cur.count += e.count
		return
	}
	o.denied[id] = e
}

func (o *Observer) flushSeen(ctx context.Context, id string, e *seenEntry) error {
	client := o.dyn.Resource(resources.IssuedCertificatesGVR)
	ic, found := o.store.Issued(id)
	if !found {
		// Not issued via the CSR API (or issued before we started watching):
		// record that it exists, without validity dates.
		ic = &resources.IssuedCertificate{Spec: resources.IssuedCertificateSpec{
			CredentialID: id,
			Source:       resources.SourceObserved,
		}}
		ic.Name = certid.ObjectName(id)
		u, err := resources.ToUnstructured(ic, "IssuedCertificate")
		if err != nil {
			return err
		}
		created, err := client.Create(ctx, u, metav1.CreateOptions{})
		if apierrors.IsAlreadyExists(err) {
			return err // cache is behind; retry next flush with fresh state
		}
		if err != nil {
			return err
		}
		if err := resources.FromUnstructured(created, ic); err != nil {
			return err
		}
		o.log.Info("recorded certificate seen in use", "credentialID", id, "user", e.user, "groups", e.groups)
	}

	st := ic.Status
	// Avoid an API write per flush for busy credentials when nothing much changed.
	if st.LastSeen != nil && e.last.Sub(st.LastSeen.Time) < time.Minute &&
		st.SeenAsUser == e.user && slices.Equal(st.SeenGroups, e.groups) {
		return nil
	}
	if st.FirstSeen == nil {
		st.FirstSeen = &metav1.Time{Time: e.first}
	}
	st.LastSeen = &metav1.Time{Time: e.last}
	st.SeenAsUser = e.user
	st.SeenGroups = e.groups
	ic.Status = st
	u, err := resources.ToUnstructured(ic, "IssuedCertificate")
	if err != nil {
		return err
	}
	_, err = client.UpdateStatus(ctx, u, metav1.UpdateOptions{})
	return err
}

func (o *Observer) flushDenied(ctx context.Context, id string, e *deniedEntry) error {
	r, found := o.store.Revocation(id)
	if !found {
		return nil // revocation was removed meanwhile
	}
	r.Status.DeniedRequests += e.count
	r.Status.LastDenied = &metav1.Time{Time: e.last}
	r.Status.LastDeniedUser = e.user
	u, err := resources.ToUnstructured(r, "CertificateRevocation")
	if err != nil {
		return err
	}
	_, err = o.dyn.Resource(resources.CertificateRevocationsGVR).UpdateStatus(ctx, u, metav1.UpdateOptions{})
	return err
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
