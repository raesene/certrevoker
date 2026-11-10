package inventory

import (
	"context"
	"log/slog"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"

	"github.com/raesene/certrevoker/internal/resources"
	"github.com/raesene/certrevoker/internal/state"
)

// GC removes records that no longer matter:
//   - revocations whose certificate has expired (kube-apiserver rejects
//     expired certificates anyway, so the entry can retire itself);
//   - inventory records for expired certificates;
//   - "Observed" records (validity unknown) not seen for observedRetention.
type GC struct {
	dyn               dynamic.Interface
	store             *state.Store
	log               *slog.Logger
	grace             time.Duration
	observedRetention time.Duration
}

func NewGC(dyn dynamic.Interface, store *state.Store, log *slog.Logger) *GC {
	return &GC{
		dyn:               dyn,
		store:             store,
		log:               log.With("component", "gc"),
		grace:             time.Hour, // allow for clock skew around NotAfter
		observedRetention: 30 * 24 * time.Hour,
	}
}

func (g *GC) Run(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			g.collect(ctx)
		}
	}
}

func (g *GC) collect(ctx context.Context) {
	cutoff := time.Now().Add(-g.grace)
	for _, r := range g.store.AllRevocations() {
		if r.Spec.NotAfter != nil && r.Spec.NotAfter.Time.Before(cutoff) {
			g.delete(ctx, resources.CertificateRevocationsGVR, r.Name, "revocation for expired certificate")
		}
	}
	for _, ic := range g.store.AllIssued() {
		switch {
		case ic.Spec.NotAfter != nil && ic.Spec.NotAfter.Time.Before(cutoff):
			g.delete(ctx, resources.IssuedCertificatesGVR, ic.Name, "expired certificate")
		case ic.Spec.Source == resources.SourceObserved && ic.Status.LastSeen != nil &&
			time.Since(ic.Status.LastSeen.Time) > g.observedRetention:
			g.delete(ctx, resources.IssuedCertificatesGVR, ic.Name, "observed certificate not seen recently")
		}
	}
}

func (g *GC) delete(ctx context.Context, gvr schema.GroupVersionResource, name, why string) {
	err := g.dyn.Resource(gvr).Delete(ctx, name, metav1.DeleteOptions{})
	if err := state.IgnoreNotFound(err); err != nil {
		g.log.Warn("garbage collection failed", "resource", gvr.Resource, "name", name, "err", err)
		return
	}
	g.log.Info("garbage collected", "resource", gvr.Resource, "name", name, "reason", why)
}
