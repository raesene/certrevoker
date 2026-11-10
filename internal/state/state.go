// Package state keeps informer-backed, in-memory views of the PoC's custom
// resources so the authorization webhook can answer without calling the API.
package state

import (
	"context"
	"fmt"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/dynamic/dynamicinformer"
	"k8s.io/client-go/tools/cache"

	"github.com/raesene/certrevoker/internal/certid"
	"github.com/raesene/certrevoker/internal/resources"
)

// Store gives read access to cached IssuedCertificates and CertificateRevocations.
type Store struct {
	factory     dynamicinformer.DynamicSharedInformerFactory
	issued      cache.SharedIndexInformer
	revocations cache.SharedIndexInformer
}

// New creates a Store. Call Start, then WaitForSync, before using it.
func New(client dynamic.Interface) *Store {
	f := dynamicinformer.NewDynamicSharedInformerFactory(client, 10*time.Minute)
	return &Store{
		factory:     f,
		issued:      f.ForResource(resources.IssuedCertificatesGVR).Informer(),
		revocations: f.ForResource(resources.CertificateRevocationsGVR).Informer(),
	}
}

func (s *Store) Start(ctx context.Context) { s.factory.Start(ctx.Done()) }

func (s *Store) WaitForSync(ctx context.Context) error {
	if !cache.WaitForCacheSync(ctx.Done(), s.issued.HasSynced, s.revocations.HasSynced) {
		return fmt.Errorf("timed out waiting for custom resource caches to sync")
	}
	return nil
}

// Revocation returns the revocation for a credential ID, if there is one.
func (s *Store) Revocation(id string) (*resources.CertificateRevocation, bool) {
	obj, exists, err := s.revocations.GetStore().GetByKey(certid.ObjectName(id))
	if err != nil || !exists {
		return nil, false
	}
	var r resources.CertificateRevocation
	if err := resources.FromUnstructured(obj.(*unstructured.Unstructured), &r); err != nil {
		return nil, false
	}
	// Names are derived from the ID and CRD validation enforces that, but
	// check anyway so a hand-made object with a mismatched name can't confuse us.
	if r.Spec.CredentialID != id {
		return nil, false
	}
	return &r, true
}

// Issued returns the inventory record for a credential ID, if there is one.
func (s *Store) Issued(id string) (*resources.IssuedCertificate, bool) {
	obj, exists, err := s.issued.GetStore().GetByKey(certid.ObjectName(id))
	if err != nil || !exists {
		return nil, false
	}
	var ic resources.IssuedCertificate
	if err := resources.FromUnstructured(obj.(*unstructured.Unstructured), &ic); err != nil {
		return nil, false
	}
	return &ic, true
}

// AllIssued returns every cached inventory record.
func (s *Store) AllIssued() []resources.IssuedCertificate {
	var out []resources.IssuedCertificate
	for _, obj := range s.issued.GetStore().List() {
		var ic resources.IssuedCertificate
		if err := resources.FromUnstructured(obj.(*unstructured.Unstructured), &ic); err == nil {
			out = append(out, ic)
		}
	}
	return out
}

// AllRevocations returns every cached revocation.
func (s *Store) AllRevocations() []resources.CertificateRevocation {
	var out []resources.CertificateRevocation
	for _, obj := range s.revocations.GetStore().List() {
		var r resources.CertificateRevocation
		if err := resources.FromUnstructured(obj.(*unstructured.Unstructured), &r); err == nil {
			out = append(out, r)
		}
	}
	return out
}

// IgnoreNotFound returns nil for NotFound errors.
func IgnoreNotFound(err error) error {
	if apierrors.IsNotFound(err) {
		return nil
	}
	return err
}
