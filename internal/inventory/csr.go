// Package inventory records which client certificates exist: those issued via
// the CSR API (watched here before csrcleaner deletes them, about an hour after
// approval), and those only seen in use by the authorization webhook.
package inventory

import (
	"context"
	"log/slog"
	"time"

	certv1 "k8s.io/api/certificates/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	"github.com/raesene/certrevoker/internal/certid"
	"github.com/raesene/certrevoker/internal/resources"
	"github.com/raesene/certrevoker/internal/state"
)

// CSRController copies issued client certificates from CSRs into
// IssuedCertificate objects, which persist after the CSR is deleted.
type CSRController struct {
	kube    kubernetes.Interface
	dyn     dynamic.Interface
	store   *state.Store
	factory informers.SharedInformerFactory
	csrs    cache.SharedIndexInformer
	queue   workqueue.TypedRateLimitingInterface[string]
	log     *slog.Logger
}

func NewCSRController(kube kubernetes.Interface, dyn dynamic.Interface, store *state.Store, log *slog.Logger) *CSRController {
	f := informers.NewSharedInformerFactory(kube, 10*time.Minute)
	c := &CSRController{
		kube:    kube,
		dyn:     dyn,
		store:   store,
		factory: f,
		csrs:    f.Certificates().V1().CertificateSigningRequests().Informer(),
		queue: workqueue.NewTypedRateLimitingQueueWithConfig(
			workqueue.DefaultTypedControllerRateLimiter[string](),
			workqueue.TypedRateLimitingQueueConfig[string]{Name: "csr"}),
		log: log.With("component", "csr-inventory"),
	}
	enqueue := func(obj any) {
		if key, err := cache.MetaNamespaceKeyFunc(obj); err == nil {
			c.queue.Add(key)
		}
	}
	_, _ = c.csrs.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    enqueue,
		UpdateFunc: func(_, obj any) { enqueue(obj) },
	})
	return c
}

func (c *CSRController) Start(ctx context.Context) { c.factory.Start(ctx.Done()) }

func (c *CSRController) WaitForSync(ctx context.Context) bool {
	return cache.WaitForCacheSync(ctx.Done(), c.csrs.HasSynced)
}

// Run processes the queue until ctx is cancelled.
func (c *CSRController) Run(ctx context.Context) {
	defer c.queue.ShutDown()
	go wait.UntilWithContext(ctx, func(ctx context.Context) {
		for c.processNext(ctx) {
		}
	}, time.Second)
	<-ctx.Done()
}

func (c *CSRController) processNext(ctx context.Context) bool {
	key, quit := c.queue.Get()
	if quit {
		return false
	}
	defer c.queue.Done(key)
	if err := c.sync(ctx, key); err != nil {
		c.log.Warn("sync failed, requeueing", "csr", key, "err", err)
		c.queue.AddRateLimited(key)
		return true
	}
	c.queue.Forget(key)
	return true
}

func (c *CSRController) sync(ctx context.Context, key string) error {
	obj, exists, err := c.csrs.GetStore().GetByKey(key)
	if err != nil || !exists {
		return err
	}
	csr := obj.(*certv1.CertificateSigningRequest)
	if len(csr.Status.Certificate) == 0 {
		return nil // not issued (yet)
	}
	cert, err := certid.FirstCertFromPEM(csr.Status.Certificate)
	if err != nil {
		c.log.Warn("CSR has unparseable certificate", "csr", csr.Name, "err", err)
		return nil
	}
	info := certid.Summarize(cert)
	if !info.ClientAuth {
		return nil // e.g. kubelet serving certificates
	}

	spec := resources.IssuedCertificateSpec{
		CredentialID:   info.CredentialID,
		Source:         resources.SourceCSR,
		CommonName:     info.CommonName,
		Organizations:  info.Organizations,
		SerialNumber:   info.SerialNumber,
		Issuer:         info.Issuer,
		NotBefore:      &metav1.Time{Time: info.NotBefore},
		NotAfter:       &metav1.Time{Time: info.NotAfter},
		SignerName:     csr.Spec.SignerName,
		CSRName:        csr.Name,
		CSRUID:         string(csr.UID),
		Requestor:      csr.Spec.Username,
		CertificatePEM: info.PEM,
	}

	client := c.dyn.Resource(resources.IssuedCertificatesGVR)
	existing, found := c.store.Issued(info.CredentialID)
	switch {
	case !found:
		ic := resources.IssuedCertificate{Spec: spec}
		ic.Name = certid.ObjectName(info.CredentialID)
		u, err := resources.ToUnstructured(&ic, "IssuedCertificate")
		if err != nil {
			return err
		}
		if _, err := client.Create(ctx, u, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
			return err
		}
		c.log.Info("recorded issued certificate", "credentialID", info.CredentialID,
			"cn", info.CommonName, "orgs", info.Organizations, "signer", csr.Spec.SignerName,
			"csr", csr.Name, "notAfter", info.NotAfter)
	case existing.Spec.Source != resources.SourceCSR:
		// We saw this certificate in use before we saw its CSR; fill in details.
		existing.Spec = spec
		u, err := resources.ToUnstructured(existing, "IssuedCertificate")
		if err != nil {
			return err
		}
		if _, err := client.Update(ctx, u, metav1.UpdateOptions{}); err != nil {
			return err
		}
		c.log.Info("enriched observed certificate from CSR", "credentialID", info.CredentialID, "csr", csr.Name)
	}
	return nil
}
