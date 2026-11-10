// Command certrevoker is a proof of concept for revoking Kubernetes x509 client
// certificates without rotating the CA. It runs:
//
//   - an authorization webhook that explicitly denies requests made with
//     revoked certificates (by credential ID);
//   - an inventory controller that records certificates issued via the CSR API;
//   - an observer that records credential IDs seen in use by the webhook;
//   - a web portal where administrators view the inventory and revoke.
//
// State lives in two cluster-scoped custom resources: IssuedCertificate and
// CertificateRevocation (group certrevoker.example.com).
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/raesene/certrevoker/internal/inventory"
	"github.com/raesene/certrevoker/internal/portal"
	"github.com/raesene/certrevoker/internal/state"
	"github.com/raesene/certrevoker/internal/webhook"
)

func main() {
	var (
		kubeconfig      = flag.String("kubeconfig", "", "kubeconfig path (default: in-cluster config)")
		webhookAddr     = flag.String("webhook-addr", "127.0.0.1:9443", "authorization webhook listen address")
		webhookCert     = flag.String("webhook-tls-cert", "/etc/certrevoker/tls/webhook.crt", "webhook serving certificate")
		webhookKey      = flag.String("webhook-tls-key", "/etc/certrevoker/tls/webhook.key", "webhook serving key")
		webhookClientCA = flag.String("webhook-client-ca", "/etc/certrevoker/tls/ca.crt", "CA for verifying kube-apiserver's client certificate (empty disables client auth)")
		portalAddr      = flag.String("portal-addr", "0.0.0.0:8443", "portal listen address")
		portalCert      = flag.String("portal-tls-cert", "/etc/certrevoker/tls/portal.crt", "portal serving certificate")
		portalKey       = flag.String("portal-tls-key", "/etc/certrevoker/tls/portal.key", "portal serving key")
		flushInterval   = flag.Duration("flush-interval", 15*time.Second, "how often observations are written to the API")
		gcInterval      = flag.Duration("gc-interval", 10*time.Minute, "how often expired records are garbage collected")
	)
	flag.Parse()
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	if err := run(log, *kubeconfig, *webhookAddr, *webhookCert, *webhookKey, *webhookClientCA,
		*portalAddr, *portalCert, *portalKey, *flushInterval, *gcInterval); err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger, kubeconfig, webhookAddr, webhookCert, webhookKey, webhookClientCA,
	portalAddr, portalCert, portalKey string, flushInterval, gcInterval time.Duration) error {

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	cfg, err := loadConfig(kubeconfig)
	if err != nil {
		return err
	}
	kube, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return err
	}
	dyn, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return err
	}

	store := state.New(dyn)
	store.Start(ctx)
	csrs := inventory.NewCSRController(kube, dyn, store, log)
	csrs.Start(ctx)

	syncCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	if err := store.WaitForSync(syncCtx); err != nil {
		return fmt.Errorf("%w (are the CRDs installed?)", err)
	}
	if !csrs.WaitForSync(syncCtx) {
		return errors.New("timed out waiting for CSR cache to sync")
	}
	log.Info("caches synced", "revocations", len(store.AllRevocations()), "issued", len(store.AllIssued()))

	observer := inventory.NewObserver(dyn, store, log)
	go csrs.Run(ctx)
	go observer.Run(ctx, flushInterval)
	go inventory.NewGC(dyn, store, log).Run(ctx, gcInterval)

	// Authorization webhook. Started only after the revocation cache has
	// synced: until then kube-apiserver gets connection errors and applies
	// the configured failurePolicy (NoOpinion), rather than us answering
	// "not revoked" from an empty cache.
	whMux := http.NewServeMux()
	whMux.Handle("POST /authorize", &webhook.Handler{Revocations: store, Recorder: observer, Log: log.With("component", "webhook")})
	whTLS, err := webhookTLSConfig(webhookClientCA)
	if err != nil {
		return err
	}
	whSrv := &http.Server{Addr: webhookAddr, Handler: whMux, TLSConfig: whTLS,
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second}

	ps, err := portal.New(kube, cfg, log, ctx.Done())
	if err != nil {
		return err
	}
	pSrv := &http.Server{Addr: portalAddr, Handler: ps,
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12},
		ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second}

	errCh := make(chan error, 2)
	go func() {
		log.Info("authorization webhook listening", "addr", webhookAddr, "clientAuth", webhookClientCA != "")
		errCh <- fmt.Errorf("webhook server: %w", whSrv.ListenAndServeTLS(webhookCert, webhookKey))
	}()
	go func() {
		log.Info("portal listening", "addr", portalAddr)
		errCh <- fmt.Errorf("portal server: %w", pSrv.ListenAndServeTLS(portalCert, portalKey))
	}()

	select {
	case <-ctx.Done():
	case err := <-errCh:
		return err
	}
	shutdownCtx, c := context.WithTimeout(context.Background(), 5*time.Second)
	defer c()
	_ = whSrv.Shutdown(shutdownCtx)
	_ = pSrv.Shutdown(shutdownCtx)
	return nil
}

func loadConfig(kubeconfig string) (*rest.Config, error) {
	var (
		cfg *rest.Config
		err error
	)
	if kubeconfig != "" {
		cfg, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
	} else {
		cfg, err = rest.InClusterConfig()
	}
	if err != nil {
		return nil, err
	}
	cfg.UserAgent = "certrevoker"
	cfg.QPS, cfg.Burst = 20, 40
	return cfg, nil
}

// webhookTLSConfig requires and verifies kube-apiserver's client certificate
// when a client CA is configured, so only the API server can query the webhook.
func webhookTLSConfig(clientCAFile string) (*tls.Config, error) {
	c := &tls.Config{MinVersion: tls.VersionTLS12}
	if clientCAFile == "" {
		return c, nil
	}
	pemData, err := os.ReadFile(clientCAFile)
	if err != nil {
		return nil, fmt.Errorf("reading webhook client CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemData) {
		return nil, errors.New("webhook client CA file contains no certificates")
	}
	c.ClientCAs = pool
	c.ClientAuth = tls.RequireAndVerifyClientCert
	return c, nil
}
