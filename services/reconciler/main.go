// reconciler is the controller-loop service. It consumes the declarative
// tenant manifest, periodically diffs it against live state in each
// downstream service (keycore, KMIP, policy, audit), and emits the
// actions required to converge.
//
// The service holds no domain state of its own — every operation is an
// HTTP call to an existing service plus an audit event. That keeps the
// reconciler stateless and horizontally scalable; multiple replicas can
// race the same reconciliation pass because each individual action is
// idempotent.
package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	pkgconfig "vecta-kms/pkg/config"
	pkgreconciler "vecta-kms/pkg/reconciler"
)

var logger = log.New(os.Stdout, "[reconciler] ", log.LstdFlags|log.Lmicroseconds)

func main() {
	cfg := pkgconfig.Load()
	_ = cfg

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	keycoreURL := envOr("KEYCORE_URL", "http://kms-keycore:8010")
	kmipURL := envOr("KMIP_URL", "http://kms-kmip:8160")
	policyURL := envOr("POLICY_URL", "http://kms-policy:8050")
	auditURL := envOr("AUDIT_URL", "http://kms-audit:8060")

	client := &http.Client{Timeout: 10 * time.Second}

	tenant := newTenantReconciler(client, keycoreURL, kmipURL, policyURL, auditURL, logger)
	keylife := newKeyLifecycleReconciler(client, keycoreURL, logger)
	kmipClients := newKMIPClientReconciler(client, kmipURL, logger)
	quota := newQuotaReconciler(client, policyURL, logger)

	runner := pkgreconciler.NewRunner(pkgreconciler.DefaultConfig(), logger,
		tenant, keylife, kmipClients, quota,
	)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /reconciler/status", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, runner.Status())
	})
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	port := envOr("HTTP_PORT", "8240")
	srv := pkgconfig.NewHTTPServer(port, mux)
	go func() {
		logger.Printf("http listening on :%s", port)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Fatalf("http server failed: %v", err)
		}
	}()

	go runner.Run(ctx)

	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdownCtx)
}

func envOr(k, d string) string {
	v := os.Getenv(k)
	if v == "" {
		return d
	}
	return v
}
