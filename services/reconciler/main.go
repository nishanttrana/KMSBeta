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
	pkgsvctls "vecta-kms/pkg/svctls"

	pkgaudit "vecta-kms/pkg/audit"
	pkgconfig "vecta-kms/pkg/config"
	pkgevents "vecta-kms/pkg/events"
	pkgjwtauth "vecta-kms/pkg/jwtauth"
	pkgreconciler "vecta-kms/pkg/reconciler"
	"vecta-kms/pkg/servicetoken"
)

var logger = log.New(os.Stdout, "[reconciler] ", log.LstdFlags|log.Lmicroseconds)

func main() {
	// Calls to platform services carry the kms-reconciler service JWT
	// (http_helpers.go authorize); keycore refuses anonymous key use.
	servicetoken.SetDefault(servicetoken.FromEnv("kms-reconciler"))
	cfg := pkgconfig.Load()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	// Internal mTLS identity from the internal-services Sub CA; nothing is
	// served or called before it (docs/SECURITY/INTERNAL_TLS.md).
	if _, err := pkgsvctls.Init(ctx, "kms-reconciler", pkgsvctls.Options{Logger: logger}); err != nil {
		logger.Fatalf("internal mTLS enrolment failed: %v", err)
	}

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

	// The status API is audited as audit.reconciler.<action> on the unified
	// stream; it refuses to serve unaudited.
	nc, err := pkgevents.Connect(cfg.NATSURL, "kms-reconciler", logger.Printf)
	if err != nil {
		logger.Fatalf("refusing to start: audit connection failed: %v", err)
	}
	defer nc.Close()
	js, err := nc.JetStream()
	if err != nil {
		logger.Fatalf("refusing to start: jetstream unavailable: %v", err)
	}
	audit, err := pkgaudit.NewClient(js, "reconciler")
	if err != nil {
		logger.Fatalf("refusing to start: %v", err)
	}
	handler := pkgjwtauth.MustWrap("RECONCILER", cfg.JWTIssuer, cfg.JWTAudience, newRouter(runner.Status, audit, logger), logger)

	port := envOr("HTTP_PORT", "8470")
	srv := pkgconfig.NewHTTPServer(port, handler)
	go func() {
		logger.Printf("https (mTLS) listening on :%s", port)
		if err := srv.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
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
