package main

import (
	"context"
	"log"
	"os"
	"strings"
	"time"

	pkgplatform "vecta-kms/pkg/platform"
)

var logger = log.New(os.Stderr, "[kms-dataprotect] ", log.LstdFlags|log.Lmsgprefix)

// main boots the platform spine and mounts the data protection service with
// its missing-receipt reconciler loop. SkipJWT is set because dataprotect
// authenticates per-route: operator APIs validate platform JWTs in handlers
// and field-encryption wrappers use their own wrapper JWTs (WithWrapperJWT).
func main() {
	rt, err := pkgplatform.Boot(pkgplatform.Options{
		ServiceName:   "dataprotect",
		JWTScope:      "DATAPROTECT",
		HTTPPort:      "8200",
		GRPCPort:      "18200",
		MigrationsDir: "services/dataprotect/migrations",
		SkipJWT:       true,
	})
	if err != nil {
		log.Fatalf("[kms-dataprotect] boot failed: %v", err)
	}
	defer rt.Close()
	logger = rt.Logger

	var publisher EventPublisher
	if rt.Audit != nil {
		publisher = rt.Audit.Publisher()
	}

	svc := NewService(
		NewSQLStore(rt.DB),
		NewHTTPKeyCoreClient(envOr("KEYCORE_URL", "http://127.0.0.1:8010"), 5*time.Second),
		publisher,
		WithCertsClient(NewHTTPCertsClient(envOr("CERTS_URL", "http://127.0.0.1:8030"), 5*time.Second)),
		WithWrapperJWT(
			firstNonEmptyEnv("DATAPROTECT_WRAPPER_JWT_SECRET", "JWT_SECRET"),
			envOr("DATAPROTECT_WRAPPER_JWT_ISSUER", "vecta-dataprotect"),
			envOr("DATAPROTECT_WRAPPER_JWT_AUDIENCE", "vecta-field-wrapper"),
			time.Duration(mustAtoi(envOr("DATAPROTECT_WRAPPER_JWT_TTL_SEC", "3600")))*time.Second,
		),
	)
	reconcileInterval := time.Duration(mustAtoi(envOr("DATAPROTECT_RECEIPT_RECONCILE_INTERVAL_SEC", "30"))) * time.Second
	if reconcileInterval < 5*time.Second {
		reconcileInterval = 5 * time.Second
	}
	reconcileBatch := mustAtoi(envOr("DATAPROTECT_RECEIPT_RECONCILE_BATCH", "500"))
	if reconcileBatch <= 0 || reconcileBatch > 5000 {
		reconcileBatch = 500
	}
	go startMissingReceiptReconciler(rt.Ctx, logger, svc, reconcileInterval, reconcileBatch)

	if err := rt.Serve(NewHandler(svc)); err != nil {
		rt.Logger.Fatalf("serve failed: %v", err)
	}
}

func startMissingReceiptReconciler(ctx context.Context, logger *log.Logger, svc *Service, interval time.Duration, batch int) {
	if svc == nil || interval <= 0 {
		return
	}
	run := func() {
		reconcileCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		scanned, revoked, err := svc.ReconcileMissingFieldEncryptionReceipts(reconcileCtx, batch)
		if err != nil {
			logger.Printf("receipt reconciler failed: %v", err)
			return
		}
		if revoked > 0 {
			logger.Printf("receipt reconciler revoked %d stale lease(s) from %d scanned", revoked, scanned)
		}
	}
	run()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			run()
		}
	}
}

func envOr(k string, d string) string {
	v := strings.TrimSpace(os.Getenv(k))
	if v == "" {
		return d
	}
	return v
}

func mustAtoi(s string) int {
	n := 0
	for i := 0; i < len(s); i++ {
		n = n*10 + int(s[i]-'0')
	}
	return n
}

func firstNonEmptyEnv(keys ...string) string {
	for _, key := range keys {
		v := strings.TrimSpace(os.Getenv(key))
		if v != "" {
			return v
		}
	}
	return ""
}
