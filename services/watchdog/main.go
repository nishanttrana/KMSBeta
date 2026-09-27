// watchdog subscribes to health.<service>.heartbeat events on NATS, tracks
// the most recent heartbeat per service, and emits an incident audit
// event when a service goes silent longer than its SLO. It also runs a
// minimal playbook engine that maps incident signals to remediation
// actions (page on-call, trigger reconciler, request key freeze).
package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
	pkgsvctls "vecta-kms/pkg/svctls"

	pkgaudit "vecta-kms/pkg/audit"
	pkgconfig "vecta-kms/pkg/config"
	pkgevents "vecta-kms/pkg/events"
	pkgjwtauth "vecta-kms/pkg/jwtauth"
)

var logger = log.New(os.Stdout, "[watchdog] ", log.LstdFlags|log.Lmicroseconds)

func main() {
	cfg := pkgconfig.Load()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	// Internal mTLS identity from the internal-services Sub CA; nothing is
	// served or called before it (docs/SECURITY/INTERNAL_TLS.md).
	if _, err := pkgsvctls.Init(ctx, "kms-watchdog", pkgsvctls.Options{Logger: logger}); err != nil {
		logger.Fatalf("internal mTLS enrolment failed: %v", err)
	}

	natsURL := envOr("NATS_URL", cfg.NATSURL)
	probe := newProbe(natsURL, logger)
	if err := probe.Start(ctx); err != nil {
		logger.Fatalf("probe start failed: %v", err)
	}
	defer probe.Close()

	pb := newPlaybookEngine(probe, logger)
	go pb.Run(ctx)

	// The read API is audited as audit.watchdog.<action> on the unified
	// stream; it refuses to serve unaudited.
	apiConn, err := pkgevents.Connect(natsURL, "kms-watchdog-api", logger.Printf)
	if err != nil {
		logger.Fatalf("refusing to start: audit connection failed: %v", err)
	}
	defer apiConn.Close()
	js, err := apiConn.JetStream()
	if err != nil {
		logger.Fatalf("refusing to start: jetstream unavailable: %v", err)
	}
	audit, err := pkgaudit.NewClient(js, "watchdog")
	if err != nil {
		logger.Fatalf("refusing to start: %v", err)
	}
	router := newRouter(probe.Snapshot, pb.Incidents, audit, logger)
	handler := pkgjwtauth.MustWrap("WATCHDOG", cfg.JWTIssuer, cfg.JWTAudience, router, logger)

	port := envOr("HTTP_PORT", "8480")
	srv := pkgconfig.NewHTTPServer(port, handler)
	go func() {
		logger.Printf("https (mTLS) listening on :%s", port)
		if err := srv.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Fatalf("http server failed: %v", err)
		}
	}()

	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdownCtx)
}

func envOr(k, d string) string {
	v := strings.TrimSpace(os.Getenv(k))
	if v == "" {
		return d
	}
	return v
}
