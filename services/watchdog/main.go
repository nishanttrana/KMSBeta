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

	pkgconfig "vecta-kms/pkg/config"
	pkgevents "vecta-kms/pkg/events"
)

var logger = log.New(os.Stdout, "[watchdog] ", log.LstdFlags|log.Lmicroseconds)

func main() {
	cfg := pkgconfig.Load()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	natsURL := envOr("NATS_URL", cfg.NATSURL)
	probe := newProbe(natsURL, logger)
	if err := probe.Start(ctx); err != nil {
		logger.Fatalf("probe start failed: %v", err)
	}
	defer probe.Close()

	pb := newPlaybookEngine(probe, logger)
	go pb.Run(ctx)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /watchdog/heartbeats", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, probe.Snapshot())
	})
	mux.HandleFunc("GET /watchdog/incidents", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, pb.Incidents())
	})
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	port := envOr("HTTP_PORT", "8250")
	srv := pkgconfig.NewHTTPServer(port, mux)
	go func() {
		logger.Printf("http listening on :%s", port)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
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

// unused-import guard
var _ = pkgevents.Connect
