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
	pkgruntimecfg "vecta-kms/pkg/runtimecfg"
)

func main() {
	logger := log.New(os.Stdout, "[kms-firstboot] ", log.LstdFlags|log.LUTC)
	server := NewServer(logger)

	port := envOr("FIRSTBOOT_PORT", "9443")
	if err := pkgruntimecfg.ValidateHTTPPort(port); err != nil {
		logger.Fatalf("config validation failed: %v", err)
	}
	srv := pkgconfig.NewHTTPServer(port, server)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		logger.Printf("first-boot wizard listening on :%s", port)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Fatalf("first-boot wizard failed: %v", err)
		}
	}()

	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdownCtx)
}
