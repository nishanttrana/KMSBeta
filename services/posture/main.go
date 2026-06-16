package main

import (
	"context"
	"crypto/tls"
	"errors"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/nats-io/nats.go"
	"google.golang.org/grpc"

	pkgaudit "vecta-kms/pkg/audit"
	pkgauditmw "vecta-kms/pkg/auditmw"
	pkgconfig "vecta-kms/pkg/config"
	pkgconsul "vecta-kms/pkg/consul"
	pkgcrypto "vecta-kms/pkg/crypto"
	pkgdb "vecta-kms/pkg/db"
	pkgevents "vecta-kms/pkg/events"
	pkggrpc "vecta-kms/pkg/grpc"
	pkgjwtauth "vecta-kms/pkg/jwtauth"
	pkgruntimecfg "vecta-kms/pkg/runtimecfg"
)

var logger = log.New(os.Stdout, "[posture] ", log.LstdFlags|log.Lmicroseconds)

func main() {
	cfg := pkgconfig.Load()
	if err := pkgruntimecfg.ValidateServiceConfig("kms-posture", cfg); err != nil {
		log.Fatalf("config validation failed: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	dbConn, err := pkgdb.Open(ctx, pkgdb.Config{
		PostgresDSN:     cfg.PostgresDSN,
		PostgresRODSN:   cfg.PostgresRODSN,
		SQLitePath:      cfg.SQLitePath,
		UseSQLite:       cfg.UseSQLite,
		MaxOpen:         cfg.DBMaxOpen,
		MaxIdle:         cfg.DBMaxIdle,
		ConnMaxIdleTime: time.Duration(cfg.DBConnMaxIdleTimeSec) * time.Second,
		ConnMaxLifetime: time.Duration(cfg.DBConnMaxLifetimeSec) * time.Second,
	})
	if err != nil {
		logger.Fatalf("db open failed: %v", err)
	}
	defer dbConn.Close() //nolint:errcheck

	if err := dbConn.RunMigrations(ctx, migrationPath()); err != nil {
		logger.Fatalf("migration failed: %v", err)
	}

	var publisher EventPublisher
	if nc, js, err := initNATS(cfg.NATSURL); err == nil {
		defer nc.Close()
		publisher = pkgevents.NewPublisher(js, 3, "audit.posture.dead_letter")
	} else {
		logger.Printf("nats unavailable, posture event publishing disabled: %v", err)
	}

	svc := NewService(
		NewSQLStore(dbConn),
		NewHTTPAuditClient(envOr("AUDIT_URL", "http://127.0.0.1:8070"), 8*time.Second),
		publisher,
	)
	if governanceClient := NewHTTPGovernanceControlClient(
		envOr("GOVERNANCE_URL", "http://127.0.0.1:8030"),
		envOr("POSTURE_GOVERNANCE_BEARER_TOKEN", ""),
		5*time.Second,
	); governanceClient != nil {
		svc.SetGovernanceControlClient(governanceClient)
	}
	engineInterval := time.Duration(envOrInt("POSTURE_ENGINE_INTERVAL_SEC", 60)) * time.Second
	hotRetention := time.Duration(envOrInt("POSTURE_HOT_RETENTION_HOURS", 72)) * time.Hour
	auditSyncLimit := envOrInt("POSTURE_AUDIT_SYNC_LIMIT", 500)
	autoRemediate := envOrBool("POSTURE_AUTO_REMEDIATE", false)
	svc.Configure(engineInterval, hotRetention, auditSyncLimit, autoRemediate)
	svc.StartScheduler(ctx)

	var rootHandler http.Handler = NewHandler(svc)
	// Optional JWT parsing: populate claims when a valid token is present so
	// tenantcheck.Enforce binds requests to the authenticated tenant. Absent
	// tokens are allowed through here (tenant-scoped feature handlers that must
	// be authenticated call requireAuthedTenant themselves) so internal,
	// tokenless callers of /posture/* (e.g. reporting) keep working.
	if parser, err := pkgjwtauth.LoadParser(pkgjwtauth.Config{Prefix: "POSTURE", Issuer: cfg.JWTIssuer, Audience: cfg.JWTAudience}); err != nil {
		logger.Printf("jwt parser disabled: %v", err)
	} else if parser != nil {
		rootHandler = optionalJWTMiddleware(rootHandler, parser)
		logger.Printf("jwt parser enabled for tenant enforcement")
	}
	handler := rootHandler

	httpPort := envOr("HTTP_PORT", "8220")
	if err := pkgruntimecfg.ValidateHTTPPort(httpPort); err != nil {
		logger.Fatalf("invalid HTTP_PORT: %v", err)
	}
	if err := pkgruntimecfg.ValidateDurationFloor("POSTURE_ENGINE_INTERVAL_SEC", engineInterval, 10*time.Second); err != nil {
		logger.Fatalf("invalid POSTURE_ENGINE_INTERVAL_SEC: %v", err)
	}
	httpSrv := pkgconfig.NewHTTPServer(httpPort, pkgauditmw.Wrap(handler, publisher, "posture"))
	go func() {
		logger.Printf("http listening on :%s", httpPort)
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Fatalf("http server failed: %v", err)
		}
	}()

	grpcPort := envOr("GRPC_PORT", "18220")
	if err := pkgruntimecfg.ValidateHTTPPort(grpcPort); err != nil {
		logger.Fatalf("invalid GRPC_PORT: %v", err)
	}
	tlsCfg, err := devMTLSConfig()
	if err != nil {
		logger.Fatalf("mtls config failed: %v", err)
	}
	grpcSrv := pkggrpc.NewServer(tlsCfg, logger)
	lis, err := net.Listen("tcp", ":"+grpcPort)
	if err != nil {
		logger.Fatalf("grpc listen failed: %v", err)
	}
	go func() {
		logger.Printf("grpc+health listening on :%s", grpcPort)
		if err := grpcSrv.Serve(lis); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			logger.Fatalf("grpc server failed: %v", err)
		}
	}()

	if reg, err := pkgconsul.NewRegistrar(cfg.ConsulAddress, "kms-posture-"+httpPort, "kms-posture", "127.0.0.1", mustAtoi(grpcPort)); err == nil {
		if err := reg.Register(ctx); err != nil {
			logger.Printf("consul register failed: %v", err)
		} else {
			defer reg.Deregister(context.Background()) //nolint:errcheck
		}
	}

	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(shutdownCtx)
	grpcSrv.GracefulStop()
}

func initNATS(url string) (*nats.Conn, nats.JetStreamContext, error) {
	nc, err := pkgevents.Connect(url, "kms-posture", logger.Printf)
	if err != nil {
		return nil, nil, err
	}
	js, err := nc.JetStream()
	if err != nil {
		nc.Close()
		return nil, nil, err
	}
	_, _ = js.AddStream(pkgaudit.StreamConfig())
	return nc, js, nil
}

func migrationPath() string {
	candidates := []string{
		filepath.Join("services", "posture", "migrations"),
		filepath.Join(".", "migrations"),
	}
	for _, c := range candidates {
		if st, err := os.Stat(c); err == nil && st.IsDir() {
			return c
		}
	}
	return filepath.Join("services", "posture", "migrations")
}

func devMTLSConfig() (*tls.Config, error) {
	return pkgcrypto.SelfSignedMTLSConfig("kms-posture-local")
}

func envOr(k string, d string) string {
	v := strings.TrimSpace(os.Getenv(k))
	if v == "" {
		return d
	}
	return v
}

func envOrInt(key string, fallback int) int {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 {
		return fallback
	}
	return n
}

func envOrBool(key string, fallback bool) bool {
	raw := strings.ToLower(strings.TrimSpace(os.Getenv(key)))
	if raw == "" {
		return fallback
	}
	switch raw {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return fallback
	}
}

func mustAtoi(s string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(s))
	return n
}
