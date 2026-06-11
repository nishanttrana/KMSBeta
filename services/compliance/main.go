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

var logger = log.New(os.Stdout, "[compliance] ", log.LstdFlags|log.Lmicroseconds)

func main() {
	cfg := pkgconfig.Load()

	if err := pkgruntimecfg.ValidateServiceConfig("kms-compliance", cfg); err != nil {
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
	var jsCtx nats.JetStreamContext
	var auditClient *pkgaudit.Client
	if nc, js, err := initNATS(cfg.NATSURL); err == nil {
		defer nc.Close()
		jsCtx = js
		auditClient, _ = pkgaudit.NewClient(js, "compliance")
		publisher = pkgevents.NewPublisher(js, 3, pkgaudit.DeadLetterSubject)
	} else {
		logger.Printf("nats unavailable, audit publishing disabled: %v", err)
	}

	keycoreURL := envOr("KEYCORE_URL", "http://127.0.0.1:8010")
	auditURL := envOr("AUDIT_URL", "http://127.0.0.1:8070")
	policyURL := envOr("POLICY_URL", "http://127.0.0.1:8040")
	certsURL := envOr("CERTS_URL", "http://127.0.0.1:8030")
	store := NewSQLStore(dbConn)
	svc := NewService(
		store,
		NewHTTPKeyCoreClient(keycoreURL, 5*time.Second),
		NewHTTPPolicyClient(policyURL, 5*time.Second),
		NewHTTPAuditClient(auditURL, 5*time.Second),
		NewHTTPCertsClient(certsURL, 5*time.Second),
		publisher,
	)
	svc.StartScheduler(ctx)

	// Playbook execution engine
	executor := NewPlaybookExecutor(store, keycoreURL, certsURL, policyURL, auditURL, auditClient, logger)

	handler := NewHandler(svc)
	handler.SetExecutor(executor)

	// Start trigger listener for automatic playbook execution via NATS events
	triggerListener := NewTriggerListener(store, executor, logger)
	go triggerListener.StartListening(ctx, jsCtx)

	httpPort := envOr("HTTP_PORT", "8110")
	authedHandler := pkgjwtauth.MustWrap("COMPLIANCE", cfg.JWTIssuer, cfg.JWTAudience, handler, logger)
	httpSrv := pkgconfig.NewHTTPServer(httpPort, pkgauditmw.Wrap(authedHandler, publisher, "compliance"))
	go func() {
		logger.Printf("http listening on :%s", httpPort)
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Fatalf("http server failed: %v", err)
		}
	}()

	grpcPort := envOr("GRPC_PORT", "18110")
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

	if reg, err := pkgconsul.NewRegistrar(cfg.ConsulAddress, "kms-compliance-"+httpPort, "kms-compliance", "127.0.0.1", mustAtoi(grpcPort)); err == nil {
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
	nc, err := pkgevents.Connect(url, "kms-compliance", logger.Printf)
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
		filepath.Join("services", "compliance", "migrations"),
		filepath.Join(".", "migrations"),
	}
	for _, c := range candidates {
		if st, err := os.Stat(c); err == nil && st.IsDir() {
			return c
		}
	}
	return filepath.Join("services", "compliance", "migrations")
}

func devMTLSConfig() (*tls.Config, error) {
	return pkgcrypto.SelfSignedMTLSConfig("kms-compliance-local")
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
