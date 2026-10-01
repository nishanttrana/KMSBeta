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
	"vecta-kms/pkg/servicetoken"
	pkgsvctls "vecta-kms/pkg/svctls"

	"github.com/nats-io/nats.go"
	"google.golang.org/grpc"

	pkgaudit "vecta-kms/pkg/audit"
	pkgauditmw "vecta-kms/pkg/auditmw"
	"vecta-kms/pkg/clusterstate"
	pkgconfig "vecta-kms/pkg/config"
	pkgconsul "vecta-kms/pkg/consul"
	pkgdb "vecta-kms/pkg/db"
	pkgevents "vecta-kms/pkg/events"
	pkggrpc "vecta-kms/pkg/grpc"
	pkgjwtauth "vecta-kms/pkg/jwtauth"
	"vecta-kms/pkg/mek"
	"vecta-kms/pkg/route"
	pkgruntimecfg "vecta-kms/pkg/runtimecfg"
)

var logger = log.New(os.Stdout, "[compliance] ", log.LstdFlags|log.Lmicroseconds)

func main() {
	// Attach this service's per-service JWT to internal keycore calls (no-op
	// when INTERNAL_SERVICE_BOOTSTRAP_SECRET is unset).
	servicetoken.SetDefault(servicetoken.FromEnv("kms-compliance"))
	cfg := pkgconfig.Load()

	if err := pkgruntimecfg.ValidateServiceConfig("kms-compliance", cfg); err != nil {
		log.Fatalf("config validation failed: %v", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	// Internal mTLS identity from the internal-services Sub CA; nothing is
	// served or called before it (docs/SECURITY/INTERNAL_TLS.md).
	if _, err := pkgsvctls.Init(ctx, "kms-compliance", pkgsvctls.Options{Logger: logger}); err != nil {
		logger.Fatalf("internal mTLS enrolment failed: %v", err)
	}

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

	keycoreURL := envOr("KEYCORE_URL", "https://keycore:8010")
	auditURL := envOr("AUDIT_URL", "https://audit:8070")
	policyURL := envOr("POLICY_URL", "https://policy:8040")
	certsURL := envOr("CERTS_URL", "https://certs:8030")
	store := NewSQLStore(dbConn)
	svc := NewService(
		store,
		NewHTTPKeyCoreClient(keycoreURL, 5*time.Second),
		NewHTTPPolicyClient(policyURL, 5*time.Second),
		NewHTTPAuditClient(auditURL, envOr("REPORTING_URL", "https://reporting:8140"), 5*time.Second),
		NewHTTPCertsClient(certsURL, 5*time.Second),
		publisher,
	)
	svc.StartScheduler(ctx)

	// Playbooks: one executor for manual, triggered and resumed runs.
	// Connection credentials are sealed under the compliance master key from
	// keycore (pkg/mek), opened in the background.
	vault := &connVault{}
	urls := platformURLsFromEnv()
	urls.Keycore, urls.Certs = keycoreURL, certsURL
	executor := NewPlaybookExecutor(store, urls, auditClient, vault, logger)
	executor.ops = svc

	handler := NewHandler(svc, auditClient, logger, vault)
	handler.SetExecutor(executor)
	usage := platformUsage{auditURL: strings.TrimRight(auditURL, "/"), governanceURL: urls.Governance,
		discoveryURL: strings.TrimRight(envOr("DISCOVERY_URL", "https://discovery:8100"), "/"), http: executor.platform}
	handler.usage, handler.sourceUsage = usage, usage.Sources

	triggerListener := NewTriggerListener(store, executor, logger)
	handler.triggers = triggerListener
	go triggerListener.StartListening(ctx, jsCtx)

	var mekAudit mek.Emitter
	if auditClient != nil {
		mekAudit = auditClient
	}
	go openConnectionKeyring(ctx, vault, func(ctx context.Context) (*mek.Keyring, error) {
		return mek.Open(ctx, mek.Options{
			Tables: mek.Catalog["compliance"],
			Source: mek.NewKeycoreSource(keycoreURL, mek.Catalog["compliance"]),
			DB:     dbConn.SQL(),
			Audit:  mekAudit,
			Member: func(ctx context.Context) bool { return !clusterstate.RunsPrimaryJobs(ctx) },
			Logf:   logger.Printf,
			Wait:   10 * time.Minute,
		})
	}, func(k *mek.Keyring) {
		kernel := route.New("compliance", auditClient, logger)
		k.Routes(kernel, "compliance")
		kernel.MountOn(handler.mux)
		go k.Watch(ctx, 15*time.Minute)
		go svc.migrateInlineSecretsLoop(ctx, vault, executor, 15*time.Minute, logger.Printf)
	}, logger.Printf)

	httpPort := envOr("HTTP_PORT", "8110")
	authedHandler := pkgjwtauth.MustWrap("COMPLIANCE", cfg.JWTIssuer, cfg.JWTAudience, handler, auditClient, logger)
	httpSrv := pkgconfig.NewHTTPServer(httpPort, pkgauditmw.Wrap(authedHandler, publisher, "compliance"))
	go func() {
		logger.Printf("https (mTLS) listening on :%s", httpPort)
		if err := httpSrv.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
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
	return pkgsvctls.Current().ServerConfig(), nil
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
