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
	"vecta-kms/pkg/credstore"
	pkgdb "vecta-kms/pkg/db"
	pkgevents "vecta-kms/pkg/events"
	pkggrpc "vecta-kms/pkg/grpc"
	pkgjwtauth "vecta-kms/pkg/jwtauth"
	pkgkeyaccess "vecta-kms/pkg/keyaccess"
	"vecta-kms/pkg/mek"
	"vecta-kms/pkg/route"
	pkgruntimecfg "vecta-kms/pkg/runtimecfg"
)

var logger = log.New(os.Stdout, "[cloud] ", log.LstdFlags|log.Lmicroseconds)

func main() {
	// Attach this service's per-service JWT to internal keycore calls (no-op
	// when INTERNAL_SERVICE_BOOTSTRAP_SECRET is unset).
	servicetoken.SetDefault(servicetoken.FromEnv("kms-cloud"))
	cfg := pkgconfig.Load()

	if err := pkgruntimecfg.ValidateServiceConfig("kms-cloud", cfg); err != nil {
		log.Fatalf("config validation failed: %v", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	// Internal mTLS identity from the internal-services Sub CA; nothing is
	// served or called before it (docs/SECURITY/INTERNAL_TLS.md).
	if _, err := pkgsvctls.Init(ctx, "kms-cloud", pkgsvctls.Options{Logger: logger}); err != nil {
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
	var audit mek.Emitter
	var auditClient *pkgaudit.Client
	if nc, js, err := initNATS(cfg.NATSURL); err == nil {
		defer nc.Close()
		publisher = pkgevents.NewPublisher(js, 3, "audit.cloud.dead_letter")
		if c, err := pkgaudit.NewClient(js, "cloud"); err == nil {
			audit, auditClient = c, c
		}
	} else {
		logger.Printf("nats unavailable, audit publishing disabled: %v", err)
	}

	keycoreURL := envOr("KEYCORE_URL", "https://keycore:8010")
	// Cloud credentials are wrapped under a master key from keycore
	// (pkg/mek); rows under an earlier release's public key are re-wrapped
	// before serving, and a start that would leave them there is refused.
	keyring, err := mek.Open(ctx, mek.Options{
		Tables: mek.Catalog["cloud"],
		Source: mek.NewKeycoreSource(keycoreURL, mek.Catalog["cloud"]),
		DB:     dbConn.SQL(),
		Audit:  audit,
		Member: func(ctx context.Context) bool { return !clusterstate.RunsPrimaryJobs(ctx) },
		Logf:   logger.Printf,
		Wait:   10 * time.Minute,
	})
	if err != nil {
		logger.Fatalf("refusing to start: %v", err)
	}
	go keyring.Watch(ctx, 15*time.Minute)
	svc := NewService(
		NewSQLStore(dbConn),
		NewHTTPKeyCoreClient(keycoreURL, 3*time.Second),
		defaultProviderRegistry(),
		publisher,
		keyring.Current(),
	)
	svc.SetKeyring(keyring)
	// Account credentials are credentials in the platform's store
	// (Playbooks → Credentials). Accounts an earlier release registered
	// with their own sealed copy are moved there by the primary, now and
	// every 15 minutes (which also catches rows a restore brings back).
	svc.SetCredentials(credstore.FromEnv())
	go svc.migrateAccountCredentialsLoop(ctx, clusterstate.RunsPrimaryJobs, 15*time.Minute, logger.Printf)
	keyAccess := pkgkeyaccess.GateFromEnv(3 * time.Second)
	svc.SetKeyAccess(keyAccess)
	logger.Printf("key access justifications deployed=%v (%s)", keyAccess.IsDeployed(), pkgkeyaccess.ProfilesEnv)
	handler := NewHandler(svc)
	kernel := route.New("cloud", audit, logger)
	keyring.Routes(kernel, "cloud")
	handler.credentialRoutes(kernel)
	kernel.MountOn(handler.mux)

	httpPort := envOr("HTTP_PORT", "8080")
	// Every request carries a verified Bearer token: a person's from the
	// dashboard or API, or a platform service's. Before 8.0.0-beta this
	// service verified none and took the tenant from the request.
	authed := pkgjwtauth.MustWrap("CLOUD", cfg.JWTIssuer, cfg.JWTAudience, handler, auditClient, logger)
	httpSrv := pkgconfig.NewHTTPServer(httpPort, pkgauditmw.Wrap(authed, publisher, "cloud"))
	go func() {
		logger.Printf("https (mTLS) listening on :%s", httpPort)
		if err := httpSrv.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Fatalf("http server failed: %v", err)
		}
	}()

	grpcPort := envOr("GRPC_PORT", "18080")
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

	if reg, err := pkgconsul.NewRegistrar(cfg.ConsulAddress, "kms-cloud-"+httpPort, "kms-cloud", "127.0.0.1", mustAtoi(grpcPort)); err == nil {
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
	nc, err := pkgevents.Connect(url, "kms-cloud", logger.Printf)
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
		filepath.Join("services", "cloud", "migrations"),
		filepath.Join(".", "migrations"),
	}
	for _, c := range candidates {
		if st, err := os.Stat(c); err == nil && st.IsDir() {
			return c
		}
	}
	return filepath.Join("services", "cloud", "migrations")
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
