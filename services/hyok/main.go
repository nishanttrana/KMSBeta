package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
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
	pkgconfig "vecta-kms/pkg/config"
	pkgconsul "vecta-kms/pkg/consul"
	pkgdb "vecta-kms/pkg/db"
	pkgevents "vecta-kms/pkg/events"
	pkggrpc "vecta-kms/pkg/grpc"
	pkgjwtauth "vecta-kms/pkg/jwtauth"
	pkgkeyaccess "vecta-kms/pkg/keyaccess"
	pkgruntimecfg "vecta-kms/pkg/runtimecfg"
)

var logger = log.New(os.Stdout, "[hyok] ", log.LstdFlags|log.Lmicroseconds)

func main() {
	// Attach this service's per-service JWT to internal keycore calls (no-op
	// when INTERNAL_SERVICE_BOOTSTRAP_SECRET is unset).
	servicetoken.SetDefault(servicetoken.FromEnv("kms-hyok-proxy"))
	cfg := pkgconfig.Load()

	if err := pkgruntimecfg.ValidateServiceConfig("kms-hyok", cfg); err != nil {
		log.Fatalf("config validation failed: %v", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	// Internal mTLS identity from the internal-services Sub CA; nothing is
	// served or called before it (docs/SECURITY/INTERNAL_TLS.md).
	if _, err := pkgsvctls.Init(ctx, "kms-hyok-proxy", pkgsvctls.Options{Logger: logger}); err != nil {
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
	if nc, js, err := initNATS(cfg.NATSURL); err == nil {
		defer nc.Close()
		publisher = pkgevents.NewPublisher(js, 3, "audit.hyok.dead_letter")
	} else {
		logger.Printf("nats unavailable, audit publishing disabled: %v", err)
	}

	keycoreURL := envOr("KEYCORE_URL", "https://keycore:8010")
	policyURL := envOr("POLICY_URL", "https://policy:8040")
	governanceURL := envOr("GOVERNANCE_URL", "https://governance:8050")

	jwtParser, err := loadJWTParser(cfg.JWTIssuer, cfg.JWTAudience)
	if err != nil {
		// Fail closed, like keycore and governance: without the key every
		// call would be refused as unauthorized.
		logger.Fatalf("refusing to start: %v", err)
	}

	svc := NewService(
		NewSQLStore(dbConn),
		NewHTTPKeyCoreClient(keycoreURL, 3*time.Second),
		NewHTTPPolicyClient(policyURL, 3*time.Second),
		NewHTTPGovernanceClient(governanceURL, 3*time.Second),
		publisher,
	)
	keyAccess := pkgkeyaccess.GateFromEnv(3 * time.Second)
	svc.SetKeyAccess(keyAccess)
	logger.Printf("key access justifications deployed=%v (%s)", keyAccess.IsDeployed(), pkgkeyaccess.ProfilesEnv)
	handler := NewHandler(svc, jwtParser)

	httpPort := envOr("HTTP_PORT", "8120")
	httpSrv := pkgconfig.NewHTTPServer(httpPort, pkgauditmw.Wrap(handler, publisher, "hyok"))
	go func() {
		tlsCert := strings.TrimSpace(os.Getenv("HYOK_TLS_CERT_FILE"))
		tlsKey := strings.TrimSpace(os.Getenv("HYOK_TLS_KEY_FILE"))
		if tlsCert != "" && tlsKey != "" {
			httpSrv.TLSConfig = loadHTTPServerTLSConfig()
			logger.Printf("https listening on :%s", httpPort)
			if err := httpSrv.ListenAndServeTLS(tlsCert, tlsKey); err != nil && !errors.Is(err, http.ErrServerClosed) {
				logger.Fatalf("https server failed: %v", err)
			}
			return
		}
		logger.Printf("https (mTLS) listening on :%s", httpPort)
		if err := httpSrv.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Fatalf("http server failed: %v", err)
		}
	}()

	azureSrv, err := startAzureListener(ctx, azureListenerConfigFromEnv(), NewAzureEKMHandler(svc, envOr("BUILD_VERSION", "dev")), logger.Printf)
	if err != nil {
		logger.Fatalf("refusing to start: %v", err)
	}

	grpcPort := envOr("GRPC_PORT", "18120")
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

	if reg, err := pkgconsul.NewRegistrar(cfg.ConsulAddress, "kms-hyok-"+httpPort, "kms-hyok-proxy", "127.0.0.1", mustAtoi(grpcPort)); err == nil {
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
	if azureSrv != nil {
		_ = azureSrv.Shutdown(shutdownCtx)
	}
	grpcSrv.GracefulStop()
}

func initNATS(url string) (*nats.Conn, nats.JetStreamContext, error) {
	nc, err := pkgevents.Connect(url, "kms-hyok", logger.Printf)
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
		filepath.Join("services", "hyok", "migrations"),
		filepath.Join(".", "migrations"),
	}
	for _, c := range candidates {
		if st, err := os.Stat(c); err == nil && st.IsDir() {
			return c
		}
	}
	return filepath.Join("services", "hyok", "migrations")
}

func loadHTTPServerTLSConfig() *tls.Config {
	cfg := &tls.Config{MinVersion: tls.VersionTLS13}
	caFile := strings.TrimSpace(os.Getenv("HYOK_TLS_CLIENT_CA_FILE"))
	if caFile == "" {
		return cfg
	}
	caRaw, err := os.ReadFile(caFile)
	if err != nil {
		return cfg
	}
	cp := x509.NewCertPool()
	if !cp.AppendCertsFromPEM(caRaw) {
		return cfg
	}
	cfg.ClientAuth = tls.RequireAndVerifyClientCert
	cfg.ClientCAs = cp
	return cfg
}

// loadJWTParser returns the token parser, or an error when no verification
// key is configured: HYOK_JWT_PUBLIC_KEY_PEM/_B64, then the shared
// JWT_PUBLIC_KEY_PEM/_B64 that compose sets.
func loadJWTParser(issuer string, audience string) (JWTParser, error) {
	parser, err := pkgjwtauth.LoadParser(pkgjwtauth.Config{Prefix: "HYOK", Issuer: issuer, Audience: audience})
	if err != nil {
		return nil, err
	}
	if parser == nil {
		return nil, errors.New("no JWT verification key: set JWT_PUBLIC_KEY_B64 (or HYOK_JWT_PUBLIC_KEY_PEM/_B64)")
	}
	return parser, nil
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
