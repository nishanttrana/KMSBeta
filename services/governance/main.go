package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
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
	pkgauth "vecta-kms/pkg/auth"
	"vecta-kms/pkg/clusterstate"
	pkgconfig "vecta-kms/pkg/config"
	pkgconsul "vecta-kms/pkg/consul"
	pkgcrypto "vecta-kms/pkg/crypto"
	pkgdb "vecta-kms/pkg/db"
	pkgevents "vecta-kms/pkg/events"
	pkggrpc "vecta-kms/pkg/grpc"
	"vecta-kms/pkg/jwtauth"
	pkgruntimecfg "vecta-kms/pkg/runtimecfg"
	"vecta-kms/pkg/servicetoken"
)

var logger = log.New(os.Stdout, "[governance] ", log.LstdFlags|log.Lmicroseconds)

func main() {
	// Governance calls the secrets, certs, cloud and ekm services as itself
	// to re-wrap backup contents under retired public keys (backup_mek.go).
	servicetoken.SetDefault(servicetoken.FromEnv("kms-governance"))
	cfg := pkgconfig.Load()

	if err := pkgruntimecfg.ValidateServiceConfig("kms-governance", cfg); err != nil {
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
		publisher = pkgevents.NewPublisher(js, 3, "audit.governance.dead_letter")
	} else {
		logger.Printf("nats unavailable, audit publishing disabled: %v", err)
	}

	baseURL := envOr("APP_BASE_URL", "http://localhost:8050")
	certsURL := envOr("CERTS_URL", "http://certs:8030")
	store := NewSQLStore(dbConn)
	var snmpPublisher SNMPPublisher = noopSNMPPublisher{}
	if strings.EqualFold(strings.TrimSpace(envOr("GOVERNANCE_SNMP_ENABLED", "true")), "true") {
		snmpPublisher = NewGoSNMPPublisher()
	}
	svc := NewService(
		store,
		publisher,
		nil,
		NewGRPCCallbackExecutor(5*time.Second),
		baseURL,
		WithCertsURL(certsURL),
		WithSNMPPublisher(snmpPublisher),
	)
	handler := NewHandler(svc)

	// System administration (backups, restore, FIPS mode) is decided from the
	// verified token, so governance can't run without the key that verifies
	// tokens (fail closed, like keycore and jwtauth.MustWrap).
	tokenParser, err := loadJWTParser(cfg.JWTIssuer, cfg.JWTAudience)
	if err != nil {
		logger.Fatalf("refusing to start: %v", err)
	}
	handler.SetTokenParser(tokenParser)

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			interval := svc.ExpiryCheckInterval(ctx, "*")
			if interval < 5*time.Second {
				interval = 5 * time.Second
			}
			timer := time.NewTimer(interval)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
				if clusterstate.RunsPrimaryJobs(ctx) {
					_ = svc.ExpireWorkerTick(ctx)
				}
			}
		}
	}()

	// Audit FIPS mode rollouts: services report the mode they start in;
	// governance turns that into audit events (see fips_mode.go).
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := svc.AuditFIPSRollout(ctx); err != nil {
					logger.Printf("fips rollout audit: %v", err)
				}
			}
		}
	}()

	httpPort := envOr("HTTP_PORT", "8050")
	httpSrv := pkgconfig.NewHTTPServer(httpPort, pkgauditmw.Wrap(handler, publisher, "governance"))
	go func() {
		logger.Printf("http listening on :%s", httpPort)
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Fatalf("http server failed: %v", err)
		}
	}()

	grpcPort := envOr("GRPC_PORT", "18050")
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

	if reg, err := pkgconsul.NewRegistrar(cfg.ConsulAddress, "kms-governance-"+httpPort, "kms-governance", "127.0.0.1", mustAtoi(grpcPort)); err == nil {
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
	nc, err := pkgevents.Connect(url, "kms-governance", logger.Printf)
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
		filepath.Join("/app", "migrations"),
		filepath.Join("services", "governance", "migrations"),
		filepath.Join(".", "migrations"),
	}
	for _, c := range candidates {
		if st, err := os.Stat(c); err == nil && st.IsDir() {
			return c
		}
	}
	return filepath.Join("/app", "migrations")
}

func devMTLSConfig() (*tls.Config, error) {
	return pkgcrypto.SelfSignedMTLSConfig("kms-governance-local")
}

// loadJWTParser returns the token parser, or an error when no verification
// key is configured. Sources, in order: GOVERNANCE_JWT_PUBLIC_KEY_PEM/_B64,
// the shared JWT_PUBLIC_KEY_PEM/_B64 (what compose sets), the
// KEYCORE_JWT_PUBLIC_KEY_* variables governance read before, then the file
// at JWT_PUBLIC_KEY_PATH (default certs/jwt_public.pem).
func loadJWTParser(issuer string, audience string) (func(string) (*pkgauth.Claims, error), error) {
	for _, prefix := range []string{"GOVERNANCE", "KEYCORE"} {
		parser, err := jwtauth.LoadParser(jwtauth.Config{Prefix: prefix, Issuer: issuer, Audience: audience})
		if err != nil {
			return nil, fmt.Errorf("jwt public key: %w", err)
		}
		if parser != nil {
			return parser, nil
		}
	}
	path := envOr("JWT_PUBLIC_KEY_PATH", "certs/jwt_public.pem")
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, errors.New("no JWT verification key: set JWT_PUBLIC_KEY_B64 (or GOVERNANCE_JWT_PUBLIC_KEY_PEM/_B64); system administration is decided from verified tokens")
	}
	if err != nil {
		return nil, err
	}
	pub, err := pkgcrypto.ParseRSAPublicKeyPEM(strings.ReplaceAll(string(raw), `\n`, "\n"))
	if err != nil {
		return nil, errors.New("unable to parse RSA JWT public key")
	}
	return func(token string) (*pkgauth.Claims, error) {
		return pkgauth.ParseRS256WithOptions(token, pub, pkgauth.ParseOptions{
			Issuer:   issuer,
			Audience: audience,
			Leeway:   30 * time.Second,
		})
	}, nil
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
