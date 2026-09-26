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
	pkgkeyaccess "vecta-kms/pkg/keyaccess"
	"vecta-kms/pkg/mek"
	"vecta-kms/pkg/route"
	pkgruntimecfg "vecta-kms/pkg/runtimecfg"
)

var logger = log.New(os.Stdout, "[ekm] ", log.LstdFlags|log.Lmicroseconds)

func main() {
	// Attach this service's per-service JWT to internal keycore calls (no-op
	// when INTERNAL_SERVICE_BOOTSTRAP_SECRET is unset).
	servicetoken.SetDefault(servicetoken.FromEnv("kms-ekm"))
	cfg := pkgconfig.Load()

	if err := pkgruntimecfg.ValidateServiceConfig("kms-ekm", cfg); err != nil {
		log.Fatalf("config validation failed: %v", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	// Internal mTLS identity from the internal-services Sub CA; nothing is
	// served or called before it (docs/SECURITY/INTERNAL_TLS.md).
	if _, err := pkgsvctls.Init(ctx, "kms-ekm", pkgsvctls.Options{Logger: logger}); err != nil {
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
	if nc, js, err := initNATS(cfg.NATSURL); err == nil {
		defer nc.Close()
		publisher = pkgevents.NewPublisher(js, 3, "audit.ekm.dead_letter")
		if c, err := pkgaudit.NewClient(js, "ekm"); err == nil {
			audit = c
		}
	} else {
		logger.Printf("nats unavailable, audit publishing disabled: %v", err)
	}

	keycoreURL := envOr("KEYCORE_URL", "https://keycore:8010")
	// BitLocker recovery keys are wrapped under a master key from keycore
	// (pkg/mek); rows under an earlier release's public key are re-wrapped
	// before serving, and a start that would leave them there is refused.
	keyring, err := mek.Open(ctx, mek.Options{
		Tables: mek.Catalog["ekm"],
		Source: mek.NewKeycoreSource(keycoreURL, mek.Catalog["ekm"]),
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
		publisher,
		keyring.Current(),
	)
	svc.SetKeyring(keyring)
	svc.SetKeyAccessClient(pkgkeyaccess.NewHTTPClient(envOr("KEY_ACCESS_URL", ""), 3*time.Second))
	handler := NewHandler(svc)
	kernel := route.New("ekm", audit, logger)
	keyring.Routes(kernel, "ekm")
	kernel.MountOn(handler.mux)

	httpPort := envOr("HTTP_PORT", "8130")
	httpSrv := pkgconfig.NewHTTPServer(httpPort, pkgauditmw.Wrap(handler, publisher, "ekm"))
	go func() {
		logger.Printf("https (mTLS) listening on :%s", httpPort)
		if err := httpSrv.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Fatalf("http server failed: %v", err)
		}
	}()

	grpcPort := envOr("GRPC_PORT", "18130")
	tlsCfg, err := devMTLSConfig()
	if err != nil {
		logger.Fatalf("mtls config failed: %v", err)
	}
	grpcSrv := pkggrpc.NewServer(tlsCfg, logger)
	registerProvisioningGRPCServer(grpcSrv, svc)
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

	if reg, err := pkgconsul.NewRegistrar(cfg.ConsulAddress, "kms-ekm-"+httpPort, "kms-ekm", "127.0.0.1", mustAtoi(grpcPort)); err == nil {
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
	nc, err := pkgevents.Connect(url, "kms-ekm", logger.Printf)
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
		filepath.Join("services", "ekm", "migrations"),
		filepath.Join(".", "migrations"),
	}
	for _, c := range candidates {
		if st, err := os.Stat(c); err == nil && st.IsDir() {
			return c
		}
	}
	return filepath.Join("services", "ekm", "migrations")
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
