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
	pkgheartbeat "vecta-kms/pkg/heartbeat"
	pkgjwtauth "vecta-kms/pkg/jwtauth"
)

var logger = log.New(os.Stdout, "[featureforge] ", log.LstdFlags|log.Lmicroseconds)

func main() {
	cfg := pkgconfig.Load()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	dbConn, err := pkgdb.Open(ctx, pkgdb.Config{
		PostgresDSN: cfg.PostgresDSN,
		SQLitePath:  cfg.SQLitePath,
		UseSQLite:   cfg.UseSQLite,
	})
	if err != nil {
		logger.Fatalf("db open failed: %v", err)
	}
	defer dbConn.Close() //nolint:errcheck

	if err := dbConn.RunMigrations(ctx, migrationPath()); err != nil {
		logger.Fatalf("migration failed: %v", err)
	}

	var publisher pkgauditmw.EventPublisher
	var natsConn *nats.Conn
	var auditClient *pkgaudit.Client
	if nc, js, err := initNATS(cfg.NATSURL); err == nil {
		natsConn = nc
		defer nc.Close()
		if ac, err := pkgaudit.NewClient(js, "featureforge"); err == nil {
			auditClient = ac
			publisher = ac.Publisher()
		} else {
			logger.Printf("audit client init failed, audit publishing disabled: %v", err)
		}
	} else {
		logger.Printf("nats unavailable, audit publishing disabled: %v", err)
	}

	// Build the service with real collaborators where configured.
	svcCfg := Config{
		Store:   NewSQLStore(dbConn),
		Sandbox: NewLocalSandbox(),
	}
	if auditClient != nil {
		svcCfg.Audit = NewSpineAudit(auditClient)
	}
	if u := envOr("POLICY_URL", "http://policy:8040"); u != "" {
		svcCfg.Policy = NewHTTPPolicyClient(u, 3*time.Second)
		logger.Printf("policy integration enabled: %s", u)
	}
	if u := envOr("GOVERNANCE_URL", "http://governance:8050"); u != "" {
		svcCfg.Governance = NewHTTPGovernanceClient(u, 3*time.Second)
		logger.Printf("governance integration enabled: %s", u)
	}
	// EXTERNAL MCP server (scaffold-mode code build/validate). Separately
	// deployed; configured via MCP_SERVER_URL. When unset, scaffold-mode
	// intents are rejected with a clear message.
	if mcp := NewHTTPMCPClient(os.Getenv("MCP_SERVER_URL"), os.Getenv("MCP_SERVER_API_KEY"), 30*time.Second); mcp != nil {
		svcCfg.MCP = mcp
		logger.Printf("external MCP build server enabled: %s", os.Getenv("MCP_SERVER_URL"))
	} else {
		logger.Printf("MCP_SERVER_URL not set: scaffold mode disabled until configured")
	}

	svc := NewService(svcCfg)
	handler := NewHandler(svc)

	if natsConn != nil {
		hb := pkgheartbeat.New(natsConn, "featureforge", envOr("CLUSTER_NODE_ID", "vecta-kms-01"), envOr("FEATUREFORGE_VERSION", "dev"))
		hb.Start(ctx)
		defer hb.Stop()
	}

	// 8300/18300: 8260/18260 belong to autokey (see commit 4b17cb599).
	httpPort := envOr("HTTP_PORT", "8300")
	authedHandler := pkgjwtauth.MustWrap("FEATUREFORGE", cfg.JWTIssuer, cfg.JWTAudience, handler, logger)
	httpSrv := pkgconfig.NewHTTPServer(httpPort, pkgauditmw.Wrap(authedHandler, publisher, "featureforge"))
	go func() {
		logger.Printf("http listening on :%s", httpPort)
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Fatalf("http server failed: %v", err)
		}
	}()

	grpcPort := envOr("GRPC_PORT", "18300")
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

	if reg, err := pkgconsul.NewRegistrar(cfg.ConsulAddress, "kms-featureforge-"+httpPort, "kms-featureforge", "127.0.0.1", mustAtoi(grpcPort)); err == nil {
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

func migrationPath() string {
	candidates := []string{
		filepath.Join("/app", "migrations"),
		filepath.Join("services", "featureforge", "migrations"),
		filepath.Join(".", "migrations"),
	}
	for _, c := range candidates {
		if st, err := os.Stat(c); err == nil && st.IsDir() {
			return c
		}
	}
	return filepath.Join("/app", "migrations")
}

func initNATS(url string) (*nats.Conn, nats.JetStreamContext, error) {
	nc, err := pkgevents.Connect(url, "kms-featureforge", logger.Printf)
	if err != nil {
		return nil, nil, err
	}
	js, err := nc.JetStream()
	if err != nil {
		nc.Close()
		return nil, nil, err
	}
	return nc, js, nil
}

func devMTLSConfig() (*tls.Config, error) {
	return pkgcrypto.SelfSignedMTLSConfig("kms-featureforge-local")
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func mustAtoi(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}
