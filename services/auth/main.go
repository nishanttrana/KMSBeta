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
	"vecta-kms/pkg/metering"
	pkgruntimecfg "vecta-kms/pkg/runtimecfg"
)

var logger = log.New(os.Stdout, "[auth] ", log.LstdFlags|log.Lmicroseconds)

func main() {
	cfg := pkgconfig.Load()

	if err := pkgruntimecfg.ValidateServiceConfig("kms-auth", cfg); err != nil {
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

	var auditPublisher AuditPublisher
	if nc, js, err := initNATS(cfg.NATSURL); err == nil {
		defer nc.Close()
		auditPublisher = pkgevents.NewPublisher(js, 3, "audit.auth.dead_letter")
	} else {
		logger.Printf("nats unavailable, audit publish is disabled: %v", err)
	}

	signingKey, err := loadOrGenerateSigningKey()
	if err != nil {
		logger.Fatalf("jwt key load failed: %v", err)
	}

	logic := NewAuthLogic(signingKey, cfg.JWTIssuer, cfg.JWTAudience)
	store := NewSQLStore(dbConn)
	bootstrapDefaultAdmin(ctx, store, logger)
	meter := metering.NewMeter(cfg.OpsLimit, cfg.MeteringWindow)
	healthChecker := NewSystemHealthChecker(cfg.ConsulAddress, logger)
	handler := NewHandler(store, logic, auditPublisher, meter, logger, healthChecker)

	httpPort := envOr("HTTP_PORT", "8001")
	httpSrv := pkgconfig.NewHTTPServer(httpPort, pkgauditmw.Wrap(handler, auditPublisher, "auth"))
	go func() {
		logger.Printf("http listening on :%s", httpPort)
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Fatalf("http server failed: %v", err)
		}
	}()

	grpcPort := envOr("GRPC_PORT", "18001")
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

	if reg, err := pkgconsul.NewRegistrar(cfg.ConsulAddress, "kms-auth-"+httpPort, "kms-auth", "127.0.0.1", mustAtoi(grpcPort)); err == nil {
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
		filepath.Join("services", "auth", "migrations"),
		filepath.Join(".", "migrations"),
	}
	for _, c := range candidates {
		if st, err := os.Stat(c); err == nil && st.IsDir() {
			return c
		}
	}
	return filepath.Join("services", "auth", "migrations")
}

func initNATS(url string) (*nats.Conn, nats.JetStreamContext, error) {
	nc, err := pkgevents.Connect(url, "kms-auth", logger.Printf)
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

func loadOrGenerateSigningKey() (*pkgcrypto.KeyPair, error) {
	return pkgcrypto.LoadOrCreateRSAKeyPEM(os.Getenv("JWT_PRIVATE_KEY_PATH"), 2048)
}

func devMTLSConfig() (*tls.Config, error) {
	return pkgcrypto.SelfSignedMTLSConfig("kms-auth-local")
}

func mustParseCert(der []byte) *x509.Certificate {
	c, err := x509.ParseCertificate(der)
	if err != nil {
		panic(err)
	}
	return c
}

func envOr(k string, d string) string {
	v := os.Getenv(k)
	if v == "" {
		return d
	}
	return v
}

func envOrBool(k string, d bool) bool {
	v := strings.TrimSpace(strings.ToLower(os.Getenv(k)))
	switch v {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return d
	}
}

func bootstrapDefaultAdmin(ctx context.Context, store Store, logger *log.Logger) {
	tenantID := envOr("AUTH_BOOTSTRAP_TENANT_ID", "root")
	tenantName := envOr("AUTH_BOOTSTRAP_TENANT_NAME", "Root")
	adminUsername := envOr("AUTH_BOOTSTRAP_ADMIN_USERNAME", "admin")
	adminPassword := envOr("AUTH_BOOTSTRAP_ADMIN_PASSWORD", "VectaAdmin@2026")
	adminEmail := envOr("AUTH_BOOTSTRAP_ADMIN_EMAIL", "admin@vecta.local")
	adminRole := envOr("AUTH_BOOTSTRAP_ADMIN_ROLE", "admin")
	mustChange := envOrBool("AUTH_BOOTSTRAP_FORCE_PASSWORD_CHANGE", true)
	cliUsername := envOr("AUTH_BOOTSTRAP_CLI_USERNAME", "cli-user")
	cliPassword := envOr("AUTH_BOOTSTRAP_CLI_PASSWORD", "VectaCLI@2026")
	cliEmail := envOr("AUTH_BOOTSTRAP_CLI_EMAIL", "cli@vecta.local")
	cliEnabled := envOrBool("AUTH_BOOTSTRAP_CLI_ENABLED", false)

	if _, err := store.GetTenant(ctx, tenantID); errors.Is(err, errNotFound) {
		if err := store.CreateTenant(ctx, Tenant{ID: tenantID, Name: tenantName, Status: "active"}); err != nil {
			logger.Printf("bootstrap: create tenant failed: %v", err)
			return
		}
	} else if err != nil {
		logger.Printf("bootstrap: read tenant failed: %v", err)
		return
	}

	roleCatalog := []TenantRole{
		{TenantID: tenantID, RoleName: "admin", Permissions: []string{"*"}},
		{TenantID: tenantID, RoleName: "tenant-admin", Permissions: []string{"*"}},
		{TenantID: tenantID, RoleName: "backup", Permissions: []string{"auth.self.read", "auth.user.read", "auth.client.read"}},
		{TenantID: tenantID, RoleName: "audit", Permissions: []string{"auth.self.read", "auth.user.read", "auth.client.read"}},
		{TenantID: tenantID, RoleName: "readonly", Permissions: []string{"auth.self.read", "auth.user.read"}},
		{TenantID: tenantID, RoleName: "cli-user", Permissions: []string{"auth.self.read"}},
	}
	for _, role := range roleCatalog {
		if _, err := store.GetRolePermissions(ctx, tenantID, role.RoleName); errors.Is(err, errNotFound) {
			if err := store.CreateTenantRole(ctx, role); err != nil {
				logger.Printf("bootstrap: create role %s failed: %v", role.RoleName, err)
				return
			}
		} else if err != nil {
			logger.Printf("bootstrap: read role %s failed: %v", role.RoleName, err)
			return
		}
	}

	if _, err := store.GetRolePermissions(ctx, tenantID, adminRole); err != nil {
		if errors.Is(err, errNotFound) {
			if err := store.CreateTenantRole(ctx, TenantRole{TenantID: tenantID, RoleName: adminRole, Permissions: []string{"*"}}); err != nil {
				logger.Printf("bootstrap: create configured admin role failed: %v", err)
				return
			}
		} else {
			logger.Printf("bootstrap: read configured admin role failed: %v", err)
			return
		}
	}

	if _, err := store.GetPasswordPolicy(ctx, tenantID); errors.Is(err, errNotFound) {
		policy := NormalizePasswordPolicy(DefaultPasswordPolicy(tenantID), tenantID)
		policy.UpdatedBy = "bootstrap"
		if _, err := store.UpsertPasswordPolicy(ctx, policy); err != nil {
			logger.Printf("bootstrap: create password policy failed: %v", err)
			return
		}
	} else if err != nil {
		logger.Printf("bootstrap: read password policy failed: %v", err)
		return
	}

	if _, err := store.GetSecurityPolicy(ctx, tenantID); errors.Is(err, errNotFound) {
		policy := NormalizeSecurityPolicy(DefaultSecurityPolicy(tenantID), tenantID)
		policy.UpdatedBy = "bootstrap"
		if _, err := store.UpsertSecurityPolicy(ctx, policy); err != nil {
			logger.Printf("bootstrap: create security policy failed: %v", err)
			return
		}
	} else if err != nil {
		logger.Printf("bootstrap: read security policy failed: %v", err)
		return
	}

	if _, err := store.GetUserByUsername(ctx, tenantID, adminUsername); errors.Is(err, errNotFound) {
		hash, err := HashPassword(adminPassword)
		if err != nil {
			logger.Printf("bootstrap: hash password failed: %v", err)
			return
		}
		user := User{
			ID:                 NewID("usr"),
			TenantID:           tenantID,
			Username:           adminUsername,
			Email:              adminEmail,
			Password:           hash,
			Role:               adminRole,
			Status:             "active",
			MustChangePassword: mustChange,
		}
		if err := store.CreateUser(ctx, user); err != nil {
			logger.Printf("bootstrap: create admin failed: %v", err)
			return
		}
		logger.Printf("bootstrap: default admin created tenant=%s username=%s must_change_password=%t", tenantID, adminUsername, mustChange)
	} else if err != nil {
		logger.Printf("bootstrap: read admin failed: %v", err)
	}

	if _, err := store.GetUserByUsername(ctx, tenantID, cliUsername); errors.Is(err, errNotFound) {
		hash, err := HashPassword(cliPassword)
		if err != nil {
			logger.Printf("bootstrap: hash cli password failed: %v", err)
			return
		}
		status := "inactive"
		if cliEnabled {
			status = "active"
		}
		user := User{
			ID:                 NewID("usr"),
			TenantID:           tenantID,
			Username:           cliUsername,
			Email:              cliEmail,
			Password:           hash,
			Role:               "cli-user",
			Status:             status,
			MustChangePassword: true,
		}
		if err := store.CreateUser(ctx, user); err != nil {
			logger.Printf("bootstrap: create cli user failed: %v", err)
			return
		}
		logger.Printf("bootstrap: default cli user created tenant=%s username=%s status=%s", tenantID, cliUsername, status)
	} else if err != nil {
		logger.Printf("bootstrap: read cli user failed: %v", err)
	}
}

func mustAtoi(s string) int {
	n := 0
	for i := 0; i < len(s); i++ {
		n = n*10 + int(s[i]-'0')
	}
	return n
}
