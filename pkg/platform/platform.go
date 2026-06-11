// Package platform boots a Vecta KMS service onto the standard spine in one
// call: validated config, database with migrations, NATS, the unified audit
// pipeline (pkg/audit), JWT authentication, the audit HTTP safety net
// (pkg/auditmw), mTLS gRPC, and Consul registration.
//
// Every new capability or feature service MUST start from platform.Boot —
// this is how features are wired into the platform by construction instead
// of by convention. A minimal service main is:
//
//	rt, err := platform.Boot(platform.Options{
//		ServiceName:   "myfeature",
//		JWTScope:      "MYFEATURE",
//		HTTPPort:      "8123",
//		GRPCPort:      "18123",
//		MigrationsDir: "services/myfeature/migrations",
//	})
//	if err != nil { log.Fatal(err) }
//	defer rt.Close()
//	svc := NewService(NewSQLStore(rt.DB), rt.Audit)
//	rt.Serve(NewHandler(svc)) // blocks until SIGINT/SIGTERM, then drains
//
// Such a service passes scripts/conformance.sh automatically: crypto comes
// from pkg/crypto, every mutating call is audited onto the unified AUDIT
// stream, and nothing private is created on the bus.
package platform

import (
	"context"
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

// Options selects which parts of the spine a service needs. ServiceName,
// JWTScope, HTTPPort and GRPCPort are required; the rest have safe defaults.
type Options struct {
	ServiceName   string // short lowercase name, e.g. "secrets"
	JWTScope      string // env prefix for jwtauth, e.g. "SECRETS"
	HTTPPort      string // default HTTP port (HTTP_PORT env overrides)
	GRPCPort      string // default gRPC port (GRPC_PORT env overrides)
	MigrationsDir string // SQL migrations dir; empty = service has no database
	SkipNATS      bool   // true only for services that genuinely never emit events
	AuditName     string // audit subject namespace; defaults to ServiceName (set only when a legacy namespace, e.g. "cert", must be preserved)
}

// Runtime exposes the booted spine to the service.
type Runtime struct {
	Ctx    context.Context
	Cfg    pkgconfig.Config
	Logger *log.Logger
	DB     *pkgdb.DB
	NC     *nats.Conn
	JS     nats.JetStreamContext
	Audit  *pkgaudit.Client

	opts Options
	stop context.CancelFunc
}

// Boot assembles the spine. It is fatal-free: every failure is returned so
// callers decide, except config validation which is a hard contract.
func Boot(opts Options) (*Runtime, error) {
	if opts.ServiceName == "" || opts.JWTScope == "" || opts.HTTPPort == "" || opts.GRPCPort == "" {
		return nil, errors.New("platform: ServiceName, JWTScope, HTTPPort and GRPCPort are required")
	}
	logger := log.New(os.Stderr, "[kms-"+opts.ServiceName+"] ", log.LstdFlags|log.Lmsgprefix)
	cfg := pkgconfig.Load()
	if err := pkgruntimecfg.ValidateServiceConfig("kms-"+opts.ServiceName, cfg); err != nil {
		return nil, err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)

	rt := &Runtime{Ctx: ctx, Cfg: cfg, Logger: logger, opts: opts, stop: stop}

	if opts.MigrationsDir != "" {
		db, err := pkgdb.Open(ctx, pkgdb.Config{
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
			stop()
			return nil, err
		}
		if err := db.RunMigrations(ctx, migrationPath(opts.MigrationsDir)); err != nil {
			_ = db.Close()
			stop()
			return nil, err
		}
		rt.DB = db
	}

	if !opts.SkipNATS {
		nc, err := pkgevents.Connect(cfg.NATSURL, "kms-"+opts.ServiceName, logger.Printf)
		if err != nil {
			logger.Printf("nats unavailable, audit publishing disabled: %v", err)
		} else {
			js, err := nc.JetStream()
			if err != nil {
				nc.Close()
				logger.Printf("jetstream unavailable, audit publishing disabled: %v", err)
			} else {
				rt.NC = nc
				rt.JS = js
				rt.Audit, err = pkgaudit.NewClient(js, opts.ServiceName)
				if err != nil {
					rt.Close()
					return nil, err
				}
			}
		}
	}
	return rt, nil
}

// Serve wraps the handler in the standard middleware chain (JWT auth, then
// the audit safety net), starts the HTTP and mTLS gRPC listeners, registers
// with Consul, and blocks until the process receives SIGINT/SIGTERM. It
// returns after graceful shutdown completes.
func (rt *Runtime) Serve(handler http.Handler) error {
	httpPort := envOr("HTTP_PORT", rt.opts.HTTPPort)
	grpcPort := envOr("GRPC_PORT", rt.opts.GRPCPort)

	var mwPublisher pkgauditmw.EventPublisher
	if rt.Audit != nil {
		mwPublisher = rt.Audit.Publisher()
	}
	auditName := rt.opts.AuditName
	if auditName == "" {
		auditName = rt.opts.ServiceName
	}
	authed := pkgjwtauth.MustWrap(rt.opts.JWTScope, rt.Cfg.JWTIssuer, rt.Cfg.JWTAudience, handler, rt.Logger)
	httpSrv := pkgconfig.NewHTTPServer(httpPort, pkgauditmw.Wrap(authed, mwPublisher, auditName))
	httpErr := make(chan error, 1)
	go func() {
		rt.Logger.Printf("http listening on :%s", httpPort)
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			httpErr <- err
		}
	}()

	tlsCfg, err := pkgcrypto.SelfSignedMTLSConfig("kms-" + rt.opts.ServiceName + "-local")
	if err != nil {
		return err
	}
	grpcSrv := pkggrpc.NewServer(tlsCfg, rt.Logger)
	lis, err := net.Listen("tcp", ":"+grpcPort)
	if err != nil {
		return err
	}
	go func() {
		rt.Logger.Printf("grpc+health listening on :%s", grpcPort)
		if err := grpcSrv.Serve(lis); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			rt.Logger.Printf("grpc server failed: %v", err)
		}
	}()

	if reg, err := pkgconsul.NewRegistrar(rt.Cfg.ConsulAddress, "kms-"+rt.opts.ServiceName+"-"+httpPort, "kms-"+rt.opts.ServiceName, "127.0.0.1", atoi(grpcPort)); err == nil {
		if err := reg.Register(rt.Ctx); err != nil {
			rt.Logger.Printf("consul register failed: %v", err)
		} else {
			defer reg.Deregister(context.Background()) //nolint:errcheck
		}
	}

	select {
	case err := <-httpErr:
		return err
	case <-rt.Ctx.Done():
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(shutdownCtx)
	grpcSrv.GracefulStop()
	return nil
}

// Close releases everything Boot acquired.
func (rt *Runtime) Close() {
	if rt.NC != nil {
		rt.NC.Close()
	}
	if rt.DB != nil {
		_ = rt.DB.Close()
	}
	rt.stop()
}

func migrationPath(dir string) string {
	candidates := []string{dir, filepath.Join(".", "migrations")}
	for _, c := range candidates {
		if st, err := os.Stat(c); err == nil && st.IsDir() {
			return c
		}
	}
	return dir
}

func envOr(k string, d string) string {
	v := strings.TrimSpace(os.Getenv(k))
	if v == "" {
		return d
	}
	return v
}

func atoi(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}
