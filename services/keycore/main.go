package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
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
	"github.com/redis/go-redis/v9"
	"google.golang.org/grpc"

	pkgaudit "vecta-kms/pkg/audit"
	pkgauditmw "vecta-kms/pkg/auditmw"
	pkgauth "vecta-kms/pkg/auth"
	pkgcache "vecta-kms/pkg/cache"
	pkgclustersync "vecta-kms/pkg/clustersync"
	pkgconfig "vecta-kms/pkg/config"
	pkgconsul "vecta-kms/pkg/consul"
	pkgcrypto "vecta-kms/pkg/crypto"
	pkgdb "vecta-kms/pkg/db"
	pkgevents "vecta-kms/pkg/events"
	pkggrpc "vecta-kms/pkg/grpc"
	pkgheartbeat "vecta-kms/pkg/heartbeat"
	"vecta-kms/pkg/metering"
	pkgratelimit "vecta-kms/pkg/ratelimit"
	pkgruntimecfg "vecta-kms/pkg/runtimecfg"
)

var logger = log.New(os.Stdout, "[keycore] ", log.LstdFlags|log.Lmicroseconds)

func main() {
	cfg := pkgconfig.Load()

	if err := pkgruntimecfg.ValidateServiceConfig("kms-keycore", cfg); err != nil {
		log.Fatalf("config validation failed: %v", err)
	}

	// FIPS 140-3 §4.9.1: run the cryptographic algorithm power-on self-test
	// battery before serving any traffic. A single failed KAT must prevent
	// the module from entering operational mode.
	if results := runFIPSSelfTests(); !allFIPSSelfTestsPassed(results) {
		log.Fatalf("FIPS self-test failed; refusing to start: %v", results)
	} else {
		logger.Printf("FIPS self-test passed: %v", results)
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

	var publisher AuditPublisher
	var auditClient *pkgaudit.Client
	if nc, js, err := initNATS(cfg.NATSURL); err == nil {
		defer nc.Close()
		auditClient, _ = pkgaudit.NewClient(js, "key")
		publisher = pkgevents.NewPublisher(js, 3, pkgaudit.DeadLetterSubject)
	} else {
		logger.Printf("nats unavailable, audit publishing disabled: %v", err)
	}

	var cache KeyCache = NewKeyCache(pkgcache.NewMemory(5*time.Minute), 5*time.Minute)
	if redisURL := envOr("REDIS_URL", ""); redisURL != "" {
		opt, err := redis.ParseURL(redisURL)
		if err == nil {
			if opt.DialTimeout == 0 {
				opt.DialTimeout = 5 * time.Second
			}
			if opt.ReadTimeout == 0 {
				opt.ReadTimeout = 3 * time.Second
			}
			if opt.WriteTimeout == 0 {
				opt.WriteTimeout = 3 * time.Second
			}
			if opt.PoolTimeout == 0 {
				opt.PoolTimeout = 4 * time.Second
			}
			if opt.ConnMaxIdleTime == 0 {
				opt.ConnMaxIdleTime = 5 * time.Minute
			}
			if opt.ConnMaxLifetime == 0 {
				opt.ConnMaxLifetime = 30 * time.Minute
			}
			if opt.MinIdleConns == 0 {
				opt.MinIdleConns = 2
			}
			// FIPS 140-3 stringency: every Redis connection that uses TLS must
			// negotiate TLS 1.3. The previous conditional left
			// caller-supplied TLS configs untouched when MinVersion was
			// already set; that allowed a stale environment to silently fall
			// back to TLS 1.2.
			if opt.TLSConfig != nil {
				opt.TLSConfig = opt.TLSConfig.Clone()
				opt.TLSConfig.MinVersion = tls.VersionTLS13
			}
			cli := redis.NewClient(opt)
			if pingErr := cli.Ping(ctx).Err(); pingErr == nil {
				cache = NewKeyCache(pkgcache.NewRedis(cli), 5*time.Minute)
				defer cli.Close()
				logger.Printf("redis metadata cache enabled")
			}
		}
	}

	mek, err := loadMEK()
	if err != nil {
		logger.Fatalf("mek load failed: %v", err)
	}
	store := NewSQLStore(dbConn)
	meter := metering.NewMeter(cfg.OpsLimit, cfg.MeteringWindow)
	policyURL := stringsTrimSpace(os.Getenv("POLICY_ENGINE_URL"))
	policyFailClosed := envBool("KEYCORE_POLICY_FAIL_CLOSED", true)
	var policy PolicyEvaluator
	if policyURL != "" {
		policy = NewHTTPPolicyClient(policyURL, 3*time.Second)
	}
	svc := NewService(store, cache, publisher, meter, mek, policy, policyFailClosed)
	svc.SetClusterSyncPublisher(pkgclustersync.NewHTTPPublisher(
		envOr("CLUSTER_URL", "http://cluster-manager:8210"),
		envOr("CLUSTER_BOOTSTRAP_PROFILE_ID", "cluster-profile-base"),
		envOr("CLUSTER_NODE_ID", "vecta-kms-01"),
		envOr("CLUSTER_SYNC_SHARED_SECRET", ""),
		2*time.Second,
	))

	// Lifecycle policy: cryptoperiods, version retention, wake-time KAT.
	// All three are passive holders consumed by the handler/reconciler.
	svc.SetCryptoperiodPolicy(NewCryptoperiodPolicy())
	svc.SetVersionPolicy(DefaultVersionPolicy())
	svc.SetWakeSelfTestRegistry(NewWakeSelfTestRegistry())

	// Cold-tier archiver. Disabled by default; operators turn it on by
	// setting KEYCORE_ARCHIVE_DIR and KEYCORE_ARCHIVE_KEK_B64. When the
	// archive KEK is missing or malformed we fail open (no archival)
	// rather than refuse to start — the archive is an optimisation, not
	// a safety property.
	if archiveDir := stringsTrimSpace(os.Getenv("KEYCORE_ARCHIVE_DIR")); archiveDir != "" {
		if kek, err := base64.StdEncoding.DecodeString(stringsTrimSpace(os.Getenv("KEYCORE_ARCHIVE_KEK_B64"))); err == nil && len(kek) == 32 {
			fs := &FilesystemArchiveStore{Root: archiveDir}
			if arch, err := NewArchiver(fs, kek); err == nil {
				svc.SetArchiver(arch)
				logger.Printf("cold-tier key archive enabled at %s", archiveDir)
			}
		}
	}
	governanceURL := stringsTrimSpace(os.Getenv("GOVERNANCE_URL"))
	if governanceURL != "" {
		svc.SetFIPSModeProvider(NewHTTPFIPSModeProvider(governanceURL, 3*time.Second, 5*time.Second))
		svc.SetGovernanceApprovalClient(newGovernanceApprovalClient(governanceURL, 5*time.Second))
		svc.SetGovernancePostureControlsProvider(NewHTTPGovernancePostureControlsProvider(governanceURL, 3*time.Second, 5*time.Second))
		logger.Printf("governance fips mode integration enabled")
	}
	handler := NewHandler(svc)

	// Zeroization verification scheduler. Runs on the keycore process
	// because it needs the live key cache; emits per-key audit events
	// so the immutable chain carries continuous evidence of FIPS 140-3
	// §4.9.2 zeroisation.
	if envBool("KEYCORE_ZEROIZATION_SCHEDULER_ENABLED", true) {
		sched := NewZeroizationScheduler(
			svc, // implements ZeroizationLister via store_lifecycle.go
			func(tenantID, keyID string) bool { return svc.ConfirmKeyMaterialZeroized(tenantID, keyID) },
			auditClient,
		)
		go sched.Run(ctx)
		logger.Printf("zeroization verification scheduler started")
	}

	// Heartbeat publisher so the watchdog observes liveness.
	if nc, _, err := initNATS(cfg.NATSURL); err == nil {
		hb := pkgheartbeat.New(nc, "keycore", envOr("CLUSTER_NODE_ID", "vecta-kms-01"), envOr("KEYCORE_VERSION", "dev"))
		hb.Start(ctx)
		defer hb.Stop()
	}
	if tokenParser, err := loadJWTParser(cfg.JWTIssuer, cfg.JWTAudience); err != nil {
		logger.Printf("jwt parser disabled: %v", err)
	} else if tokenParser != nil {
		handler.SetTokenParser(tokenParser)
		logger.Printf("jwt parser enabled for key access control")
	}

	rl := pkgratelimit.New(pkgratelimit.Config{
		RequestsPerSecond: cfg.RateLimitRPS,
		BurstSize:         cfg.RateLimitBurst,
	})
	httpPort := envOr("HTTP_PORT", "8010")
	httpSrv := pkgconfig.NewHTTPServer(httpPort, rl.Middleware(pkgauditmw.Wrap(handler, publisher, "key")))
	go func() {
		logger.Printf("http listening on :%s", httpPort)
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Fatalf("http server failed: %v", err)
		}
	}()

	grpcPort := envOr("GRPC_PORT", "18010")
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

	if reg, err := pkgconsul.NewRegistrar(cfg.ConsulAddress, "kms-keycore-"+httpPort, "kms-keycore", "127.0.0.1", mustAtoi(grpcPort)); err == nil {
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
		filepath.Join("services", "keycore", "migrations"),
		filepath.Join(".", "migrations"),
	}
	for _, c := range candidates {
		if st, err := os.Stat(c); err == nil && st.IsDir() {
			return c
		}
	}
	return filepath.Join("services", "keycore", "migrations")
}

func initNATS(url string) (*nats.Conn, nats.JetStreamContext, error) {
	nc, err := pkgevents.Connect(url, "kms-keycore", logger.Printf)
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

func loadMEK() ([]byte, error) {
	raw := stringsTrimSpace(os.Getenv("KEYCORE_MEK_B64"))
	if raw == "" {
		return loadOrCreateMEKFile(envOr("KEYCORE_MEK_FILE", "/app/data/mek.b64"))
	}
	mek, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, err
	}
	if len(mek) != 32 {
		return nil, errors.New("KEYCORE_MEK_B64 must decode to 32 bytes")
	}
	return mek, nil
}

func loadOrCreateMEKFile(path string) ([]byte, error) {
	path = stringsTrimSpace(path)
	if path == "" {
		path = "/app/data/mek.b64"
	}
	if raw, err := os.ReadFile(path); err == nil {
		decoded, decErr := base64.StdEncoding.DecodeString(stringsTrimSpace(string(raw)))
		if decErr != nil {
			return nil, decErr
		}
		if len(decoded) != 32 {
			return nil, errors.New("persisted MEK must be 32 bytes")
		}
		return decoded, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	mek := make([]byte, 32)
	if _, err := rand.Read(mek); err != nil {
		return nil, err
	}
	out := []byte(base64.StdEncoding.EncodeToString(mek))
	if err := os.WriteFile(path, out, 0o600); err != nil {
		return nil, err
	}
	return mek, nil
}

func devMTLSConfig() (*tls.Config, error) {
	return pkgcrypto.SelfSignedMTLSConfig("kms-keycore-local")
}

func envOr(k string, d string) string {
	v := os.Getenv(k)
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

func stringsTrimSpace(v string) string {
	return strings.TrimSpace(v)
}

func envBool(k string, d bool) bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv(k)))
	if v == "" {
		return d
	}
	return v == "true" || v == "1" || v == "yes"
}

func loadJWTParser(issuer string, audience string) (func(string) (*pkgauth.Claims, error), error) {
	pubPEM := strings.TrimSpace(os.Getenv("KEYCORE_JWT_PUBLIC_KEY_PEM"))
	if pubPEM == "" {
		if b64 := strings.TrimSpace(os.Getenv("KEYCORE_JWT_PUBLIC_KEY_B64")); b64 != "" {
			raw, err := base64.StdEncoding.DecodeString(b64)
			if err != nil {
				return nil, err
			}
			pubPEM = string(raw)
		}
	}
	// Fall back to the cluster-wide key the common deployment supplies to every
	// service, so token parsing (and thus tenant enforcement) works without a
	// keycore-specific key override.
	if pubPEM == "" {
		pubPEM = strings.TrimSpace(os.Getenv("JWT_PUBLIC_KEY_PEM"))
	}
	if pubPEM == "" {
		if b64 := strings.TrimSpace(os.Getenv("JWT_PUBLIC_KEY_B64")); b64 != "" {
			raw, err := base64.StdEncoding.DecodeString(b64)
			if err != nil {
				return nil, err
			}
			pubPEM = string(raw)
		}
	}
	pubPEM = strings.ReplaceAll(pubPEM, `\n`, "\n")
	if pubPEM == "" {
		return nil, nil
	}
	block, _ := pem.Decode([]byte(pubPEM))
	if block == nil {
		return nil, errors.New("invalid public key PEM")
	}
	var pub *rsa.PublicKey
	if parsed, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
		if p, ok := parsed.(*rsa.PublicKey); ok {
			pub = p
		}
	}
	if pub == nil {
		if p, err := x509.ParsePKCS1PublicKey(block.Bytes); err == nil {
			pub = p
		}
	}
	if pub == nil {
		return nil, errors.New("unable to parse RSA public key")
	}
	return func(token string) (*pkgauth.Claims, error) {
		return pkgauth.ParseRS256WithOptions(token, pub, pkgauth.ParseOptions{
			Issuer:   issuer,
			Audience: audience,
			Leeway:   30 * time.Second,
		})
	}, nil
}
