package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"log"
	"math/big"
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

	pkgauth "vecta-kms/pkg/auth"
	pkgclustersync "vecta-kms/pkg/clustersync"
	pkgconfig "vecta-kms/pkg/config"
	pkgconsul "vecta-kms/pkg/consul"
	pkgdb "vecta-kms/pkg/db"
	pkgevents "vecta-kms/pkg/events"
	pkggrpc "vecta-kms/pkg/grpc"
	"vecta-kms/pkg/metering"
	pkgruntimecfg "vecta-kms/pkg/runtimecfg"
)

var logger = log.New(os.Stdout, "[keycore] ", log.LstdFlags|log.Lmicroseconds)

func main() {
	cfg := pkgconfig.Load()

	if err := pkgruntimecfg.ValidateServiceConfig("kms-keycore", cfg); err != nil {
		log.Fatalf("config validation failed: %v", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	dbConn, err := pkgdb.Open(ctx, pkgdb.Config{
		PostgresDSN: cfg.PostgresDSN,
		SQLitePath:  cfg.SQLitePath,
		UseSQLite:   cfg.UseSQLite,
		MaxOpen:     30,
		MaxIdle:     15,
	})
	if err != nil {
		logger.Fatalf("db open failed: %v", err)
	}
	defer dbConn.Close() //nolint:errcheck

	if err := dbConn.RunMigrations(ctx, migrationPath()); err != nil {
		logger.Fatalf("migration failed: %v", err)
	}

	var publisher AuditPublisher
	if nc, js, err := initNATS(cfg.NATSURL); err == nil {
		defer nc.Close()
		publisher = pkgevents.NewPublisher(js, 3, "audit.key.dead_letter")
	} else {
		logger.Printf("nats unavailable, audit publishing disabled: %v", err)
	}

	var cache KeyCache = newMemoryCache(5 * time.Minute)
	if redisURL := envOr("REDIS_URL", ""); redisURL != "" {
		opt, err := redis.ParseURL(redisURL)
		if err == nil {
			cli := redis.NewClient(opt)
			if pingErr := cli.Ping(ctx).Err(); pingErr == nil {
				cache = newRedisKeyCache(cli, 5*time.Minute)
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
	qrngURL := stringsTrimSpace(os.Getenv("QRNG_URL"))
	if qrngURL != "" {
		svc.SetQRNGClient(NewHTTPQRNGClient(qrngURL, 5*time.Second))
		logger.Printf("qrng entropy integration enabled (%s)", qrngURL)
	}
	governanceURL := stringsTrimSpace(os.Getenv("GOVERNANCE_URL"))
	if governanceURL != "" {
		svc.SetFIPSModeProvider(NewHTTPFIPSModeProvider(governanceURL, 3*time.Second, 5*time.Second))
		svc.SetGovernanceApprovalClient(newGovernanceApprovalClient(governanceURL, 5*time.Second))
		svc.SetGovernancePostureControlsProvider(NewHTTPGovernancePostureControlsProvider(governanceURL, 3*time.Second, 5*time.Second))
		logger.Printf("governance fips mode integration enabled")
	}
	handler := NewHandler(svc)
	if tokenParser, err := loadJWTParser(); err != nil {
		logger.Printf("jwt parser disabled: %v", err)
	} else if tokenParser != nil {
		handler.SetTokenParser(tokenParser)
		logger.Printf("jwt parser enabled for key access control")
	}

	httpPort := envOr("HTTP_PORT", "8010")
	httpSrv := &http.Server{
		Addr:              ":" + httpPort,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}
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
	nc, err := nats.Connect(url, nats.Name("kms-keycore"))
	if err != nil {
		return nil, nil, err
	}
	js, err := nc.JetStream()
	if err != nil {
		nc.Close()
		return nil, nil, err
	}
	_, _ = js.AddStream(&nats.StreamConfig{Name: "AUDIT", Subjects: []string{"audit.key.*"}})
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
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "kms-keycore-local"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	cp := x509.NewCertPool()
	c, _ := x509.ParseCertificate(der)
	cp.AddCert(c)
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    cp,
	}, nil
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

func loadJWTParser() (func(string) (*pkgauth.Claims, error), error) {
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
		return pkgauth.ParseRS256(token, pub)
	}, nil
}
