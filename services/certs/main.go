package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"log"
	"math/big"
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

	pkgconfig "vecta-kms/pkg/config"
	pkgconsul "vecta-kms/pkg/consul"
	pkgdb "vecta-kms/pkg/db"
	pkgevents "vecta-kms/pkg/events"
	pkggrpc "vecta-kms/pkg/grpc"
)

func main() {
	cfg := pkgconfig.Load()
	logger := log.New(os.Stdout, "[kms-certs] ", log.LstdFlags|log.LUTC)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	dbConn, err := pkgdb.Open(ctx, pkgdb.Config{
		PostgresDSN: cfg.PostgresDSN,
		SQLitePath:  cfg.SQLitePath,
		UseSQLite:   cfg.UseSQLite,
		MaxOpen:     20,
		MaxIdle:     10,
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
		publisher = pkgevents.NewPublisher(js, 3, "audit.cert.dead_letter")
	} else {
		logger.Printf("nats unavailable, audit publishing disabled: %v", err)
	}

	keycoreURL := envOr("KEYCORE_URL", "http://127.0.0.1:8010")
	keycoreClient := NewHTTPKeyCoreSigner(keycoreURL, 3*time.Second)

	rootCfg := loadCertRootKeyConfig()
	rootProvider, rootErr := newCertRootKeyProvider(rootCfg)
	if rootErr != nil {
		logger.Printf("cert root key provider init warning: %v", rootErr)
	}
	if rootProvider != nil {
		defer rootProvider.Close() //nolint:errcheck
	}
	legacyMEK := loadLegacyMEK()
	svc := NewServiceWithSecurity(
		NewSQLStore(dbConn),
		publisher,
		keycoreClient,
		ServiceSecurityConfig{
			CertStorageMode: rootCfg.StorageMode,
			RootKeyMode:     rootCfg.RootKeyMode,
			RootProvider:    rootProvider,
			SecurityErr:     errString(rootErr),
			LegacyMEK:       legacyMEK,
		},
		envBool("FIPS_STRICT", false),
		envBool("CERTS_KEYCORE_FAIL_CLOSED", true),
	)
	runtimeCfg := loadRuntimeMaterializerConfig()
	if runtimeCfg.Enabled {
		go func() {
			run := func() {
				mCtx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
				defer cancel()
				if err := svc.MaterializeRuntimeCerts(mCtx, runtimeCfg); err != nil {
					logger.Printf("runtime cert materializer warning: %v", err)
				}
			}
			run()
			interval := runtimeCfg.Interval
			if interval <= 0 {
				interval = 5 * time.Minute
			}
			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					run()
				}
			}
		}()
	}
	go func() {
		migrateCtx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		n, err := svc.RewrapLegacyCASigners(migrateCtx)
		if err != nil {
			logger.Printf("legacy signer rewrap warning: %v", err)
			return
		}
		if n > 0 {
			logger.Printf("legacy signer rewrap completed: %d ca signer keys migrated to %s/%s", n, rootCfg.StorageMode, rootCfg.RootKeyMode)
		}
	}()
	go func() {
		ticker := time.NewTicker(2 * time.Minute)
		defer ticker.Stop()
		_ = svc.RunExpiryAlertSweep(context.Background())
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				_ = svc.RunExpiryAlertSweep(context.Background())
			}
		}
	}()
	handler := NewHandler(svc)

	httpPort := envOr("HTTP_PORT", "8030")
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

	grpcPort := envOr("GRPC_PORT", "18030")
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

	if reg, err := pkgconsul.NewRegistrar(cfg.ConsulAddress, "kms-certs-"+httpPort, "kms-certs", "127.0.0.1", mustAtoi(grpcPort)); err == nil {
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
	nc, err := nats.Connect(url, nats.Name("kms-certs"))
	if err != nil {
		return nil, nil, err
	}
	js, err := nc.JetStream()
	if err != nil {
		nc.Close()
		return nil, nil, err
	}
	_, _ = js.AddStream(&nats.StreamConfig{Name: "AUDIT_CERTS", Subjects: []string{"audit.cert.*"}})
	return nc, js, nil
}

func migrationPath() string {
	candidates := []string{
		filepath.Join("services", "certs", "migrations"),
		filepath.Join(".", "migrations"),
	}
	for _, c := range candidates {
		if st, err := os.Stat(c); err == nil && st.IsDir() {
			return c
		}
	}
	return filepath.Join("services", "certs", "migrations")
}

func devMTLSConfig() (*tls.Config, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "kms-certs-local"},
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

func loadLegacyMEK() []byte {
	raw := strings.TrimSpace(os.Getenv("CERTS_MEK_B64"))
	if raw != "" {
		if out, err := base64.StdEncoding.DecodeString(raw); err == nil && len(out) >= 32 {
			return out[:32]
		}
	}
	sum := sha256.Sum256([]byte("vecta-certs-dev-mek"))
	return sum[:]
}

func loadCertRootKeyConfig() CertRootKeyConfig {
	return CertRootKeyConfig{
		StorageMode:             envOr("CERTS_STORAGE_MODE", "db_encrypted"),
		RootKeyMode:             envOr("CERTS_ROOT_KEY_MODE", "software"),
		SealedPath:              envOr("CERTS_CRWK_SEALED_PATH", defaultCRWKSealedPath),
		BootstrapPassphrase:     strings.TrimSpace(os.Getenv("CERTS_CRWK_BOOTSTRAP_PASSPHRASE")),
		BootstrapPassphraseFile: envOr("CERTS_CRWK_PASSPHRASE_FILE", ""),
		ArgonMemoryKB:           uint32(envInt("CERTS_CRWK_ARGON_MEMORY_KB", defaultCRWKMemKB)),
		ArgonIterations:         uint32(envInt("CERTS_CRWK_ARGON_ITERATIONS", defaultCRWKIterations)),
		ArgonParallel:           uint8(envInt("CERTS_CRWK_ARGON_PARALLEL", int(defaultCRWKParallel))),
		MlockRequired:           envBool("CERTS_CRWK_MLOCK_REQUIRED", false),
		UseTPMSeal:              envBool("CERTS_CRWK_USE_TPM_SEAL", false),
	}
}

func loadRuntimeMaterializerConfig() RuntimeCertMaterializerConfig {
	return RuntimeCertMaterializerConfig{
		Enabled:        envBool("CERTS_RUNTIME_MATERIALIZER_ENABLED", true),
		MaterializeDir: envOr("CERTS_RUNTIME_MATERIALIZER_DIR", "/run/vecta/certs"),
		TenantID:       envOr("CERTS_RUNTIME_TENANT_ID", "root"),
		RootCAName:     envOr("CERTS_RUNTIME_ROOT_CA_NAME", "vecta-runtime-root"),
		ValidityDays:   int64(envInt("CERTS_RUNTIME_VALIDITY_DAYS", 90)),
		Interval:       envDuration("CERTS_RUNTIME_MATERIALIZER_INTERVAL", 5*time.Minute),
		RenewBefore:    envDuration("CERTS_RUNTIME_MATERIALIZER_RENEW_BEFORE", 24*time.Hour),
		EnvoyCN:        envOr("CERTS_RUNTIME_ENVOY_CN", "vecta-envoy"),
		EnvoySANs:      splitCSV(envOr("CERTS_RUNTIME_ENVOY_SANS", "localhost,envoy,127.0.0.1")),
		KMIPCN:         envOr("CERTS_RUNTIME_KMIP_CN", "vecta-kmip"),
		KMIPSANs:       splitCSV(envOr("CERTS_RUNTIME_KMIP_SANS", "localhost,kmip,127.0.0.1")),
	}
}

func envOr(k string, d string) string {
	v := strings.TrimSpace(os.Getenv(k))
	if v == "" {
		return d
	}
	return v
}

func envBool(k string, d bool) bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv(k)))
	if v == "" {
		return d
	}
	return v == "1" || v == "true" || v == "yes"
}

func envInt(k string, d int) int {
	v := strings.TrimSpace(os.Getenv(k))
	if v == "" {
		return d
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return d
	}
	return n
}

func envDuration(k string, d time.Duration) time.Duration {
	v := strings.TrimSpace(os.Getenv(k))
	if v == "" {
		return d
	}
	if parsed, err := time.ParseDuration(v); err == nil {
		return parsed
	}
	if seconds, err := strconv.Atoi(v); err == nil && seconds > 0 {
		return time.Duration(seconds) * time.Second
	}
	return d
}

func splitCSV(raw string) []string {
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		out = append(out, p)
	}
	return out
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func mustAtoi(s string) int {
	n := 0
	for i := 0; i < len(s); i++ {
		n = n*10 + int(s[i]-'0')
	}
	return n
}
