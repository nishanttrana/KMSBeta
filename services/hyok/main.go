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
	"google.golang.org/grpc"

	pkgauditmw "vecta-kms/pkg/auditmw"
	pkgauth "vecta-kms/pkg/auth"
	pkgconfig "vecta-kms/pkg/config"
	pkgconsul "vecta-kms/pkg/consul"
	pkgdb "vecta-kms/pkg/db"
	pkgevents "vecta-kms/pkg/events"
	pkggrpc "vecta-kms/pkg/grpc"
	pkgruntimecfg "vecta-kms/pkg/runtimecfg"
)

var logger = log.New(os.Stdout, "[hyok] ", log.LstdFlags|log.Lmicroseconds)

func main() {
	cfg := pkgconfig.Load()

	if err := pkgruntimecfg.ValidateServiceConfig("kms-hyok", cfg); err != nil {
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
		publisher = pkgevents.NewPublisher(js, 3, "audit.hyok.dead_letter")
	} else {
		logger.Printf("nats unavailable, audit publishing disabled: %v", err)
	}

	keycoreURL := envOr("KEYCORE_URL", "http://127.0.0.1:8010")
	policyURL := envOr("POLICY_URL", "http://127.0.0.1:8040")
	governanceURL := envOr("GOVERNANCE_URL", "http://127.0.0.1:8050")
	policyFailClosed := envBool("HYOK_POLICY_FAIL_CLOSED", true)

	jwtParser, err := loadJWTParser(cfg.JWTIssuer, cfg.JWTAudience)
	if err != nil {
		logger.Fatalf("jwt parser setup failed: %v", err)
	}

	svc := NewService(
		NewSQLStore(dbConn),
		NewHTTPKeyCoreClient(keycoreURL, 3*time.Second),
		NewHTTPPolicyClient(policyURL, 3*time.Second),
		NewHTTPGovernanceClient(governanceURL, 3*time.Second),
		publisher,
		policyFailClosed,
	)
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
		logger.Printf("http listening on :%s", httpPort)
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Fatalf("http server failed: %v", err)
		}
	}()

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
	_, _ = js.AddStream(&nats.StreamConfig{Name: "AUDIT_HYOK", Subjects: []string{"audit.hyok.*"}})
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
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
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

func loadJWTParser(issuer string, audience string) (JWTParser, error) {
	pubPEM := strings.TrimSpace(os.Getenv("HYOK_JWT_PUBLIC_KEY_PEM"))
	if pubPEM == "" {
		if b64 := strings.TrimSpace(os.Getenv("HYOK_JWT_PUBLIC_KEY_B64")); b64 != "" {
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

func devMTLSConfig() (*tls.Config, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "kms-hyok-local"},
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

func mustAtoi(s string) int {
	n := 0
	for i := 0; i < len(s); i++ {
		n = n*10 + int(s[i]-'0')
	}
	return n
}
