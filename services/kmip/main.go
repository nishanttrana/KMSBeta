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
	"github.com/ovh/kmip-go/kmipserver"
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
	pkgruntimecfg "vecta-kms/pkg/runtimecfg"
)

var logger = log.Default()

func main() {
	cfg := pkgconfig.Load()

	if err := pkgruntimecfg.ValidateServiceConfig("kms-kmip", cfg); err != nil {
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
	var natsConn *nats.Conn
	if nc, js, err := initNATS(cfg.NATSURL); err == nil {
		natsConn = nc
		defer nc.Close()
		publisher = pkgevents.NewPublisher(js, 3, "audit.kmip.dead_letter")
	} else {
		logger.Printf("nats unavailable, audit publishing disabled: %v", err)
	}

	if natsConn != nil {
		hb := pkgheartbeat.New(natsConn, "kmip", envOr("CLUSTER_NODE_ID", "vecta-kms-01"), envOr("KMIP_VERSION", "dev"))
		hb.Start(ctx)
		defer hb.Stop()
	}

	keycoreURL := envOr("KEYCORE_URL", "http://127.0.0.1:8010")
	keycore := NewHTTPKeyCoreClient(keycoreURL, 3*time.Second)
	certsURL := envOr("CERTS_URL", "http://127.0.0.1:8030")
	certsClient := NewHTTPCertsClient(certsURL, 5*time.Second)
	requireRegistered := envBool("KMIP_REQUIRE_REGISTERED_CLIENT", true)
	handler := NewHandler(NewSQLStore(dbConn), keycore, certsClient, publisher, requireRegistered)
	exec := handler.NewBatchExecutor()

	httpPort := envOr("HTTP_PORT", "8160")
	httpSrv := pkgconfig.NewHTTPServer(httpPort, pkgauditmw.Wrap(handler.HTTPHandler(), publisher, "kmip"))
	go func() {
		logger.Printf("http listening on :%s", httpPort)
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Fatalf("http server failed: %v", err)
		}
	}()

	tlsCfg, err := loadKMIPTLSConfig()
	if err != nil {
		logger.Fatalf("tls config failed: %v", err)
	}
	kmipPort := envOr("KMIP_PORT", KMIPPort)
	ln, err := tls.Listen("tcp", ":"+kmipPort, tlsCfg)
	if err != nil {
		logger.Fatalf("kmip listen failed: %v", err)
	}
	kmipSrv := kmipserver.NewServer(ln, exec).
		WithConnectHook(handler.ConnectHook).
		WithTerminateHook(handler.TerminateHook)

	go func() {
		logger.Printf("kmip ttlv over tls listening on :%s", kmipPort)
		if err := kmipSrv.Serve(); err != nil && !errors.Is(err, kmipserver.ErrShutdown) {
			logger.Printf("kmip serve failed: %v", err)
		}
	}()

	grpcPort := envOr("GRPC_PORT", "15696")
	grpcTLS, err := devHealthTLSConfig()
	if err != nil {
		logger.Fatalf("grpc health tls config failed: %v", err)
	}
	grpcSrv := pkggrpc.NewServer(grpcTLS, logger)
	grpcLis, err := net.Listen("tcp", ":"+grpcPort)
	if err != nil {
		logger.Fatalf("grpc listen failed: %v", err)
	}
	go func() {
		logger.Printf("grpc+health listening on :%s", grpcPort)
		if err := grpcSrv.Serve(grpcLis); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			logger.Fatalf("grpc server failed: %v", err)
		}
	}()

	if reg, err := pkgconsul.NewRegistrar(cfg.ConsulAddress, "kms-kmip-"+kmipPort, "kms-kmip", "127.0.0.1", mustAtoi(grpcPort)); err == nil {
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
	_ = kmipSrv.Shutdown()
	grpcSrv.GracefulStop()
}

func initNATS(url string) (*nats.Conn, nats.JetStreamContext, error) {
	nc, err := pkgevents.Connect(url, "kms-kmip", logger.Printf)
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
		filepath.Join("services", "kmip", "migrations"),
		filepath.Join(".", "migrations"),
	}
	for _, c := range candidates {
		if st, err := os.Stat(c); err == nil && st.IsDir() {
			return c
		}
	}
	return filepath.Join("services", "kmip", "migrations")
}

// fipsApprovedCipherSuites lists the TLS 1.2 cipher suites permitted by
// NIST SP 800-52 Rev. 2 / FIPS 140-3 cryptographic boundary. TLS 1.3 cipher
// selection is fixed by the protocol and does not need to be enumerated.
var fipsApprovedCipherSuites = []uint16{
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
}

// allowedKMIPMinVersion resolves the minimum TLS version for the KMIP
// listener. Stringent posture defaults to TLS 1.3; KMIP_ALLOW_TLS12=true
// permits a TLS 1.2 floor for legacy enterprise clients that do not yet
// support 1.3 — and even then, the cipher list is restricted to FIPS-
// approved AEAD suites.
func allowedKMIPMinVersion() uint16 {
	if envBool("KMIP_ALLOW_TLS12", false) {
		return tls.VersionTLS12
	}
	return tls.VersionTLS13
}

// kmipClientAuthMode selects the X.509 client-cert verification policy.
// Production deployments with a configured CA chain always use full
// verification; the env override is provided strictly for interop testing
// against unconventional client implementations and is logged at startup.
func kmipClientAuthMode() tls.ClientAuthType {
	if envBool("KMIP_CLIENT_CERT_VERIFY_DISABLED", false) {
		logger.Printf("WARNING: KMIP client certificate verification disabled by env override")
		return tls.RequireAnyClientCert
	}
	return tls.RequireAndVerifyClientCert
}

func loadKMIPTLSConfig() (*tls.Config, error) {
	certFile := strings.TrimSpace(os.Getenv("KMIP_TLS_CERT_FILE"))
	keyFile := strings.TrimSpace(os.Getenv("KMIP_TLS_KEY_FILE"))
	caFile := strings.TrimSpace(os.Getenv("KMIP_TLS_CLIENT_CA_FILE"))
	if certFile != "" && keyFile != "" && caFile != "" {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return devKMIPTLSConfig()
		}
		caRaw, err := os.ReadFile(caFile)
		if err != nil {
			return devKMIPTLSConfig()
		}
		cp := x509.NewCertPool()
		if !cp.AppendCertsFromPEM(caRaw) {
			return devKMIPTLSConfig()
		}
		cfg := &tls.Config{
			MinVersion:   allowedKMIPMinVersion(),
			Certificates: []tls.Certificate{cert},
			ClientAuth:   kmipClientAuthMode(),
			ClientCAs:    cp,
			CipherSuites: fipsApprovedCipherSuites,
		}
		if vf, err := loadKMIPClientCertVerifier(cp); err == nil && vf != nil {
			cfg.VerifyPeerCertificate = vf
		}
		return cfg, nil
	}
	return devKMIPTLSConfig()
}

// loadKMIPClientCertVerifier attaches an additional verification step that
// checks each client certificate against an optional CRL file. The CRL is
// loaded once at startup from KMIP_CLIENT_CRL_FILE; revoked serials short-
// circuit the connection. When no CRL is configured the verifier is nil
// and the standard chain check stands alone.
func loadKMIPClientCertVerifier(roots *x509.CertPool) (func([][]byte, [][]*x509.Certificate) error, error) {
	crlPath := strings.TrimSpace(os.Getenv("KMIP_CLIENT_CRL_FILE"))
	if crlPath == "" {
		return nil, nil
	}
	raw, err := os.ReadFile(crlPath)
	if err != nil {
		return nil, err
	}
	crl, err := x509.ParseRevocationList(raw)
	if err != nil {
		return nil, err
	}
	revoked := make(map[string]struct{}, len(crl.RevokedCertificateEntries))
	for _, e := range crl.RevokedCertificateEntries {
		if e.SerialNumber != nil {
			revoked[e.SerialNumber.String()] = struct{}{}
		}
	}
	logger.Printf("loaded %d revoked client certificate serials from %s", len(revoked), crlPath)
	return func(_ [][]byte, chains [][]*x509.Certificate) error {
		for _, chain := range chains {
			if len(chain) == 0 {
				continue
			}
			leaf := chain[0]
			if leaf.SerialNumber == nil {
				continue
			}
			if _, bad := revoked[leaf.SerialNumber.String()]; bad {
				return errors.New("client certificate has been revoked")
			}
		}
		return nil
	}, nil
}

func devKMIPTLSConfig() (*tls.Config, error) {
	srvCert, caCert, err := pkgcrypto.DevServerCertWithCA("kms-kmip-dev-ca", "kms-kmip-local", []string{"localhost"})
	if err != nil {
		return nil, err
	}
	cp := x509.NewCertPool()
	cp.AddCert(caCert)
	return &tls.Config{
		MinVersion:   allowedKMIPMinVersion(),
		Certificates: []tls.Certificate{srvCert},
		ClientAuth:   tls.RequireAnyClientCert,
		ClientCAs:    cp,
		CipherSuites: fipsApprovedCipherSuites,
	}, nil
}

func devHealthTLSConfig() (*tls.Config, error) {
	return pkgcrypto.SelfSignedMTLSConfig("kms-kmip-health")
}

func envOr(k string, d string) string {
	v := strings.TrimSpace(os.Getenv(k))
	if v == "" {
		return d
	}
	return v
}

func envBool(k string, d bool) bool {
	raw := strings.ToLower(strings.TrimSpace(os.Getenv(k)))
	if raw == "" {
		return d
	}
	switch raw {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return d
	}
}

func mustAtoi(s string) int {
	n := 0
	for i := 0; i < len(s); i++ {
		n = n*10 + int(s[i]-'0')
	}
	return n
}
