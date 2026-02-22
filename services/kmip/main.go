package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
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
	"github.com/ovh/kmip-go/kmipserver"
	"google.golang.org/grpc"

	pkgconfig "vecta-kms/pkg/config"
	pkgconsul "vecta-kms/pkg/consul"
	pkgdb "vecta-kms/pkg/db"
	pkgevents "vecta-kms/pkg/events"
	pkggrpc "vecta-kms/pkg/grpc"
)

func main() {
	cfg := pkgconfig.Load()
	logger := log.New(os.Stdout, "[kms-kmip] ", log.LstdFlags|log.LUTC)
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
		publisher = pkgevents.NewPublisher(js, 3, "audit.kmip.dead_letter")
	} else {
		logger.Printf("nats unavailable, audit publishing disabled: %v", err)
	}

	keycoreURL := envOr("KEYCORE_URL", "http://127.0.0.1:8010")
	keycore := NewHTTPKeyCoreClient(keycoreURL, 3*time.Second)
	certsURL := envOr("CERTS_URL", "http://127.0.0.1:8030")
	certsClient := NewHTTPCertsClient(certsURL, 5*time.Second)
	requireRegistered := envBool("KMIP_REQUIRE_REGISTERED_CLIENT", true)
	handler := NewHandler(NewSQLStore(dbConn), keycore, certsClient, publisher, requireRegistered)
	exec := handler.NewBatchExecutor()

	httpPort := envOr("HTTP_PORT", "8160")
	httpSrv := &http.Server{
		Addr:              ":" + httpPort,
		Handler:           handler.HTTPHandler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
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
	nc, err := nats.Connect(url, nats.Name("kms-kmip"))
	if err != nil {
		return nil, nil, err
	}
	js, err := nc.JetStream()
	if err != nil {
		nc.Close()
		return nil, nil, err
	}
	_, _ = js.AddStream(&nats.StreamConfig{Name: "AUDIT_KMIP", Subjects: []string{"audit.kmip.*"}})
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
		return &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{cert},
			ClientAuth:   tls.RequireAnyClientCert,
			ClientCAs:    cp,
		}, nil
	}
	return devKMIPTLSConfig()
}

func devKMIPTLSConfig() (*tls.Config, error) {
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	caTpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "kms-kmip-dev-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(7 * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTpl, caTpl, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, err
	}

	srvKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	srvTpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "kms-kmip-local"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
	}
	srvDER, err := x509.CreateCertificate(rand.Reader, srvTpl, caCert, &srvKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	srvPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srvDER})
	srvKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(srvKey)})
	srvCert, err := tls.X509KeyPair(srvPEM, srvKeyPEM)
	if err != nil {
		return nil, err
	}
	cp := x509.NewCertPool()
	cp.AddCert(caCert)
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{srvCert},
		ClientAuth:   tls.RequireAnyClientCert,
		ClientCAs:    cp,
	}, nil
}

func devHealthTLSConfig() (*tls.Config, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "kms-kmip-health"},
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
