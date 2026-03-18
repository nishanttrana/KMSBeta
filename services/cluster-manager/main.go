package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
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

	pkgauditmw "vecta-kms/pkg/auditmw"
	pkgconfig "vecta-kms/pkg/config"
	pkgconsul "vecta-kms/pkg/consul"
	pkgdb "vecta-kms/pkg/db"
	pkgevents "vecta-kms/pkg/events"
	pkggrpc "vecta-kms/pkg/grpc"
	pkgruntimecfg "vecta-kms/pkg/runtimecfg"
)

var logger = log.New(os.Stdout, "[cluster-manager] ", log.LstdFlags|log.Lmicroseconds)

func main() {
	cfg := pkgconfig.Load()

	if err := pkgruntimecfg.ValidateServiceConfig("kms-cluster-manager", cfg); err != nil {
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
		publisher = pkgevents.NewPublisher(js, 3, "audit.cluster.dead_letter")
	} else {
		logger.Printf("nats unavailable, cluster event publishing disabled: %v", err)
	}

	svc := NewService(NewSQLStore(dbConn), publisher)
	handler := NewHandler(svc)

	httpPort := envOr("HTTP_PORT", "8210")
	httpSrv := pkgconfig.NewHTTPServer(httpPort, pkgauditmw.Wrap(handler, publisher, "cluster"))
	httpTLSEnabled := envBool("CLUSTER_HTTP_TLS_ENABLE", false)
	httpTLSCertFile := strings.TrimSpace(os.Getenv("CLUSTER_HTTP_TLS_CERT_FILE"))
	httpTLSKeyFile := strings.TrimSpace(os.Getenv("CLUSTER_HTTP_TLS_KEY_FILE"))
	if httpTLSEnabled {
		tlsCfg, tlsErr := buildClusterHTTPServerTLSConfig()
		if tlsErr != nil {
			logger.Fatalf("cluster http tls config failed: %v", tlsErr)
		}
		httpSrv.TLSConfig = tlsCfg
	}
	go func() {
		if httpTLSEnabled {
			logger.Printf("https(mtls) listening on :%s", httpPort)
			if httpTLSCertFile == "" || httpTLSKeyFile == "" {
				logger.Fatalf("cluster http tls enabled but cert/key file missing")
			}
			if err := httpSrv.ListenAndServeTLS(httpTLSCertFile, httpTLSKeyFile); err != nil && !errors.Is(err, http.ErrServerClosed) {
				logger.Fatalf("https server failed: %v", err)
			}
			return
		}
		logger.Printf("http listening on :%s", httpPort)
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Fatalf("http server failed: %v", err)
		}
	}()

	grpcPort := envOr("GRPC_PORT", "18210")
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

	if reg, err := pkgconsul.NewRegistrar(cfg.ConsulAddress, "kms-cluster-manager-"+httpPort, "kms-cluster-manager", "127.0.0.1", mustAtoi(grpcPort)); err == nil {
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
	nc, err := pkgevents.Connect(url, "kms-cluster-manager", logger.Printf)
	if err != nil {
		return nil, nil, err
	}
	js, err := nc.JetStream()
	if err != nil {
		nc.Close()
		return nil, nil, err
	}
	_, _ = js.AddStream(&nats.StreamConfig{Name: "AUDIT_CLUSTER", Subjects: []string{"audit.cluster.*"}})
	_, _ = js.AddStream(&nats.StreamConfig{Name: "CLUSTER_SYNC", Subjects: []string{"cluster.sync.*"}})
	return nc, js, nil
}

func migrationPath() string {
	candidates := []string{
		filepath.Join("services", "cluster-manager", "migrations"),
		filepath.Join(".", "migrations"),
	}
	for _, c := range candidates {
		if st, err := os.Stat(c); err == nil && st.IsDir() {
			return c
		}
	}
	return filepath.Join("services", "cluster-manager", "migrations")
}

func devMTLSConfig() (*tls.Config, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "kms-cluster-manager-local"},
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

func envOr(key string, defaultValue string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return defaultValue
	}
	return value
}

func mustAtoi(v string) int {
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil {
		return 0
	}
	return n
}

func envBool(key string, defaultValue bool) bool {
	raw := strings.TrimSpace(strings.ToLower(os.Getenv(key)))
	if raw == "" {
		return defaultValue
	}
	switch raw {
	case "1", "true", "yes", "y", "on":
		return true
	case "0", "false", "no", "n", "off":
		return false
	default:
		return defaultValue
	}
}

func buildClusterHTTPServerTLSConfig() (*tls.Config, error) {
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
	}
	requireClientCert := envBool("CLUSTER_HTTP_REQUIRE_CLIENT_CERT", true)
	clientCAPath := strings.TrimSpace(os.Getenv("CLUSTER_HTTP_TLS_CLIENT_CA_FILE"))
	if requireClientCert {
		if clientCAPath == "" {
			return nil, errors.New("CLUSTER_HTTP_REQUIRE_CLIENT_CERT=true but CLUSTER_HTTP_TLS_CLIENT_CA_FILE is empty")
		}
		caPEM, err := os.ReadFile(clientCAPath)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, errors.New("invalid CLUSTER_HTTP_TLS_CLIENT_CA_FILE")
		}
		tlsCfg.ClientCAs = pool
		tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
	} else {
		tlsCfg.ClientAuth = tls.NoClientCert
	}
	return tlsCfg, nil
}
