package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
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
	"strings"
	"syscall"
	"time"

	"github.com/nats-io/nats.go"
	"google.golang.org/grpc"

	pkgauditmw "vecta-kms/pkg/auditmw"
	pkgclustersync "vecta-kms/pkg/clustersync"
	pkgconfig "vecta-kms/pkg/config"
	pkgconsul "vecta-kms/pkg/consul"
	pkgdb "vecta-kms/pkg/db"
	pkgevents "vecta-kms/pkg/events"
	pkggrpc "vecta-kms/pkg/grpc"
	pkgruntimecfg "vecta-kms/pkg/runtimecfg"
)

var logger = log.New(os.Stdout, "[audit] ", log.LstdFlags|log.Lmicroseconds)

func main() {
	cfg := pkgconfig.Load()

	if err := pkgruntimecfg.ValidateServiceConfig("kms-audit", cfg); err != nil {
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

	nc, js, err := initNATS(cfg.NATSURL)
	if err != nil {
		logger.Fatalf("nats init failed: %v", err)
	}
	defer nc.Close()

	pub := pkgevents.NewPublisher(js, 3, "audit.logger.dead_letter")

	ac := loadAuditConfig()
	wal := NewWALBuffer(ac.WALPath, ac.WALMaxSizeMB, ac.WALHMACKey)
	store := NewSQLStore(dbConn)
	svc := NewService(store, ac, wal, pub)
	handler := NewHandler(svc, store)
	handler.SetClusterSyncPublisher(pkgclustersync.NewHTTPPublisher(
		envOr("CLUSTER_URL", "http://cluster-manager:8210"),
		envOr("CLUSTER_BOOTSTRAP_PROFILE_ID", "cluster-profile-base"),
		envOr("CLUSTER_NODE_ID", "vecta-kms-01"),
		envOr("CLUSTER_SYNC_SHARED_SECRET", ""),
		2*time.Second,
	))

	if _, err := nc.Subscribe("audit.>", func(msg *nats.Msg) {
		if err := svc.HandleNATSMessage(ctx, msg); err != nil && ac.FailClosed {
			logger.Printf("nats ingest failed: %v", err)
		}
	}); err != nil {
		logger.Fatalf("subscribe failed: %v", err)
	}

	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				_ = svc.DrainWAL(ctx)
			}
		}
	}()

	go func() {
		t := time.NewTicker(1 * time.Hour)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				// Verify chain for all tenants seen in events table.
				rows, err := dbConn.SQL().QueryContext(ctx, `SELECT DISTINCT tenant_id FROM audit_events`)
				if err != nil {
					continue
				}
				for rows.Next() {
					var tenantID string
					if err := rows.Scan(&tenantID); err == nil {
						_, _, _ = svc.VerifyChain(ctx, tenantID)
					}
				}
				rows.Close() //nolint:errcheck
			}
		}
	}()

	// Merkle epoch builder — builds epochs every hour or when 1000+ events accumulate
	go func() {
		t := time.NewTicker(1 * time.Hour)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				rows, err := dbConn.SQL().QueryContext(ctx, `SELECT DISTINCT tenant_id FROM audit_events`)
				if err != nil {
					continue
				}
				for rows.Next() {
					var tenantID string
					if err := rows.Scan(&tenantID); err == nil {
						if result, err := store.BuildMerkleEpoch(ctx, tenantID, 1000); err == nil && result != nil {
							logger.Printf("merkle epoch built: tenant=%s epoch=%d root=%s leaves=%d",
								tenantID, result.Epoch.EpochNumber, result.Epoch.TreeRoot, result.Leaves)
						}
					}
				}
				rows.Close() //nolint:errcheck
			}
		}
	}()

	httpPort := envOr("HTTP_PORT", "8070")
	httpSrv := pkgconfig.NewHTTPServer(httpPort, pkgauditmw.Wrap(handler, pub, "logger"))
	go func() {
		logger.Printf("http listening on :%s", httpPort)
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Fatalf("http server failed: %v", err)
		}
	}()

	grpcPort := envOr("GRPC_PORT", "18070")
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

	if reg, err := pkgconsul.NewRegistrar(cfg.ConsulAddress, "kms-audit-"+httpPort, "kms-audit", "127.0.0.1", mustAtoi(grpcPort)); err == nil {
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

func loadAuditConfig() AuditConfig {
	return AuditConfig{
		FailClosed:          envBool("AUDIT_FAIL_CLOSED", true),
		WALPath:             envOr("AUDIT_WAL_PATH", filepath.Join("var", "audit-wal", "buffer.log")),
		WALMaxSizeMB:        int64(envInt("AUDIT_WAL_MAX_SIZE_MB", 512)),
		WALHMACKey:          walHMACKey(),
		DedupWindowSeconds:  envInt("ALERT_DEDUP_WINDOW_SECONDS", 60),
		EscalationThreshold: envInt("ALERT_ESCALATION_THRESHOLD", 5),
		EscalationMinutes:   envInt("ALERT_ESCALATION_WINDOW_MINUTES", 10),
	}
}

func walHMACKey() []byte {
	raw := strings.TrimSpace(os.Getenv("AUDIT_WAL_HMAC_KEY_B64"))
	if raw == "" {
		b := make([]byte, 32)
		_, _ = rand.Read(b)
		return b
	}
	key, err := base64.StdEncoding.DecodeString(raw)
	if err != nil || len(key) < 16 {
		b := make([]byte, 32)
		_, _ = rand.Read(b)
		return b
	}
	return key
}

func initNATS(url string) (*nats.Conn, nats.JetStreamContext, error) {
	nc, err := pkgevents.Connect(url, "kms-audit", logger.Printf)
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

func migrationPath() string {
	candidates := []string{
		filepath.Join("services", "audit", "migrations"),
		filepath.Join(".", "migrations"),
	}
	for _, c := range candidates {
		if st, err := os.Stat(c); err == nil && st.IsDir() {
			return c
		}
	}
	return filepath.Join("services", "audit", "migrations")
}

func devMTLSConfig() (*tls.Config, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "kms-audit-local"},
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

func envInt(k string, d int) int {
	v := strings.TrimSpace(os.Getenv(k))
	if v == "" {
		return d
	}
	n := 0
	for i := 0; i < len(v); i++ {
		if v[i] < '0' || v[i] > '9' {
			return d
		}
		n = n*10 + int(v[i]-'0')
	}
	return n
}

func envBool(k string, d bool) bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv(k)))
	if v == "" {
		return d
	}
	return v == "true" || v == "1" || v == "yes"
}

func mustAtoi(s string) int {
	n := 0
	for i := 0; i < len(s); i++ {
		n = n*10 + int(s[i]-'0')
	}
	return n
}
