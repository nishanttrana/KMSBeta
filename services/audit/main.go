package main

import (
	"context"
	"crypto/tls"
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
	pkgclustersync "vecta-kms/pkg/clustersync"
	pkgconfig "vecta-kms/pkg/config"
	pkgconsul "vecta-kms/pkg/consul"
	pkgcrypto "vecta-kms/pkg/crypto"
	pkgdb "vecta-kms/pkg/db"
	pkgevents "vecta-kms/pkg/events"
	pkggrpc "vecta-kms/pkg/grpc"
	pkgheartbeat "vecta-kms/pkg/heartbeat"
	pkgjwtauth "vecta-kms/pkg/jwtauth"
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

	// The audit service owns the single unified AUDIT stream (audit.>).
	// All services publish into it; downstream visibility services attach
	// their own durable consumers for fan-out.
	if err := pkgaudit.EnsureStream(js, logger.Printf); err != nil {
		logger.Fatalf("audit stream init failed: %v", err)
	}

	pub := pkgevents.NewPublisher(js, 3, pkgaudit.DeadLetterSubject)

	hb := pkgheartbeat.New(nc, "audit", envOr("CLUSTER_NODE_ID", "vecta-kms-01"), envOr("AUDIT_VERSION", "dev"))
	hb.Start(ctx)
	defer hb.Stop()

	ac := loadAuditConfig()
	wal := NewWALBuffer(ac.WALPath, ac.WALMaxSizeMB, ac.WALHMACKey)
	store := NewSQLStore(dbConn)
	store.SetEventSigningKey(ac.EventSigningKey)
	svc := NewService(store, ac, wal, pub)

	// Closed-loop detectors. Each runs as a side-effect of normal event
	// processing; they consume the same publisher that ingestion uses so
	// their findings join the immutable audit chain rather than being
	// recorded in a separate, easy-to-bypass store.
	hndl := NewHNDLDetector(pub)
	quarantine := NewQuarantineEvaluator(pub)
	svc.SetDetectors(hndl, quarantine)

	handler := NewHandler(svc, store)
	handler.SetClusterSyncPublisher(pkgclustersync.NewHTTPPublisher(
		envOr("CLUSTER_URL", "http://cluster-manager:8210"),
		envOr("CLUSTER_BOOTSTRAP_PROFILE_ID", "cluster-profile-base"),
		envOr("CLUSTER_NODE_ID", "vecta-kms-01"),
		envOr("CLUSTER_SYNC_SHARED_SECRET", ""),
		2*time.Second,
	))

	// Durable JetStream ingest: events survive audit-service restarts and are
	// redelivered until acked, unlike the previous lossy core NATS subscribe.
	if _, err := pkgaudit.SubscribeDurable(js, "audit-ingest", func(_ *pkgaudit.Event, msg *nats.Msg) {
		if err := svc.HandleNATSMessage(ctx, msg); err != nil {
			if ac.FailClosed {
				logger.Printf("nats ingest failed (will redeliver): %v", err)
				_ = msg.Nak()
				return
			}
			logger.Printf("nats ingest failed (dropped, fail-open): %v", err)
		}
		_ = msg.Ack()
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
	authedHandler := pkgjwtauth.MustWrap("AUDIT", cfg.JWTIssuer, cfg.JWTAudience, handler, logger)
	httpSrv := pkgconfig.NewHTTPServer(httpPort, pkgauditmw.Wrap(authedHandler, pub, "logger"))
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
		WALHMACKey:          loadKey32("AUDIT_WAL_HMAC_KEY_B64"),
		EventSigningKey:     loadKey32("AUDIT_EVENT_SIGNING_KEY_B64"),
		DedupWindowSeconds:  envInt("ALERT_DEDUP_WINDOW_SECONDS", 60),
		EscalationThreshold: envInt("ALERT_ESCALATION_THRESHOLD", 5),
		EscalationMinutes:   envInt("ALERT_ESCALATION_WINDOW_MINUTES", 10),
	}
}

func loadKey32(envVar string) []byte {
	return pkgcrypto.LoadKey32(envVar, logger.Printf)
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
	return pkgcrypto.SelfSignedMTLSConfig("kms-audit-local")
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
