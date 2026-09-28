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
	pkgsvctls "vecta-kms/pkg/svctls"

	"github.com/nats-io/nats.go"
	"google.golang.org/grpc"

	pkgaudit "vecta-kms/pkg/audit"
	pkgauditmw "vecta-kms/pkg/auditmw"
	"vecta-kms/pkg/clusterstate"
	pkgclustersync "vecta-kms/pkg/clustersync"
	pkgconfig "vecta-kms/pkg/config"
	pkgconsul "vecta-kms/pkg/consul"
	pkgcrypto "vecta-kms/pkg/crypto"
	pkgdb "vecta-kms/pkg/db"
	pkgevents "vecta-kms/pkg/events"
	pkggrpc "vecta-kms/pkg/grpc"
	pkgheartbeat "vecta-kms/pkg/heartbeat"
	pkgjwtauth "vecta-kms/pkg/jwtauth"
	"vecta-kms/pkg/mek"
	"vecta-kms/pkg/route"
	pkgruntimecfg "vecta-kms/pkg/runtimecfg"
	"vecta-kms/pkg/servicetoken"
)

var logger = log.New(os.Stdout, "[audit] ", log.LstdFlags|log.Lmicroseconds)

func main() {
	cfg := pkgconfig.Load()

	if err := pkgruntimecfg.ValidateServiceConfig("kms-audit", cfg); err != nil {
		log.Fatalf("config validation failed: %v", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	// Internal mTLS identity from the internal-services Sub CA; nothing is
	// served or called before it (docs/SECURITY/INTERNAL_TLS.md).
	if _, err := pkgsvctls.Init(ctx, "kms-audit", pkgsvctls.Options{Logger: logger}); err != nil {
		logger.Fatalf("internal mTLS enrolment failed: %v", err)
	}
	// Service JWT for keycore (the webhook credentials master key).
	servicetoken.SetDefault(servicetoken.FromEnv("kms-audit"))

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
	if err := loadClusterSigningKey(store, clusterAuditKeyFile()); err != nil {
		logger.Fatalf("cluster audit signing key: %v", err)
	}
	store.SetChainNode(func(ctx context.Context) string { return clusterstate.Default().Get(ctx).ChainNode() })
	if err := store.EnsureUpcomingPartitions(ctx, time.Now().UTC()); err != nil {
		logger.Printf("audit partitions: %v", err)
	}
	svc := NewService(store, ac, wal, pub)

	// Closed-loop detectors. Each runs as a side-effect of normal event
	// processing; they consume the same publisher that ingestion uses so
	// their findings join the immutable audit chain rather than being
	// recorded in a separate, easy-to-bypass store.
	hndl := NewHNDLDetector(pub)
	quarantine := NewQuarantineEvaluator(pub)
	svc.SetDetectors(hndl, quarantine)

	// Event streams send through compliance connections, opened over
	// internal mTLS as kms-audit (stream_connections.go).
	conns := complianceConnections{base: strings.TrimRight(envOr("COMPLIANCE_URL", "https://compliance:8110"), "/"), http: &http.Client{Timeout: 10 * time.Second}}
	fanout := newWebhookFanout(store, svc.creds, conns, func(ctx context.Context, ev AuditEvent) { _, _ = svc.ProcessEvent(ctx, ev) }, logger)
	fanout.Start(ctx)
	svc.SetWebhookFanout(fanout)
	handler := NewHandler(svc, store)

	// Webhook credentials master key from keycore (pkg/mek). It opens in the
	// background: the audit pipeline never waits on keycore (webhook_creds.go).
	selfAudit := selfEmitter{svc}
	auditFn := func(ctx context.Context, ev AuditEvent) { _, _ = svc.ProcessEvent(ctx, ev) }
	mekSource := mek.NewKeycoreSource(envOr("KEYCORE_URL", "https://keycore:8010"), mek.Catalog["audit"])
	go svc.openCredsKeyring(ctx, func(ctx context.Context) (*mek.Keyring, error) {
		return mek.Open(ctx, mek.Options{
			Tables: mek.Catalog["audit"],
			Source: mekSource,
			DB:     dbConn.SQL(),
			Audit:  selfAudit,
			Member: func(ctx context.Context) bool { return !clusterstate.RunsPrimaryJobs(ctx) },
			Logf:   logger.Printf,
			Wait:   10 * time.Minute,
		})
	}, func(k *mek.Keyring) {
		// The event HMAC key comes from the master key (event_hmac_key.go);
		// checkpoints start only once events are signed with it, so their
		// key registrations stay verifiable across restarts.
		if err := svc.installEventHMACKeys(ctx, k, mekSource.Derive); err != nil {
			logger.Printf("audit event HMAC key: %v", err)
		} else {
			go svc.checkpointLoop(ctx, logger.Printf)
		}
		kernel := route.New("audit", selfAudit, logger)
		k.Routes(kernel, "audit")
		kernel.MountOn(handler.mux)
		go k.Watch(ctx, 15*time.Minute)
		go svc.sealLegacyLoop(ctx, k, clusterstate.RunsPrimaryJobs, auditFn, 15*time.Minute, logger.Printf)
		go svc.migrateLegacyStreamsLoop(ctx, k, conns, clusterstate.RunsPrimaryJobs, auditFn, 15*time.Minute, logger.Printf)
	}, logger.Printf)
	handler.SetClusterSyncPublisher(pkgclustersync.NewHTTPPublisher(
		envOr("CLUSTER_URL", "https://cluster-manager:8210"),
		envOr("CLUSTER_BOOTSTRAP_PROFILE_ID", "cluster-profile-base"),
		envOr("CLUSTER_NODE_ID", "vecta-kms-01"),
		envOr("CLUSTER_SYNC_SHARED_SECRET", ""),
		2*time.Second,
	))

	// Durable JetStream ingest: events survive audit-service restarts and are
	// redelivered until acked, unlike the previous lossy core NATS subscribe.
	if _, err := pkgaudit.SubscribeDurable(js, "audit-ingest", func(_ *pkgaudit.Event, msg *nats.Msg) {
		if err := svc.HandleNATSMessage(ctx, msg); err != nil {
			if errors.Is(err, errUnparseableEvent) {
				// Never ingestible: terminate it rather than stall the stream.
				logger.Printf("nats ingest rejected (terminated, not redelivered): %v", err)
				_ = msg.Term()
				return
			}
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

	// Cluster: relay members' replicated events to this primary's consumers,
	// and keep audit_events partitions ahead of replicated rows.
	go func() {
		t := time.NewTicker(5 * time.Second)
		defer t.Stop()
		lastPartitionCheck := time.Now()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if _, err := store.RelayMemberEvents(ctx, pub, 500); err != nil {
					logger.Printf("cluster audit relay: %v", err)
				}
				if time.Since(lastPartitionCheck) > time.Hour {
					lastPartitionCheck = time.Now()
					if err := store.EnsureUpcomingPartitions(ctx, time.Now().UTC()); err != nil {
						logger.Printf("audit partitions: %v", err)
					}
				}
			}
		}
	}()

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

	httpPort := envOr("HTTP_PORT", "8070")
	authedHandler := pkgjwtauth.MustWrap("AUDIT", cfg.JWTIssuer, cfg.JWTAudience, handler, logger)
	httpSrv := pkgconfig.NewHTTPServer(httpPort, pkgauditmw.Wrap(authedHandler, pub, "logger"))
	go func() {
		logger.Printf("https (mTLS) listening on :%s", httpPort)
		if err := httpSrv.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
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
		FailClosed:      envBool("AUDIT_FAIL_CLOSED", true),
		WALPath:         envOr("AUDIT_WAL_PATH", filepath.Join("var", "audit-wal", "buffer.log")),
		WALMaxSizeMB:    int64(envInt("AUDIT_WAL_MAX_SIZE_MB", 512)),
		WALHMACKey:      loadKey32("AUDIT_WAL_HMAC_KEY_B64"),
		EventSigningKey: legacyEventKey(),
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
	return pkgsvctls.Current().ServerConfig(), nil
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
