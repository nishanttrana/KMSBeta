package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"vecta-kms/pkg/clusterstate"
	"vecta-kms/pkg/servicetoken"

	"vecta-kms/pkg/mek"
	pkgplatform "vecta-kms/pkg/platform"
	"vecta-kms/pkg/route"
	"vecta-kms/pkg/svctls"
)

var logger = log.Default()

// main boots the standard platform spine and mounts the certs (internal PKI)
// service with its background loops: runtime cert materializer, legacy CA
// signer rewrap, and certificate expiry alert sweep.
func main() {
	// Attach this service's per-service JWT to internal keycore calls (no-op
	// when INTERNAL_SERVICE_BOOTSTRAP_SECRET is unset).
	servicetoken.SetDefault(servicetoken.FromEnv("kms-certs"))
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	keycoreURL := envOr("KEYCORE_URL", "https://keycore:8010")
	keycoreClient := NewHTTPKeyCoreSigner(keycoreURL, 3*time.Second)

	rootCfg := loadCertRootKeyConfig()
	rootProvider, rootErr := newCertRootKeyProvider(rootCfg)
	if rootErr != nil {
		// A public or weak CRWK passphrase. There is no database or bus yet to
		// audit to: the refusal shows as this exit and the container's restart
		// loop (docs/SECURITY/SECURE_DEFAULTS.md).
		logger.Fatalf("refusing to start: %v", rootErr)
	}
	if rootProvider != nil {
		defer rootProvider.Close() //nolint:errcheck
	}
	// Built before the database: the store and publisher are attached once
	// Postgres and NATS are reachable over mTLS, and the master key arrives
	// from keycore after that (SetLegacyMEK).
	svc := NewServiceWithSecurity(
		nil,
		nil,
		keycoreClient,
		ServiceSecurityConfig{
			CertStorageMode: rootCfg.StorageMode,
			RootKeyMode:     rootCfg.RootKeyMode,
			RootProvider:    rootProvider,
			SecurityErr:     errString(rootErr),
		},
		envBool("FIPS_STRICT", false),
		envBool("CERTS_KEYCORE_FAIL_CLOSED", true),
	)

	// Internal PKI before anything else (docs/SECURITY/INTERNAL_TLS.md):
	// runtime root -> internal-services Sub CA from the sealed cache, the
	// public trust bundle, certs' own certificate, and the Postgres, NATS,
	// Valkey and Consul server certificates. Only then can the database and
	// the bus be reached, since both require internal mTLS.
	internalTenant := envOr("CERTS_RUNTIME_TENANT_ID", "root")
	trustDir := envOr("CERTS_TRUST_DIR", "/run/vecta/trust")
	pki, err := svc.BootstrapInternalPKI(internalTenant, envOr("CERTS_INTERNAL_PKI_CACHE", defaultPKICachePath))
	if err != nil {
		logger.Fatalf("refusing to start: internal PKI: %v", err)
	}
	if err := WriteTrustBundle(trustDir, pki.root, pki.sub); err != nil {
		logger.Fatalf("refusing to start: trust bundle: %v", err)
	}
	identity, err := svctls.Init(ctx, "kms-certs", svctls.Options{
		Enroller:  pki,
		TrustFile: filepath.Join(trustDir, "internal-ca.crt"),
		Logger:    logger,
	})
	if err != nil {
		logger.Fatalf("refusing to start: own internal certificate: %v", err)
	}
	infraDir := envOr("CERTS_INFRA_TLS_DIR", "/run/vecta/infra-tls")
	if err := pki.WriteInfraCerts(infraDir); err != nil {
		logger.Fatalf("refusing to start: infrastructure certificates: %v", err)
	}

	// Postgres starts once its certificate exists, so the first connection
	// attempts may fail; retry rather than restart.
	var rt *pkgplatform.Runtime
	for attempt := 1; ; attempt++ {
		rt, err = pkgplatform.Boot(pkgplatform.Options{
			ServiceName:   "certs",
			JWTScope:      "CERTS",
			HTTPPort:      "8030",
			GRPCPort:      "18030",
			MigrationsDir: "services/certs/migrations",
			AuditName:     "cert", // preserves the audit.cert.* namespace reporting depends on
			DeferTLS:      true,   // enrolled above, before the database
		})
		if err == nil {
			break
		}
		if attempt >= 60 || ctx.Err() != nil {
			log.Fatalf("[kms-certs] boot failed: %v", err)
		}
		logger.Printf("waiting for the database over mTLS (attempt %d): %v", attempt, err)
		time.Sleep(3 * time.Second)
	}
	defer rt.Close()
	logger = rt.Logger

	var publisher EventPublisher
	if rt.Audit != nil {
		publisher = rt.Audit.Publisher()
	}
	svc.AttachStore(NewSQLStore(rt.DB))
	svc.SetPublisher(publisher)
	if err := pki.Reconcile(rt.Ctx); err != nil {
		logger.Fatalf("refusing to start: internal PKI reconcile: %v", err)
	}
	var enrollAudit route.Emitter
	if rt.Audit != nil {
		enrollAudit = rt.Audit
	}
	// A CRWK passphrase rotation (or the migration off the retired public
	// default) rewraps every CA signer before enrolment is served. Members
	// leave it to the primary, whose rows replicate.
	if clusterstate.RunsPrimaryJobs(rt.Ctx) {
		if err := svc.CompleteCRWKRotation(rt.Ctx, enrollAudit, pki); err != nil {
			logger.Printf("CRWK rotation incomplete, retried on next start (both keys stay usable): %v", err)
		}
	}

	bootstrapSecret := os.Getenv("INTERNAL_SERVICE_BOOTSTRAP_SECRET")
	if err := servicetoken.ValidateBootstrapSecret(bootstrapSecret); err != nil {
		logger.Fatalf("refusing to start: enrolment needs %v", err)
	}
	if err := svc.StartEnrollmentListener(rt.Ctx, identity, envOr("CERTS_ENROLL_PORT", "8035"), internalTenant, bootstrapSecret, enrollAudit); err != nil {
		logger.Fatalf("refusing to start: enrolment listener: %v", err)
	}

	// CA signing keys in the "legacy" format are wrapped under a master key
	// from keycore (pkg/mek). Rows under an earlier release's public key are
	// re-wrapped before serving, and recorded as exposed.
	var audit mek.Emitter
	if rt.Audit != nil {
		audit = rt.Audit
	}
	keyring, err := mek.Open(rt.Ctx, mek.Options{
		Tables: mek.Catalog["certs"],
		Source: mek.NewKeycoreSource(keycoreURL, mek.Catalog["certs"]),
		DB:     rt.DB.SQL(),
		Audit:  audit,
		Member: func(ctx context.Context) bool { return !clusterstate.RunsPrimaryJobs(ctx) },
		Logf:   logger.Printf,
		Wait:   10 * time.Minute,
	})
	if err != nil {
		logger.Fatalf("refusing to start: %v", err)
	}
	go keyring.Watch(rt.Ctx, 15*time.Minute)
	if err := svc.SetLegacyMEK(keyring.Current()); err != nil {
		logger.Fatalf("refusing to start: %v", err)
	}

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
				case <-rt.Ctx.Done():
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
		if !clusterstate.RunsPrimaryJobs(migrateCtx) {
			return // the primary rewraps; the result replicates
		}
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
		sweep := func() {
			if clusterstate.RunsPrimaryJobs(rt.Ctx) {
				_ = svc.RunExpiryAlertSweep(context.Background())
			}
		}
		sweep()
		for {
			select {
			case <-rt.Ctx.Done():
				return
			case <-ticker.C:
				sweep()
			}
		}
	}()

	svc.SetKeyring(keyring)
	handler := NewHandler(svc)
	kernel := route.New("cert", audit, logger)
	keyring.Routes(kernel, "cert")
	kernel.MountOn(handler.mux)
	if err := rt.Serve(handler); err != nil {
		rt.Logger.Fatalf("serve failed: %v", err)
	}
}

func loadCertRootKeyConfig() CertRootKeyConfig {
	return CertRootKeyConfig{
		StorageMode:             envOr("CERTS_STORAGE_MODE", "db_encrypted"),
		RootKeyMode:             envOr("CERTS_ROOT_KEY_MODE", "software"),
		SealedPath:              envOr("CERTS_CRWK_SEALED_PATH", defaultCRWKSealedPath),
		BootstrapPassphrase:     strings.TrimSpace(os.Getenv("CERTS_CRWK_BOOTSTRAP_PASSPHRASE")),
		BootstrapPassphraseFile: envOr("CERTS_CRWK_PASSPHRASE_FILE", ""),
		PreviousPassphraseFile:  envOr("CERTS_CRWK_PREVIOUS_PASSPHRASE_FILE", ""),
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
		// Dedicated volume mounted only by certs and the dashboard.
		DashboardTLSDir: envOr("CERTS_DASHBOARD_TLS_DIR", "/run/vecta/dashboard-tls"),
		InfraTLSDir:     envOr("CERTS_INFRA_TLS_DIR", "/run/vecta/infra-tls"),
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
