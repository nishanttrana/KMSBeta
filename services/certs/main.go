package main

import (
	"context"
	"encoding/base64"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	pkgcrypto "vecta-kms/pkg/crypto"
	pkgplatform "vecta-kms/pkg/platform"
)

var logger = log.Default()

// main boots the standard platform spine and mounts the certs (internal PKI)
// service with its background loops: runtime cert materializer, legacy CA
// signer rewrap, and certificate expiry alert sweep.
func main() {
	rt, err := pkgplatform.Boot(pkgplatform.Options{
		ServiceName:   "certs",
		JWTScope:      "CERTS",
		HTTPPort:      "8030",
		GRPCPort:      "18030",
		MigrationsDir: "services/certs/migrations",
		AuditName:     "cert", // preserves the audit.cert.* namespace reporting depends on
	})
	if err != nil {
		log.Fatalf("[kms-certs] boot failed: %v", err)
	}
	defer rt.Close()
	logger = rt.Logger

	var publisher EventPublisher
	if rt.Audit != nil {
		publisher = rt.Audit.Publisher()
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
	svc := NewServiceWithSecurity(
		NewSQLStore(rt.DB),
		publisher,
		keycoreClient,
		ServiceSecurityConfig{
			CertStorageMode: rootCfg.StorageMode,
			RootKeyMode:     rootCfg.RootKeyMode,
			RootProvider:    rootProvider,
			SecurityErr:     errString(rootErr),
			LegacyMEK:       loadLegacyMEK(),
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
			case <-rt.Ctx.Done():
				return
			case <-ticker.C:
				_ = svc.RunExpiryAlertSweep(context.Background())
			}
		}
	}()

	// Discover the live mTLS mesh from the consul catalog so the dashboard
	// shows every internal service and stays current as services register.
	svc.StartMeshDiscovery(rt.Ctx, logger)

	if err := rt.Serve(NewHandler(svc)); err != nil {
		rt.Logger.Fatalf("serve failed: %v", err)
	}
}

func loadLegacyMEK() []byte {
	raw := strings.TrimSpace(os.Getenv("CERTS_MEK_B64"))
	if raw != "" {
		if out, err := base64.StdEncoding.DecodeString(raw); err == nil && len(out) >= 32 {
			return out[:32]
		}
	}
	sum, err := pkgcrypto.Hash("SHA-256", []byte("vecta-certs-dev-mek"))
	if err != nil {
		panic(err)
	}
	return sum
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
