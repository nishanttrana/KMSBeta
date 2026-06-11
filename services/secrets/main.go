package main

import (
	"encoding/base64"
	"log"
	"os"
	"strings"

	pkgcrypto "vecta-kms/pkg/crypto"
	pkgplatform "vecta-kms/pkg/platform"
)

// main boots the standard platform spine (config, DB+migrations, NATS,
// unified audit, JWT auth, audit safety net, mTLS gRPC, Consul) and mounts
// the secrets handler. This is the reference layout for new feature services.
func main() {
	rt, err := pkgplatform.Boot(pkgplatform.Options{
		ServiceName:   "secrets",
		JWTScope:      "SECRETS",
		HTTPPort:      "8020",
		GRPCPort:      "18020",
		MigrationsDir: "services/secrets/migrations",
	})
	if err != nil {
		log.Fatalf("[kms-secrets] boot failed: %v", err)
	}
	defer rt.Close()

	svc := NewService(NewSQLStore(rt.DB), rt.Audit, loadMEK(rt.Logger))
	if err := rt.Serve(NewHandler(svc)); err != nil {
		rt.Logger.Fatalf("serve failed: %v", err)
	}
}

func loadMEK(logger *log.Logger) []byte {
	b64 := strings.TrimSpace(os.Getenv("SECRETS_MEK_B64"))
	if b64 != "" {
		if raw, err := base64.StdEncoding.DecodeString(b64); err == nil && len(raw) >= 32 {
			return raw[:32]
		}
	}
	logger.Printf("WARNING: SECRETS_MEK_B64 not set — using derived dev MEK, not for production")
	sum, err := pkgcrypto.Hash("SHA-256", []byte("vecta-secrets-dev-mek"))
	if err != nil {
		panic(err)
	}
	return sum
}
