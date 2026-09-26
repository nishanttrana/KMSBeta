package main

import (
	"log"
	"os"

	"vecta-kms/pkg/clusterstate"
	pkgplatform "vecta-kms/pkg/platform"
	"vecta-kms/pkg/route"
)

// main boots the standard platform spine (config, DB+migrations, NATS,
// unified audit, JWT auth, audit safety net, mTLS gRPC, Consul) and mounts
// the secrets handler. This is the reference layout for new feature services.
func main() {
	// The MEK is checked first: without a valid one nothing may start, and
	// there is no fallback key (docs/SECURITY/SECURE_DEFAULTS.md).
	keys, err := loadMEKs(os.Getenv)
	if err != nil {
		log.Fatalf("[kms-secrets] refusing to start: %v", err)
	}

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

	var audit route.Emitter
	if rt.Audit != nil {
		audit = rt.Audit
	}
	store := NewSQLStore(rt.DB)
	member := !clusterstate.RunsPrimaryJobs(rt.Ctx)
	if err := migrateMEK(rt.Ctx, store, keys, audit, member, rt.Logger.Printf); err != nil {
		rt.Logger.Fatalf("refusing to start: %v", err)
	}

	svc := NewService(store, keys.Current)
	if err := rt.Serve(NewHandler(svc, audit, rt.Logger)); err != nil {
		rt.Logger.Fatalf("serve failed: %v", err)
	}
}
