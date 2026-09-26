package main

import (
	"context"
	"log"
	"os"
	"strings"
	"time"

	"vecta-kms/pkg/clusterstate"
	"vecta-kms/pkg/mek"
	pkgplatform "vecta-kms/pkg/platform"
	"vecta-kms/pkg/route"
	"vecta-kms/pkg/servicetoken"
)

// main boots the standard platform spine (config, DB+migrations, NATS,
// unified audit, JWT auth, audit safety net, mTLS gRPC, Consul) and mounts
// the secrets handler. This is the reference layout for new feature services.
func main() {
	servicetoken.SetDefault(servicetoken.FromEnv("kms-secrets"))
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
	// The master key comes from keycore (pkg/mek): no configuration, no
	// fallback. Values still under a key earlier releases used are re-wrapped
	// before serving; a start that would leave them there is refused.
	keyring, err := mek.Open(rt.Ctx, mek.Options{
		Tables: mek.Catalog["secrets"],
		Source: mek.NewKeycoreSource(envOr("KEYCORE_URL", "http://127.0.0.1:8010"), mek.Catalog["secrets"]),
		DB:     rt.DB.SQL(),
		Audit:  audit,
		Member: func(ctx context.Context) bool { return !clusterstate.RunsPrimaryJobs(ctx) },
		Logf:   rt.Logger.Printf,
		Wait:   10 * time.Minute,
	})
	if err != nil {
		rt.Logger.Fatalf("refusing to start: %v", err)
	}
	go keyring.Watch(rt.Ctx, 15*time.Minute)

	svc := NewService(NewSQLStore(rt.DB), keyring.Current())
	if err := rt.Serve(NewHandler(svc, audit, rt.Logger, keyring)); err != nil {
		rt.Logger.Fatalf("serve failed: %v", err)
	}
}

func envOr(k, d string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return d
}
