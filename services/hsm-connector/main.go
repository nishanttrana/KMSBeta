package main

import (
	"log"
	"time"

	pkgdb "vecta-kms/pkg/db"
	"vecta-kms/pkg/hsmconnector"
	pkgplatform "vecta-kms/pkg/platform"
	"vecta-kms/pkg/route"
)

// main boots the hsm-connector: the one process that loads a tenant's
// PKCS#11 library and holds its HSM PIN (docs/SECURITY/HSM_INTEGRATION.md).
// It is built with cgo on a glibc image because vendor PKCS#11 libraries are
// glibc builds; keycore stays a static, cgo-free binary.
func main() {
	rt, err := pkgplatform.Boot(pkgplatform.Options{
		ServiceName: "hsm",
		JWTScope:    "HSM_CONNECTOR",
		HTTPPort:    "8430",
		GRPCPort:    "18430",
	})
	if err != nil {
		log.Fatalf("[kms-hsm] boot failed: %v", err)
	}
	defer rt.Close()

	// The connector only reads the tenants' HSM profiles, so it opens the
	// database without migrations.
	db, err := pkgdb.Open(rt.Ctx, pkgdb.Config{
		PostgresDSN:     rt.Cfg.PostgresDSN,
		PostgresRODSN:   rt.Cfg.PostgresRODSN,
		MaxOpen:         4,
		MaxIdle:         2,
		ConnMaxIdleTime: 5 * time.Minute,
	})
	if err != nil {
		rt.Logger.Fatalf("refusing to start: database: %v", err)
	}
	defer db.Close() //nolint:errcheck

	var audit route.Emitter
	if rt.Audit != nil {
		audit = rt.Audit
	}
	h := hsmconnector.NewHandler(&hsmconnector.DBConfigs{DB: db.ROSQL()}, hsmconnector.NewProvider(), audit, rt.Logger)
	if err := rt.Serve(h); err != nil {
		rt.Logger.Fatalf("serve failed: %v", err)
	}
}
