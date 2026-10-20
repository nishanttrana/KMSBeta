package main

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// The 24-hour summary counts every record in the window, in the database:
// it counted the newest 100 rows (13.24.0-beta). Real Postgres, real schema.
func TestSummaryCountsEveryRecordPostgres(t *testing.T) {
	f := newSigningFixture(t)
	ctx := context.Background()
	now := time.Now().UTC()
	insert := func(id, artifact, mode, entry, status string, at time.Time) {
		t.Helper()
		if _, err := f.conn.SQL().ExecContext(ctx, `INSERT INTO signing_records (id, tenant_id, profile_id, artifact_type, digest_sha256, signature_b64, key_id, signing_algorithm, identity_mode, transparency_entry_id, verification_status, created_at)
VALUES ($1,'sum-t','p',$2,'d','s','k','ECDSA-P256',$3,$4,$5,$6)`, id, artifact, mode, entry, status, at); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 600; i++ {
		insert(fmt.Sprintf("r%03d", i), "blob", "oidc", "e", "logged", now.Add(-time.Duration(i)*time.Second))
	}
	insert("w1", "oci", "workload", "", "failed", now.Add(-time.Hour))
	insert("old", "blob", "oidc", "e", "logged", now.Add(-25*time.Hour))

	sum, err := f.svc.GetSummary(ctx, "sum-t")
	if err != nil {
		t.Fatal(err)
	}
	if sum.RecordCount24h != 601 || sum.TransparencyLogged24h != 600 || sum.OIDCSigned24h != 600 || sum.WorkloadSigned24h != 1 || sum.VerificationFailures24h != 1 {
		t.Fatalf("summary over every record in the window: %+v", sum)
	}
	if len(sum.ArtifactCounts) != 2 || sum.ArtifactCounts[0].Count24h != 600 {
		t.Fatalf("per artifact type: %+v", sum.ArtifactCounts)
	}
}
