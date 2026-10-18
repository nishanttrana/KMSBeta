package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The buffer's HMAC key was random at every start (no installer set
// AUDIT_WAL_HMAC_KEY_B64), so every record still buffered at a restart failed
// its HMAC and was dropped without a trace. The key now lives on the audit
// volume, and a record that fails is quarantined and audited.

func TestWALKeySurvivesARestart(t *testing.T) {
	t.Setenv(walKeyEnv, "")
	dir := t.TempDir()
	keyPath := filepath.Join(dir, walKeyFileName)
	walPath := filepath.Join(dir, "audit-wal", "buffer.log")

	first, err := loadOrCreateWALKey(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := NewWALBuffer(walPath, 8, first).Append("publish", "audit.auth.login", []byte(`{"action":"audit.auth.login"}`)); err != nil {
		t.Fatal(err)
	}
	if st, err := os.Stat(keyPath); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("key file: %v %v", st, err)
	}

	// The "restart": the key is read again from the volume.
	second, err := loadOrCreateWALKey(keyPath)
	if err != nil || !bytes.Equal(first, second) {
		t.Fatalf("the key changed across a restart (err %v)", err)
	}
	var drained []string
	var rejected []string
	err = NewWALBuffer(walPath, 8, second).Drain(func(rec WALRecord, _ []byte) error {
		drained = append(drained, rec.Subject)
		return nil
	}, func(_ WALRecord, reason string) { rejected = append(rejected, reason) })
	if err != nil || len(drained) != 1 || len(rejected) != 0 {
		t.Fatalf("drained %v rejected %v err %v", drained, rejected, err)
	}
}

func TestWALKeyAdoptsTheKeyAnOperatorSet(t *testing.T) {
	sixteen := []byte("0123456789abcdef")
	t.Setenv(walKeyEnv, base64.StdEncoding.EncodeToString(sixteen))
	key, err := loadOrCreateWALKey(filepath.Join(t.TempDir(), walKeyFileName))
	if err != nil {
		t.Fatal(err)
	}
	want := make([]byte, 32)
	copy(want, sixteen)
	if !bytes.Equal(key, want) {
		t.Fatal("an operator's key must be adopted as earlier releases read it, so its records still verify")
	}
	t.Setenv(walKeyEnv, "not base64!")
	if _, err := loadOrCreateWALKey(filepath.Join(t.TempDir(), walKeyFileName)); err == nil {
		t.Fatal("an unusable operator key must stop the service, not be replaced by a random one")
	}
}

func TestMalformedWALKeyStopsTheService(t *testing.T) {
	t.Setenv(walKeyEnv, "")
	path := filepath.Join(t.TempDir(), walKeyFileName)
	if err := os.WriteFile(path, []byte("short\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadOrCreateWALKey(path); err == nil || !strings.Contains(err.Error(), "malformed") {
		t.Fatalf("a damaged key must not be replaced: %v", err)
	}
	if raw, _ := os.ReadFile(path); string(raw) != "short\n" {
		t.Fatal("the damaged key file was overwritten")
	}
}

func TestATamperedBufferedRecordIsQuarantinedAndAudited(t *testing.T) {
	// The publisher is down, so the refusal is recorded directly.
	_, svc, store, walPath := newAuditHandler(t, false, true)
	if err := svc.wal.Append("ingest", "audit.auth.login", []byte(`{"tenant_id":"t1","action":"audit.auth.login","service":"auth","actor_id":"u1","result":"success"}`)); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(walPath)
	if err != nil {
		t.Fatal(err)
	}
	var rec WALRecord
	if err := json.Unmarshal(bytes.TrimSpace(raw), &rec); err != nil {
		t.Fatal(err)
	}
	rec.PayloadB64 = base64.StdEncoding.EncodeToString([]byte(`{"tenant_id":"t1","action":"audit.auth.login","service":"auth","actor_id":"someone-else","result":"success"}`))
	tampered, _ := json.Marshal(rec)
	if err := os.WriteFile(walPath, append(append(tampered, '\n'), []byte("{not json\n")...), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := svc.DrainWAL(context.Background()); err != nil {
		t.Fatal(err)
	}

	var n int
	if err := store.db.SQL().QueryRow(`SELECT COUNT(*) FROM audit_events WHERE actor_id='someone-else'`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("a tampered record was ingested (%d, %v)", n, err)
	}
	rows, err := store.db.SQL().Query(`SELECT result, details FROM audit_events WHERE action='audit.audit.wal_record_refused' ORDER BY sequence`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close() //nolint:errcheck
	var reasons []string
	for rows.Next() {
		var result string
		var details []byte
		if err := rows.Scan(&result, &details); err != nil {
			t.Fatal(err)
		}
		var d map[string]interface{}
		_ = json.Unmarshal(details, &d)
		if result != "refused" {
			t.Fatalf("stored result %q", result)
		}
		reasons = append(reasons, d["reason"].(string))
	}
	if strings.Join(reasons, ",") != reasonWALHMACMismatch+","+reasonWALUnreadable {
		t.Fatalf("refusals audited: %v", reasons)
	}
	quarantined, err := os.ReadFile(walPath + ".rejected")
	if err != nil || !bytes.Contains(quarantined, tampered) || !bytes.Contains(quarantined, []byte("{not json")) {
		t.Fatalf("rejected lines must be kept: %q %v", quarantined, err)
	}
	if left, _ := os.ReadFile(walPath); len(bytes.TrimSpace(left)) != 0 {
		t.Fatalf("rejected lines stay out of the buffer: %q", left)
	}
}
