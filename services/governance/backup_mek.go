package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"vecta-kms/pkg/clusterroute"
	pkgcrypto "vecta-kms/pkg/crypto"
	"vecta-kms/pkg/mek"
	"vecta-kms/pkg/servicetoken"
)

// Re-protecting backups (docs/SECURITY/SERVICE_MASTER_KEYS.md).
//
// Backups taken before 1.2.0-beta hold rows whose data keys are wrapped under
// public development keys: stored secrets, CA signing keys, cloud credentials
// and BitLocker recovery keys. Re-wrapping the live rows doesn't help a
// backup kept in the platform, which could still be restored or decrypted.
// So governance:
//
//   - re-protects every stored backup: it decrypts the artifact, finds the
//     rows of catalogued tables under a public key (the keys are public, so
//     no service is needed for that), sends their wrapped data keys to the
//     owning service
//     (POST /mek/rewrap-legacy, governance identity only; the service
//     re-wraps only what a legacy key opens), and re-seals the artifact
//     under a fresh backup key. The old key package no longer opens it.
//     Copies downloaded before then can't be changed; the exposure register
//     is what tracks them.
//   - re-wraps a restore's payload the same way before any row is written,
//     so restored rows go live under the service key. Items that were under
//     a public key are (re)opened in the owning service's exposure register.

// backupRewrapper re-wraps wrapped DEKs through the owning service.
type backupRewrapper interface {
	Rewrap(ctx context.Context, service string, req mek.RewrapRequest) ([]mek.RewrapResult, error)
}

// WithBackupRewrapper replaces the HTTP rewrapper (tests).
func WithBackupRewrapper(rw backupRewrapper) ServiceOption {
	return func(s *Service) { s.rewrapper = rw }
}

type httpBackupRewrapper struct{ client *http.Client }

func (h httpBackupRewrapper) Rewrap(ctx context.Context, service string, req mek.RewrapRequest) ([]mek.RewrapResult, error) {
	st := mek.Catalog[service]
	base := strings.TrimSpace(os.Getenv(strings.ToUpper(service) + "_URL"))
	if base == "" {
		base = clusterroute.Services[st.ClientID]
	}
	if base == "" {
		return nil, fmt.Errorf("no URL for %s", st.ClientID)
	}
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(base, "/")+"/mek/rewrap-legacy", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	servicetoken.Authorize(ctx, httpReq)
	resp, err := h.client.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("%s re-wrap: %d %s", st.ClientID, resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	var out struct {
		Entries []mek.RewrapResult `json:"entries"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	if len(out.Entries) != len(req.Entries) {
		return nil, fmt.Errorf("%s re-wrap returned %d entries for %d", st.ClientID, len(out.Entries), len(req.Entries))
	}
	return out.Entries, nil
}

// rewrapBatch bounds one call to a service.
const rewrapBatch = 1000

// reprotectTables re-wraps, in place, the data keys of every catalogued
// table in tables that a public legacy key opens. It returns rows re-wrapped
// per service. It calls a service only when such rows exist; if that service
// can't be reached, it's an error and the payload is left as is.
func reprotectTables(ctx context.Context, rw backupRewrapper, tables map[string]json.RawMessage, restoring bool) (map[string]int, error) {
	counts := map[string]int{}
	services := make([]string, 0, len(mek.Catalog))
	for name := range mek.Catalog {
		services = append(services, name)
	}
	sort.Strings(services)
	for _, name := range services {
		for _, t := range mek.Catalog[name].Tables {
			raw, ok := tables[t.Name]
			if !ok {
				continue
			}
			dec := json.NewDecoder(bytes.NewReader(raw))
			dec.UseNumber() // keep numbers exactly as captured
			var rows []map[string]interface{}
			if err := dec.Decode(&rows); err != nil {
				return nil, fmt.Errorf("backup table %s: %w", t.Name, err)
			}
			// Only rows under a public key need the service: they're found
			// here with the public keys, so a clean backup never depends on
			// the service being up. (Rows under an operator's old env key are
			// re-wrapped by the service's own rescan after a restore.)
			public := mek.Catalog[name].PublicLegacyKeys()
			var entries []mek.RewrapEntry
			var index []int
			for i, row := range rows {
				iv, ok1 := decodeWrapped(row[t.WrappedIV], t.Base64)
				dek, ok2 := decodeWrapped(row[t.WrappedDEK], t.Base64)
				if !ok1 || !ok2 || !underAny(public, iv, dek) {
					continue
				}
				entries = append(entries, mek.RewrapEntry{
					IV: base64.StdEncoding.EncodeToString(iv), DEK: base64.StdEncoding.EncodeToString(dek),
					Table: t.Name, Tenant: fmt.Sprint(row[t.Tenant]), Item: fmt.Sprint(row[t.Item]),
				})
				index = append(index, i)
			}
			changed := 0
			for start := 0; start < len(entries); start += rewrapBatch {
				end := min(start+rewrapBatch, len(entries))
				res, err := rw.Rewrap(ctx, name, mek.RewrapRequest{Entries: entries[start:end], Restoring: restoring})
				if err != nil {
					return nil, err
				}
				for j, r := range res {
					if r.Status != "rewrapped" {
						continue
					}
					iv, err1 := base64.StdEncoding.DecodeString(r.IV)
					dek, err2 := base64.StdEncoding.DecodeString(r.DEK)
					if err1 != nil || err2 != nil {
						return nil, fmt.Errorf("%s returned an invalid re-wrap", name)
					}
					row := rows[index[start+j]]
					row[t.WrappedIV], row[t.WrappedDEK] = encodeWrapped(iv, t.Base64), encodeWrapped(dek, t.Base64)
					changed++
				}
			}
			if changed == 0 {
				continue
			}
			out, err := json.Marshal(rows)
			if err != nil {
				return nil, err
			}
			tables[t.Name] = out
			counts[name] += changed
		}
	}
	return counts, nil
}

// decodeWrapped reads a wrapped-DEK column as captured by row_to_json:
// bytea as "\x<hex>", base64 text as itself.
func decodeWrapped(v interface{}, isBase64 bool) ([]byte, bool) {
	s, ok := v.(string)
	if !ok || s == "" {
		return nil, false
	}
	if isBase64 {
		b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
		return b, err == nil
	}
	b, err := hex.DecodeString(strings.TrimPrefix(s, `\x`))
	return b, err == nil
}

func encodeWrapped(b []byte, isBase64 bool) string {
	if isBase64 {
		return base64.StdEncoding.EncodeToString(b)
	}
	return `\x` + hex.EncodeToString(b)
}

// ReprotectStoredBackups re-protects every stored backup not yet processed.
// It runs on the primary (backups are replicated). It returns how many were
// processed; a backup it can't open or a service it can't reach is audited
// and retried on the next run.
func (s *Service) ReprotectStoredBackups(ctx context.Context) (int, error) {
	store, ok := s.store.(*SQLStore)
	if !ok || store == nil {
		return 0, errors.New("backup store is unavailable")
	}
	pending, err := store.listUnreprotectedBackups(ctx)
	if err != nil {
		return 0, err
	}
	done := 0
	for _, ref := range pending {
		if err := s.reprotectBackup(ctx, store, ref[0], ref[1]); err != nil {
			_ = s.publishAudit(ctx, "audit.governance.backup_reprotect_refused", ref[0], map[string]interface{}{
				"backup_id": ref[1], "reason": err.Error(), "result": "refused", "severity": "warning",
				"description": "a stored backup could not be re-protected yet; it is retried on the next run",
			})
			continue
		}
		done++
	}
	return done, nil
}

func (s *Service) reprotectBackup(ctx context.Context, store *SQLStore, tenantID, backupID string) error {
	job, err := store.getBackupJob(ctx, tenantID, backupID, true)
	if err != nil {
		return err
	}
	key, err := s.resolveRestoreBackupKey(ctx, store, job.TenantID, job.KeyPackage)
	if err != nil {
		return fmt.Errorf("key_unavailable: %w", err)
	}
	aad, err := backupAAD(job.Scope, job.TenantID, job.TargetTenantID, job.BackupFormat)
	if err != nil {
		return err
	}
	plaintext, err := decryptAESGCM(job.ArtifactCiphertext, key, job.ArtifactNonce, aad)
	if err != nil {
		if plaintext, err = decryptAESGCM(job.ArtifactCiphertext, key, job.ArtifactNonce, nil); err != nil {
			return errors.New("artifact_unreadable: the stored key package does not open the artifact")
		}
	}
	zr, err := gzip.NewReader(bytes.NewReader(plaintext))
	if err != nil {
		return err
	}
	raw, err := io.ReadAll(zr)
	if err != nil {
		return err
	}
	var snapshot backupSnapshotPayload
	if err := json.Unmarshal(raw, &snapshot); err != nil {
		return errors.New("backup payload JSON is invalid")
	}
	counts, err := reprotectTables(ctx, s.backupRewrapper(), snapshot.Tables, false)
	if err != nil {
		return fmt.Errorf("service_unreachable: %w", err)
	}
	total := 0
	for _, n := range counts {
		total += n
	}
	if total == 0 {
		return store.markBackupReprotected(ctx, job.ID, nil)
	}
	payload, err := json.Marshal(snapshot)
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(payload); err != nil {
		return err
	}
	if err := zw.Close(); err != nil {
		return err
	}
	newKey, err := randomBytes(32)
	if err != nil {
		return err
	}
	ciphertext, nonce, err := encryptAESGCM(buf.Bytes(), newKey, aad)
	if err != nil {
		return err
	}
	hsmTenant := job.TenantID
	if job.Scope == backupScopeTenant {
		hsmTenant = job.TargetTenantID
	}
	_, keyPackageRaw, err := buildBackupKeyPackage(newKey, job.HSMBound, store.loadHSMBinding(ctx, hsmTenant), job.TenantID, job.TargetTenantID, snapshot.Coverage)
	if err != nil {
		return err
	}
	if err := store.markBackupReprotected(ctx, job.ID, &reprotectedArtifact{
		ciphertext: ciphertext, nonce: nonce, sha: sha256Hex(string(ciphertext)), keyPackageRaw: keyPackageRaw,
	}); err != nil {
		return err
	}
	_ = s.publishAudit(ctx, "audit.governance.backup_reprotected", job.TenantID, map[string]interface{}{
		"backup_id": job.ID, "rows_rewrapped": counts, "severity": "warning",
		"previous_key_package_invalidated": true,
		"description": "rows under a public development key were re-wrapped by their services and the backup re-sealed under a new key; " +
			"copies downloaded earlier are unchanged, see the services' exposure registers",
	})
	return nil
}

func backupAAD(scope, tenantID, targetTenantID, format string) ([]byte, error) {
	if format == "" {
		format = backupFormatJSONGzAESGCM
	}
	return json.Marshal(map[string]interface{}{
		"service": "governance", "scope": scope, "tenant_id": tenantID, "target_tenant_id": targetTenantID, "format": format,
	})
}

func (s *Service) backupRewrapper() backupRewrapper {
	if s.rewrapper != nil {
		return s.rewrapper
	}
	return httpBackupRewrapper{client: &http.Client{Timeout: 30 * time.Second}}
}

type reprotectedArtifact struct {
	ciphertext, nonce []byte
	sha               string
	keyPackageRaw     []byte
}

func (s *SQLStore) listUnreprotectedBackups(ctx context.Context) ([][2]string, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT tenant_id, id FROM governance_backup_jobs
WHERE mek_reprotected_at IS NULL AND status = 'completed'
ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	var out [][2]string
	for rows.Next() {
		var r [2]string
		if err := rows.Scan(&r[0], &r[1]); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// markBackupReprotected records the run, replacing the artifact and key
// package when rows were re-wrapped.
func (s *SQLStore) markBackupReprotected(ctx context.Context, id string, a *reprotectedArtifact) error {
	if a == nil {
		_, err := s.db.SQL().ExecContext(ctx, `UPDATE governance_backup_jobs SET mek_reprotected_at = NOW() WHERE id = $1`, id)
		return err
	}
	_, err := s.db.SQL().ExecContext(ctx, `
UPDATE governance_backup_jobs
SET artifact_ciphertext = $1, artifact_nonce = $2, ciphertext_sha256 = $3, artifact_size_bytes = $4,
    key_package_json = $5::jsonb, mek_reprotected_at = NOW()
WHERE id = $6`, a.ciphertext, a.nonce, a.sha, int64(len(a.ciphertext)), string(a.keyPackageRaw), id)
	return err
}

func underAny(keys [][]byte, iv, dek []byte) bool {
	env := &pkgcrypto.EnvelopeCiphertext{WrappedDEKIV: iv, WrappedDEK: dek}
	for _, k := range keys {
		if pkgcrypto.EnvelopeWrappedUnder(k, env) {
			return true
		}
	}
	return false
}
