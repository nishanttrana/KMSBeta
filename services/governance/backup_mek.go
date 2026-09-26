package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
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

// Backup contents and retired master keys
// (docs/SECURITY/SERVICE_MASTER_KEYS.md).
//
// Rows of catalogued tables (stored secrets, CA signing keys, cloud
// credentials, BitLocker recovery keys) found under a public development key
// are re-wrapped by their owning service (POST /mek/rewrap-legacy,
// governance identity only; the service re-wraps only what a legacy key
// opens):
//
//   - when a backup is captured, so no new artifact holds a row under a
//     public key;
//   - when a backup is restored, before any row is written, so restored rows
//     go live under the service key. Items that were under a public key are
//     (re)opened in the owning service's exposure register.
//
// The keys are public, so governance finds such rows itself: a clean backup
// never needs the services. Governance can't re-seal backups it already
// stores, because it doesn't keep their keys (docs/SECURITY/BACKUP_KEYS.md).

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

func (s *Service) backupRewrapper() backupRewrapper {
	if s.rewrapper != nil {
		return s.rewrapper
	}
	return httpBackupRewrapper{client: &http.Client{Timeout: 30 * time.Second}}
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
