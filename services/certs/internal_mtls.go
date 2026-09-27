package main

import (
	"context"
	"crypto/fips140"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	pkgaudit "vecta-kms/pkg/audit"
	"vecta-kms/pkg/route"
	"vecta-kms/pkg/svctls"
)

// Service mTLS management (docs/SECURITY/INTERNAL_TLS.md, slice 3): the
// per-identity policy (certificate key, key-exchange profile), rotation and
// restart, and what every identity actually runs.
//
// Two kinds of identity:
//   - "service": a Go service that enrols itself (svctls). It reads the
//     policy certs publishes (mtls-policy.json on the trust volume) and
//     restarts when its entry changes; the new process enrols with a fresh
//     key. It reports what it runs to platform_mtls_observed.
//   - "file": Envoy's client certificate, the dashboard and the Postgres,
//     NATS, Valkey and Consul servers. Certs writes their key and
//     certificate; the daemon reloads the files (tls-entry.sh, tls-watch.sh,
//     Envoy SDS). Their TLS groups are the daemon's own configuration.

const (
	mtlsKindService = "service"
	mtlsKindFile    = "file"
	// Rotate-all restarts one service per step so the platform stays up.
	mtlsRotateAllStep = 20 * time.Second
	mtlsFileInstance  = "certs-files"
)

var errMTLSNotFound = errors.New("not found")

type mtlsPolicyRow struct {
	Identity          string    `json:"identity"`
	KeyAlgorithm      string    `json:"key_algorithm"`
	KXProfile         string    `json:"kx_profile"`
	Generation        int64     `json:"generation"`
	RestartMode       string    `json:"restart_mode"`
	ApplyAfter        time.Time `json:"apply_after,omitempty"`
	Reason            string    `json:"reason,omitempty"`
	UpdatedBy         string    `json:"updated_by,omitempty"`
	UpdatedAt         time.Time `json:"updated_at,omitempty"`
	AuditedGeneration int64     `json:"-"`
}

type mtlsObservedRow struct {
	Identity           string    `json:"identity"`
	Instance           string    `json:"instance"`
	Serial             string    `json:"serial"`
	NotAfter           time.Time `json:"not_after"`
	KeyAlgorithm       string    `json:"key_algorithm"`
	KXProfile          string    `json:"kx_profile"`
	ServerGroups       []string  `json:"server_groups"`
	Generation         int64     `json:"generation"`
	LastHandshakeGroup string    `json:"last_handshake_group,omitempty"`
	LastHandshakeAt    time.Time `json:"last_handshake_at,omitempty"`
	StartedAt          time.Time `json:"started_at,omitempty"`
	UpdatedAt          time.Time `json:"updated_at"`
}

// mtlsStore is implemented by SQLStore.
type mtlsStore interface {
	ListMTLSPolicies(ctx context.Context) (map[string]mtlsPolicyRow, error)
	UpsertMTLSPolicy(ctx context.Context, row mtlsPolicyRow) error
	MarkMTLSPolicyAudited(ctx context.Context, identity string, generation int64) error
	ListMTLSObserved(ctx context.Context) ([]mtlsObservedRow, error)
	UpsertMTLSObserved(ctx context.Context, row mtlsObservedRow) error
}

func (s *SQLStore) ListMTLSPolicies(ctx context.Context) (map[string]mtlsPolicyRow, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT identity, key_algorithm, kx_profile, generation, restart_mode, apply_after, reason, updated_by, updated_at, audited_generation
FROM cert_internal_mtls_policy`)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := map[string]mtlsPolicyRow{}
	for rows.Next() {
		var r mtlsPolicyRow
		var applyAfter, updated interface{}
		if err := rows.Scan(&r.Identity, &r.KeyAlgorithm, &r.KXProfile, &r.Generation, &r.RestartMode, &applyAfter, &r.Reason, &r.UpdatedBy, &updated, &r.AuditedGeneration); err != nil {
			return nil, err
		}
		r.ApplyAfter, r.UpdatedAt = parseTimeValue(applyAfter), parseTimeValue(updated)
		out[r.Identity] = r
	}
	return out, rows.Err()
}

func (s *SQLStore) UpsertMTLSPolicy(ctx context.Context, r mtlsPolicyRow) error {
	var applyAfter interface{}
	if !r.ApplyAfter.IsZero() {
		applyAfter = r.ApplyAfter.UTC()
	}
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO cert_internal_mtls_policy (identity, key_algorithm, kx_profile, generation, restart_mode, apply_after, reason, updated_by, updated_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,CURRENT_TIMESTAMP)
ON CONFLICT (identity) DO UPDATE SET key_algorithm = EXCLUDED.key_algorithm, kx_profile = EXCLUDED.kx_profile,
	generation = EXCLUDED.generation, restart_mode = EXCLUDED.restart_mode, apply_after = EXCLUDED.apply_after,
	reason = EXCLUDED.reason, updated_by = EXCLUDED.updated_by, updated_at = CURRENT_TIMESTAMP`,
		r.Identity, r.KeyAlgorithm, r.KXProfile, r.Generation, r.RestartMode, applyAfter, r.Reason, r.UpdatedBy)
	return err
}

func (s *SQLStore) MarkMTLSPolicyAudited(ctx context.Context, identity string, generation int64) error {
	_, err := s.db.SQL().ExecContext(ctx, `UPDATE cert_internal_mtls_policy SET audited_generation = $1 WHERE identity = $2 AND audited_generation < $1`, generation, identity)
	return err
}

func (s *SQLStore) ListMTLSObserved(ctx context.Context) ([]mtlsObservedRow, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT identity, instance, serial, not_after, key_algorithm, kx_profile, server_groups, generation,
	last_handshake_group, last_handshake_at, started_at, updated_at
FROM platform_mtls_observed ORDER BY identity, instance`)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	var out []mtlsObservedRow
	for rows.Next() {
		var r mtlsObservedRow
		var notAfter, lastAt, started, updated interface{}
		var groups string
		if err := rows.Scan(&r.Identity, &r.Instance, &r.Serial, &notAfter, &r.KeyAlgorithm, &r.KXProfile, &groups, &r.Generation,
			&r.LastHandshakeGroup, &lastAt, &started, &updated); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(groups), &r.ServerGroups)
		r.NotAfter, r.LastHandshakeAt, r.StartedAt, r.UpdatedAt = parseTimeValue(notAfter), parseTimeValue(lastAt), parseTimeValue(started), parseTimeValue(updated)
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *SQLStore) UpsertMTLSObserved(ctx context.Context, r mtlsObservedRow) error {
	groups, _ := json.Marshal(r.ServerGroups)
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO platform_mtls_observed (identity, instance, serial, not_after, key_algorithm, kx_profile, server_groups, generation, started_at, updated_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,CURRENT_TIMESTAMP)
ON CONFLICT (identity, instance) DO UPDATE SET serial = EXCLUDED.serial, not_after = EXCLUDED.not_after,
	key_algorithm = EXCLUDED.key_algorithm, kx_profile = EXCLUDED.kx_profile, server_groups = EXCLUDED.server_groups,
	generation = EXCLUDED.generation, started_at = EXCLUDED.started_at, updated_at = CURRENT_TIMESTAMP`,
		r.Identity, r.Instance, r.Serial, r.NotAfter.UTC(), r.KeyAlgorithm, r.KXProfile, string(groups), r.Generation, r.StartedAt.UTC())
	return err
}

func (s *Service) mtls() (mtlsStore, error) {
	st, ok := s.store.(mtlsStore)
	if !ok {
		return nil, errors.New("internal mTLS policy needs the SQL store")
	}
	return st, nil
}

// mtlsKind names the kind of a registered identity, "" if unknown.
func mtlsKind(identity string) string {
	if _, ok := svctls.Services[identity]; ok {
		return mtlsKindService
	}
	if _, ok := svctls.Materialized[identity]; ok {
		return mtlsKindFile
	}
	if _, ok := svctls.Infrastructure[identity]; ok {
		return mtlsKindFile
	}
	return ""
}

func mtlsIdentities() []string {
	var out []string
	for _, m := range []map[string]string{svctls.Services, svctls.Materialized, svctls.Infrastructure} {
		for id := range m {
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}

// effectivePolicy is the stored entry or the default. A file identity has no
// key-exchange profile of ours: the daemon's TLS library chooses.
func effectivePolicy(identity string, rows map[string]mtlsPolicyRow) svctls.ServicePolicy {
	p := svctls.DefaultPolicy()
	if r, ok := rows[identity]; ok {
		p = svctls.ServicePolicy{KeyAlgorithm: r.KeyAlgorithm, KXProfile: r.KXProfile, Generation: r.Generation, RestartMode: r.RestartMode, ApplyAfter: r.ApplyAfter}
		if n, err := p.Normalize(); err == nil {
			p = n
		}
	}
	if mtlsKind(identity) == mtlsKindFile {
		p.KXProfile = ""
	}
	return p
}

// PublishMTLSPolicy writes the policy of every service identity to
// dir/mtls-policy.json (public: algorithms and generations only).
func (s *Service) PublishMTLSPolicy(ctx context.Context, dir string) error {
	st, err := s.mtls()
	if err != nil {
		return err
	}
	rows, err := st.ListMTLSPolicies(ctx)
	if err != nil {
		return err
	}
	f := svctls.PolicyFile{Version: 1, Services: map[string]svctls.ServicePolicy{}}
	var latest time.Time
	for id := range svctls.Services {
		if r, ok := rows[id]; ok {
			f.Services[id] = effectivePolicy(id, rows)
			if r.UpdatedAt.After(latest) {
				latest = r.UpdatedAt
			}
		}
	}
	f.UpdatedAt = latest.UTC()
	raw, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(dir, svctls.PolicyFileName)
	if cur, err := os.ReadFile(path); err == nil && string(cur) == string(raw) {
		return nil
	}
	return writeFileAtomically(path, raw, 0o644)
}

// mtlsIdentityView is one row of the Service mTLS page.
type mtlsIdentityView struct {
	Identity     string               `json:"identity"`
	Host         string               `json:"host"`
	Kind         string               `json:"kind"`
	Policy       svctls.ServicePolicy `json:"policy"`
	Certificates []mtlsCertView       `json:"certificates"`
	Observed     []mtlsObservedRow    `json:"observed"`
	Applied      bool                 `json:"applied"`
	RestartModes []string             `json:"restart_modes"`
	KXProfiles   []string             `json:"kx_profiles,omitempty"`
	Note         string               `json:"note,omitempty"`
	PolicyRecord *mtlsPolicyRow       `json:"policy_record,omitempty"`
	ServedFile   *mtlsObservedRow     `json:"served_file,omitempty"`
}

type mtlsCertView struct {
	ID           string    `json:"id"`
	Serial       string    `json:"serial"`
	KeyAlgorithm string    `json:"key_algorithm"`
	NotAfter     time.Time `json:"not_after"`
	Issuer       string    `json:"issuer"`
}

// MTLSInventory lists every internal identity with its policy, its active
// certificates from the internal Sub CA, and what its instances report.
func (s *Service) MTLSInventory(ctx context.Context, tenantID string) ([]mtlsIdentityView, map[string]interface{}, error) {
	st, err := s.mtls()
	if err != nil {
		return nil, nil, err
	}
	rows, err := st.ListMTLSPolicies(ctx)
	if err != nil {
		return nil, nil, err
	}
	observed, err := st.ListMTLSObserved(ctx)
	if err != nil {
		return nil, nil, err
	}
	_, sub, err := s.EnsureInternalPKI(ctx, tenantID)
	if err != nil {
		return nil, nil, err
	}
	active, err := s.activeInternalCerts(ctx, tenantID, sub.ID)
	if err != nil {
		return nil, nil, err
	}
	var out []mtlsIdentityView
	for _, id := range mtlsIdentities() {
		host, _ := svctls.HostFor(id)
		v := mtlsIdentityView{Identity: id, Host: host, Kind: mtlsKind(id), Policy: effectivePolicy(id, rows)}
		if r, ok := rows[id]; ok {
			rr := r
			v.PolicyRecord = &rr
		}
		for _, c := range active[id] {
			v.Certificates = append(v.Certificates, mtlsCertView{ID: c.ID, Serial: c.SerialNumber, KeyAlgorithm: c.Algorithm, NotAfter: c.NotAfter, Issuer: sub.Name})
		}
		for _, o := range observed {
			if o.Identity != id {
				continue
			}
			if o.Instance == mtlsFileInstance {
				oo := o
				v.ServedFile = &oo
				continue
			}
			v.Observed = append(v.Observed, o)
		}
		if v.Kind == mtlsKindService {
			v.RestartModes = []string{svctls.RestartGraceful, svctls.RestartForce}
			v.KXProfiles = svctls.KXProfiles
			v.Applied = len(v.Observed) > 0
			for _, o := range v.Observed {
				if o.Generation != v.Policy.Generation || o.KeyAlgorithm != v.Policy.KeyAlgorithm || o.KXProfile != v.Policy.KXProfile {
					v.Applied = false
				}
			}
		} else {
			v.RestartModes = []string{svctls.RestartGraceful}
			v.Note = "certs writes this certificate; the daemon reloads it within 30 s (no restart). Its TLS groups are the daemon's own configuration."
			v.Applied = v.ServedFile != nil && v.ServedFile.Generation == v.Policy.Generation && v.ServedFile.KeyAlgorithm == v.Policy.KeyAlgorithm
		}
		out = append(out, v)
	}
	meta := map[string]interface{}{
		"key_algorithms":  svctls.KeyAlgorithms,
		"kx_profiles":     svctls.KXProfiles,
		"fips_mode":       fips140.Enabled(),
		"sub_ca":          sub.Name,
		"groups":          map[string][]string{svctls.KXPQCRequired: groupNames(svctls.KXPQCRequired), svctls.KXPQCPreferred: groupNames(svctls.KXPQCPreferred), svctls.KXClassical: groupNames(svctls.KXClassical)},
		"signature_note":  "Certificate signatures are classical: Go's TLS can't present ML-DSA certificates. Post-quantum protection is the key exchange.",
		"rotate_all_step": mtlsRotateAllStep.Seconds(),
	}
	return out, meta, nil
}

func groupNames(profile string) []string {
	var out []string
	for _, g := range svctls.ServerGroups(profile) {
		out = append(out, svctls.GroupName(g))
	}
	return out
}

// activeInternalCerts groups the active certificates issued by the internal
// Sub CA by subject (identity).
func (s *Service) activeInternalCerts(ctx context.Context, tenantID, subID string) (map[string][]Certificate, error) {
	out := map[string][]Certificate{}
	for offset := 0; ; offset += 500 {
		page, err := s.store.ListCertificates(ctx, tenantID, CertStatusActive, "internal-mtls", 500, offset)
		if err != nil {
			return nil, err
		}
		for _, c := range page {
			if c.CAID == subID {
				out[c.SubjectCN] = append(out[c.SubjectCN], c)
			}
		}
		if len(page) < 500 {
			return out, nil
		}
	}
}

// revokeIdentityCerts revokes identity's active certificates from the Sub CA
// (never another CA's certificate with the same subject, like the edge
// certificate of vecta-envoy), except keepID.
func (s *Service) revokeIdentityCerts(ctx context.Context, tenantID, identity, keepID, reason string) (int, error) {
	_, sub, err := s.EnsureInternalPKI(ctx, tenantID)
	if err != nil {
		return 0, err
	}
	active, err := s.activeInternalCerts(ctx, tenantID, sub.ID)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, c := range active[identity] {
		if c.ID == keepID {
			continue
		}
		if err := s.RevokeCertificate(ctx, RevokeCertificateRequest{TenantID: tenantID, CertID: c.ID, Reason: reason}); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

type mtlsChange struct {
	Identity     string
	KeyAlgorithm string // "" keeps
	KXProfile    string // "" keeps
	Rotate       bool
	RestartMode  string
	ApplyAfter   time.Time
	Reason       string
	Actor        string
}

type mtlsChangeResult struct {
	Policy     svctls.ServicePolicy `json:"policy"`
	Revoked    int                  `json:"revoked"`
	Reissued   bool                 `json:"reissued"`
	Kind       string               `json:"kind"`
	PrevPolicy svctls.ServicePolicy `json:"previous_policy"`
}

// mtlsRefusal is a change the caller asked for that isn't possible.
type mtlsRefusal struct{ reason, msg string }

func (e mtlsRefusal) Error() string { return e.msg }

// ApplyMTLSChange changes an identity's policy and/or rotates its
// certificate. A service identity's old certificate is revoked and a new
// generation published; the service restarts and enrols a fresh key. A file
// identity's certificate is reissued at once under a fresh key.
func (s *Service) ApplyMTLSChange(ctx context.Context, tenantID string, ch mtlsChange) (mtlsChangeResult, error) {
	kind := mtlsKind(ch.Identity)
	if kind == "" {
		return mtlsChangeResult{}, mtlsRefusal{"unknown_identity", fmt.Sprintf("%q is not a platform identity", ch.Identity)}
	}
	st, err := s.mtls()
	if err != nil {
		return mtlsChangeResult{}, err
	}
	rows, err := st.ListMTLSPolicies(ctx)
	if err != nil {
		return mtlsChangeResult{}, err
	}
	prev := effectivePolicy(ch.Identity, rows)
	next := prev
	if ch.KeyAlgorithm != "" {
		next.KeyAlgorithm = ch.KeyAlgorithm
	}
	if ch.KXProfile != "" {
		if kind == mtlsKindFile {
			return mtlsChangeResult{}, mtlsRefusal{"kx_profile_not_applicable", ch.Identity + "'s TLS groups are the daemon's own configuration; only its certificate key can be chosen"}
		}
		next.KXProfile = ch.KXProfile
	}
	next.RestartMode = ch.RestartMode
	if next.RestartMode == "" {
		next.RestartMode = svctls.RestartGraceful
	}
	if kind == mtlsKindFile && next.RestartMode == svctls.RestartForce {
		return mtlsChangeResult{}, mtlsRefusal{"force_not_available", ch.Identity + " is not restarted by the KMS: certs rewrites its certificate and the daemon reloads it"}
	}
	check := next
	if kind == mtlsKindFile {
		check.KXProfile = svctls.KXPQCPreferred
	}
	if _, err := check.Normalize(); err != nil {
		return mtlsChangeResult{}, mtlsRefusal{"invalid_policy", err.Error()}
	}
	if !ch.Rotate && next.KeyAlgorithm == prev.KeyAlgorithm && next.KXProfile == prev.KXProfile {
		return mtlsChangeResult{}, mtlsRefusal{"unchanged", "the policy is already in effect; use rotate to replace the certificate"}
	}
	next.Generation = prev.Generation + 1
	next.ApplyAfter = ch.ApplyAfter
	res := mtlsChangeResult{Kind: kind, PrevPolicy: prev}

	revokeReason := "superseded"
	if next.RestartMode == svctls.RestartForce {
		revokeReason = "keyCompromise"
	}
	if kind == mtlsKindService && ch.Rotate {
		if res.Revoked, err = s.revokeIdentityCerts(ctx, tenantID, ch.Identity, "", revokeReason); err != nil {
			return res, fmt.Errorf("revoke the current certificate: %w", err)
		}
	}
	if err := st.UpsertMTLSPolicy(ctx, mtlsPolicyRow{
		Identity: ch.Identity, KeyAlgorithm: next.KeyAlgorithm, KXProfile: next.KXProfile, Generation: next.Generation,
		RestartMode: next.RestartMode, ApplyAfter: next.ApplyAfter, Reason: ch.Reason, UpdatedBy: ch.Actor,
	}); err != nil {
		return res, err
	}
	if kind == mtlsKindFile {
		if err := s.reissueFileIdentity(ctx, tenantID, ch.Identity, next); err != nil {
			return res, fmt.Errorf("reissue %s: %w", ch.Identity, err)
		}
		res.Reissued = true
	}
	if dir := strings.TrimSpace(s.trustDir); dir != "" {
		if err := s.PublishMTLSPolicy(ctx, dir); err != nil {
			return res, fmt.Errorf("publish the policy: %w", err)
		}
	}
	res.Policy = next
	return res, nil
}

// RotateAllMTLS rotates every identity, one service per step so the
// platform stays available; certs itself goes last.
func (s *Service) RotateAllMTLS(ctx context.Context, tenantID, mode, reason, actor string) ([]map[string]interface{}, time.Duration, error) {
	var services, files []string
	for _, id := range mtlsIdentities() {
		if mtlsKind(id) == mtlsKindService {
			if id != "kms-certs" {
				services = append(services, id)
			}
		} else {
			files = append(files, id)
		}
	}
	services = append(services, "kms-certs")
	start := time.Now().UTC()
	var out []map[string]interface{}
	for i, id := range services {
		at := start.Add(time.Duration(i) * mtlsRotateAllStep)
		r, err := s.ApplyMTLSChange(ctx, tenantID, mtlsChange{Identity: id, Rotate: true, RestartMode: mode, ApplyAfter: at, Reason: reason, Actor: actor})
		if err != nil {
			return out, 0, fmt.Errorf("%s: %w", id, err)
		}
		out = append(out, map[string]interface{}{"identity": id, "generation": r.Policy.Generation, "apply_after": at, "revoked": r.Revoked})
	}
	for _, id := range files {
		r, err := s.ApplyMTLSChange(ctx, tenantID, mtlsChange{Identity: id, Rotate: true, RestartMode: svctls.RestartGraceful, Reason: reason, Actor: actor})
		if err != nil {
			return out, 0, fmt.Errorf("%s: %w", id, err)
		}
		out = append(out, map[string]interface{}{"identity": id, "generation": r.Policy.Generation, "reissued": true, "revoked": r.Revoked})
	}
	return out, time.Duration(len(services)) * mtlsRotateAllStep, nil
}

// fileTarget is where certs writes a file identity's certificate.
type fileTarget struct {
	dir, certType string
	sans          []string
	shareGID      int
}

func (s *Service) fileTarget(identity string) (fileTarget, bool) {
	cfg := s.runtimeCfg
	host, _ := svctls.HostFor(identity)
	switch identity {
	case "vecta-envoy":
		if cfg.MaterializeDir == "" {
			return fileTarget{}, false
		}
		return fileTarget{dir: filepath.Join(cfg.MaterializeDir, "envoy-client"), certType: "tls-client", sans: []string{"envoy", "vecta-envoy"}, shareGID: -1}, true
	case "vecta-dashboard":
		if cfg.DashboardTLSDir == "" {
			return fileTarget{}, false
		}
		return fileTarget{dir: cfg.DashboardTLSDir, certType: "tls-server", sans: []string{"dashboard", "vecta-dashboard"}, shareGID: envInt("CERTS_DASHBOARD_TLS_GID", -1)}, true
	}
	if _, ok := svctls.Infrastructure[identity]; ok && cfg.InfraTLSDir != "" {
		return fileTarget{dir: filepath.Join(cfg.InfraTLSDir, host), certType: infraCertType(host), sans: []string{host, identity}, shareGID: -1}, true
	}
	return fileTarget{}, false
}

// reissueFileIdentity writes a new certificate and key for a file identity
// under policy, revokes the ones it replaces, and records what was written.
func (s *Service) reissueFileIdentity(ctx context.Context, tenantID, identity string, p svctls.ServicePolicy) error {
	t, ok := s.fileTarget(identity)
	if !ok {
		return errors.New("its certificate directory is not configured on this node")
	}
	_, sub, err := s.EnsureInternalPKI(ctx, tenantID)
	if err != nil {
		return err
	}
	days := internalCertValidityDays()
	issued, err := s.writeRuntimeEndpointCert(ctx, tenantID, sub, t.dir, p.KeyAlgorithm, t.certType, identity, t.sans, days, sub.CertPEM)
	if err != nil {
		return err
	}
	if t.shareGID >= 0 {
		if err := shareWithGroup(t.dir, t.shareGID); err != nil {
			return err
		}
	}
	if _, err := s.revokeIdentityCerts(ctx, tenantID, identity, issued.ID, "superseded"); err != nil {
		return err
	}
	return s.recordFileIdentity(ctx, identity, issued, p)
}

func (s *Service) recordFileIdentity(ctx context.Context, identity string, c Certificate, p svctls.ServicePolicy) error {
	st, err := s.mtls()
	if err != nil {
		return err
	}
	return st.UpsertMTLSObserved(ctx, mtlsObservedRow{
		Identity: identity, Instance: mtlsFileInstance, Serial: c.SerialNumber, NotAfter: c.NotAfter,
		KeyAlgorithm: c.Algorithm, Generation: p.Generation, StartedAt: time.Now().UTC(),
	})
}

// AuditAppliedMTLS emits audit.certs.internal_mtls_applied once per
// generation, when every reporting instance of an identity runs it (or,
// for a file identity, certs has written it). Primary only: the audited
// marker is replicated.
func (s *Service) AuditAppliedMTLS(ctx context.Context, emit route.Emitter) error {
	inv, _, err := s.MTLSInventory(ctx, s.internalTenant())
	if err != nil {
		return err
	}
	st, err := s.mtls()
	if err != nil {
		return err
	}
	for _, v := range inv {
		rec := v.PolicyRecord
		if rec == nil || !v.Applied || rec.AuditedGeneration >= rec.Generation {
			continue
		}
		details := map[string]interface{}{
			"identity": v.Identity, "kind": v.Kind, "generation": v.Policy.Generation, "key_algorithm": v.Policy.KeyAlgorithm,
			"kx_profile": v.Policy.KXProfile, "restart_mode": v.Policy.RestartMode, "tenant_scope": "platform",
		}
		var serials []string
		for _, o := range v.Observed {
			serials = append(serials, o.Instance+":"+o.Serial)
		}
		if v.ServedFile != nil {
			serials = append(serials, "file:"+v.ServedFile.Serial)
		}
		details["serials"] = serials
		if emit != nil {
			_ = emit.Emit(ctx, "internal_mtls_applied", pkgaudit.Event{
				TenantID: "root", ActorID: "kms-certs", ActorType: "service", TargetType: "internal_mtls_identity",
				TargetID: v.Identity, Result: "success", Details: details,
			})
		}
		if err := st.MarkMTLSPolicyAudited(ctx, v.Identity, v.Policy.Generation); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) internalTenant() string { return envOr("CERTS_RUNTIME_TENANT_ID", "root") }
