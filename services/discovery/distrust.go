package main

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	pkgaudit "vecta-kms/pkg/audit"
	pkgcrypto "vecta-kms/pkg/crypto"
	"vecta-kms/pkg/route"
)

// Distrusted CAs (13.46.0-beta; docs/API_REFERENCE.md, Discovery, "Certificate chains, distrusted CAs and revocation").
// A TLS scan records the chain an endpoint presented, each certificate by
// the SHA-256 of its SubjectPublicKeyInfo (discovery_cert_chains). A chain
// runs through a distrusted CA when one of those keys is on the list: the
// platform's own (builtinDistrusted) or one a tenant adds. The match is made
// when findings are read, against the list as it is then, so a CA distrusted
// after a scan is found without rescanning. The first time a certificate is
// found under a distrusted CA, audit.discovery.distrusted_ca_found is
// emitted, a playbook trigger.

// builtinDistrusted is the list Go's crypto/x509 refuses in every chain
// (verify.go, distrustedSPKIHashes, go1.27.3): the eight eMudhra emSign G3
// intermediates whose keys were compromised in October 2026. Go reports a
// chain through one only as untrusted; this list says which key it was.
// TestBuiltinDistrustMatchesGoToolchain fails when the toolchain's list
// changes.
var builtinDistrusted = map[string]string{
	"ebed6475c2c2d80fcb199f3fe8dd6e6b3ce60b77eb15d4e42c3dec0c6f5b5105": builtinEMudhraLabel,
	"49dd353dc2b919a3770645117d0e60c16115e7d1bc259eefe734b00ea434fe5f": builtinEMudhraLabel,
	"e0254c7fcdc265e2f0f8a428dabb75ab4ae039b4872d62f5ee57f0877d5a8a41": builtinEMudhraLabel,
	"5c0660a2b164910d8ff589c18e14552e9e0ec237dcefe2cb736d41a4811f81a0": builtinEMudhraLabel,
	"43bffa19d6ef651451f6841e019931e96f6f2eaeff28ab4b6f1ce4576de2717b": builtinEMudhraLabel,
	"63ecefee431d49523bc1136c4e72d0206a477086caf606cd5cf025686c109cf8": builtinEMudhraLabel,
	"ec4ffa1ad0ac88081314b7aaffef6a91f97cd57291bb5ba686c5415f5eb4f6b6": builtinEMudhraLabel,
	"92c063d67e8f14db71d288e11266ffdaf69cbf115f7bab14f3bc2f68d25e0e30": builtinEMudhraLabel,
}

const builtinEMudhraLabel = "eMudhra emSign G3 intermediate (key compromised, October 2026)"

var spkiHashPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

var errInvalidDistrust = errors.New("invalid distrusted CA")

// ChainCert is one certificate of a presented chain; position 0 is the leaf.
type ChainCert struct {
	Position   int    `json:"position"`
	Subject    string `json:"subject"`
	Issuer     string `json:"issuer"`
	SPKISHA256 string `json:"spki_sha256"`
	NotAfter   string `json:"not_after,omitempty"`
}

// DistrustedCA is one entry of a tenant's effective list. Affected counts
// the discovered certificates whose recorded chain contains the key.
type DistrustedCA struct {
	SPKISHA256 string     `json:"spki_sha256"`
	Label      string     `json:"label"`
	Source     string     `json:"source"` // "platform" or "tenant"
	AddedBy    string     `json:"added_by,omitempty"`
	CreatedAt  *time.Time `json:"created_at,omitempty"`
	Affected   int64      `json:"affected"`
}

// DistrustFinding is a discovered certificate under a distrusted CA.
type DistrustFinding struct {
	Asset   CryptoAsset    `json:"asset"`
	Matches []DistrustedCA `json:"matches"`
}

func spkiSHA256(c *x509.Certificate) string {
	return hex.EncodeToString(pkgcrypto.SHA256(c.RawSubjectPublicKeyInfo))
}

func chainOf(certs []*x509.Certificate) []ChainCert {
	out := make([]ChainCert, 0, len(certs))
	for i, c := range certs {
		out = append(out, ChainCert{Position: i, Subject: c.Subject.String(), Issuer: c.Issuer.String(),
			SPKISHA256: spkiSHA256(c), NotAfter: c.NotAfter.UTC().Format(time.RFC3339)})
	}
	return out
}

// distrustList is the tenant's effective list: the platform's and its own.
func (s *Service) distrustList(ctx context.Context, tenantID string) (map[string]DistrustedCA, error) {
	out := make(map[string]DistrustedCA, len(builtinDistrusted))
	for h, label := range builtinDistrusted {
		out[h] = DistrustedCA{SPKISHA256: h, Label: label, Source: "platform"}
	}
	own, err := s.store.ListDistrustedCAs(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	for _, d := range own {
		if _, platform := out[d.SPKISHA256]; !platform {
			out[d.SPKISHA256] = d
		}
	}
	return out, nil
}

func hashesOf(list map[string]DistrustedCA) []string {
	out := make([]string, 0, len(list))
	for h := range list {
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}

// ListDistrustedCAs is the effective list, each with how many discovered
// certificates it affects, counted over the whole inventory.
func (s *Service) ListDistrustedCAs(ctx context.Context, tenantID string) ([]DistrustedCA, error) {
	list, err := s.distrustList(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	counts, err := s.store.CountAssetsByChainSPKI(ctx, tenantID, hashesOf(list))
	if err != nil {
		return nil, err
	}
	out := make([]DistrustedCA, 0, len(list))
	for h, d := range list {
		d.Affected = counts[h]
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Affected != out[j].Affected {
			return out[i].Affected > out[j].Affected
		}
		return out[i].SPKISHA256 < out[j].SPKISHA256
	})
	return out, nil
}

// DistrustInput adds a CA: by the SHA-256 of its SPKI, or by its
// certificate (PEM), from which the hash is taken.
type DistrustInput struct {
	Label          string `json:"label"`
	SPKISHA256     string `json:"spki_sha256"`
	CertificatePEM string `json:"certificate_pem"`
}

// AddDistrustedCA distrusts a CA for the tenant and returns it, with the
// discovered certificates it already affects, each of which is announced.
func (s *Service) AddDistrustedCA(ctx context.Context, tenantID string, in DistrustInput, userID string) (DistrustedCA, error) {
	label := strings.TrimSpace(in.Label)
	hash := strings.ToLower(strings.TrimSpace(in.SPKISHA256))
	if pemText := strings.TrimSpace(in.CertificatePEM); pemText != "" {
		block, _ := pem.Decode([]byte(pemText))
		if block == nil || block.Type != "CERTIFICATE" {
			return DistrustedCA{}, fmt.Errorf("%w: certificate_pem is not a PEM certificate", errInvalidDistrust)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return DistrustedCA{}, fmt.Errorf("%w: certificate_pem: %v", errInvalidDistrust, err)
		}
		if h := spkiSHA256(cert); hash != "" && hash != h {
			return DistrustedCA{}, fmt.Errorf("%w: spki_sha256 is not the certificate's key", errInvalidDistrust)
		} else {
			hash = h
		}
		if label == "" {
			label = cert.Subject.String()
		}
	}
	switch {
	case !spkiHashPattern.MatchString(hash):
		return DistrustedCA{}, fmt.Errorf("%w: give certificate_pem, or spki_sha256 as 64 hex digits", errInvalidDistrust)
	case label == "" || len(label) > 200:
		return DistrustedCA{}, fmt.Errorf("%w: label is required (at most 200 characters)", errInvalidDistrust)
	case builtinDistrusted[hash] != "":
		return DistrustedCA{}, fmt.Errorf("%w: the platform already distrusts this key", errInvalidDistrust)
	}
	now := s.now().UTC()
	d := DistrustedCA{SPKISHA256: hash, Label: label, Source: "tenant", AddedBy: userID, CreatedAt: &now}
	if err := s.store.PutDistrustedCA(ctx, tenantID, d); err != nil {
		return DistrustedCA{}, err
	}
	ids, total, err := s.store.AssetsWithChainSPKI(ctx, tenantID, []string{hash}, 0, 0)
	if err != nil {
		return DistrustedCA{}, err
	}
	d.Affected = int64(total)
	for _, id := range ids {
		if a, err := s.store.GetAsset(ctx, tenantID, id); err == nil {
			s.distrustedFound(ctx, a, d)
		}
	}
	return d, nil
}

// RemoveDistrustedCA removes a tenant's own entry; the platform's stay.
func (s *Service) RemoveDistrustedCA(ctx context.Context, tenantID, hash string) error {
	hash = strings.ToLower(strings.TrimSpace(hash))
	if builtinDistrusted[hash] != "" {
		return fmt.Errorf("%w: the platform's list can't be changed per tenant", errInvalidDistrust)
	}
	return s.store.DeleteDistrustedCA(ctx, tenantID, hash)
}

// DistrustFindings lists the discovered certificates under a distrusted CA
// (one CA when spki is given), with the total, counted over the whole
// inventory, and how many certificates were found before chains were
// recorded (their chain is unknown until they are scanned again).
func (s *Service) DistrustFindings(ctx context.Context, tenantID, spki string, limit, offset int) (total, unrecorded int, items []DistrustFinding, err error) {
	list, err := s.distrustList(ctx, tenantID)
	if err != nil {
		return 0, 0, nil, err
	}
	hashes := hashesOf(list)
	if spki = strings.ToLower(strings.TrimSpace(spki)); spki != "" {
		if _, ok := list[spki]; !ok {
			return 0, 0, nil, fmt.Errorf("%w: %s is not on the list", errInvalidDistrust, spki)
		}
		hashes = []string{spki}
	}
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	ids, total, err := s.store.AssetsWithChainSPKI(ctx, tenantID, hashes, limit, offset)
	if err != nil {
		return 0, 0, nil, err
	}
	matches, err := s.store.ChainSPKIsOf(ctx, tenantID, ids)
	if err != nil {
		return 0, 0, nil, err
	}
	items = []DistrustFinding{}
	for _, id := range ids {
		a, err := s.store.GetAsset(ctx, tenantID, id)
		if err != nil {
			continue
		}
		f := DistrustFinding{Asset: withReview(a), Matches: []DistrustedCA{}}
		for _, h := range matches[id] {
			if d, ok := list[h]; ok {
				f.Matches = append(f.Matches, d)
			}
		}
		items = append(items, f)
	}
	if unrecorded, err = s.store.CountCertificatesWithoutChain(ctx, tenantID); err != nil {
		return 0, 0, nil, err
	}
	return total, unrecorded, items, nil
}

// recordChain stores a scanned certificate's chain and announces each
// distrusted CA it is found under for the first time, and a revocation the
// first time it is seen.
func (s *Service) recordChain(ctx context.Context, a CryptoAsset, previous *CryptoAsset) {
	chain, ok := a.Metadata["chain"].([]ChainCert)
	if !ok || a.AssetType != "tls_certificate" {
		return
	}
	before, err := s.store.ChainSPKIsOf(ctx, a.TenantID, []string{a.ID})
	if err != nil {
		logger.Printf("chain of %s: %v", a.ID, err)
		return
	}
	if err := s.store.PutCertChain(ctx, a.TenantID, a.ID, chain); err != nil {
		logger.Printf("chain of %s: %v", a.ID, err)
		return
	}
	list, err := s.distrustList(ctx, a.TenantID)
	if err != nil {
		logger.Printf("distrust list: %v", err)
		return
	}
	seen := map[string]bool{}
	for _, h := range before[a.ID] {
		seen[h] = true
	}
	for _, c := range chain {
		if d, bad := list[c.SPKISHA256]; bad && !seen[c.SPKISHA256] {
			seen[c.SPKISHA256] = true
			s.distrustedFound(ctx, a, d)
		}
	}
	if rev, _ := a.Metadata["revocation"].(map[string]interface{}); rev["status"] == "revoked" {
		was := ""
		if previous != nil {
			if prev, _ := previous.Metadata["revocation"].(map[string]interface{}); prev != nil {
				was, _ = prev["status"].(string)
			}
		}
		if was != "revoked" {
			s.emitDiscovery(ctx, "revoked_certificate_found", a, 85, map[string]interface{}{
				"location": a.Location, "subject": a.Metadata["subject"], "issuer": a.Metadata["issuer"],
				"revoked_at": rev["revoked_at"], "reason": rev["reason"], "responder": rev["responder"],
			})
		}
	}
}

func (s *Service) distrustedFound(ctx context.Context, a CryptoAsset, d DistrustedCA) {
	s.emitDiscovery(ctx, "distrusted_ca_found", a, 90, map[string]interface{}{
		"location": a.Location, "subject": a.Metadata["subject"], "issuer": a.Metadata["issuer"],
		"distrusted_spki_sha256": d.SPKISHA256, "distrusted_label": d.Label, "distrusted_source": d.Source,
	})
}

func (s *Service) emitDiscovery(ctx context.Context, action string, a CryptoAsset, risk int, details map[string]interface{}) {
	if s.audit == nil {
		return
	}
	details["scan_id"] = a.ScanID
	_ = s.audit.Emit(ctx, action, pkgaudit.Event{
		TenantID: a.TenantID, ActorID: "kms-discovery", ActorType: "service", Result: "success",
		TargetType: "crypto_asset", TargetID: a.ID, RiskScore: risk, Details: details,
	})
}

// ── store ────────────────────────────────────────────────────────────

func (s *SQLStore) PutCertChain(ctx context.Context, tenantID, assetID string, chain []ChainCert) error {
	tx, err := s.db.SQL().BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	if _, err := tx.ExecContext(ctx, `DELETE FROM discovery_cert_chains WHERE tenant_id=$1 AND asset_id=$2`, tenantID, assetID); err != nil {
		return err
	}
	for _, c := range chain {
		if _, err := tx.ExecContext(ctx, `INSERT INTO discovery_cert_chains (tenant_id, asset_id, position, spki_sha256, subject, issuer) VALUES ($1,$2,$3,$4,$5,$6)`,
			tenantID, assetID, c.Position, c.SPKISHA256, c.Subject, c.Issuer); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// inList is "$n,$n+1,..." for values appended to args.
func inList(args *[]interface{}, values []string) string {
	marks := make([]string, len(values))
	for i, v := range values {
		*args = append(*args, v)
		marks[i] = "$" + strconv.Itoa(len(*args))
	}
	return strings.Join(marks, ",")
}

// ChainSPKIsOf returns each asset's recorded chain keys.
func (s *SQLStore) ChainSPKIsOf(ctx context.Context, tenantID string, assetIDs []string) (map[string][]string, error) {
	out := map[string][]string{}
	if len(assetIDs) == 0 {
		return out, nil
	}
	args := []interface{}{tenantID}
	rows, err := s.db.SQL().QueryContext(ctx, `SELECT asset_id, spki_sha256 FROM discovery_cert_chains WHERE tenant_id=$1 AND asset_id IN (`+inList(&args, assetIDs)+`) ORDER BY asset_id, position`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	for rows.Next() {
		var id, h string
		if err := rows.Scan(&id, &h); err != nil {
			return nil, err
		}
		out[id] = append(out[id], h)
	}
	return out, rows.Err()
}

// CountAssetsByChainSPKI counts, per key, the certificates whose recorded
// chain contains it.
func (s *SQLStore) CountAssetsByChainSPKI(ctx context.Context, tenantID string, hashes []string) (map[string]int64, error) {
	out := map[string]int64{}
	if len(hashes) == 0 {
		return out, nil
	}
	args := []interface{}{tenantID}
	rows, err := s.db.SQL().QueryContext(ctx, `SELECT spki_sha256, COUNT(DISTINCT asset_id) FROM discovery_cert_chains WHERE tenant_id=$1 AND spki_sha256 IN (`+inList(&args, hashes)+`) GROUP BY spki_sha256`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	for rows.Next() {
		var h string
		var n int64
		if err := rows.Scan(&h, &n); err != nil {
			return nil, err
		}
		out[h] = n
	}
	return out, rows.Err()
}

// AssetsWithChainSPKI pages the certificates whose chain contains any of
// hashes, and counts them all; limit 0 returns every one.
func (s *SQLStore) AssetsWithChainSPKI(ctx context.Context, tenantID string, hashes []string, limit, offset int) ([]string, int, error) {
	if len(hashes) == 0 {
		return nil, 0, nil
	}
	args := []interface{}{tenantID}
	where := `FROM discovery_cert_chains WHERE tenant_id=$1 AND spki_sha256 IN (` + inList(&args, hashes) + `)`
	var total int
	if err := s.db.SQL().QueryRowContext(ctx, `SELECT COUNT(DISTINCT asset_id) `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	page := ""
	if limit > 0 {
		page = fmt.Sprintf(" LIMIT %d OFFSET %d", limit, offset)
	}
	rows, err := s.db.SQL().QueryContext(ctx, `SELECT DISTINCT asset_id `+where+` ORDER BY asset_id`+page, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close() //nolint:errcheck
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, 0, err
		}
		ids = append(ids, id)
	}
	return ids, total, rows.Err()
}

// CountCertificatesWithoutChain counts TLS certificates found before chains
// were recorded.
func (s *SQLStore) CountCertificatesWithoutChain(ctx context.Context, tenantID string) (int, error) {
	var n int
	err := s.db.SQL().QueryRowContext(ctx, `SELECT COUNT(*) FROM discovery_assets a WHERE a.tenant_id=$1 AND a.asset_type='tls_certificate'
AND NOT EXISTS (SELECT 1 FROM discovery_cert_chains c WHERE c.tenant_id=a.tenant_id AND c.asset_id=a.id)`, tenantID).Scan(&n)
	return n, err
}

func (s *SQLStore) ListDistrustedCAs(ctx context.Context, tenantID string) ([]DistrustedCA, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `SELECT spki_sha256, label, added_by, created_at FROM discovery_distrusted_cas WHERE tenant_id=$1 ORDER BY created_at, spki_sha256`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := []DistrustedCA{}
	for rows.Next() {
		d := DistrustedCA{Source: "tenant"}
		var created interface{}
		if err := rows.Scan(&d.SPKISHA256, &d.Label, &d.AddedBy, &created); err != nil {
			return nil, err
		}
		if t := parseTimeValue(created); !t.IsZero() {
			d.CreatedAt = &t
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func (s *SQLStore) PutDistrustedCA(ctx context.Context, tenantID string, d DistrustedCA) error {
	_, err := s.db.SQL().ExecContext(ctx, `INSERT INTO discovery_distrusted_cas (tenant_id, spki_sha256, label, added_by, created_at) VALUES ($1,$2,$3,$4,$5)
ON CONFLICT (tenant_id, spki_sha256) DO UPDATE SET label=excluded.label`, tenantID, d.SPKISHA256, d.Label, d.AddedBy, d.CreatedAt.UTC())
	return err
}

func (s *SQLStore) DeleteDistrustedCA(ctx context.Context, tenantID, hash string) error {
	res, err := s.db.SQL().ExecContext(ctx, `DELETE FROM discovery_distrusted_cas WHERE tenant_id=$1 AND spki_sha256=$2`, tenantID, hash)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errNotFound
	}
	return nil
}

// ── routes ───────────────────────────────────────────────────────────

func (h *Handler) distrustRoutes(r *route.Router) {
	r.Handle("GET /discovery/distrusted-cas", route.Spec{Action: "distrusted_cas_list", Permission: "discovery.read", Resource: "distrusted_ca"}, h.listDistrustedCAs)
	r.Handle("POST /discovery/distrusted-cas", route.Spec{Action: "distrusted_ca_add", Permission: "discovery.write", Resource: "distrusted_ca", Severity: "warning"}, h.addDistrustedCA)
	r.Handle("DELETE /discovery/distrusted-cas/{spki}", route.Spec{Action: "distrusted_ca_remove", Permission: "discovery.write", Resource: "distrusted_ca", TargetParam: "spki", Severity: "warning"}, h.removeDistrustedCA)
	r.Handle("GET /discovery/distrusted", route.Spec{Action: "distrusted_findings_list", Permission: "discovery.read", Resource: "crypto_asset"}, h.distrustFindings)
}

func (h *Handler) listDistrustedCAs(c *route.Call) {
	items, err := h.svc.ListDistrustedCAs(c.R.Context(), c.Tenant)
	if err != nil {
		c.Error(http.StatusInternalServerError, "distrust_unavailable", "the distrusted CA list could not be read")
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"items": items})
}

func (h *Handler) addDistrustedCA(c *route.Call) {
	var in DistrustInput
	if !c.Decode(&in) {
		return
	}
	d, err := h.svc.AddDistrustedCA(c.R.Context(), c.Tenant, in, c.Actor())
	if errors.Is(err, errInvalidDistrust) {
		c.Refuse(http.StatusBadRequest, "invalid_distrusted_ca", err.Error())
		return
	}
	if err != nil {
		c.Error(http.StatusInternalServerError, "distrust_save_failed", "the distrusted CA could not be saved")
		return
	}
	c.Target(d.SPKISHA256)
	c.Detail("label", d.Label)
	c.Detail("affected", d.Affected)
	c.JSON(http.StatusCreated, map[string]interface{}{"distrusted_ca": d})
}

func (h *Handler) removeDistrustedCA(c *route.Call) {
	err := h.svc.RemoveDistrustedCA(c.R.Context(), c.Tenant, c.R.PathValue("spki"))
	switch {
	case errors.Is(err, errInvalidDistrust):
		c.Refuse(http.StatusBadRequest, "invalid_distrusted_ca", err.Error())
	case errors.Is(err, errNotFound):
		c.Error(http.StatusNotFound, "not_found", "the tenant does not distrust this key")
	case err != nil:
		c.Error(http.StatusInternalServerError, "distrust_delete_failed", "the distrusted CA could not be removed")
	default:
		c.JSON(http.StatusOK, map[string]interface{}{"status": "removed"})
	}
}

func (h *Handler) distrustFindings(c *route.Call) {
	q := c.R.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	offset, _ := strconv.Atoi(q.Get("offset"))
	total, unrecorded, items, err := h.svc.DistrustFindings(c.R.Context(), c.Tenant, q.Get("spki"), limit, max(offset, 0))
	if errors.Is(err, errInvalidDistrust) {
		c.Refuse(http.StatusBadRequest, "invalid_distrusted_ca", err.Error())
		return
	}
	if err != nil {
		c.Error(http.StatusInternalServerError, "findings_unavailable", "distrusted CA findings could not be read")
		return
	}
	c.Detail("total", total)
	c.JSON(http.StatusOK, map[string]interface{}{"total": total, "chain_unrecorded": unrecorded, "items": items})
}
