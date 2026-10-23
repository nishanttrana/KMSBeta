package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	neturl "net/url"
	"strings"
	"time"

	"github.com/digitorus/pkcs7"
	"github.com/digitorus/timestamp"

	"vecta-kms/pkg/credstore"
	pkgcrypto "vecta-kms/pkg/crypto"
	"vecta-kms/pkg/route"
	"vecta-kms/pkg/ssrfguard"
	"vecta-kms/pkg/tenantcheck"
)

// Timestamped checkpoints (13.47.0-beta; docs/SECURITY/AUDIT_INTEGRITY.md,
// "Timestamped checkpoints"). A checkpoint is signed by the audit service's
// own key, so whoever controls the platform could rewrite history and sign
// it again. With anchoring on, each new checkpoint's signature is sent to an
// RFC 3161 time-stamp authority (a "tsa" credential, Playbooks →
// Credentials, root tenant). The token it signs proves the checkpoint, and
// with it every earlier event of the chain, existed at that time: a history
// rewritten later can only get a later time. The token is the audit event
// audit.audit.checkpoint_timestamped in the same chain; a failure is
// audit.audit.checkpoint_timestamp_failed, a playbook trigger.

const (
	actionCheckpointTimestamped = "audit.audit.checkpoint_timestamped"
	actionTimestampFailed       = "audit.audit.checkpoint_timestamp_failed"
	anchorTenant                = "root"
	anchorPermission            = "auth.tenant.write"
	// anchorLateAfter: a token issued this long after its checkpoint was
	// signed doesn't prove when the checkpoint existed.
	anchorLateAfter = time.Hour
	tsaTimeout      = 20 * time.Second
	maxTSAResponse  = 1 << 20
)

// Anchor statuses a checkpoint reports.
const (
	anchorVerified = "anchored"
	anchorLate     = "late"
	anchorInvalid  = "invalid"
	anchorMissing  = "not_anchored"
)

// AnchorSettings is the platform's anchoring choice.
type AnchorSettings struct {
	Enabled      bool       `json:"enabled"`
	ConnectionID string     `json:"connection_id"`
	UpdatedBy    string     `json:"updated_by,omitempty"`
	UpdatedAt    *time.Time `json:"updated_at,omitempty"`
}

// AnchorStatus is a checkpoint's timestamp as verified now.
type AnchorStatus struct {
	Status   string `json:"status"`
	GenTime  string `json:"gen_time,omitempty"`
	TSA      string `json:"tsa,omitempty"`
	Serial   string `json:"serial,omitempty"`
	Trust    string `json:"trust,omitempty"` // "system roots" or the administrator's root fingerprint
	TokenB64 string `json:"token_b64,omitempty"`
	Error    string `json:"error,omitempty"`
}

// tsaConfig is an opened tsa credential.
type tsaConfig struct {
	url, host, username, password string
	trustPEM                      string
}

func tsaConfigFrom(cred credstore.Credential) (tsaConfig, error) {
	if cred.Type != "tsa" {
		return tsaConfig{}, credstore.ErrWrongType
	}
	u, err := neturl.Parse(strings.TrimSpace(cred.Fields["url"]))
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return tsaConfig{}, errors.New("the time-stamp authority's url must be https")
	}
	return tsaConfig{url: u.String(), host: u.Hostname(), username: cred.Fields["username"], password: cred.Fields["password"], trustPEM: strings.TrimSpace(cred.Fields["trust_pem"])}, nil
}

// trustRoots are the roots a token's signer must chain to: the
// administrator's (trust_pem) or the system's. label says which.
func trustRoots(trustPEM string) (*x509.CertPool, string, error) {
	if trustPEM == "" {
		pool, err := x509.SystemCertPool()
		if err != nil {
			return nil, "", fmt.Errorf("system roots: %w", err)
		}
		return pool, "system roots", nil
	}
	pool := x509.NewCertPool()
	var fps []string
	rest := []byte(trustPEM)
	for {
		var block *pem.Block
		if block, rest = pem.Decode(rest); block == nil {
			break
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, "", fmt.Errorf("trust_pem: %w", err)
		}
		pool.AddCert(cert)
		fps = append(fps, hex.EncodeToString(pkgcrypto.SHA256(cert.Raw))[:16])
	}
	if len(fps) == 0 {
		return nil, "", errors.New("trust_pem holds no certificate")
	}
	return pool, "root " + strings.Join(fps, ", "), nil
}

// verifyToken checks a token signed by a time-stamp authority over digest:
// it names SHA-256 and exactly that digest, carries its signer's
// certificate, is signed with a SHA-2 digest, and the signer chains to
// roots with the timestamping key usage at the time it states.
func verifyToken(token, digest []byte, roots *x509.CertPool) (*timestamp.Timestamp, error) {
	ts, err := timestamp.Parse(token)
	if err != nil {
		return nil, fmt.Errorf("token: %w", err)
	}
	if !ts.AddTSACertificate {
		return nil, errors.New("the token carries no signer certificate, so its signature can't be checked")
	}
	if ts.HashAlgorithm != crypto.SHA256 || !bytes.Equal(ts.HashedMessage, digest) {
		return nil, errors.New("the token is for other data")
	}
	p7, err := pkcs7.Parse(token)
	if err != nil {
		return nil, fmt.Errorf("token: %w", err)
	}
	for _, signer := range p7.Signers {
		alg := signer.DigestAlgorithm.Algorithm
		if !alg.Equal(pkcs7.OIDDigestAlgorithmSHA256) && !alg.Equal(pkcs7.OIDDigestAlgorithmSHA384) && !alg.Equal(pkcs7.OIDDigestAlgorithmSHA512) {
			return nil, fmt.Errorf("the token is signed with digest %v; only SHA-256, SHA-384 and SHA-512 are accepted", alg)
		}
	}
	inter := x509.NewCertPool()
	for _, c := range p7.Certificates {
		inter.AddCert(c)
	}
	if err := p7.VerifyWithOpts(x509.VerifyOptions{Roots: roots, Intermediates: inter, CurrentTime: ts.Time,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping}}); err != nil {
		return nil, fmt.Errorf("the token's signer: %w", err)
	}
	return ts, nil
}

// requestTimestamp asks the authority for a token over digest, with a
// fresh nonce the answer must carry, and verifies it.
func requestTimestamp(ctx context.Context, client *http.Client, cfg tsaConfig, digest []byte, roots *x509.CertPool) ([]byte, *timestamp.Timestamp, error) {
	raw, err := pkgcrypto.RandomBytes(16)
	if err != nil {
		return nil, nil, err
	}
	nonce := new(big.Int).SetBytes(raw)
	body, err := (&timestamp.Request{HashAlgorithm: crypto.SHA256, HashedMessage: digest, Certificates: true, Nonce: nonce}).Marshal()
	if err != nil {
		return nil, nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.url, bytes.NewReader(body))
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Content-Type", "application/timestamp-query")
	if cfg.username != "" {
		req.SetBasicAuth(cfg.username, cfg.password)
	}
	resp, err := client.Do(req)
	if err != nil {
		// The reason without the URL, which the credential may consider private.
		var ue *neturl.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return nil, nil, fmt.Errorf("%s unreachable: %w", cfg.host, err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("%s answered HTTP %d", cfg.host, resp.StatusCode)
	}
	answer, err := io.ReadAll(io.LimitReader(resp.Body, maxTSAResponse))
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", cfg.host, err)
	}
	ts, err := timestamp.ParseResponse(answer)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", cfg.host, err)
	}
	if ts.Nonce == nil || ts.Nonce.Cmp(nonce) != 0 {
		return nil, nil, fmt.Errorf("%s answered without this request's nonce", cfg.host)
	}
	if _, err := verifyToken(ts.RawToken, digest, roots); err != nil {
		return nil, nil, fmt.Errorf("%s: %w", cfg.host, err)
	}
	return ts.RawToken, ts, nil
}

func (s *Service) tsaClient() *http.Client {
	if s.tsaHTTP != nil {
		return s.tsaHTTP
	}
	return ssrfguard.NewHTTPSClient(tsaTimeout)
}

// openTSA resolves the anchoring credential.
func (s *Service) openTSA(ctx context.Context, connID string) (tsaConfig, error) {
	if s.tsaCreds == nil {
		return tsaConfig{}, credstore.ErrNotDeployed
	}
	cred, err := s.tsaCreds.Resolve(ctx, anchorTenant, connID)
	if err != nil {
		return tsaConfig{}, err
	}
	return tsaConfigFrom(cred)
}

// anchorCheckpoint timestamps one checkpoint and records the outcome in
// its chain.
func (s *Service) anchorCheckpoint(ctx context.Context, cp AuditEvent, signature []byte, settings AnchorSettings) {
	digest := pkgcrypto.SHA256(signature)
	fail := func(reason string, err error) {
		s.reportOnStream(ctx, AuditEvent{
			TenantID: cp.TenantID, Service: "audit", Action: actionTimestampFailed, ActorID: "system", ActorType: "service",
			TargetType: "audit_checkpoint", TargetID: cp.ID, Result: "failure", ErrorMessage: err.Error(),
			Details: map[string]interface{}{"reason": reason, "connection_id": settings.ConnectionID, "severity": "high"},
		})
	}
	cfg, err := s.openTSA(ctx, settings.ConnectionID)
	if err != nil {
		fail("credential_unavailable", err)
		return
	}
	roots, trust, err := trustRoots(cfg.trustPEM)
	if err != nil {
		fail("trust_roots", err)
		return
	}
	token, ts, err := requestTimestamp(ctx, s.tsaClient(), cfg, digest, roots)
	if err != nil {
		fail("timestamp_refused", err)
		return
	}
	details := map[string]interface{}{
		"checkpoint_event_id": cp.ID, "chain_node": cp.Details["chain_node"], "sequence": cp.Details["sequence"],
		"imprint_sha256": hex.EncodeToString(digest), "gen_time": ts.Time.UTC().Format(time.RFC3339Nano),
		"tsa": cfg.host, "tsa_serial": ts.SerialNumber.String(), "trust": trust,
		"token_b64": base64.StdEncoding.EncodeToString(token),
	}
	if cfg.trustPEM != "" {
		details["trust_pem"] = cfg.trustPEM // public certificates, kept to verify the token later
	}
	_, _ = s.ProcessEvent(ctx, AuditEvent{
		TenantID: cp.TenantID, Service: "audit", Action: actionCheckpointTimestamped, ActorID: "system", ActorType: "service",
		TargetType: "audit_checkpoint", TargetID: cp.ID, Result: "success", Details: details,
	})
}

// anchorStatus verifies the stored token of a checkpoint whose signature is
// sig and which was signed at signedAt.
func anchorStatus(ev *AuditEvent, sig []byte, signedAt string) AnchorStatus {
	if ev == nil {
		return AnchorStatus{Status: anchorMissing}
	}
	d := ev.Details
	st := AnchorStatus{TSA: str(d["tsa"]), Serial: str(d["tsa_serial"]), Trust: str(d["trust"]), TokenB64: str(d["token_b64"])}
	invalid := func(err error) AnchorStatus { st.Status, st.Error = anchorInvalid, err.Error(); return st }
	token, err := base64.StdEncoding.DecodeString(st.TokenB64)
	if err != nil || len(token) == 0 {
		return invalid(errors.New("the stored token is unreadable"))
	}
	roots, _, err := trustRoots(str(d["trust_pem"]))
	if err != nil {
		return invalid(err)
	}
	ts, err := verifyToken(token, pkgcrypto.SHA256(sig), roots)
	if err != nil {
		return invalid(err)
	}
	st.GenTime = ts.Time.UTC().Format(time.RFC3339)
	st.Status = anchorVerified
	if signed, err := time.Parse(time.RFC3339Nano, signedAt); err != nil || ts.Time.Sub(signed) > anchorLateAfter || ts.Time.Before(signed.Add(-5*time.Minute)) {
		st.Status = anchorLate
		st.Error = "the authority's time is not within an hour of when the checkpoint was signed"
	}
	return st
}

// ---- store ----

func (s *SQLStore) AnchorSettings(ctx context.Context) (AnchorSettings, error) {
	var a AnchorSettings
	var updated interface{}
	err := s.db.SQL().QueryRowContext(ctx, `SELECT enabled, connection_id, updated_by, updated_at FROM audit_anchor_settings WHERE id=1`).Scan(&a.Enabled, &a.ConnectionID, &a.UpdatedBy, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return AnchorSettings{}, nil
	}
	if t := parseTimeValue(updated); !t.IsZero() {
		a.UpdatedAt = &t
	}
	return a, err
}

func (s *SQLStore) PutAnchorSettings(ctx context.Context, a AnchorSettings) error {
	_, err := s.db.SQL().ExecContext(ctx, `INSERT INTO audit_anchor_settings (id, enabled, connection_id, updated_by, updated_at) VALUES (1,$1,$2,$3,$4)
ON CONFLICT (id) DO UPDATE SET enabled=excluded.enabled, connection_id=excluded.connection_id, updated_by=excluded.updated_by, updated_at=excluded.updated_at`,
		a.Enabled, a.ConnectionID, a.UpdatedBy, time.Now().UTC())
	return err
}

// anchorEvents returns each checkpoint's newest timestamp event.
func (s *SQLStore) anchorEvents(ctx context.Context, tenantID string, checkpointIDs []string) (map[string]AuditEvent, error) {
	out := map[string]AuditEvent{}
	for _, id := range checkpointIDs {
		items, err := s.QueryEvents(ctx, tenantID, EventQuery{Action: actionCheckpointTimestamped, TargetID: id, Limit: 1})
		if err != nil {
			return nil, err
		}
		if len(items) > 0 {
			out[id] = items[0]
		}
	}
	return out, nil
}

// ---- routes ----

func (h *Handler) anchorRouter(audit route.Emitter) *route.Router {
	r := route.New("audit", audit, nil)
	r.Handle("GET /audit/anchor", route.Spec{Action: "anchor_settings_read", Permission: "audit.events.read", Resource: "audit_anchor", Tenancy: route.PlatformScoped}, h.getAnchor)
	r.Handle("PUT /audit/anchor", route.Spec{Action: "anchor_settings_updated", Permission: anchorPermission, Resource: "audit_anchor", Tenancy: route.PlatformScoped, Severity: "warning"}, h.putAnchor)
	return r
}

func (h *Handler) getAnchor(c *route.Call) {
	a, err := h.store.AnchorSettings(c.R.Context())
	if err != nil {
		c.Error(http.StatusInternalServerError, "anchor_unavailable", "anchoring settings could not be read")
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"anchor": a})
}

// putAnchor turns anchoring on or off for the platform. Turning it on takes
// a real timestamp from the authority first; a credential that doesn't
// produce a valid token is refused.
func (h *Handler) putAnchor(c *route.Call) {
	if c.Claims == nil || tenantcheck.IsServicePrincipal(c.Claims) || !strings.EqualFold(strings.TrimSpace(c.Claims.TenantID), anchorTenant) {
		c.Refuse(http.StatusForbidden, "not_root_tenant", "anchoring is set by the root tenant's administrators")
		return
	}
	var in struct {
		Enabled      bool   `json:"enabled"`
		ConnectionID string `json:"connection_id"`
	}
	if !c.Decode(&in) {
		return
	}
	in.ConnectionID = strings.TrimSpace(in.ConnectionID)
	c.Detail("enabled", in.Enabled)
	c.Detail("connection_id", in.ConnectionID)
	if in.Enabled {
		if in.ConnectionID == "" {
			c.Refuse(http.StatusBadRequest, "connection_required", "choose a time-stamp authority credential")
			return
		}
		if !route.Allowed(c.Claims, credstore.PermissionUse) {
			c.Refuse(http.StatusForbidden, "permission_denied", "attaching a credential needs "+credstore.PermissionUse)
			return
		}
		cfg, err := h.svc.openTSA(c.R.Context(), in.ConnectionID)
		if err != nil {
			c.Refuse(http.StatusBadRequest, "credential_unusable", err.Error())
			return
		}
		roots, _, err := trustRoots(cfg.trustPEM)
		if err == nil {
			_, _, err = requestTimestamp(c.R.Context(), h.svc.tsaClient(), cfg, pkgcrypto.SHA256([]byte("vecta-kms anchoring test")), roots)
		}
		if h.svc.tsaCreds != nil {
			_ = h.svc.tsaCreds.ReportTest(c.R.Context(), anchorTenant, in.ConnectionID, err)
		}
		if err != nil {
			c.Refuse(http.StatusBadRequest, "timestamp_test_failed", err.Error())
			return
		}
		c.Detail("tested", true)
	}
	a := AnchorSettings{Enabled: in.Enabled, ConnectionID: in.ConnectionID, UpdatedBy: c.Actor()}
	if err := h.store.PutAnchorSettings(c.R.Context(), a); err != nil {
		c.Error(http.StatusInternalServerError, "anchor_save_failed", "anchoring settings could not be saved")
		return
	}
	saved, _ := h.store.AnchorSettings(c.R.Context())
	c.JSON(http.StatusOK, map[string]interface{}{"anchor": saved})
}
