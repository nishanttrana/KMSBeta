package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	pkgauth "vecta-kms/pkg/auth"
	"vecta-kms/pkg/clusterroute"
	"vecta-kms/pkg/clusterstate"
	pkgconfig "vecta-kms/pkg/config"
	"vecta-kms/pkg/servicetoken"
)

// Write forwarding, primary side (docs/CLUSTERING.md, slice 3).
//
// A member's services send lifecycle writes to /cluster/forward/{service}/...
// on this primary's cluster-manager (pinned TLS). This handler authenticates
// the member by its per-member credential (issued at join, stored hashed),
// allows only requests pkg/clusterroute says must be forwarded, has this
// node's auth mint a short-lived token for the identity the member verified,
// and proxies the request to the local service. Every forward and refusal is
// audited.

var errForwardCredential = errors.New("unknown member or invalid forwarding credential")

func credentialHash(cred string) string {
	sum := sha256.Sum256([]byte(cred))
	return hex.EncodeToString(sum[:])
}

// ---- store ----

func (s *SQLStore) SetMemberCredential(ctx context.Context, nodeID, hash string) error {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO cluster_member_credentials (node_id, credential_hash, created_at, revoked_at)
VALUES ($1,$2,CURRENT_TIMESTAMP,NULL)
ON CONFLICT (node_id) DO UPDATE SET credential_hash = EXCLUDED.credential_hash, created_at = CURRENT_TIMESTAMP, revoked_at = NULL`, nodeID, hash)
	return err
}

func (s *SQLStore) MemberCredentialHash(ctx context.Context, nodeID string) (string, error) {
	var hash string
	err := s.db.SQL().QueryRowContext(ctx, `SELECT credential_hash FROM cluster_member_credentials WHERE node_id = $1 AND revoked_at IS NULL`, nodeID).Scan(&hash)
	if errors.Is(err, sql.ErrNoRows) {
		return "", errForwardCredential
	}
	return hash, err
}

func (s *SQLStore) RevokeMemberCredential(ctx context.Context, nodeID string) error {
	_, err := s.db.SQL().ExecContext(ctx, `UPDATE cluster_member_credentials SET revoked_at = CURRENT_TIMESTAMP WHERE node_id = $1`, nodeID)
	return err
}

func (s *SQLStore) SetLocalState(ctx context.Context, st clusterstate.State) error {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO cluster_local_state (id, node_id, role, primary_node_id, primary_url, primary_fingerprint, forward_credential, updated_at)
VALUES (1,$1,$2,$3,$4,$5,$6,CURRENT_TIMESTAMP)
ON CONFLICT (id) DO UPDATE SET node_id = EXCLUDED.node_id, role = EXCLUDED.role, primary_node_id = EXCLUDED.primary_node_id,
	primary_url = EXCLUDED.primary_url, primary_fingerprint = EXCLUDED.primary_fingerprint,
	forward_credential = EXCLUDED.forward_credential, updated_at = CURRENT_TIMESTAMP`,
		st.NodeID, st.Role, st.PrimaryNodeID, st.PrimaryURL, st.PrimaryFingerprint, st.ForwardCredential)
	return err
}

// ---- minting ----

// TokenMinter gets a token from this node's auth for a forwarded identity.
type TokenMinter interface {
	Mint(ctx context.Context, claims *pkgauth.Claims, forwardedBy string) (string, error)
}

type httpMinter struct {
	authURL string
	client  *http.Client
}

func (m httpMinter) Mint(ctx context.Context, claims *pkgauth.Claims, node string) (string, error) {
	raw, _ := json.Marshal(map[string]any{"claims": claims, "forwarded_by": node})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.authURL+"/auth/cluster/mint", bytes.NewReader(raw))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	servicetoken.Authorize(ctx, req)
	resp, err := m.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close() //nolint:errcheck
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("auth refused the forwarded identity (%d): %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var out struct {
		Token string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &out); err != nil || out.Token == "" {
		return "", errors.New("auth returned no token")
	}
	return out.Token, nil
}

// ---- handler ----

func (h *Handler) handleForward(w http.ResponseWriter, r *http.Request) {
	s := h.svc
	reqID := requestID(r)
	node := strings.TrimSpace(r.Header.Get(pkgconfig.HeaderClusterNode))
	svc := r.PathValue("svc")
	path := "/" + r.PathValue("rest")
	refuse := func(status int, code, msg string) {
		_ = s.publishAudit(r.Context(), "audit.cluster.forward_refused", "root", map[string]interface{}{
			"member_node_id": node, "service": svc, "method": r.Method, "path": path, "reason": msg,
			"severity": "warning", "result": "refused",
		})
		writeErr(w, status, code, msg, reqID, "root")
	}
	want, err := s.store.MemberCredentialHash(r.Context(), node)
	got := credentialHash(r.Header.Get(pkgconfig.HeaderClusterCredential))
	if node == "" || err != nil || subtle.ConstantTimeCompare([]byte(want), []byte(got)) != 1 {
		refuse(http.StatusUnauthorized, "member_unauthorized", errForwardCredential.Error())
		return
	}
	if clusterroute.Decide(svc, r.Method, path) != clusterroute.Forward {
		refuse(http.StatusForbidden, "not_forwardable", "only lifecycle writes of known services are forwarded")
		return
	}
	base, ok := s.forwardTarget(svc)
	if !ok {
		refuse(http.StatusForbidden, "not_forwardable", "unknown service")
		return
	}
	var bearer string
	var claims pkgauth.Claims
	if enc := r.Header.Get(pkgconfig.HeaderForwardClaims); enc != "" {
		raw, err := base64.RawURLEncoding.DecodeString(enc)
		if err != nil || json.Unmarshal(raw, &claims) != nil {
			refuse(http.StatusBadRequest, "bad_claims", "malformed forwarded claims")
			return
		}
		if s.minter == nil {
			refuse(http.StatusServiceUnavailable, "minter_unavailable", "token minting not configured")
			return
		}
		tok, err := s.minter.Mint(r.Context(), &claims, node)
		if err != nil {
			refuse(http.StatusForbidden, "identity_refused", err.Error())
			return
		}
		bearer = tok
	}
	target := base + path
	if r.URL.RawQuery != "" {
		target += "?" + r.URL.RawQuery
	}
	req, err := http.NewRequestWithContext(r.Context(), r.Method, target, r.Body)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "forward_failed", err.Error(), reqID, "root")
		return
	}
	for k, vs := range r.Header {
		if k == "Authorization" || k == "Host" || strings.HasPrefix(k, "X-Vecta-Cluster-") || k == pkgconfig.HeaderForwardClaims {
			continue
		}
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	req.Header.Set("X-Vecta-Forwarded-By", node)
	resp, err := s.forwardClient.Do(req)
	if err != nil {
		writeErr(w, http.StatusBadGateway, "service_unreachable", err.Error(), reqID, "root")
		return
	}
	defer resp.Body.Close() //nolint:errcheck
	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
	_ = s.publishAudit(r.Context(), "audit.cluster.write_forwarded", "root", map[string]interface{}{
		"member_node_id": node, "service": svc, "method": r.Method, "path": path,
		"tenant_id": claims.TenantID, "user_id": claims.UserID, "client_id": claims.ClientID,
		"status": resp.StatusCode, "severity": "info", "result": "success",
	})
}

func (s *Service) forwardTarget(svc string) (string, bool) {
	if s.forwardTargets != nil {
		return s.forwardTargets(svc)
	}
	u, ok := clusterroute.Services[svc]
	return u, ok
}

// WithForwarding configures the primary side of write forwarding.
func (s *Service) WithForwarding(minter TokenMinter) *Service {
	s.minter = minter
	s.forwardClient = &http.Client{Timeout: 60 * time.Second}
	return s
}
