package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"vecta-kms/pkg/clientip"
	pkgcrypto "vecta-kms/pkg/crypto"
	"vecta-kms/pkg/route"
)

// Edge devices (13.52.0-beta; docs/SECURITY/EDGE_DEVICES.md). A device works
// offline with keys it leases from the KMS:
//
//   - An administrator adds the device, names the keys it may lease (each
//     checked as the administrator: they must be able to wrap with it) and
//     the longest lease, and issues a one-use registration token.
//   - The device enrols with the token and two public keys of its own: an
//     ML-KEM-768 encapsulation key and an ECDSA P-256 key, proving the second
//     by signing the token. It receives a device credential, kept here only
//     as a SHA-256.
//   - A lease is a data key from keycore under an allowed key, sealed to the
//     device's ML-KEM key (pkg/crypto KEMSeal). Only keycore's wrapped copy
//     is kept, so the device's data stays decryptable centrally through
//     keycore after the lease has expired.
//   - The device reports what it did offline as receipts, in sequence and
//     signed with its P-256 key. A replayed batch is refused, a gap is
//     recorded.
//   - Revoking a device or a lease stops new leases; the device drops
//     revoked leases at its next check-in.

const (
	edgeTokenPrefix     = "vedge-reg"
	edgeDeviceKeyHeader = "X-Edge-Device-Key"
	edgeLeaseLabel      = "edge-lease"
	edgeEnrollProof     = "vecta-edge-enroll|"

	edgePending = "pending"
	edgeActive  = "active"
	edgeRevoked = "revoked"

	edgeDefaultLease  = 24 * time.Hour
	edgeMaxLease      = 30 * 24 * time.Hour
	edgeMinLease      = time.Minute
	edgeMaxLeases     = 32
	edgeMaxBatch      = 1000
	edgeMaxAllowed    = 64
	edgeListLimit     = 500
	edgeReceiptMaxAge = 400 * 24 * time.Hour
)

var edgeNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$`)

type edgeDevice struct {
	TenantID         string
	ID               string
	Name             string
	Status           string
	AllowedKeyIDs    []string
	MaxLeaseSeconds  int64
	TokenHash        string
	TokenExpiresAt   time.Time
	CredentialHash   string
	SigningPublicKey string
	KEMPublicKey     string
	LastReceiptSeq   int64
	LastSeenAt       *time.Time
	LastSourceIP     string
	AgentVersion     string
	CreatedBy        string
	CreatedAt        time.Time
	EnrolledAt       *time.Time
	RevokedAt        *time.Time
	RevokedBy        string
	RevokeReason     string
}

// EdgeDeviceView is what the API shows: never a hash or a credential.
type EdgeDeviceView struct {
	ID              string     `json:"id"`
	Name            string     `json:"name"`
	Status          string     `json:"status"`
	AllowedKeyIDs   []string   `json:"allowed_key_ids"`
	MaxLeaseSeconds int64      `json:"max_lease_seconds"`
	TokenPending    bool       `json:"token_pending"`
	LastReceiptSeq  int64      `json:"last_receipt_seq"`
	LastSeenAt      *time.Time `json:"last_seen_at,omitempty"`
	LastSourceIP    string     `json:"last_source_ip,omitempty"`
	AgentVersion    string     `json:"agent_version,omitempty"`
	CreatedBy       string     `json:"created_by"`
	CreatedAt       time.Time  `json:"created_at"`
	EnrolledAt      *time.Time `json:"enrolled_at,omitempty"`
	RevokedAt       *time.Time `json:"revoked_at,omitempty"`
	RevokedBy       string     `json:"revoked_by,omitempty"`
	RevokeReason    string     `json:"revoke_reason,omitempty"`
}

func edgeView(d edgeDevice, now time.Time) EdgeDeviceView {
	return EdgeDeviceView{ID: d.ID, Name: d.Name, Status: d.Status, AllowedKeyIDs: d.AllowedKeyIDs, MaxLeaseSeconds: d.MaxLeaseSeconds,
		TokenPending: d.TokenHash != "" && now.Before(d.TokenExpiresAt), LastReceiptSeq: d.LastReceiptSeq, LastSeenAt: d.LastSeenAt,
		LastSourceIP: d.LastSourceIP, AgentVersion: d.AgentVersion, CreatedBy: d.CreatedBy, CreatedAt: d.CreatedAt,
		EnrolledAt: d.EnrolledAt, RevokedAt: d.RevokedAt, RevokedBy: d.RevokedBy, RevokeReason: d.RevokeReason}
}

type edgeLease struct {
	TenantID     string     `json:"-"`
	ID           string     `json:"id"`
	DeviceID     string     `json:"device_id"`
	KeyID        string     `json:"key_id"`
	KeyVersion   int64      `json:"key_version"`
	WrappedDEK   string     `json:"wrapped_dek"`
	WrappedDEKIV string     `json:"wrapped_dek_iv"`
	IssuedAt     time.Time  `json:"issued_at"`
	ExpiresAt    time.Time  `json:"expires_at"`
	RevokedAt    *time.Time `json:"revoked_at,omitempty"`
}

type edgeReceipt struct {
	Seq        int64     `json:"seq"`
	LeaseID    string    `json:"lease_id"`
	Operation  string    `json:"operation"`
	Bytes      int64     `json:"bytes"`
	At         time.Time `json:"at"`
	ReceivedAt time.Time `json:"received_at,omitempty"`
}

// edgeLeaseAAD binds a lease's data key to its tenant, device and lease: in
// keycore's wrap and in the seal to the device.
func edgeLeaseAAD(tenantID, deviceID, leaseID string) []byte {
	return []byte("vecta-edge-lease|" + tenantID + "|" + deviceID + "|" + leaseID)
}

func parseEdgeToken(token string) (tenantID, deviceID string, ok bool) {
	parts := strings.Split(strings.TrimSpace(token), ".")
	if len(parts) != 4 || parts[0] != edgeTokenPrefix || parts[2] == "" || parts[3] == "" {
		return "", "", false
	}
	tenant, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || len(tenant) == 0 {
		return "", "", false
	}
	return string(tenant), parts[2], true
}

// checkEdgeKeys normalizes a device's allowed keys and checks that the
// administrator in ctx may wrap with each: keycore is asked for a data key
// as them (pkg/delegation, usage wrap), and nothing it returns is kept. An
// administrator can't let a device lease a key they couldn't use.
func (s *Service) checkEdgeKeys(ctx context.Context, tenantID string, keys []string) ([]string, error) {
	out := []string{}
	seen := map[string]bool{}
	for _, k := range keys {
		if k = strings.TrimSpace(k); k != "" && !seen[k] {
			seen[k] = true
			out = append(out, k)
		}
	}
	if len(out) == 0 || len(out) > edgeMaxAllowed {
		return nil, newServiceError(http.StatusBadRequest, "allowed_keys_required", fmt.Sprintf("a device leases 1 to %d keys", edgeMaxAllowed))
	}
	for _, k := range out {
		if _, err := s.keycore.GenerateDataKey(ctx, tenantID, k, "", false, "wrap"); err != nil {
			var kerr *keycoreError
			if errors.As(err, &kerr) && (kerr.Status == http.StatusForbidden || kerr.Status == http.StatusNotFound) {
				return nil, newServiceError(http.StatusForbidden, "key_not_usable", fmt.Sprintf("you can't wrap with key %s, so a device can't lease it: %s", k, kerr.Msg))
			}
			return nil, fmt.Errorf("check key %s: %w", k, err)
		}
	}
	return out, nil
}

func edgeMaxLeaseSeconds(v int64) (int64, error) {
	if v == 0 {
		return int64(edgeDefaultLease / time.Second), nil
	}
	if v < int64(edgeMinLease/time.Second) || v > int64(edgeMaxLease/time.Second) {
		return 0, newServiceError(http.StatusBadRequest, "invalid_lease_length", fmt.Sprintf("max_lease_seconds is between %d and %d", int64(edgeMinLease/time.Second), int64(edgeMaxLease/time.Second)))
	}
	return v, nil
}

// issueEdgeLease leases a data key under keyID to an active device.
func (s *Service) issueEdgeLease(ctx context.Context, d edgeDevice, keyID string, ttl int64, now time.Time) (edgeLease, []byte, error) {
	allowed := false
	for _, k := range d.AllowedKeyIDs {
		allowed = allowed || k == keyID
	}
	if !allowed {
		return edgeLease{}, nil, newServiceError(http.StatusForbidden, "key_not_allowed", "this device may not lease that key")
	}
	if ttl == 0 || ttl > d.MaxLeaseSeconds {
		ttl = d.MaxLeaseSeconds
	}
	if ttl < int64(edgeMinLease/time.Second) {
		return edgeLease{}, nil, newServiceError(http.StatusBadRequest, "invalid_lease_length", "a lease lasts at least a minute")
	}
	leases, err := s.store.ListEdgeLeases(ctx, d.TenantID, d.ID, edgeListLimit)
	if err != nil {
		return edgeLease{}, nil, err
	}
	active := 0
	for _, l := range leases {
		if l.RevokedAt == nil && l.ExpiresAt.After(now) {
			active++
		}
	}
	if active >= edgeMaxLeases {
		return edgeLease{}, nil, newServiceError(http.StatusConflict, "too_many_leases", fmt.Sprintf("a device holds at most %d active leases", edgeMaxLeases))
	}
	l := edgeLease{TenantID: d.TenantID, ID: newID("lease"), DeviceID: d.ID, KeyID: keyID, IssuedAt: now, ExpiresAt: now.Add(time.Duration(ttl) * time.Second)}
	aad := edgeLeaseAAD(d.TenantID, d.ID, l.ID)
	dk, err := s.keycore.GenerateDataKey(ctx, d.TenantID, keyID, base64.StdEncoding.EncodeToString(aad), true, "")
	if err != nil {
		var kerr *keycoreError
		if errors.As(err, &kerr) && kerr.Status < http.StatusInternalServerError {
			return edgeLease{}, nil, newServiceError(kerr.Status, defaultString(kerr.Code, "key_refused"), kerr.Msg)
		}
		return edgeLease{}, nil, err
	}
	dek, err := base64.StdEncoding.DecodeString(dk.PlaintextDEK)
	dk.PlaintextDEK = ""
	if err != nil || len(dek) != 32 {
		pkgcrypto.Zeroize(dek)
		return edgeLease{}, nil, errors.New("keycore returned no usable data key")
	}
	defer pkgcrypto.Zeroize(dek)
	kem, err := base64.StdEncoding.DecodeString(d.KEMPublicKey)
	if err != nil {
		return edgeLease{}, nil, err
	}
	sealed, err := pkgcrypto.KEMSeal(kem, dek, aad, edgeLeaseLabel)
	if err != nil {
		return edgeLease{}, nil, err
	}
	l.KeyVersion, l.WrappedDEK, l.WrappedDEKIV = dk.Version, dk.WrappedDEK, dk.WrappedDEKIV
	if err := s.store.CreateEdgeLease(ctx, l); err != nil {
		return edgeLease{}, nil, err
	}
	return l, sealed, nil
}

// acceptEdgeReceipts verifies and stores a signed batch. It returns how many
// receipts were missing before it (a gap).
func (s *Service) acceptEdgeReceipts(ctx context.Context, d edgeDevice, raw string, sigB64 string, now time.Time) (int, int64, error) {
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(sigB64))
	if err != nil || len(sig) == 0 {
		return 0, 0, newServiceError(http.StatusBadRequest, "receipt_signature_invalid", "signature is base64")
	}
	pub, err := pkgcrypto.ParsePublicKeyPEM(d.SigningPublicKey)
	if err != nil || pkgcrypto.Verify(pkgcrypto.AlgECDSAP256, pub, []byte(raw), sig) != nil {
		return 0, 0, newServiceError(http.StatusUnauthorized, "receipt_signature_invalid", "the receipts are not signed by this device's key")
	}
	var batch []edgeReceipt
	if err := json.Unmarshal([]byte(raw), &batch); err != nil || len(batch) == 0 || len(batch) > edgeMaxBatch {
		return 0, 0, newServiceError(http.StatusBadRequest, "receipts_invalid", fmt.Sprintf("receipts is a JSON list of 1 to %d receipts", edgeMaxBatch))
	}
	if batch[0].Seq <= d.LastReceiptSeq {
		return 0, 0, newServiceError(http.StatusConflict, "receipts_replayed", fmt.Sprintf("receipts up to %d were already received", d.LastReceiptSeq))
	}
	leases := map[string]bool{}
	for i, r := range batch {
		if i > 0 && r.Seq != batch[i-1].Seq+1 {
			return 0, 0, newServiceError(http.StatusBadRequest, "receipts_invalid", "receipts in a batch are numbered one after another")
		}
		if r.Operation != "encrypt" && r.Operation != "decrypt" {
			return 0, 0, newServiceError(http.StatusBadRequest, "receipts_invalid", fmt.Sprintf("receipt %d: operation is encrypt or decrypt", r.Seq))
		}
		if r.Bytes < 0 || r.At.IsZero() || r.At.After(now.Add(24*time.Hour)) || r.At.Before(now.Add(-edgeReceiptMaxAge)) {
			return 0, 0, newServiceError(http.StatusBadRequest, "receipts_invalid", fmt.Sprintf("receipt %d: bytes or time out of range", r.Seq))
		}
		if !leases[r.LeaseID] {
			l, err := s.store.GetEdgeLease(ctx, d.TenantID, r.LeaseID)
			if err != nil || l.DeviceID != d.ID {
				return 0, 0, newServiceError(http.StatusBadRequest, "receipt_lease_unknown", fmt.Sprintf("receipt %d names a lease this device doesn't hold", r.Seq))
			}
			leases[r.LeaseID] = true
		}
	}
	ok, err := s.store.AddEdgeReceipts(ctx, d.TenantID, d.ID, d.LastReceiptSeq, batch, now)
	if err != nil {
		return 0, 0, err
	}
	if !ok {
		return 0, 0, newServiceError(http.StatusConflict, "receipts_conflict", "another batch was received at the same time; send again")
	}
	return len(batch), batch[0].Seq - d.LastReceiptSeq - 1, nil
}

// ---- routes ----

func (h *Handler) edgeRoutes(rt *route.Router) {
	rt.Handle("GET /ekm/edge/devices", route.Spec{Action: "edge_devices_listed", Permission: "ekm.read", Resource: "edge_device"}, h.listEdgeDevices)
	rt.Handle("POST /ekm/edge/devices", route.Spec{Action: "edge_device_created", Permission: "ekm.write", Resource: "edge_device", Severity: "warning"}, h.createEdgeDevice)
	rt.Handle("PUT /ekm/edge/devices/{id}", route.Spec{Action: "edge_device_updated", Permission: "ekm.write", Resource: "edge_device", TargetParam: "id", Severity: "warning"}, h.updateEdgeDevice)
	rt.Handle("POST /ekm/edge/devices/{id}/registration-token", route.Spec{Action: "edge_device_token_issued", Permission: "ekm.write", Resource: "edge_device", TargetParam: "id", Severity: "warning"}, h.issueEdgeToken)
	rt.Handle("POST /ekm/edge/devices/{id}/revoke", route.Spec{Action: "edge_device_revoked", Permission: "ekm.write", Resource: "edge_device", TargetParam: "id", Severity: "warning"}, h.revokeEdgeDevice)
	rt.Handle("GET /ekm/edge/devices/{id}/leases", route.Spec{Action: "edge_leases_listed", Permission: "ekm.read", Resource: "edge_device", TargetParam: "id"}, h.listEdgeLeases)
	rt.Handle("GET /ekm/edge/devices/{id}/receipts", route.Spec{Action: "edge_receipts_listed", Permission: "ekm.read", Resource: "edge_device", TargetParam: "id"}, h.listEdgeReceipts)
	rt.Handle("POST /ekm/edge/leases/{id}/revoke", route.Spec{Action: "edge_lease_revoked", Permission: "ekm.write", Resource: "edge_lease", TargetParam: "id", Severity: "warning"}, h.revokeEdgeLease)
	// The device has no auth-service token: these verify its own credential.
	rt.Handle("POST /ekm/edge/enroll", route.Spec{Action: "edge_device_enrolled", Public: true, Resource: "edge_device", Severity: "warning"}, h.enrollEdgeDevice)
	rt.Handle("POST /ekm/edge/devices/{id}/leases", route.Spec{Action: "edge_lease_issued", Public: true, Resource: "edge_device", TargetParam: "id", Severity: "warning"}, h.edgeLease)
	rt.Handle("POST /ekm/edge/devices/{id}/receipts", route.Spec{Action: "edge_receipts_received", Public: true, Resource: "edge_device", TargetParam: "id"}, h.edgeReceipts)
	rt.Handle("POST /ekm/edge/devices/{id}/check-in", route.Spec{Action: "edge_device_check_in", Public: true, Resource: "edge_device", TargetParam: "id"}, h.edgeCheckIn)
}

// edgeFail answers an error: a service refusal is audited with its reason.
func edgeFail(c *route.Call, err error) {
	var se serviceError
	switch {
	case errors.Is(err, errNotFound):
		c.Error(http.StatusNotFound, "not_found", "no such edge device or lease")
	case errors.As(err, &se):
		if se.HTTPStatus < http.StatusInternalServerError {
			c.Refuse(se.HTTPStatus, se.Code, se.Message)
			return
		}
		c.Error(se.HTTPStatus, se.Code, se.Message)
	case strings.Contains(strings.ToLower(err.Error()), "unique"):
		c.Refuse(http.StatusConflict, "name_taken", "an edge device with that name exists")
	default:
		c.Error(http.StatusInternalServerError, "edge_failed", err.Error())
	}
}

func (h *Handler) listEdgeDevices(c *route.Call) {
	items, err := h.svc.store.ListEdgeDevices(c.R.Context(), c.Tenant)
	if err != nil {
		edgeFail(c, err)
		return
	}
	now := time.Now().UTC()
	out := make([]EdgeDeviceView, 0, len(items))
	for _, d := range items {
		out = append(out, edgeView(d, now))
	}
	c.Detail("count", len(out))
	c.JSON(http.StatusOK, map[string]interface{}{"items": out})
}

func (h *Handler) createEdgeDevice(c *route.Call) {
	var in struct {
		Name            string   `json:"name"`
		AllowedKeyIDs   []string `json:"allowed_key_ids"`
		MaxLeaseSeconds int64    `json:"max_lease_seconds"`
	}
	if !c.Decode(&in) {
		return
	}
	name := strings.TrimSpace(in.Name)
	c.Detail("name", name)
	if !edgeNameRE.MatchString(name) {
		c.Refuse(http.StatusBadRequest, "invalid_name", "name is 3 to 64 letters, digits, dots, dashes or underscores")
		return
	}
	maxLease, err := edgeMaxLeaseSeconds(in.MaxLeaseSeconds)
	if err != nil {
		edgeFail(c, err)
		return
	}
	keys, err := h.svc.checkEdgeKeys(c.R.Context(), c.Tenant, in.AllowedKeyIDs)
	if err != nil {
		edgeFail(c, err)
		return
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	d := edgeDevice{TenantID: c.Tenant, ID: newID("edge"), Name: name, Status: edgePending, AllowedKeyIDs: keys, MaxLeaseSeconds: maxLease, CreatedBy: c.Actor(), CreatedAt: now}
	if err := h.svc.store.CreateEdgeDevice(c.R.Context(), d); err != nil {
		edgeFail(c, err)
		return
	}
	c.Target(d.ID)
	c.Detail("allowed_key_ids", keys)
	c.Detail("max_lease_seconds", maxLease)
	c.JSON(http.StatusCreated, map[string]interface{}{"device": edgeView(d, now)})
}

func (h *Handler) updateEdgeDevice(c *route.Call) {
	var in struct {
		AllowedKeyIDs   []string `json:"allowed_key_ids"`
		MaxLeaseSeconds int64    `json:"max_lease_seconds"`
	}
	if !c.Decode(&in) {
		return
	}
	ctx := c.R.Context()
	d, err := h.svc.store.GetEdgeDevice(ctx, c.Tenant, c.R.PathValue("id"))
	if err != nil {
		edgeFail(c, err)
		return
	}
	maxLease, err := edgeMaxLeaseSeconds(in.MaxLeaseSeconds)
	if err == nil {
		in.AllowedKeyIDs, err = h.svc.checkEdgeKeys(ctx, c.Tenant, in.AllowedKeyIDs)
	}
	if err == nil {
		err = h.svc.store.UpdateEdgeDevicePolicy(ctx, c.Tenant, d.ID, in.AllowedKeyIDs, maxLease)
	}
	if err != nil {
		edgeFail(c, err)
		return
	}
	c.Detail("allowed_key_ids", in.AllowedKeyIDs)
	c.Detail("max_lease_seconds", maxLease)
	d, _ = h.svc.store.GetEdgeDevice(ctx, c.Tenant, d.ID)
	c.JSON(http.StatusOK, map[string]interface{}{"device": edgeView(d, time.Now().UTC())})
}

func (h *Handler) issueEdgeToken(c *route.Call) {
	ctx := c.R.Context()
	d, err := h.svc.store.GetEdgeDevice(ctx, c.Tenant, c.R.PathValue("id"))
	if err != nil {
		edgeFail(c, err)
		return
	}
	if d.Status == edgeRevoked {
		c.Refuse(http.StatusConflict, "device_revoked", "a revoked device is not enrolled again; add a new one")
		return
	}
	secret, err := newClientSecret()
	if err != nil {
		edgeFail(c, err)
		return
	}
	token := strings.Join([]string{edgeTokenPrefix, base64.RawURLEncoding.EncodeToString([]byte(c.Tenant)), d.ID, secret}, ".")
	expires := time.Now().UTC().Add(registrationTokenTTL).Truncate(time.Microsecond)
	if err := h.svc.store.SetEdgeDeviceToken(ctx, c.Tenant, d.ID, verifierHash(token), expires); err != nil {
		edgeFail(c, err)
		return
	}
	c.Detail("name", d.Name)
	c.Detail("expires_at", expires.Format(time.RFC3339))
	c.Detail("reenrolment", d.Status == edgeActive)
	c.W.Header().Set("Cache-Control", "no-store")
	c.JSON(http.StatusCreated, map[string]interface{}{"token": token, "expires_at": expires, "device_id": d.ID, "enroll_path": "/ekm/edge/enroll"})
}

func (h *Handler) revokeEdgeDevice(c *route.Call) {
	var in struct {
		Reason string `json:"reason"`
	}
	if !c.Decode(&in) {
		return
	}
	reason := strings.TrimSpace(in.Reason)
	if len(reason) > 256 {
		c.Refuse(http.StatusBadRequest, "invalid_reason", "reason is at most 256 characters")
		return
	}
	ctx := c.R.Context()
	d, err := h.svc.store.GetEdgeDevice(ctx, c.Tenant, c.R.PathValue("id"))
	if err == nil && d.Status == edgeRevoked {
		c.Refuse(http.StatusConflict, "already_revoked", "the device is already revoked")
		return
	}
	if err == nil {
		err = h.svc.store.RevokeEdgeDevice(ctx, c.Tenant, d.ID, c.Actor(), reason, time.Now().UTC().Truncate(time.Microsecond))
	}
	if err != nil {
		edgeFail(c, err)
		return
	}
	c.Detail("name", d.Name)
	c.Detail("reason", reason)
	d, _ = h.svc.store.GetEdgeDevice(ctx, c.Tenant, d.ID)
	c.JSON(http.StatusOK, map[string]interface{}{"device": edgeView(d, time.Now().UTC())})
}

func edgeLimit(c *route.Call) int {
	n, _ := strconv.Atoi(c.R.URL.Query().Get("limit"))
	if n <= 0 || n > edgeListLimit {
		return edgeListLimit
	}
	return n
}

func (h *Handler) listEdgeLeases(c *route.Call) {
	ctx := c.R.Context()
	d, err := h.svc.store.GetEdgeDevice(ctx, c.Tenant, c.R.PathValue("id"))
	if err != nil {
		edgeFail(c, err)
		return
	}
	items, err := h.svc.store.ListEdgeLeases(ctx, c.Tenant, d.ID, edgeLimit(c))
	if err != nil {
		edgeFail(c, err)
		return
	}
	c.Detail("count", len(items))
	c.JSON(http.StatusOK, map[string]interface{}{"items": items})
}

func (h *Handler) listEdgeReceipts(c *route.Call) {
	ctx := c.R.Context()
	d, err := h.svc.store.GetEdgeDevice(ctx, c.Tenant, c.R.PathValue("id"))
	if err != nil {
		edgeFail(c, err)
		return
	}
	items, err := h.svc.store.ListEdgeReceipts(ctx, c.Tenant, d.ID, edgeLimit(c))
	if err != nil {
		edgeFail(c, err)
		return
	}
	c.Detail("count", len(items))
	c.JSON(http.StatusOK, map[string]interface{}{"items": items, "last_receipt_seq": d.LastReceiptSeq})
}

func (h *Handler) revokeEdgeLease(c *route.Call) {
	ctx := c.R.Context()
	l, err := h.svc.store.GetEdgeLease(ctx, c.Tenant, c.R.PathValue("id"))
	if err == nil && l.RevokedAt != nil {
		c.Refuse(http.StatusConflict, "already_revoked", "the lease is already revoked")
		return
	}
	if err == nil {
		err = h.svc.store.RevokeEdgeLease(ctx, c.Tenant, l.ID, time.Now().UTC().Truncate(time.Microsecond))
	}
	if err != nil {
		edgeFail(c, err)
		return
	}
	c.Detail("device_id", l.DeviceID)
	c.Detail("key_id", l.KeyID)
	c.JSON(http.StatusOK, map[string]interface{}{"revoked": l.ID})
}

func (h *Handler) enrollEdgeDevice(c *route.Call) {
	var in struct {
		TenantID         string `json:"tenant_id"`
		Token            string `json:"token"`
		SigningPublicKey string `json:"signing_public_key"`
		Proof            string `json:"proof"`
		KEMPublicKey     string `json:"kem_public_key"`
		Version          string `json:"version"`
	}
	if !c.Decode(&in) {
		return
	}
	ctx := c.R.Context()
	refuse := func(reason, msg string) { c.Refuse(http.StatusUnauthorized, reason, msg) }
	tokenTenant, id, ok := parseEdgeToken(in.Token)
	var d edgeDevice
	if ok && tokenTenant == c.Tenant {
		d, _ = h.svc.store.GetEdgeDevice(ctx, c.Tenant, id)
	}
	// Compared even when no device was found, so the answer takes as long.
	if !sameVerifier(d.TokenHash, strings.TrimSpace(in.Token)) {
		refuse("invalid_registration_token", "the registration token was not accepted")
		return
	}
	c.Target(d.ID)
	c.Detail("name", d.Name)
	now := time.Now().UTC().Truncate(time.Microsecond)
	if !now.Before(d.TokenExpiresAt) {
		refuse("registration_token_expired", "the registration token has expired: issue a new one")
		return
	}
	pub, err := pkgcrypto.ParsePublicKeyPEM(in.SigningPublicKey)
	proof, perr := base64.StdEncoding.DecodeString(strings.TrimSpace(in.Proof))
	if err != nil || perr != nil || pkgcrypto.Verify(pkgcrypto.AlgECDSAP256, pub, []byte(edgeEnrollProof+strings.TrimSpace(in.Token)), proof) != nil {
		c.Refuse(http.StatusBadRequest, "signing_key_invalid", "signing_public_key is an ECDSA P-256 public key (PEM) and proof its signature of \"vecta-edge-enroll|\" and the token")
		return
	}
	kem, err := base64.StdEncoding.DecodeString(strings.TrimSpace(in.KEMPublicKey))
	if err == nil {
		_, err = pkgcrypto.KEMSeal(kem, []byte("check"), nil, "edge-enroll-check")
	}
	if err != nil {
		c.Refuse(http.StatusBadRequest, "kem_key_invalid", "kem_public_key is an ML-KEM-768 encapsulation key (base64)")
		return
	}
	version := strings.TrimSpace(in.Version)
	if len(version) > 64 {
		c.Error(http.StatusBadRequest, "bad_request", "version is at most 64 characters")
		return
	}
	credential, err := newClientSecret()
	if err != nil {
		edgeFail(c, err)
		return
	}
	ip := clientip.From(c.R)
	d.CredentialHash, d.SigningPublicKey, d.KEMPublicKey = verifierHash(credential), strings.TrimSpace(in.SigningPublicKey), strings.TrimSpace(in.KEMPublicKey)
	d.EnrolledAt, d.LastSourceIP, d.AgentVersion = &now, ip, version
	used, err := h.svc.store.ConsumeEdgeDeviceToken(ctx, d, d.TokenHash)
	if err != nil {
		edgeFail(c, err)
		return
	}
	if !used {
		refuse("invalid_registration_token", "the registration token was not accepted")
		return
	}
	c.Authenticated(d.ID, "edge_device")
	c.Detail("device_source_ip", ip)
	c.Detail("version", version)
	c.W.Header().Set("Cache-Control", "no-store")
	c.JSON(http.StatusOK, map[string]interface{}{
		"device_id": d.ID, "tenant_id": c.Tenant, "device_key": credential, "device_key_header": edgeDeviceKeyHeader,
		"allowed_key_ids": d.AllowedKeyIDs, "max_lease_seconds": d.MaxLeaseSeconds,
	})
}

// edgeCaller verifies the device credential for the device in the path.
func (h *Handler) edgeCaller(c *route.Call) (edgeDevice, bool) {
	d, err := h.svc.store.GetEdgeDevice(c.R.Context(), c.Tenant, c.R.PathValue("id"))
	if err != nil && !errors.Is(err, errNotFound) {
		edgeFail(c, err)
		return edgeDevice{}, false
	}
	// Compared even when no device was found.
	if !sameVerifier(d.CredentialHash, strings.TrimSpace(c.R.Header.Get(edgeDeviceKeyHeader))) {
		if d.Status == edgeRevoked {
			c.Refuse(http.StatusForbidden, "device_revoked", "this device was revoked")
			return edgeDevice{}, false
		}
		c.Refuse(http.StatusUnauthorized, "invalid_device_key", "the device credential was not accepted")
		return edgeDevice{}, false
	}
	if d.Status != edgeActive {
		c.Refuse(http.StatusForbidden, "device_not_active", "this device is not active")
		return edgeDevice{}, false
	}
	c.Authenticated(d.ID, "edge_device")
	return d, true
}

func (h *Handler) edgeLease(c *route.Call) {
	var in struct {
		TenantID   string `json:"tenant_id"`
		KeyID      string `json:"key_id"`
		TTLSeconds int64  `json:"ttl_seconds"`
	}
	if !c.Decode(&in) {
		return
	}
	d, ok := h.edgeCaller(c)
	if !ok {
		return
	}
	c.Detail("key_id", in.KeyID)
	now := time.Now().UTC().Truncate(time.Microsecond)
	l, sealed, err := h.svc.issueEdgeLease(c.R.Context(), d, strings.TrimSpace(in.KeyID), in.TTLSeconds, now)
	if err != nil {
		edgeFail(c, err)
		return
	}
	_ = h.svc.store.TouchEdgeDevice(c.R.Context(), c.Tenant, d.ID, clientip.From(c.R), d.AgentVersion, now)
	c.Detail("lease_id", l.ID)
	c.Detail("key_version", l.KeyVersion)
	c.Detail("expires_at", l.ExpiresAt.Format(time.RFC3339))
	c.W.Header().Set("Cache-Control", "no-store")
	c.JSON(http.StatusCreated, map[string]interface{}{
		"lease": l, "sealed_dek": base64.StdEncoding.EncodeToString(sealed),
		"aad": base64.StdEncoding.EncodeToString(edgeLeaseAAD(c.Tenant, d.ID, l.ID)),
	})
}

func (h *Handler) edgeReceipts(c *route.Call) {
	var in struct {
		TenantID  string `json:"tenant_id"`
		Receipts  string `json:"receipts"`
		Signature string `json:"signature"`
	}
	if !c.Decode(&in) {
		return
	}
	d, ok := h.edgeCaller(c)
	if !ok {
		return
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	n, gap, err := h.svc.acceptEdgeReceipts(c.R.Context(), d, in.Receipts, in.Signature, now)
	if err != nil {
		edgeFail(c, err)
		return
	}
	c.Detail("received", n)
	c.Detail("from_seq", d.LastReceiptSeq+gap+1)
	if gap > 0 {
		c.Detail("gap", gap)
		c.Detail("severity", "warning")
	}
	_ = h.svc.store.TouchEdgeDevice(c.R.Context(), c.Tenant, d.ID, clientip.From(c.R), d.AgentVersion, now)
	c.JSON(http.StatusOK, map[string]interface{}{"received": n, "gap": gap, "last_receipt_seq": d.LastReceiptSeq + gap + int64(n)})
}

func (h *Handler) edgeCheckIn(c *route.Call) {
	var in struct {
		TenantID string `json:"tenant_id"`
		Version  string `json:"version"`
	}
	if !c.Decode(&in) {
		return
	}
	d, ok := h.edgeCaller(c)
	if !ok {
		return
	}
	ctx := c.R.Context()
	now := time.Now().UTC().Truncate(time.Microsecond)
	version := strings.TrimSpace(in.Version)
	if len(version) > 64 {
		version = d.AgentVersion
	}
	_ = h.svc.store.TouchEdgeDevice(ctx, c.Tenant, d.ID, clientip.From(c.R), version, now)
	leases, err := h.svc.store.ListEdgeLeases(ctx, c.Tenant, d.ID, edgeListLimit)
	if err != nil {
		edgeFail(c, err)
		return
	}
	revoked := []string{}
	for _, l := range leases {
		if l.RevokedAt != nil && l.ExpiresAt.After(now) {
			revoked = append(revoked, l.ID)
		}
	}
	c.Detail("revoked_leases", len(revoked))
	c.JSON(http.StatusOK, map[string]interface{}{"status": d.Status, "revoked_lease_ids": revoked, "last_receipt_seq": d.LastReceiptSeq, "server_time": now})
}
