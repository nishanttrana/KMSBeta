package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"vecta-kms/pkg/crypto"
	"vecta-kms/pkg/deployed"
	"vecta-kms/pkg/hsm"
	"vecta-kms/pkg/route"
	"vecta-kms/pkg/tenantcheck"
)

// Where an HSM key lives (7.38.0-beta). A tenant has one HSM profile (HSM
// tab): the KMS's root of trust, which holds the tenant key and, when HSM
// keys are on, keys. It may also add HSMs as credentials (Playbooks →
// Credentials, type pkcs11_hsm): each is a target a key can be created,
// formed or imported on. A key records its target and every later operation
// goes back to it; nothing is ever re-created on another HSM.

const (
	// labelHSMConnection is the HSM credential a key's objects are on;
	// absent for a key on the tenant's HSM profile.
	labelHSMConnection     = "hsm_connection"
	labelHSMConnectionName = "hsm_connection_name"
	labelHSMTopology       = "hsm_topology"
	// labelHSMOrigin is "imported" for material placed in the HSM from
	// outside; a generated key carries none.
	labelHSMOrigin = "hsm_origin"

	hsmCredentialType = "pkcs11_hsm"
)

// HSMCredential is an HSM credential as compliance lists it: no PIN.
type HSMCredential struct {
	ID         string            `json:"id"`
	Name       string            `json:"name"`
	Type       string            `json:"type"`
	Endpoint   string            `json:"endpoint"`
	Attributes map[string]string `json:"attributes"`
}

// HSMCredentials reads HSM credentials from compliance with the caller's
// own verified token, so compliance decides whether that person may attach
// one (compliance.connection.use).
type HSMCredentials interface {
	List(ctx context.Context, tenantID string) ([]HSMCredential, error)
	Get(ctx context.Context, tenantID, id string) (HSMCredential, error)
}

var (
	errHSMCredentialNotFound  = errors.New("no such HSM credential")
	errHSMCredentialForbidden = errors.New("the caller may not use HSM credentials")
)

type httpHSMCredentials struct {
	base string
	http *http.Client
}

// hsmCredentialsFromEnv returns nil when the deployment leaves out the
// compliance service, which holds the credentials.
func hsmCredentialsFromEnv() HSMCredentials {
	if !deployed.Has("compliance_dashboard") {
		return nil
	}
	base := strings.TrimSpace(os.Getenv("COMPLIANCE_URL"))
	if base == "" {
		base = "https://compliance:8110"
	}
	return &httpHSMCredentials{base: strings.TrimRight(base, "/"), http: &http.Client{Timeout: 5 * time.Second}}
}

func (c *httpHSMCredentials) call(ctx context.Context, tenantID, path string, out interface{}) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+path, nil)
	if err != nil {
		return err
	}
	// servicetoken-exempt: forwards the verified caller's own token, so the
	// credential store checks that person's permission to use a credential.
	if tok, _ := ctx.Value(rawBearerTokenCtxKey).(string); strings.TrimSpace(tok) != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	req.Header.Set("X-Tenant-ID", tenantID)
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("the credential store is unreachable: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return errHSMCredentialNotFound
	case resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnauthorized:
		return errHSMCredentialForbidden
	case resp.StatusCode >= 300:
		return fmt.Errorf("the credential store answered HTTP %d", resp.StatusCode)
	}
	return json.Unmarshal(raw, out)
}

func (c *httpHSMCredentials) List(ctx context.Context, tenantID string) ([]HSMCredential, error) {
	var out struct {
		Data []HSMCredential `json:"data"`
	}
	err := c.call(ctx, tenantID, "/compliance/connections?type="+hsmCredentialType+"&tenant_id="+url.QueryEscape(tenantID), &out)
	return out.Data, err
}

func (c *httpHSMCredentials) Get(ctx context.Context, tenantID, id string) (HSMCredential, error) {
	var out struct {
		Data HSMCredential `json:"data"`
	}
	if err := c.call(ctx, tenantID, "/compliance/connections/"+url.PathEscape(id)+"?tenant_id="+url.QueryEscape(tenantID), &out); err != nil {
		return HSMCredential{}, err
	}
	if out.Data.Type != hsmCredentialType {
		return HSMCredential{}, errHSMCredentialNotFound
	}
	return out.Data, nil
}

// SetHSMCredentials wires the credential store client.
func (s *Service) SetHSMCredentials(c HSMCredentials) { s.hsmCreds = c }

// hsmOn is the connector client for an HSM credential, or for the tenant's
// profile when connectionID is "".
func (s *Service) hsmOn(connectionID string) HSMBackend {
	if connectionID == "" || s.hsm == nil {
		return s.hsm
	}
	if r, ok := s.hsm.(interface{ On(string) *hsm.Client }); ok {
		return r.On(connectionID)
	}
	return s.hsm
}

// hsmOf is the connector client for the HSM key k's objects are on.
func (s *Service) hsmOf(k Key) HSMBackend { return s.hsmOn(k.Labels[labelHSMConnection]) }

// HSMTarget is one HSM a key can be created on.
type HSMTarget struct {
	// ID is the HSM credential's ID; "" is the tenant's HSM profile.
	ID   string `json:"id"`
	Kind string `json:"kind"` // "tenant_profile" | "credential"
	Name string `json:"name"`
	// Topology is what the operator declared for a credential: "single" or
	// "ha_group" (the vendor's HA group, which the library presents as one
	// slot). The KMS can't see behind the slot, so it is shown as declared.
	Topology string `json:"topology,omitempty"`
	Vendor   string `json:"vendor,omitempty"`
	// Usable: a key can be created on it now. Reason says why not.
	Usable bool       `json:"usable"`
	Reason string     `json:"reason,omitempty"`
	Status hsm.Status `json:"status"`
}

// HSMTargets is what the create, form and import dialogs offer.
type HSMTargets struct {
	Targets []HSMTarget `json:"targets"`
	// CredentialsState is "listed", "not_deployed" (the deployment has no
	// credential store), "not_permitted" (the caller lacks
	// compliance.connection.use) or "unavailable" (with CredentialsError).
	// Only "listed" means the absence of a credential target is real.
	CredentialsState string `json:"credentials_state"`
	CredentialsError string `json:"credentials_error,omitempty"`
}

// ListHSMTargets returns the tenant's HSM profile and its HSM credentials,
// each with the connector's live status.
func (s *Service) ListHSMTargets(ctx context.Context, tenantID string) (HSMTargets, error) {
	out := HSMTargets{Targets: []HSMTarget{}}
	settings, err := s.store.GetHSMSettings(ctx, tenantID)
	if err != nil {
		return out, err
	}
	status := func(connectionID string) hsm.Status {
		st, err := s.hsmOn(connectionID).Status(ctx, tenantID)
		if err != nil {
			st.Error = err.Error()
		}
		return st
	}
	usable := func(t *HSMTarget) {
		switch {
		case t.Status.Connected:
			t.Usable = true
		case t.Status.Error != "":
			t.Reason = t.Status.Error
		default:
			t.Reason = "the HSM is not connected"
		}
	}
	if s.hsm != nil {
		if st := status(""); st.Configured {
			t := HSMTarget{Kind: "tenant_profile", Name: "Tenant HSM (HSM tab)", Vendor: st.ProviderName, Status: st}
			if usable(&t); t.Usable && !settings.HSMKeysEnabled {
				t.Usable, t.Reason = false, "HSM keys are off for the tenant's HSM: turn them on in the HSM tab"
			}
			out.Targets = append(out.Targets, t)
		}
	}
	switch {
	case s.hsmCreds == nil:
		out.CredentialsState = "not_deployed"
	case s.hsm == nil:
		out.CredentialsState, out.CredentialsError = "unavailable", "the HSM connector is not enabled on this platform"
	default:
		creds, err := s.hsmCreds.List(ctx, tenantID)
		switch {
		case errors.Is(err, errHSMCredentialForbidden):
			out.CredentialsState = "not_permitted"
		case err != nil:
			out.CredentialsState, out.CredentialsError = "unavailable", err.Error()
		default:
			out.CredentialsState = "listed"
			for _, c := range creds {
				t := HSMTarget{ID: c.ID, Kind: "credential", Name: c.Name, Topology: firstNonEmptyString(c.Attributes["topology"], "single"),
					Vendor: c.Attributes["vendor"], Status: status(c.ID)}
				usable(&t)
				out.Targets = append(out.Targets, t)
			}
		}
	}
	return out, nil
}

// hsmTarget resolves where req's HSM key goes and checks it can go there:
// the HSM credential it names (which the caller must be allowed to use), or
// the tenant's HSM profile with HSM keys on. It returns the connector
// client and the labels that record the target on the key.
func (s *Service) hsmTarget(ctx context.Context, req CreateKeyRequest, operation string) (HSMBackend, map[string]string, error) {
	refuse := func(status int, reason, msg string) (HSMBackend, map[string]string, error) {
		return nil, nil, s.refuseHSM(ctx, req.TenantID, "", operation, status, reason, msg)
	}
	if s.hsm == nil {
		return refuse(http.StatusServiceUnavailable, "hsm_unavailable", "the HSM connector is not enabled on this platform")
	}
	id := strings.TrimSpace(req.HSMConnectionID)
	if id == "" {
		settings, err := s.store.GetHSMSettings(ctx, req.TenantID)
		if err != nil {
			return nil, nil, err
		}
		if !settings.HSMKeysEnabled {
			return refuse(http.StatusConflict, "hsm_keys_disabled", "HSM keys are off for the tenant's HSM: turn them on in the HSM tab, or choose an HSM credential")
		}
		return s.hsm, map[string]string{}, nil
	}
	if s.hsmCreds == nil {
		return refuse(http.StatusConflict, "hsm_credentials_not_deployed", "this deployment has no credential store (Playbooks): HSM credentials can't be used")
	}
	cred, err := s.hsmCreds.Get(ctx, req.TenantID, id)
	switch {
	case errors.Is(err, errHSMCredentialNotFound):
		return refuse(http.StatusConflict, "hsm_connection_not_found", "no PKCS#11 HSM credential "+id+" for this tenant: add it in Playbooks, Credentials")
	case errors.Is(err, errHSMCredentialForbidden):
		return refuse(http.StatusForbidden, "hsm_credential_not_permitted", "using an HSM credential needs the compliance.connection.use permission")
	case err != nil:
		return refuse(http.StatusServiceUnavailable, "hsm_credentials_unavailable", err.Error())
	}
	backend := s.hsmOn(id)
	st, err := backend.Status(ctx, req.TenantID)
	if err != nil {
		return nil, nil, s.hsmFailure(ctx, req.TenantID, "", operation, err)
	}
	if !st.Connected {
		return refuse(http.StatusConflict, "hsm_not_connected", "HSM credential "+cred.Name+" is not reachable: "+st.Error)
	}
	return backend, map[string]string{
		labelHSMConnection: id, labelHSMConnectionName: cred.Name,
		labelHSMTopology: firstNonEmptyString(cred.Attributes["topology"], "single"),
	}, nil
}

// importHSMKey places existing material in an HSM as a non-extractable key:
// AES material (an imported key, or one formed from components), or an
// imported RSA or ECDSA private key. Keycore keeps no copy.
func (s *Service) importHSMKey(ctx context.Context, req CreateKeyRequest, raw []byte, expectedKCV, operation, auditSubject string) (Key, error) {
	alg := hsm.NormalizeAlgorithm(req.Algorithm)
	symmetric := strings.HasPrefix(alg, "AES-")
	var private *crypto.HSMPrivateKey
	if alg != "" && !symmetric {
		// The material itself says what it is; a public key or a
		// certificate is not something an HSM holds for the KMS.
		var err error
		if private, err = crypto.HSMPrivateKeyFromDER(raw); err == nil {
			defer private.Zeroize()
			if private.Algorithm != alg {
				alg = ""
			}
		} else {
			alg = ""
		}
	}
	if alg == "" {
		return Key{}, s.refuseHSM(ctx, req.TenantID, "", operation, http.StatusBadRequest, "hsm_import_not_supported",
			"AES-128/192/256 material and RSA-2048/3072/4096 or ECDSA P-256/P-384 private keys can be placed in an HSM; create other keys in the HSM instead")
	}
	backend, target, err := s.hsmTarget(ctx, req, operation)
	if err != nil {
		return Key{}, err
	}
	if err := s.enforceFIPSKeyAlgorithm(ctx, req.TenantID, req.Algorithm, operation); err != nil {
		return Key{}, err
	}
	if req.KeyType == "" {
		req.KeyType = inferKeyTypeFromAlgorithm(req.Algorithm)
	}
	if req.CreatedBy == "" {
		req.CreatedBy = "system"
	}
	req.IVMode = "internal" // the HSM generates every IV
	req.Tags = normalizeTags(req.Tags)
	_ = s.store.EnsureDefaultTags(ctx, req.TenantID)
	initialStatus, activationAt, err := resolveActivation(req.ActivationMode, req.ActivationDate)
	if err != nil {
		return Key{}, err
	}
	if err := s.checkPolicy(ctx, PolicyEvaluateRequest{
		TenantID: req.TenantID, Operation: operation, Algorithm: req.Algorithm, Purpose: req.Purpose,
		IVMode: req.IVMode, OpsLimit: req.OpsLimit, KeyStatus: initialStatus,
	}); err != nil {
		return Key{}, err
	}
	// What the HSM must end up holding: an AES key with this check value,
	// or a private key with this public key.
	var want []byte
	if symmetric {
		if want, _, err = computeKCVStrict(req.Algorithm, raw); err != nil {
			return Key{}, err
		}
	} else {
		want, _ = hsmKCV(hsm.GenerateResult{PublicKey: private.PublicKey})
	}
	if expectedKCV != "" && !strings.EqualFold(strings.TrimSpace(expectedKCV), hex.EncodeToString(want)) {
		return Key{}, errors.New("kcv mismatch")
	}
	keyID := newID("key")
	label := hsm.KeyLabel(req.TenantID, keyID, 1)
	gen, err := backend.Import(ctx, req.TenantID, label, alg, raw)
	if errors.Is(err, hsm.ErrImportRefused) {
		return Key{}, s.refuseHSM(ctx, req.TenantID, keyID, operation, http.StatusConflict, "hsm_import_refused", err.Error())
	} else if err != nil {
		return Key{}, s.hsmFailure(ctx, req.TenantID, keyID, operation, err)
	}
	// The HSM answered with its own check value, or the public key of what
	// it now holds: it must be the material that was sent.
	kcv, kcvMethod := want, "aes-ecb-zero"
	if symmetric {
		if len(gen.KCV) > 0 && !crypto.ConstantTimeEqual(gen.KCV, want) {
			_ = backend.Destroy(ctx, req.TenantID, label)
			return Key{}, s.refuseHSM(ctx, req.TenantID, keyID, operation, http.StatusBadGateway, "hsm_kcv_mismatch",
				"the HSM's check value for the imported key differs from the material's: the object was removed")
		}
		if len(gen.KCV) > 0 {
			kcvMethod = "aes-ecb-zero-hsm"
		}
	} else {
		if !bytes.Equal(gen.PublicKey, private.PublicKey) {
			_ = backend.Destroy(ctx, req.TenantID, label)
			return Key{}, s.refuseHSM(ctx, req.TenantID, keyID, operation, http.StatusBadGateway, "hsm_public_key_mismatch",
				"the HSM's public key for the imported key differs from the material's: the objects were removed")
		}
		kcvMethod = "sha256-spki"
	}
	labels := hsmKeyLabels(req.Labels, target, gen.HSM)
	labels[labelHSMOrigin] = "imported"
	key := Key{
		ID: keyID, TenantID: req.TenantID, Name: req.Name, Description: req.Description, Algorithm: req.Algorithm, KeyType: req.KeyType,
		Purpose: req.Purpose, Status: initialStatus, ActivationDate: activationAt, CurrentVersion: 1,
		KCV: kcv, KCVAlgorithm: kcvMethod, IVMode: req.IVMode, Owner: req.Owner, Cloud: req.Cloud, Region: req.Region,
		Compliance: req.Compliance, Tags: req.Tags, Labels: labels,
		ExportAllowed: false, // the key never leaves the HSM
		OpsLimit:      req.OpsLimit, OpsLimitWindow: req.OpsLimitWindow,
		ApprovalRequired: req.ApprovalRequired, ApprovalPolicyID: req.ApprovalPolicyID, CreatedBy: req.CreatedBy,
	}
	ver := KeyVersion{
		ID: newID("kv"), TenantID: req.TenantID, KeyID: keyID, Version: 1,
		EncryptedMaterial: []byte{}, MaterialIV: []byte{}, WrappedDEK: []byte{},
		PublicKey: gen.PublicKey, KCV: kcv, Status: initialStatus, Protection: protectionHSMResident, HSMLabel: label,
	}
	if err := s.store.CreateKeyWithVersion(ctx, key, ver); err != nil {
		_ = backend.Destroy(ctx, req.TenantID, label) // don't leave an orphan in the HSM
		return Key{}, err
	}
	s.exists.AddString(existsToken(req.TenantID, keyID))
	_ = s.cache.Set(ctx, key)
	_ = s.publishAudit(ctx, firstNonEmptyString(auditSubject, "audit.key.create"), req.TenantID, hsmAuditDetails(keyID, kcv, label, alg, labels, gen.HSM))
	return key, nil
}

// hsmKeyLabels are a key's labels with its HSM target and device recorded.
func hsmKeyLabels(requested, target map[string]string, device hsm.Identity) map[string]string {
	labels := map[string]string{}
	for k, v := range requested {
		// A caller can't pre-set where the KMS will look for the key.
		if !strings.HasPrefix(k, "hsm") {
			labels[k] = v
		}
	}
	for k, v := range target {
		labels[k] = v
	}
	labels[labelHSM] = labelHSMResident
	labels[labelHSMSerial], labels[labelHSMToken] = device.SerialNumber, device.TokenLabel
	labels[labelHSMModel], labels[labelHSMManufacturer] = device.Model, device.Manufacturer
	return labels
}

func hsmAuditDetails(keyID string, kcv []byte, label, alg string, labels map[string]string, device hsm.Identity) map[string]any {
	d := map[string]any{
		"key_id": keyID, "kcv": strings.ToUpper(hex.EncodeToString(kcv)), "hsm": true, "hsm_label": label, "algorithm": alg,
		"hsm_serial": device.SerialNumber, "hsm_token": device.TokenLabel, "hsm_model": device.Model,
		"hsm_manufacturer": device.Manufacturer,
	}
	for _, k := range []string{labelHSMConnection, labelHSMConnectionName, labelHSMTopology, labelHSMOrigin} {
		if v := labels[k]; v != "" {
			d[k] = v
		}
	}
	return d
}

// HSMCredentialUse is one HSM credential's keys, for the credential store's
// "used by" and its delete guard.
type HSMCredentialUse struct {
	ConnectionID string `json:"connection_id"`
	Label        string `json:"label"`
}

func (h *Handler) listHSMTargets(c *route.Call) {
	out, err := h.svc.ListHSMTargets(c.R.Context(), c.Tenant)
	if err != nil {
		c.Error(http.StatusInternalServerError, "hsm_targets_failed", err.Error())
		return
	}
	c.Detail("targets", len(out.Targets))
	c.Detail("credentials_state", out.CredentialsState)
	c.JSON(http.StatusOK, map[string]any{"targets": out.Targets, "credentials_state": out.CredentialsState, "credentials_error": out.CredentialsError})
}

// hsmCredentialUsage names the keys on each HSM credential. Only the
// compliance service asks (its delete guard and "used by").
func (h *Handler) hsmCredentialUsage(c *route.Call) {
	if !tenantcheck.IsServicePrincipal(c.Claims) || c.Claims.ClientID != "kms-compliance" {
		c.Refuse(http.StatusForbidden, "caller_not_allowed", "only the credential store asks where HSM credentials are used")
		return
	}
	items := []HSMCredentialUse{}
	const page = 500
	for offset := 0; ; offset += page {
		keys, err := h.svc.store.ListKeys(c.R.Context(), c.Tenant, page, offset)
		if err != nil {
			c.Error(http.StatusInternalServerError, "internal_error", "list HSM keys failed")
			return
		}
		for _, k := range keys {
			// A destroyed key's objects are gone from the HSM.
			if id := k.Labels[labelHSMConnection]; id != "" && !isDeletedLike(k.Status) {
				items = append(items, HSMCredentialUse{ConnectionID: id, Label: "key " + k.Name})
			}
		}
		if len(keys) < page {
			break
		}
	}
	c.Detail("keys", len(items))
	c.JSON(http.StatusOK, map[string]any{"items": items})
}
