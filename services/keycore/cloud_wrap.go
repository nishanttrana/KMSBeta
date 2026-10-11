package main

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"

	"vecta-kms/pkg/crypto"
	"vecta-kms/pkg/hsm"
	"vecta-kms/pkg/route"
	"vecta-kms/pkg/tenantcheck"
)

// Cloud BYOK: POST /keys/{id}/cloud-wrap wraps a key version to a cloud
// KMS's RSA import key, so the cloud service can import it
// (docs/SECURITY/CLOUD_BYOK.md). The material never leaves keycore or the
// HSM in the clear:
//   - a KMS key (keycore's DRBG) is unwrapped from its envelope here and
//     wrapped to the cloud key with pkg/crypto;
//   - an HSM key made with cloud import allowed (sensitive, extractable) is
//     wrapped inside the HSM with C_WrapKey (pkg/hsmconnector/byok.go).
//
// Only the cloud service may call it, acting for the user who asked: the
// user's grants must allow the "cloud-import" usage, and the key's export
// policy must allow it to leave. It is an export, with every check export
// makes (posture, access, policy), plus the FIPS mode.

// labelHSMCloudImport marks an HSM key generated extractable for cloud
// import; rotations keep generating it that way. hsm* labels are never taken
// from a caller (hsmKeyLabels, UpdateKey).
const labelHSMCloudImport = "hsm_cloud_import"

// cloudWrapCaller is the only identity that may ask for a cloud wrap.
const cloudWrapCaller = "kms-cloud"

type CloudWrapRequest struct {
	TenantID string `json:"tenant_id"`
	// WrappingKeyB64 is the cloud's RSA import key: DER or PEM, base64.
	WrappingKeyB64 string `json:"wrapping_key_b64"`
	Scheme         string `json:"scheme"`
	// Version to wrap; 0 is the current one. Reimporting the same material
	// (renewing its expiry, restoring it) needs an earlier version.
	Version int `json:"version"`
	// Digest also returns SHA-256 over the material (Salesforce Shield).
	Digest bool `json:"digest"`
}

type CloudWrapResponse struct {
	KeyID             string `json:"key_id"`
	Version           int    `json:"version"`
	Scheme            string `json:"scheme"`
	WrappedB64        string `json:"wrapped_b64"`
	MaterialSHA256B64 string `json:"material_sha256_b64,omitempty"`
	KCV               string `json:"kcv"`
	// Source is where the material lives: "kms" or "hsm".
	Source            string `json:"source"`
	WrappingKeySHA256 string `json:"wrapping_key_sha256"`
	MaterialFormat    string `json:"material_format"` // "raw" | "pkcs8"
}

var errCloudWrapRefused = errors.New("cloud wrap refused")

type cloudWrapRefusal struct {
	status      int
	reason, msg string
}

func (e *cloudWrapRefusal) Error() string { return e.msg }
func (e *cloudWrapRefusal) Unwrap() error { return errCloudWrapRefused }

// gateExport is every check before key material leaves keycore, in any form:
// posture step-up and sync pause, the key access decision for accessOp, the
// key's export policy and the tenant's policy.
func (s *Service) gateExport(ctx context.Context, tenantID string, key Key, accessOp string) error {
	if isDeletedLike(key.Status) {
		return errors.New("cannot export a deleted key")
	}
	if err := s.enforcePostureStepUp(ctx, tenantID, "key.export"); err != nil {
		return err
	}
	if err := s.enforcePostureSyncPause(ctx, tenantID, "key.export"); err != nil {
		return err
	}
	if err := s.enforceKeyAccess(ctx, key, accessOp); err != nil {
		return err
	}
	if !key.ExportAllowed {
		return errors.New("export is disabled by key policy")
	}
	return s.checkPolicy(ctx, PolicyEvaluateRequest{
		TenantID: tenantID, Operation: "key.export", KeyID: key.ID, Algorithm: key.Algorithm, Purpose: key.Purpose,
		IVMode: key.IVMode, OpsTotal: key.OpsTotal, OpsLimit: key.OpsLimit, KeyStatus: key.Status,
		DaysSinceRotation: daysSince(key.UpdatedAt),
		Labels:            map[string]any{"step_up_authenticated": stepUpAuthFromContext(ctx)},
	})
}

// hsmCloudImporter is the part of the connector client cloud import uses.
type hsmCloudImporter interface {
	GenerateForCloudImport(ctx context.Context, tenant, label, algorithm string) (hsm.GenerateResult, error)
	WrapForCloudImport(ctx context.Context, tenant, label string, wrappingKey []byte, scheme string, digest bool) ([]byte, []byte, error)
}

func (s *Service) CloudWrap(ctx context.Context, keyID string, req CloudWrapRequest) (CloudWrapResponse, error) {
	refuse := func(status int, reason, msg string) (CloudWrapResponse, error) {
		return CloudWrapResponse{}, &cloudWrapRefusal{status: status, reason: reason, msg: msg}
	}
	known := false
	for _, sc := range crypto.CloudWrapSchemes {
		known = known || sc == req.Scheme
	}
	if !known {
		return refuse(http.StatusBadRequest, "scheme_not_supported", "scheme must be one of "+strings.Join(crypto.CloudWrapSchemes, ", "))
	}
	rawKey, err := base64.StdEncoding.DecodeString(strings.TrimSpace(req.WrappingKeyB64))
	if err != nil {
		return refuse(http.StatusBadRequest, "bad_wrapping_key", "wrapping_key_b64 must be base64")
	}
	pub, err := crypto.ParseCloudWrappingKey(rawKey)
	if err != nil {
		return refuse(http.StatusBadRequest, "bad_wrapping_key", err.Error())
	}
	if pub.N.BitLen() < 2048 {
		return refuse(http.StatusBadRequest, "bad_wrapping_key", "the cloud's wrapping key must be RSA of at least 2048 bits")
	}
	der, _ := x509.MarshalPKIXPublicKey(pub)
	fingerprint, _ := crypto.FingerprintPublicKey(pub)

	key, err := s.GetKey(ctx, req.TenantID, keyID)
	if err != nil {
		return CloudWrapResponse{}, err
	}
	if err := s.gateExport(ctx, req.TenantID, key, "cloud-import"); err != nil {
		return CloudWrapResponse{}, err
	}
	ver, err := s.GetVersion(ctx, req.TenantID, keyID, req.Version)
	if err != nil {
		return CloudWrapResponse{}, err
	}
	if isDeletedLike(ver.Status) {
		return refuse(http.StatusConflict, "version_destroyed", "this key version is destroyed")
	}
	out := CloudWrapResponse{
		KeyID: key.ID, Version: ver.Version, Scheme: req.Scheme, KCV: strings.ToUpper(hex.EncodeToString(ver.KCV)),
		WrappingKeySHA256: fingerprint, MaterialFormat: "raw",
	}
	if isPublicKeyType(key.KeyType) || inferKeyTypeFromAlgorithm(key.Algorithm) != "symmetric" {
		out.MaterialFormat = "pkcs8"
		if req.Scheme != crypto.CloudWrapRSAAESKWP256 && req.Scheme != crypto.CloudWrapRSAAESKWPSHA1 {
			return refuse(http.StatusBadRequest, "scheme_not_supported", "a private key is wrapped with rsa-aes-kwp-sha256 or rsa-aes-kwp-sha1")
		}
	}

	var wrapped, digest []byte
	if ver.Protection == protectionHSMResident {
		out.Source = "hsm"
		imp, ok := s.hsmOf(key).(hsmCloudImporter)
		if !ok || s.hsm == nil {
			return refuse(http.StatusServiceUnavailable, "hsm_unavailable", "the HSM connector is not enabled on this platform")
		}
		wrapped, digest, err = imp.WrapForCloudImport(ctx, req.TenantID, ver.HSMLabel, der, req.Scheme, req.Digest)
		if errors.Is(err, hsm.ErrNotExtractable) {
			return refuse(http.StatusConflict, "key_not_extractable", "this HSM key was created without cloud import allowed; its value never leaves the HSM")
		}
		if err != nil {
			return CloudWrapResponse{}, s.hsmFailure(ctx, req.TenantID, key.ID, "key.cloud_wrap", err)
		}
	} else {
		out.Source = "kms"
		if crypto.CloudWrapNeedsModuleOutside(req.Scheme) {
			if err := s.enforceFIPSKeyAlgorithm(ctx, req.TenantID, "cloud-wrap:"+req.Scheme, "key.cloud_wrap"); err != nil {
				return CloudWrapResponse{}, err
			}
		}
		material, err := s.decryptMaterial(ver)
		if err != nil {
			return CloudWrapResponse{}, err
		}
		defer crypto.Zeroize(material)
		if out.MaterialFormat == "pkcs8" {
			if _, err := x509.ParsePKCS8PrivateKey(material); err != nil {
				return refuse(http.StatusConflict, "material_not_pkcs8", "this key's private material is not PKCS#8 and can't be imported to a cloud")
			}
		}
		if wrapped, err = crypto.WrapForCloudImport(pub, material, req.Scheme); err != nil {
			if errors.Is(err, crypto.ErrCloudWrapStrict) {
				return CloudWrapResponse{}, fipsModeViolationError{Operation: "key.cloud_wrap", Algorithm: req.Scheme}
			}
			return CloudWrapResponse{}, err
		}
		if req.Digest {
			digest = crypto.SHA256(material)
		}
	}
	out.WrappedB64 = base64.StdEncoding.EncodeToString(wrapped)
	if len(digest) > 0 {
		out.MaterialSHA256B64 = base64.StdEncoding.EncodeToString(digest)
	}
	// Audited by the route kernel as audit.key.cloud_wrapped, with these
	// details (cloudWrap).
	return out, nil
}

func (h *Handler) cloudWrapRouter(audit route.Emitter) *route.Router {
	r := route.New("key", audit, nil)
	r.Handle("POST /keys/{id}/cloud-wrap", route.Spec{Action: "cloud_wrapped", Permission: "key.cloud_import", Resource: "key", TargetParam: "id", Severity: "warning"}, h.cloudWrap)
	return r
}

func (h *Handler) cloudWrap(c *route.Call) {
	// Material for a cloud leaves only through the cloud service, which
	// fetched the wrapping key from the cloud itself.
	if !tenantcheck.IsServicePrincipal(c.Claims) || strings.TrimSpace(c.Claims.ClientID) != cloudWrapCaller {
		c.Refuse(http.StatusForbidden, "caller_not_allowed", "only the cloud service may wrap a key for a cloud import")
		return
	}
	var req CloudWrapRequest
	if !c.Decode(&req) {
		return
	}
	req.TenantID = c.Tenant
	c.Detail("scheme", req.Scheme)
	out, err := h.svc.CloudWrap(c.R.Context(), c.R.PathValue("id"), req)
	var refusal *cloudWrapRefusal
	var denied policyDeniedError
	var fipsDenied fipsModeViolationError
	var hsmRefused *hsmRefusal
	switch {
	case err == nil:
	case errors.As(err, &refusal):
		c.Refuse(refusal.status, refusal.reason, refusal.msg)
		return
	case errors.Is(err, errStoreNotFound):
		c.Error(http.StatusNotFound, "not_found", "key or key version not found")
		return
	case errors.As(err, &denied):
		c.Refuse(http.StatusForbidden, "policy_denied", denied.Error())
		return
	case errors.As(err, &fipsDenied):
		c.Refuse(http.StatusForbidden, "fips_mode_violation", fipsDenied.Error())
		return
	case errors.As(err, new(*accessRefusal)):
		c.Refuse(http.StatusForbidden, "access_denied", err.Error())
		return
	case errors.As(err, &hsmRefused):
		c.Refuse(hsmRefused.Status, hsmRefused.Reason, hsmRefused.Error())
		return
	case strings.Contains(err.Error(), "export is disabled by key policy"):
		c.Refuse(http.StatusForbidden, "export_not_allowed", err.Error())
		return
	default:
		c.Error(http.StatusBadRequest, "cloud_wrap_failed", err.Error())
		return
	}
	c.Detail("version", out.Version)
	c.Detail("source", out.Source)
	c.Detail("wrapping_key_sha256", out.WrappingKeySHA256)
	c.Detail("kcv", out.KCV)
	c.Detail("material_format", out.MaterialFormat)
	c.JSON(http.StatusOK, map[string]interface{}{"data": out})
}
