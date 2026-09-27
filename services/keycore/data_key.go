package main

import (
	"encoding/base64"
	"errors"
	"net/http"

	pkgcrypto "vecta-kms/pkg/crypto"
	"vecta-kms/pkg/route"
)

// Envelope encryption: keycore generates a fresh data key (DEK) and returns
// it wrapped under the named key (the KEK), plus the plaintext DEK unless the
// caller asks for the wrapped copy only. The caller encrypts its data locally
// and stores the wrapped DEK beside the ciphertext; POST /keys/{id}/unwrap
// recovers the DEK. Wrapping goes through Service.Encrypt, so key access,
// policy, FIPS mode, approval, metering and ops limits all apply.

// dataKeyRouter serves data-key generation through the pkg/route kernel; the
// legacy mux mounts it.
func (h *Handler) dataKeyRouter(audit route.Emitter) *route.Router {
	r := route.New("key", audit, nil)
	r.Handle("POST /keys/{id}/generate-data-key", route.Spec{
		Action: "data_key_generated", Permission: "key.wrap", Resource: "key", TargetParam: "id",
	}, h.generateDataKey)
	return r
}

func (h *Handler) generateDataKey(c *route.Call) {
	var req struct {
		TenantID         string `json:"tenant_id"` // enforced by the kernel
		KeyBytes         int    `json:"key_bytes"`
		AAD              string `json:"aad"`
		IncludePlaintext *bool  `json:"include_plaintext"`
	}
	if !c.Decode(&req) {
		return
	}
	if req.KeyBytes == 0 {
		req.KeyBytes = 32
	}
	if req.KeyBytes != 16 && req.KeyBytes != 24 && req.KeyBytes != 32 {
		c.Error(http.StatusBadRequest, "bad_request", "key_bytes must be 16, 24 or 32")
		return
	}
	withPlaintext := req.IncludePlaintext == nil || *req.IncludePlaintext
	c.Detail("key_bytes", req.KeyBytes)
	c.Detail("include_plaintext", withPlaintext)

	dek, err := pkgcrypto.RandomBytes(req.KeyBytes)
	if err != nil {
		c.Error(http.StatusInternalServerError, "random_failed", err.Error())
		return
	}
	defer pkgcrypto.Zeroize(dek)
	dekB64 := base64.StdEncoding.EncodeToString(dek)

	resp, err := h.svc.Encrypt(c.R.Context(), c.R.PathValue("id"), EncryptRequest{
		TenantID: c.Tenant, PlaintextB64: dekB64, AADB64: req.AAD, Operation: "wrap",
	})
	if err != nil {
		refuseKeyOp(c, err, "generate_data_key_failed")
		return
	}
	c.Detail("version", resp.Version)
	out := map[string]interface{}{
		"key_id": resp.KeyID, "version": resp.Version, "kcv": resp.KCV,
		"wrapped_dek": resp.CipherB64, "wrapped_dek_iv": resp.IVB64, "key_bytes": req.KeyBytes,
	}
	if withPlaintext {
		out["plaintext_dek"] = dekB64
	}
	c.JSON(http.StatusOK, out)
}

// refuseKeyOp maps a key-operation error to an audited refusal or error.
func refuseKeyOp(c *route.Call, err error, failCode string) {
	var (
		refusedHSM *hsmRefusal
		denied     policyDeniedError
		fipsDenied fipsModeViolationError
		access     *accessRefusal
		approval   approvalRequiredError
	)
	switch {
	case errors.As(err, &refusedHSM):
		c.Refuse(refusedHSM.Status, refusedHSM.Reason, refusedHSM.Error())
	case errors.Is(err, errOpsLimit):
		c.Refuse(http.StatusTooManyRequests, "ops_limit_reached", "Operation limit reached for this key")
	case errors.As(err, &denied):
		c.Refuse(http.StatusForbidden, "policy_denied", denied.Error())
	case errors.As(err, &fipsDenied):
		c.Refuse(http.StatusForbidden, "fips_mode_violation", fipsDenied.Error())
	case errors.As(err, &access):
		c.Refuse(http.StatusForbidden, access.reason, access.Error())
	case errors.As(err, &approval):
		c.Detail("approval_request_id", approval.RequestID)
		c.JSON(http.StatusAccepted, map[string]interface{}{"status": "pending_approval", "approval_request_id": approval.RequestID})
	case errors.Is(err, errStoreNotFound):
		c.Error(http.StatusNotFound, "not_found", "key not found")
	default:
		c.Error(http.StatusBadRequest, failCode, err.Error())
	}
}
