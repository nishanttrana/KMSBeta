package main

import (
	"context"
	"net/http"

	pkgkeyaccess "vecta-kms/pkg/keyaccess"
)

// evaluateKeyAccess asks the key access gate. When key access is deployed
// (or its deployment is unknown) and gives no decision, the operation is
// refused with 424 key_access_unavailable and audited; it never falls back
// to allow. Without the service the decision reason is key_access_not_deployed.
func (s *Service) evaluateKeyAccess(ctx context.Context, req pkgkeyaccess.EvaluateRequest) (pkgkeyaccess.EvaluateResponse, error) {
	out, err := s.keyAccess.Evaluate(ctx, req)
	if err != nil {
		s.auditKeyAccessRefused(ctx, req, pkgkeyaccess.ReasonUnavailable, err.Error())
		return pkgkeyaccess.EvaluateResponse{}, newServiceError(http.StatusFailedDependency, pkgkeyaccess.ReasonUnavailable, pkgkeyaccess.ErrUnavailable.Error())
	}
	return out, nil
}

// auditKeyAccessRefused records a key operation refused by key access: a
// deny decision, or the service unavailable.
func (s *Service) auditKeyAccessRefused(ctx context.Context, req pkgkeyaccess.EvaluateRequest, reason string, detail string) {
	data := map[string]interface{}{
		"key_id":             req.KeyID,
		"operation":          req.Operation,
		"connector":          req.Connector,
		"resource_id":        req.ResourceID,
		"justification_code": req.JustificationCode,
		"reason":             reason,
		"result":             "refused",
		"severity":           "warning",
	}
	for _, k := range []string{"agent_id", "database_id"} {
		if v, ok := req.Metadata[k]; ok {
			data[k] = v
		}
	}
	if detail != "" {
		data["error"] = detail
	}
	_ = s.publishAudit(ctx, "audit.ekm.key_access_denied", req.TenantID, data)
}

func buildEKMKeyAccessMetadata(engine string, agentID string, databaseID string) map[string]interface{} {
	meta := map[string]interface{}{}
	if engine != "" {
		meta["engine"] = engine
	}
	if agentID != "" {
		meta["agent_id"] = agentID
	}
	if databaseID != "" {
		meta["database_id"] = databaseID
	}
	return meta
}
