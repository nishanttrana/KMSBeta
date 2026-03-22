package main

import (
	"context"

	pkgkeyaccess "vecta-kms/pkg/keyaccess"
)

func (s *Service) evaluateKeyAccess(ctx context.Context, req pkgkeyaccess.EvaluateRequest) (pkgkeyaccess.EvaluateResponse, error) {
	if s.keyAccess == nil {
		return pkgkeyaccess.EvaluateResponse{Action: "allow"}, nil
	}
	out, err := s.keyAccess.Evaluate(ctx, req)
	if err != nil {
		return pkgkeyaccess.EvaluateResponse{Action: "allow", Reason: "key access justifications service unavailable"}, nil
	}
	return out, nil
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
