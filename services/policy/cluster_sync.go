package main

import (
	"fmt"
	"strings"

	"vecta-kms/pkg/clustersync"
)

func policySyncRequest(subject string, tenantID string, data map[string]any) (clustersync.PublishRequest, bool) {
	subject = strings.TrimSpace(strings.ToLower(subject))
	if !strings.HasPrefix(subject, "audit.policy.") {
		return clustersync.PublishRequest{}, false
	}
	action := strings.TrimSpace(strings.TrimPrefix(subject, "audit.policy."))
	switch action {
	case "created", "updated", "deleted":
	default:
		return clustersync.PublishRequest{}, false
	}
	entityID := strings.TrimSpace(fmt.Sprint(data["policy_id"]))
	if entityID == "" || entityID == "<nil>" {
		entityID = strings.TrimSpace(tenantID)
	}
	if entityID == "" {
		return clustersync.PublishRequest{}, false
	}
	payload := map[string]interface{}{}
	for k, v := range data {
		payload[k] = v
	}
	return clustersync.PublishRequest{
		TenantID:   strings.TrimSpace(tenantID),
		Component:  "policy",
		EntityType: "policy",
		EntityID:   entityID,
		Operation:  action,
		Payload:    payload,
	}, true
}
