package main

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"

	"vecta-kms/pkg/clustersync"
)

func (s *Service) keycoreSyncRequest(ctx context.Context, subject string, tenantID string, data map[string]any) (clustersync.PublishRequest, bool) {
	subject = strings.TrimSpace(strings.ToLower(subject))
	if !strings.HasPrefix(subject, "audit.key.") {
		return clustersync.PublishRequest{}, false
	}
	action := strings.TrimSpace(strings.TrimPrefix(subject, "audit.key."))
	if !isKeycoreWriteAction(action) {
		return clustersync.PublishRequest{}, false
	}

	entityType := "key"
	entityID := firstNonEmptyAny(data, "key_id", "id")

	switch {
	case strings.HasPrefix(action, "access_group_"):
		entityType = "access_group"
		entityID = firstNonEmptyAny(data, "group_id", "id", "key_id")
	case strings.HasPrefix(action, "interface_policy_"):
		entityType = "interface_policy"
		entityID = firstNonEmptyAny(data, "id")
	case strings.HasPrefix(action, "interface_port_"):
		entityType = "interface_port"
		entityID = firstNonEmptyAny(data, "interface_name", "name")
	case action == "access_settings_updated":
		entityType = "access_settings"
		entityID = strings.TrimSpace(tenantID)
	case action == "access_policy_updated":
		entityType = "key_access_policy"
	case action == "iv_mode_updated":
		entityType = "key_iv_mode"
	case strings.HasPrefix(action, "version_"):
		entityType = "key_version"
		if keyID := strings.TrimSpace(firstNonEmptyAny(data, "key_id")); keyID != "" {
			if version := strings.TrimSpace(firstNonEmptyAny(data, "version")); version != "" {
				entityID = fmt.Sprintf("%s:%s", keyID, version)
			} else {
				entityID = keyID
			}
		}
	}

	if strings.TrimSpace(entityID) == "" {
		entityID = strings.TrimSpace(tenantID)
	}
	if strings.TrimSpace(entityID) == "" {
		return clustersync.PublishRequest{}, false
	}

	payload := cloneAnyMap(data)
	s.enrichKeycoreSyncPayload(ctx, tenantID, payload)

	return clustersync.PublishRequest{
		TenantID:   strings.TrimSpace(tenantID),
		Component:  "keycore",
		EntityType: entityType,
		EntityID:   entityID,
		Operation:  action,
		Payload:    payload,
	}, true
}

func (s *Service) enrichKeycoreSyncPayload(ctx context.Context, tenantID string, payload map[string]interface{}) {
	keyID := strings.TrimSpace(firstNonEmptyAnyAny(payload, "key_id", "id"))
	if keyID != "" {
		if key, err := s.GetKey(ctx, tenantID, keyID); err == nil {
			payload["key_id"] = key.ID
			payload["key_name"] = key.Name
			payload["key_status"] = key.Status
			payload["key_algorithm"] = key.Algorithm
			payload["key_type"] = key.KeyType
			payload["key_purpose"] = key.Purpose
			payload["key_export_allowed"] = key.ExportAllowed
			payload["key_labels"] = key.Labels
			payload["approval_required"] = key.ApprovalRequired
			payload["approval_policy_id"] = key.ApprovalPolicyID
			payload["key_cloud"] = key.Cloud
			payload["key_region"] = key.Region

			hsmKeyLabel := firstLabel(key.Labels, "hsm_key_label", "pkcs11_label", "hsm_label", "key_label")
			hsmPartition := firstLabel(key.Labels, "hsm_partition_label", "partition_label", "hsm_partition")
			hsmSlotID := firstLabel(key.Labels, "hsm_slot_id", "slot_id")
			hsmProvider := firstLabel(key.Labels, "hsm_provider", "provider")
			nonExportableLabel := firstLabel(key.Labels, "hsm_non_exportable", "non_exportable", "non_exportable_key")
			hsmNonExportable := !key.ExportAllowed || parseBoolString(nonExportableLabel)

			if hsmKeyLabel != "" {
				payload["hsm_key_label"] = hsmKeyLabel
			}
			if hsmPartition != "" {
				payload["hsm_partition_label"] = hsmPartition
			}
			if hsmSlotID != "" {
				payload["hsm_slot_id"] = hsmSlotID
			}
			if hsmProvider != "" {
				payload["hsm_provider"] = hsmProvider
			}
			payload["hsm_non_exportable"] = hsmNonExportable
			if hsmNonExportable {
				payload["key_material_sync"] = "metadata_only"
			} else {
				payload["key_material_sync"] = "wrapped_blob_allowed"
			}
		}
	}

	payload["source_node_id"] = strings.TrimSpace(os.Getenv("CLUSTER_NODE_ID"))
	payload["source_hsm_partition_label"] = firstNonEmptyStringLocal(
		os.Getenv("CLUSTER_HSM_PARTITION_LABEL"),
		os.Getenv("HSM_PARTITION_LABEL"),
		os.Getenv("THALES_PARTITION"),
	)
	payload["source_hsm_key_replication_enabled"] = envBoolLocal("CLUSTER_HSM_KEY_REPLICATION_ENABLED")
	payload["source_mek_in_hsm"] = envBoolLocal("KEYCORE_MEK_IN_HSM")
	payload["source_mek_logical_id"] = strings.TrimSpace(os.Getenv("KEYCORE_MEK_LOGICAL_ID"))
}

func isKeycoreWriteAction(action string) bool {
	switch strings.TrimSpace(action) {
	case "create",
		"import",
		"form",
		"update",
		"rotate",
		"active",
		"activated",
		"deactivated",
		"disabled",
		"destroy_scheduled",
		"destroyed",
		"usage_limit_updated",
		"usage_reset",
		"export_policy_updated",
		"approval_updated",
		"activation_updated",
		"access_policy_updated",
		"access_group_created",
		"access_group_deleted",
		"access_group_members_updated",
		"access_settings_updated",
		"interface_policy_upserted",
		"interface_policy_deleted",
		"interface_port_upserted",
		"interface_port_deleted",
		"iv_mode_updated",
		"version_activated",
		"version_deactivated",
		"version_deleted":
		return true
	default:
		return false
	}
}

func firstNonEmptyAny(m map[string]any, keys ...string) string {
	if m == nil {
		return ""
	}
	for _, key := range keys {
		raw, ok := m[key]
		if !ok || raw == nil {
			continue
		}
		switch v := raw.(type) {
		case string:
			if strings.TrimSpace(v) != "" {
				return strings.TrimSpace(v)
			}
		case fmt.Stringer:
			out := strings.TrimSpace(v.String())
			if out != "" {
				return out
			}
		default:
			out := strings.TrimSpace(fmt.Sprint(v))
			if out != "" && out != "<nil>" {
				return out
			}
		}
	}
	return ""
}

func firstNonEmptyAnyAny(m map[string]interface{}, keys ...string) string {
	if m == nil {
		return ""
	}
	for _, key := range keys {
		raw, ok := m[key]
		if !ok || raw == nil {
			continue
		}
		switch v := raw.(type) {
		case string:
			if strings.TrimSpace(v) != "" {
				return strings.TrimSpace(v)
			}
		default:
			out := strings.TrimSpace(fmt.Sprint(v))
			if out != "" && out != "<nil>" {
				return out
			}
		}
	}
	return ""
}

func cloneAnyMap(in map[string]any) map[string]interface{} {
	if len(in) == 0 {
		return map[string]interface{}{}
	}
	out := make(map[string]interface{}, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func firstLabel(labels KeyLabels, keys ...string) string {
	if len(labels) == 0 {
		return ""
	}
	for _, key := range keys {
		if v := strings.TrimSpace(labels[key]); v != "" {
			return v
		}
	}
	return ""
}

func parseBoolString(v string) bool {
	v = strings.TrimSpace(strings.ToLower(v))
	return v == "true" || v == "1" || v == "yes" || v == "y"
}

func envBoolLocal(key string) bool {
	v := strings.TrimSpace(strings.ToLower(os.Getenv(key)))
	if v == "" {
		return false
	}
	n, err := strconv.ParseBool(v)
	if err == nil {
		return n
	}
	return v == "yes" || v == "y"
}

func firstNonEmptyStringLocal(values ...string) string {
	for _, item := range values {
		if strings.TrimSpace(item) != "" {
			return strings.TrimSpace(item)
		}
	}
	return ""
}
