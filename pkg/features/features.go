// Package features is the single catalogue of features that are not
// production-complete (docs/PREVIEW_FEATURES.md). A preview feature stores
// configuration but enforces or executes nothing, so every surface must say
// so: services label responses (HeaderStatus, feature_status), the dashboard
// shows a Preview badge (web/dashboard/src/lib/featureStatus.ts, kept in sync
// by scripts/conformance.sh), and the docs list them. Never present a preview
// feature as implemented (CLAUDE.md rule 7).
package features

import "net/http"

// HeaderStatus is set to StatusPreview on every response of a preview feature.
const HeaderStatus = "X-Vecta-Feature-Status"

const (
	StatusAvailable = "available"
	StatusPreview   = "preview"
)

type Feature struct {
	ID      string `json:"id"`
	Service string `json:"service"`
	Name    string `json:"name"`
	// Limitation states plainly what does not happen.
	Limitation string `json:"limitation"`
}

// Preview lists every preview feature. IDs are stable; the dashboard mirrors
// them.
var Preview = []Feature{
	{"keycore.federation", "keycore", "Key federation / multi-KMS failover", "Providers, mappings and failovers are stored; no key is replicated and no failover happens."},
	{"keycore.binding_policy", "keycore", "Key binding policies", "Stored only; key operations do not evaluate them."},
	{"keycore.sharing_grant", "keycore", "Fine-grained key sharing grants", "Stored only; use key access grants for enforced sharing."},
	{"keycore.metadata_profile", "keycore", "Key metadata profiles", "Stored only; key creation does not apply or validate them."},
	{"keycore.escrow_tier", "keycore", "Escrow tiers", "Stored only; Shamir split/verify and escrow recovery do not use them."},
	{"keycore.edge", "keycore", "Edge & IoT agents, leases and receipts", "Stored only; the edge runtime lives in the KMSExtension product."},
	{"keycore.advanced_encryption_modes", "keycore", "Homomorphic / functional encryption modes", "Registered as controls; no homomorphic or functional encryption is performed. Searchable HMAC tokens are available."},
	{"keycore.audit_chain_anchor", "keycore", "External audit-chain anchors", "Records an external reference in a local hash chain; nothing is anchored externally. Audit tamper evidence comes from the audit service (hash chain, per-event HMAC, Merkle epochs)."},
	{"backup.scheduler", "backup", "Backup policies, runs and restore points (Backup tab)", "Policies are stored but no backup is executed or restored. Real encrypted backups: System Administration > Backups."},
}

// controlCategories maps keycore enterprise control categories to features.
var controlCategories = map[string]string{
	"federation_provider": "keycore.federation",
	"federation_mapping":  "keycore.federation",
	"federation_failover": "keycore.federation",
	"binding_policy":      "keycore.binding_policy",
	"sharing_grant":       "keycore.sharing_grant",
	"metadata_profile":    "keycore.metadata_profile",
	"escrow_tier":         "keycore.escrow_tier",
	"edge_agent":          "keycore.edge",
	"edge_lease":          "keycore.edge",
	"edge_receipt":        "keycore.edge",
	"advanced_encryption": "keycore.advanced_encryption_modes",
}

// ControlCategoryStatus returns the status of a keycore enterprise control
// category and, for a preview, its feature ID.
func ControlCategoryStatus(category string) (status, featureID string) {
	if id, ok := controlCategories[category]; ok {
		return StatusPreview, id
	}
	return StatusAvailable, ""
}

// IsPreview reports whether id names a preview feature.
func IsPreview(id string) bool {
	for _, f := range Preview {
		if f.ID == id {
			return true
		}
	}
	return false
}

// MarkPreview labels an HTTP response as coming from a preview feature.
func MarkPreview(w http.ResponseWriter, id string) {
	w.Header().Set(HeaderStatus, StatusPreview)
	w.Header().Set(HeaderStatus+"-Id", id)
}
