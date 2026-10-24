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
	// StatusRetired: a preview replaced by a real feature. Its old records
	// read as retired and new ones are refused (Retired says where it went).
	StatusRetired = "retired"
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
	{"keycore.advanced_encryption_modes", "keycore", "Homomorphic / functional encryption modes", "Registered as controls; no homomorphic or functional encryption is performed. Searchable HMAC tokens are available."},
}

// controlCategories maps keycore enterprise control categories to features.
var controlCategories = map[string]string{
	"advanced_encryption": "keycore.advanced_encryption_modes",
}

// Retired maps keycore enterprise control categories whose preview was
// replaced by a real feature to where that feature is.
var Retired = map[string]string{
	"metadata_profile":    "key metadata profiles: /metadata-profiles in keycore, Keys → Metadata Profiles (13.50.0-beta)",
	"binding_policy":      "key binding policies: /binding-policies in keycore, Keys → Binding policies (13.51.0-beta)",
	"sharing_grant":       "key access grants: PUT /keys/{id}/access-policy, which keycore enforces (13.51.0-beta)",
	"edge_agent":          "edge devices: /ekm/edge/devices and the edge-agent, Enterprise KM → Edge devices (13.52.0-beta)",
	"edge_lease":          "edge devices: leases are issued to enrolled devices at /ekm/edge/devices/{id}/leases (13.52.0-beta)",
	"edge_receipt":        "edge devices: signed receipts at /ekm/edge/devices/{id}/receipts (13.52.0-beta)",
	"federation_provider": "key federation: peers at /federation/peers in keycore, Keys → Federation (13.60.0-beta)",
	"federation_mapping":  "key federation: links at /federation/links replicate keys to a peer (13.60.0-beta)",
	"federation_failover": "key federation: POST /federation/keys/{id}/promote fails a key over to this installation (13.60.0-beta)",
}

// ControlCategoryStatus returns the status of a keycore enterprise control
// category and, for a preview, its feature ID.
func ControlCategoryStatus(category string) (status, featureID string) {
	if _, ok := Retired[category]; ok {
		return StatusRetired, ""
	}
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
