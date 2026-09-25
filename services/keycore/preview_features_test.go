package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"vecta-kms/pkg/features"
)

// Record-only enterprise controls must say they are previews, on the record
// and on the response, and real capabilities must not.
func TestEnterpriseControlsCarryFeatureStatus(t *testing.T) {
	h, _ := newHandlerForTest(t)
	post := func(path string, body map[string]any) *httptest.ResponseRecorder {
		raw, _ := json.Marshal(body)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, path+"?tenant_id=t1", bytes.NewReader(raw)))
		return rr
	}
	for _, path := range []string{"/enterprise/federation/providers", "/enterprise/binding/policies", "/enterprise/sharing/grants",
		"/enterprise/edge/agents", "/enterprise/metadata/profiles", "/enterprise/escrow/tiers", "/enterprise/advanced-encryption/modes"} {
		rr := post(path, map[string]any{"name": "x", "status": "active"})
		if rr.Code != http.StatusCreated {
			t.Fatalf("%s: %d %s", path, rr.Code, rr.Body.String())
		}
		var out struct {
			Control EnterpriseControlRecord `json:"control"`
		}
		_ = json.Unmarshal(rr.Body.Bytes(), &out)
		if out.Control.FeatureStatus != features.StatusPreview || !features.IsPreview(out.Control.FeatureID) ||
			rr.Header().Get(features.HeaderStatus) != features.StatusPreview {
			t.Fatalf("%s must be labelled preview: %+v header=%q", path, out.Control, rr.Header().Get(features.HeaderStatus))
		}
	}
	rr := post("/enterprise/threat/signals", map[string]any{"name": "signal", "status": "open"})
	var out struct {
		Control EnterpriseControlRecord `json:"control"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	if out.Control.FeatureStatus != features.StatusAvailable || rr.Header().Get(features.HeaderStatus) != "" {
		t.Fatalf("threat signal intake is a real capability and must not be labelled preview: %+v", out.Control)
	}
}

// The audit-chain anchor must not claim a Merkle root or external anchoring.
func TestAuditChainAnchorClaimsNothingFalse(t *testing.T) {
	h, _ := newHandlerForTest(t)
	raw, _ := json.Marshal(map[string]any{"anchor_type": "external", "external_reference": "ticket-42"})
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/enterprise/audit-chain/anchors?tenant_id=t1", bytes.NewReader(raw)))
	if rr.Code != http.StatusCreated {
		t.Fatalf("%d %s", rr.Code, rr.Body.String())
	}
	var out struct {
		Anchor AuditChainAnchor `json:"anchor"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	if out.Anchor.MerkleRoot != "" || out.Anchor.Status != "recorded" || out.Anchor.FeatureStatus != features.StatusPreview ||
		rr.Header().Get(features.HeaderStatus) != features.StatusPreview {
		t.Fatalf("anchor must be an honest preview record: %+v", out.Anchor)
	}
}
