package main

import (
	"strings"
	"time"
)

// WorkflowTemplate bundles a complete lifecycle posture for a class of
// keys. Operators pick a template at creation time instead of choosing
// ten settings individually; the reconciler then enforces the bundled
// policy across the key's lifetime.
//
// Templates are intentionally opinionated. They reflect concrete
// regulatory baselines (PCI DSS, HIPAA, FIPS 140-3 Level 2) rather than
// the union of "everything someone might want." Operators who need
// off-template behaviour create a key manually.
type WorkflowTemplate struct {
	ID                  string
	Description         string
	Algorithm           string
	KeyType             string
	Purpose             string
	IVMode              string
	OpsLimit            int64
	Cryptoperiod        time.Duration
	ExportAllowed       bool
	ApprovalRequired    bool
	ApprovalQuorum      int
	MinAlgorithmTier    string
	RequiredLabels      []string
	GraceWindow         time.Duration
	AutoArchive         bool
	AutoRotateOnExpire  bool
}

// builtinTemplates is the curated registry. Operators reference templates
// by ID at key-creation time; the reconciler reads from this table when
// applying lifecycle decisions, so a template change is the single point
// of policy update for all keys using it.
var builtinTemplates = map[string]WorkflowTemplate{
	"pci-dss-payment": {
		ID:                 "pci-dss-payment",
		Description:        "PCI DSS v4.0 payment card data encryption key (Req 3.6, 3.7).",
		Algorithm:          "AES-256-GCM",
		KeyType:            "symmetric",
		Purpose:            "symmetric_encrypt",
		IVMode:             "internal",
		OpsLimit:           1 << 30,
		Cryptoperiod:       365 * 24 * time.Hour,
		ExportAllowed:      false,
		ApprovalRequired:   true,
		ApprovalQuorum:     2,
		MinAlgorithmTier:   "classical-256",
		RequiredLabels:     []string{"owner", "data_class"},
		GraceWindow:        30 * 24 * time.Hour,
		AutoArchive:        true,
		AutoRotateOnExpire: true,
	},
	"hipaa-phi": {
		ID:                 "hipaa-phi",
		Description:        "HIPAA Security Rule §164.312 PHI encryption key.",
		Algorithm:          "AES-256-GCM",
		KeyType:            "symmetric",
		Purpose:            "symmetric_encrypt",
		IVMode:             "internal",
		OpsLimit:           1 << 30,
		Cryptoperiod:       730 * 24 * time.Hour,
		ExportAllowed:      false,
		ApprovalRequired:   true,
		ApprovalQuorum:     2,
		MinAlgorithmTier:   "classical-256",
		RequiredLabels:     []string{"owner", "data_class", "data_subject_region"},
		GraceWindow:        90 * 24 * time.Hour,
		AutoArchive:        true,
		AutoRotateOnExpire: true,
	},
	"fips-140-3-internal": {
		ID:                 "fips-140-3-internal",
		Description:        "FIPS 140-3 Level 1+ internal symmetric encryption key.",
		Algorithm:          "AES-256-GCM",
		KeyType:            "symmetric",
		Purpose:            "symmetric_encrypt",
		IVMode:             "internal",
		OpsLimit:           1 << 32,
		Cryptoperiod:       730 * 24 * time.Hour,
		ExportAllowed:      false,
		ApprovalRequired:   false,
		MinAlgorithmTier:   "classical-256",
		RequiredLabels:     []string{"owner"},
		GraceWindow:        30 * 24 * time.Hour,
		AutoArchive:        true,
		AutoRotateOnExpire: true,
	},
	"pqc-hybrid-data": {
		ID:                 "pqc-hybrid-data",
		Description:        "Hybrid PQC envelope key (X25519 + ML-KEM-768) for long-retention data.",
		Algorithm:          "AES-256-GCM+ML-KEM-768",
		KeyType:            "symmetric",
		Purpose:            "symmetric_encrypt",
		IVMode:             "internal",
		OpsLimit:           1 << 30,
		Cryptoperiod:       730 * 24 * time.Hour,
		ExportAllowed:      false,
		ApprovalRequired:   false,
		MinAlgorithmTier:   "pqc-hybrid",
		RequiredLabels:     []string{"owner", "y2q_window_years"},
		GraceWindow:        180 * 24 * time.Hour,
		AutoArchive:        true,
		AutoRotateOnExpire: true,
	},
	"signing-pqc-hybrid": {
		ID:                 "signing-pqc-hybrid",
		Description:        "Composite signing key (ML-DSA-65 + ECDSA-P256) for transitional verifier support.",
		Algorithm:          "ML-DSA-65+ECDSA-P256",
		KeyType:            "asymmetric",
		Purpose:            "signing",
		OpsLimit:           1 << 24,
		Cryptoperiod:       365 * 24 * time.Hour,
		ExportAllowed:      false,
		ApprovalRequired:   true,
		ApprovalQuorum:     2,
		MinAlgorithmTier:   "pqc-hybrid",
		RequiredLabels:     []string{"owner", "signer_scope"},
		GraceWindow:        30 * 24 * time.Hour,
		AutoArchive:        true,
		AutoRotateOnExpire: true,
	},
}

// LookupWorkflowTemplate returns the named template (case-insensitive)
// and a found flag. Unknown templates do not error — callers fall back
// to the create-key path's individual flags.
func LookupWorkflowTemplate(id string) (WorkflowTemplate, bool) {
	id = strings.ToLower(strings.TrimSpace(id))
	if id == "" {
		return WorkflowTemplate{}, false
	}
	tpl, ok := builtinTemplates[id]
	return tpl, ok
}

// ListWorkflowTemplates is the GET endpoint payload. Returned templates
// are deep-copied so callers cannot mutate the registry.
func ListWorkflowTemplates() []WorkflowTemplate {
	out := make([]WorkflowTemplate, 0, len(builtinTemplates))
	for _, t := range builtinTemplates {
		cp := t
		// Slice fields need explicit copies to avoid sharing the backing array.
		if len(t.RequiredLabels) > 0 {
			cp.RequiredLabels = append([]string(nil), t.RequiredLabels...)
		}
		out = append(out, cp)
	}
	return out
}

// ApplyTemplate overlays a template's settings onto a CreateKeyRequest.
// Operator-supplied values take precedence — the template is a baseline,
// not an override.
func ApplyTemplate(req *CreateKeyRequest, tpl WorkflowTemplate) {
	if req.Algorithm == "" {
		req.Algorithm = tpl.Algorithm
	}
	if req.KeyType == "" {
		req.KeyType = tpl.KeyType
	}
	if req.Purpose == "" {
		req.Purpose = tpl.Purpose
	}
	if req.IVMode == "" {
		req.IVMode = tpl.IVMode
	}
	if req.OpsLimit == 0 {
		req.OpsLimit = tpl.OpsLimit
	}
	if !tpl.ExportAllowed {
		req.ExportAllowed = false
	}
	if tpl.ApprovalRequired {
		req.ApprovalRequired = true
	}
}
