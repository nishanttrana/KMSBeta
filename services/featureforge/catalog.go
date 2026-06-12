package main

// DefaultCatalog is the allow-list of config-mode actions. Config mode can ONLY
// produce an action from this list — this bounds the universe of outcomes to a
// reviewed, finite set. Extending self-service means adding a catalog entry AND
// an applier, both through normal code review.
//
// Applier semantics:
//   - "policy" => applied to the real policy service over HTTP.
//   - "stub"   => persisted in featureforge only (wire a real applier later).
func DefaultCatalog() []CatalogAction {
	return []CatalogAction{
		{
			Name:    "policy.restrict_algorithm",
			Summary: "Disallow a named crypto algorithm for a tenant (e.g. RSA-1024).",
			RequiredParams: map[string]string{
				"algorithm": "algorithm identifier to block, e.g. RSA-1024",
			},
			RequiresQuorum: false,
			Sensitive:      false,
			Applier:        "policy",
		},
		{
			Name:    "policy.set_min_key_size",
			Summary: "Set a minimum key size for a key type.",
			RequiredParams: map[string]string{
				"key_type": "key type, e.g. RSA or EC",
				"min_bits": "minimum size in bits, e.g. 2048",
			},
			RequiresQuorum: false,
			Sensitive:      false,
			Applier:        "policy",
		},
		{
			Name:    "policy.require_approval_for",
			Summary: "Require governance approval before a named operation.",
			RequiredParams: map[string]string{
				"operation": "operation name, e.g. key.delete or key.export",
			},
			RequiresQuorum: true,
			Sensitive:      true,
			Applier:        "stub",
		},
		{
			Name:    "pqc.enable_hybrid",
			Summary: "Enable hybrid (classical+PQC) posture on an interface.",
			RequiredParams: map[string]string{
				"interface": "interface name, e.g. rest or kmip",
			},
			RequiresQuorum: true,
			Sensitive:      false,
			Applier:        "stub",
		},
	}
}

// FindAction returns the catalog entry by name, or nil.
func FindAction(catalog []CatalogAction, name string) *CatalogAction {
	for i := range catalog {
		if catalog[i].Name == name {
			return &catalog[i]
		}
	}
	return nil
}
