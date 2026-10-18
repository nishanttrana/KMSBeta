package main

import "vecta-kms/pkg/cryptocatalog"

// AlgorithmFacts is pkg/cryptocatalog's assessment of a certificate's
// algorithm, returned with the certificate so that no client keeps its own
// algorithm list (CLAUDE.md, "Crypto and transport standards"). Assessed is
// false when the name states no parameter set; the other fields are then
// unset, never guessed.
type AlgorithmFacts struct {
	Assessed          bool   `json:"assessed"`
	SecurityBits      int    `json:"security_bits,omitempty"`
	Weak              bool   `json:"weak"`
	QuantumVulnerable bool   `json:"quantum_vulnerable"`
	PostQuantum       bool   `json:"post_quantum"`
	Note              string `json:"note,omitempty"`
}

func algorithmFacts(algorithm string) *AlgorithmFacts {
	a := cryptocatalog.Assess(algorithm)
	if !a.Assessed {
		return &AlgorithmFacts{}
	}
	e := a.Entry
	return &AlgorithmFacts{Assessed: true, SecurityBits: e.SecurityBits, Weak: e.Weak, QuantumVulnerable: e.QuantumVulnerable, PostQuantum: e.PostQuantum, Note: e.Note}
}

func withAlgorithmFacts(c Certificate) Certificate {
	c.AlgorithmFacts = algorithmFacts(c.Algorithm)
	return c
}
