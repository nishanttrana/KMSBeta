package main

import (
	"context"
	"testing"
	"time"
)

type memStore struct {
	policy  AttestationPolicy
	records []AttestedReleaseRecord
}

func (m *memStore) GetAttestationPolicy(context.Context, string) (AttestationPolicy, error) {
	return m.policy, nil
}
func (m *memStore) UpsertAttestationPolicy(_ context.Context, p AttestationPolicy) (AttestationPolicy, error) {
	m.policy = p
	return p, nil
}
func (m *memStore) InsertReleaseRecord(_ context.Context, r AttestedReleaseRecord) error {
	m.records = append(m.records, r)
	return nil
}
func (m *memStore) ListReleaseRecords(context.Context, string, int) ([]AttestedReleaseRecord, error) {
	return m.records, nil
}
func (m *memStore) GetReleaseRecord(context.Context, string, string) (AttestedReleaseRecord, error) {
	return AttestedReleaseRecord{}, nil
}

// Generic evidence is whatever the caller typed; a request that asserts every
// safety property is still never allowed.
func TestGenericEvidenceIsNeverAllowed(t *testing.T) {
	pol := defaultAttestationPolicy("t1")
	pol.Enabled, pol.Provider = true, "generic"
	pol.RequiredMeasurements = map[string]string{}
	svc := NewService(&memStore{policy: pol}, nil, "node-1")
	d, err := svc.EvaluateAttestedRelease(context.Background(), AttestedReleaseRequest{
		TenantID: "t1", KeyID: "k1", Provider: "generic",
		SecureBoot: true, DebugDisabled: true, EvidenceIssuedAt: time.Now().UTC().Format(time.RFC3339),
	})
	if err != nil {
		t.Fatal(err)
	}
	if d.Allowed || d.Decision == "allow" {
		t.Fatalf("self-asserted evidence allowed: %+v", d)
	}
}
