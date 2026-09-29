package main

import (
	"context"
	"crypto"
	"crypto/sha256"
	"errors"
	"testing"
)

type usageRecorder struct {
	usage string
	actor any
}

type ctxKeyProbe struct{}

func (u *usageRecorder) CreateHSMSigningKey(context.Context, string, string, string) (string, []byte, error) {
	return "", nil, errors.New("not used")
}
func (u *usageRecorder) SignDigest(ctx context.Context, _, _, _ string, _ []byte, usage string) ([]byte, error) {
	u.usage, u.actor = usage, ctx.Value(ctxKeyProbe{})
	return []byte("sig"), nil
}

// crypto.Signer has no context, so the HSM signer carries the request's:
// keycore then signs for the user who asked, with the usage named.
func TestHSMSignerCarriesRequestContextAndUsage(t *testing.T) {
	rec := &usageRecorder{}
	ctx := context.WithValue(context.Background(), ctxKeyProbe{}, "alice")
	signer := &hsmSigner{keys: rec, tenantID: "t1", keyID: "k", ctx: ctx, usage: "crl-sign"}
	digest := sha256.Sum256([]byte("tbs"))
	if _, err := signer.Sign(nil, digest[:], crypto.SHA256); err != nil {
		t.Fatal(err)
	}
	if rec.usage != "crl-sign" || rec.actor != "alice" {
		t.Fatalf("signed with usage %q in context of %v", rec.usage, rec.actor)
	}
}
