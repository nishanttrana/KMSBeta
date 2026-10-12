package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"testing"

	"vecta-kms/pkg/clusterstate"
)

// newPair creates a software key pair the way the dashboard does: the
// private key, then its public component with the same pair_id.
func newPair(t *testing.T, svc *Service, tenant, name, algorithm string) (private, public Key) {
	t.Helper()
	ctx := adminCtx()
	labels := func(role string) map[string]string {
		return map[string]string{labelPairID: "pair_" + name, labelComponentRole: role, "pair_name": name}
	}
	private, err := svc.CreateKey(ctx, CreateKeyRequest{TenantID: tenant, Name: name, Algorithm: algorithm, KeyType: "asymmetric-private", Purpose: "sign-verify", CreatedBy: "tester", Labels: labels("private")})
	if err != nil {
		t.Fatalf("private key: %v", err)
	}
	public, err = svc.CreateKey(ctx, CreateKeyRequest{TenantID: tenant, Name: name, Algorithm: algorithm, KeyType: "asymmetric-public", Purpose: "verify", CreatedBy: "tester", Labels: labels("public")})
	if err != nil {
		t.Fatalf("public key: %v", err)
	}
	return private, public
}

func currentMaterial(t *testing.T, svc *Service, tenant, keyID string) (KeyVersion, []byte) {
	t.Helper()
	ver, err := svc.GetVersion(adminCtx(), tenant, keyID, 0)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := svc.decryptMaterial(ver)
	if err != nil {
		t.Fatal(err)
	}
	return ver, raw
}

// inStep reports whether the public component holds the public half of the
// private key's current material.
func inStep(t *testing.T, svc *Service, tenant string, private, public Key) bool {
	t.Helper()
	priv, err := svc.store.GetKey(adminCtx(), tenant, private.ID)
	if err != nil {
		t.Fatal(err)
	}
	_, privRaw := currentMaterial(t, svc, tenant, private.ID)
	want, err := derivePublicFromPrivateMaterial(priv.Algorithm, privRaw)
	if err != nil {
		t.Fatal(err)
	}
	_, have := currentMaterial(t, svc, tenant, public.ID)
	return bytes.Equal(have, want)
}

// Rotating a private key gives its public component the new public key in the
// same step: a signature made after the rotation verifies under the public
// key, and both keys record the rotation.
func TestRotatingAPrivateKeyRenewsItsPublicKey(t *testing.T) {
	for _, algorithm := range []string{"ECDSA-P256", "RSA-2048"} {
		t.Run(algorithm, func(t *testing.T) {
			_, svc, rec := newActorTestHandler(t)
			ctx := adminCtx()
			private, public := newPair(t, svc, "t1", "signer", algorithm)
			_, publicBefore := currentMaterial(t, svc, "t1", public.ID)

			ver, err := svc.RotateKey(ctx, "t1", private.ID, "scheduled", "deactivate")
			if err != nil {
				t.Fatalf("rotate: %v", err)
			}
			if ver.Version != 2 {
				t.Fatalf("private version = %d", ver.Version)
			}
			pubVer, publicAfter := currentMaterial(t, svc, "t1", public.ID)
			if pubVer.Version != 2 || bytes.Equal(publicBefore, publicAfter) {
				t.Fatalf("the public key was not renewed (version %d)", pubVer.Version)
			}
			if !inStep(t, svc, "t1", private, public) {
				t.Fatal("the public key is not the public half of the rotated private key")
			}
			// The version it replaced is kept, deactivated, with its own key.
			old, err := svc.GetVersion(ctx, "t1", public.ID, 1)
			if err != nil || old.Status != "deactivated" {
				t.Fatalf("public v1: %+v %v", old.Status, err)
			}
			if raw, err := svc.decryptMaterial(old); err != nil || !bytes.Equal(raw, publicBefore) {
				t.Fatalf("public v1 no longer holds its key: %v", err)
			}

			data := base64.StdEncoding.EncodeToString([]byte("signed after the rotation"))
			sig, err := svc.Sign(ctx, private.ID, SignRequest{TenantID: "t1", DataB64: data})
			if err != nil {
				t.Fatalf("sign: %v", err)
			}
			res, err := svc.Verify(ctx, public.ID, VerifyRequest{TenantID: "t1", DataB64: data, SignatureB64: sig.SignatureB64})
			if err != nil || !res.Verified {
				t.Fatalf("the public key does not verify its private key's signature: %+v %v", res, err)
			}

			var forPrivate, forPublic map[string]any
			for _, ev := range rec.events {
				if ev["_subject"] != "audit.key.rotate" {
					continue
				}
				d, _ := ev["details"].(map[string]any)
				switch d["key_id"] {
				case private.ID:
					forPrivate = d
				case public.ID:
					forPublic = d
				}
			}
			if forPrivate["public_key_id"] != public.ID {
				t.Fatalf("the private key's rotation does not name its public key: %+v", forPrivate)
			}
			if forPublic["follows_key_id"] != private.ID || forPublic["version"] != float64(2) {
				t.Fatalf("the public key's rotation is not audited as following: %+v", forPublic)
			}
		})
	}
}

// A rotation onto another algorithm moves both halves: the public key takes
// the new algorithm with its private key, under the same two key ids.
func TestPairMovesToANewAlgorithmTogether(t *testing.T) {
	_, svc, _ := newActorTestHandler(t)
	ctx := adminCtx()
	private, public := newPair(t, svc, "t1", "signer", "ECDSA-P256")
	if _, err := svc.RotateKeyTo(ctx, "t1", private.ID, "migration", "deactivate", "ECDSA-P384"); err != nil {
		t.Fatalf("rotate onto ECDSA-P384: %v", err)
	}
	for _, id := range []string{private.ID, public.ID} {
		k, err := svc.store.GetKey(ctx, "t1", id)
		if err != nil || k.Algorithm != "ECDSA-P384" || k.CurrentVersion != 2 {
			t.Fatalf("%s: algorithm %q version %d (%v)", id, k.Algorithm, k.CurrentVersion, err)
		}
	}
	if !inStep(t, svc, "t1", private, public) {
		t.Fatal("the public key did not move to the new algorithm with its private key")
	}
	data := base64.StdEncoding.EncodeToString([]byte("signed with P-384"))
	sig, err := svc.Sign(ctx, private.ID, SignRequest{TenantID: "t1", DataB64: data})
	if err != nil {
		t.Fatal(err)
	}
	if res, err := svc.Verify(ctx, public.ID, VerifyRequest{TenantID: "t1", DataB64: data, SignatureB64: sig.SignatureB64}); err != nil || !res.Verified {
		t.Fatalf("verify under the moved public key: %+v %v", res, err)
	}
}

// A public key is not rotated on its own: one in a pair is pointed at its
// private key, one that was imported has none. Both refusals are audited and
// nothing changes.
func TestPublicKeyIsNotRotatedOnItsOwn(t *testing.T) {
	h, svc, rec := newActorTestHandler(t)
	private, public := newPair(t, svc, "t1", "signer", "ECDSA-P256")
	_, before := currentMaterial(t, svc, "t1", public.ID)

	w := callKeycore(h, http.MethodPost, "/keys/"+public.ID+"/rotate", `{"reason":"manual"}`, textAdmin)
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "public_key_not_rotatable") || !strings.Contains(w.Body.String(), private.ID) {
		t.Fatalf("rotate a paired public key: %d %s", w.Code, w.Body)
	}
	if d := refusalDetails(t, rec, "audit.key.rotate_refused"); d["reason"] != "public_key_follows_private_key" || d["private_key_id"] != private.ID || d["key_id"] != public.ID {
		t.Fatalf("audited as %+v", d)
	}
	if ver, after := currentMaterial(t, svc, "t1", public.ID); ver.Version != 1 || !bytes.Equal(before, after) {
		t.Fatalf("a refused rotation changed the public key (version %d)", ver.Version)
	}

	// An imported public key has no private key here.
	_, pubRaw := currentMaterial(t, svc, "t1", public.ID)
	imported, err := svc.ImportKey(adminCtx(), ImportKeyRequest{
		CreateKeyRequest: CreateKeyRequest{TenantID: "t1", Name: "partner", Algorithm: "ECDSA-P256", KeyType: "asymmetric-public", Purpose: "verify", CreatedBy: "tester"},
		MaterialB64:      base64.StdEncoding.EncodeToString(pubRaw), ImportMethod: "raw",
	})
	if err != nil {
		t.Fatalf("import a public key: %v", err)
	}
	if _, err := svc.RotateKey(adminCtx(), "t1", imported.ID, "manual", "deactivate"); !errors.Is(err, errPublicKeyRotation) {
		t.Fatalf("rotating an imported public key: %v", err)
	}
	if d := refusalDetails(t, rec, "audit.key.rotate_refused"); d["reason"] != "public_key_has_no_private_key" || d["key_id"] != imported.ID {
		t.Fatalf("audited as %+v", d)
	}

	// Nor is one generated on its own: that made a pair and discarded its private key.
	w = callKeycore(h, http.MethodPost, "/keys", `{"tenant_id":"t1","name":"orphan","algorithm":"ECDSA-P256","key_type":"asymmetric-public","purpose":"verify"}`, textAdmin)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "public_key_needs_private_key") {
		t.Fatalf("generate a public key alone: %d %s", w.Code, w.Body)
	}
	if d := refusalDetails(t, rec, "audit.key.create_refused"); d["reason"] != "public_key_needs_private_key" {
		t.Fatalf("audited as %+v", d)
	}
}

// A policy that sweeps keys up rotates the private key and leaves its public
// component to follow; a policy that names the public key is told why not.
func TestRotationPolicyLeavesPublicKeysToFollow(t *testing.T) {
	_, svc, _ := newActorTestHandler(t)
	ctx := adminCtx()
	private, public := newPair(t, svc, "t1", "signer", "ECDSA-P256")

	policy := func(id, filter string) RotationPolicy {
		t.Helper()
		p, err := svc.store.CreateRotationPolicy(ctx, RotationPolicy{ID: id, TenantID: "t1", Name: id, TargetType: rotationTargetKey, TargetFilter: filter, IntervalDays: 90, Enabled: true, Status: "active"})
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	out, err := svc.RunRotationPolicy(ctx, policy("rp_all", "*"), "manual:tester")
	if err != nil || out.Matched != 1 || out.Rotated != 1 || out.Failed != 0 || out.Runs[0].TargetID != private.ID {
		t.Fatalf("policy *: %+v %v", out, err)
	}
	if !inStep(t, svc, "t1", private, public) {
		t.Fatal("the public key did not follow the policy's rotation")
	}

	out, err = svc.RunRotationPolicy(ctx, policy("rp_pub", "id:"+public.ID), "manual:tester")
	if err != nil || out.Matched != 1 || out.Failed != 1 || !strings.Contains(out.Runs[0].Error, private.ID) {
		t.Fatalf("policy id:<public key>: %+v %v", out, err)
	}
}

// A pair left out of step by a rotation before 12.3.0-beta is brought back on
// the primary, once, and audited. A cluster member writes nothing.
func TestResyncPairPublicKeys(t *testing.T) {
	_, svc, rec := newActorTestHandler(t)
	ctx := adminCtx()
	private, public := newPair(t, svc, "t1", "signer", "ECDSA-P256")
	settled, _ := newPair(t, svc, "t1", "untouched", "ECDSA-P256")
	_ = settled

	// What the old rotation did: a new private version, and nothing else.
	raw, err := generateMaterialForCreate("ECDSA-P256", "asymmetric-private")
	if err != nil {
		t.Fatal(err)
	}
	kcv, _, err := computeKCVStrict("ECDSA-P256", raw)
	if err != nil {
		t.Fatal(err)
	}
	stale := KeyVersion{ID: newID("kv"), TenantID: "t1", KeyID: private.ID, Version: 2, KCV: kcv, RotatedFrom: 1, Status: "active"}
	if err := svc.protectMaterial(ctx, &stale, raw); err != nil {
		t.Fatal(err)
	}
	if err := svc.store.RotateVersion(ctx, "t1", private.ID, stale, "old rotation", "deactivate"); err != nil {
		t.Fatal(err)
	}
	_ = svc.cache.Delete(ctx, "t1", private.ID)
	if inStep(t, svc, "t1", private, public) {
		t.Fatal("the pair should be out of step before the resync")
	}

	clusterstate.SetDefault(clusterstate.Static(clusterstate.State{NodeID: "node-2", Role: clusterstate.RoleFollower, PrimaryNodeID: "node-1", PrimaryURL: "https://primary:8210", ForwardCredential: "cred"}))
	n, err := svc.ResyncPairPublicKeys(ctx)
	clusterstate.SetDefault(nil)
	if err != nil || n != 0 || inStep(t, svc, "t1", private, public) {
		t.Fatalf("a cluster member resynced %d key(s): %v", n, err)
	}

	if n, err := svc.ResyncPairPublicKeys(ctx); err != nil || n != 1 {
		t.Fatalf("resync: %d %v", n, err)
	}
	if !inStep(t, svc, "t1", private, public) {
		t.Fatal("the public key is still not its private key's")
	}
	ev := rec.find("audit.key.pair_public_resynced")
	if ev == nil {
		t.Fatal("no audit.key.pair_public_resynced event")
	}
	if d, _ := ev["details"].(map[string]any); d["key_id"] != public.ID || d["private_key_id"] != private.ID || d["version"] != float64(2) || d["from_version"] != float64(1) {
		t.Fatalf("audited as %+v", d)
	}
	if n, err := svc.ResyncPairPublicKeys(context.Background()); err != nil || n != 0 {
		t.Fatalf("a second resync changed %d key(s): %v", n, err)
	}
}
