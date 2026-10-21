package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	pkgcrypto "vecta-kms/pkg/crypto"
)

func wrapperTokenStatus(t *testing.T, err error) int {
	t.Helper()
	var se serviceError
	if !errors.As(err, &se) {
		t.Fatalf("expected a service error, got %v", err)
	}
	return se.HTTPStatus
}

// identifierSignedToken signs wrapper claims the way releases before
// 13.41.0-beta did when no secret was configured: with a key derived from
// the tenant, wrapper and app IDs alone.
func identifierSignedToken(t *testing.T, w FieldEncryptionWrapper, kid string) string {
	t.Helper()
	ikm, err := pkgcrypto.Hash("SHA-256", []byte(fmt.Sprintf("%s|%s|%s|field-wrapper", w.TenantID, w.WrapperID, w.AppID)))
	if err != nil {
		t.Fatal(err)
	}
	key, err := pkgcrypto.HKDFSHA256(ikm, nil, []byte("vecta-field-wrapper-jwt-v1"), 32)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss": "vecta-dataprotect", "aud": "vecta-field-wrapper", "sub": w.WrapperID,
		"tenant_id": w.TenantID, "app_id": w.AppID, "wrapper_id": w.WrapperID,
		"scope": []string{"field-encryption:lease"}, "iat": now.Unix(), "nbf": now.Unix(), "exp": now.Add(time.Hour).Unix(),
	})
	if kid != "" {
		tok.Header["kid"] = kid
	}
	signed, err := tok.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

// issuedWrapperToken issues a token for a wrapper record; the X25519 and
// attestation steps of registration don't touch the token key.
func issuedWrapperToken(t *testing.T, svc *Service, tenant, wrapper, app string) (FieldEncryptionWrapper, string) {
	t.Helper()
	w := FieldEncryptionWrapper{TenantID: tenant, WrapperID: wrapper, AppID: app}
	profile, err := svc.issueWrapperAuthProfile(context.Background(), w)
	if err != nil {
		t.Fatal(err)
	}
	return w, profile.Token
}

func TestWrapperTokenSignedFromIdentifiersIsRefused(t *testing.T) {
	svc, _, _ := newDataProtectService(t)
	ctx := context.Background()
	wrapper, token := issuedWrapperToken(t, svc, "tenant-forge", "wrapper-forge", "app-forge")
	if err := svc.verifyWrapperAuthProfileToken(ctx, token, wrapper, "field-encryption:lease"); err != nil {
		t.Fatalf("issued token refused: %v", err)
	}
	for _, kid := range []string{"", "1"} {
		forged := identifierSignedToken(t, wrapper, kid)
		err := svc.verifyWrapperAuthProfileToken(ctx, forged, wrapper, "field-encryption:lease")
		if err == nil || wrapperTokenStatus(t, err) != http.StatusUnauthorized {
			t.Fatalf("identifier-signed token (kid %q): want 401, got %v", kid, err)
		}
	}
}

func TestWrapperTokenOutlivesSigningKeyRotation(t *testing.T) {
	svc, _, _ := newDataProtectService(t)
	ctx := context.Background()
	wrapper, token := issuedWrapperToken(t, svc, "tenant-rotate", "wrapper-rotate", "app-rotate")
	svc.jwtKeys.src.(*fakeWrapperTokenSource).version = 2
	if err := svc.verifyWrapperAuthProfileToken(ctx, token, wrapper, "field-encryption:lease"); err != nil {
		t.Fatalf("token signed before rotation refused: %v", err)
	}
	profile, err := svc.issueWrapperAuthProfile(ctx, wrapper)
	if err != nil {
		t.Fatal(err)
	}
	parsed, _, err := jwt.NewParser().ParseUnverified(profile.Token, jwt.MapClaims{})
	if err != nil || parsed.Header["kid"] != "2" {
		t.Fatalf("token after rotation: want kid 2, got %v (%v)", parsed.Header["kid"], err)
	}
	if err := svc.verifyWrapperAuthProfileToken(ctx, profile.Token, wrapper, "field-encryption:lease"); err != nil {
		t.Fatalf("token signed after rotation refused: %v", err)
	}
}

func TestWrapperTokenFailsClosedWithoutKeycore(t *testing.T) {
	svc, _, _ := newDataProtectService(t)
	ctx := context.Background()
	wrapper, token := issuedWrapperToken(t, svc, "tenant-down", "wrapper-down", "app-down")

	down := NewService(svc.store, svc.keycore, svc.events, WithWrapperTokenKeys(&fakeWrapperTokenSource{version: 1, fail: true}))
	if _, err := down.issueWrapperAuthProfile(ctx, wrapper); err == nil || wrapperTokenStatus(t, err) != http.StatusServiceUnavailable {
		t.Fatalf("issue without keycore: want 503, got %v", err)
	}
	if err := down.verifyWrapperAuthProfileToken(ctx, token, wrapper, "field-encryption:lease"); err == nil || wrapperTokenStatus(t, err) != http.StatusServiceUnavailable {
		t.Fatalf("verify without keycore: want 503, got %v", err)
	}
	unset := NewService(svc.store, svc.keycore, svc.events)
	if _, err := unset.issueWrapperAuthProfile(ctx, wrapper); err == nil {
		t.Fatal("a service with no wrapper token key issued a token")
	}
}
