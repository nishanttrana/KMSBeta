package sigv4

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

// Requests signed by the AWS SDK's own SigV4 signer, as AWS KMS signs XKS
// proxy calls, verify; any change to what was signed does not.

const (
	keyID  = "AKIAXKSPROXYEXAMPLE2"
	secret = "Ds7qWm2yVdS9xF8u3kP0nL5tB1gR6hJ4cZ8vX2wQ7eY"
)

func lookup(id string) (string, bool) { return secret, id == keyID }

func signed(t *testing.T, path string, body []byte, at time.Time, svc, region string) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "https://kms.example.com"+path, bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	sum := sha256.Sum256(body)
	err := v4.NewSigner().SignHTTP(context.Background(), aws.Credentials{AccessKeyID: keyID, SecretAccessKey: secret}, r, hex.EncodeToString(sum[:]), svc, region, at)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestVerifiesTheAWSSignerAndRefusesAlterations(t *testing.T) {
	now := time.Date(2026, 10, 21, 10, 0, 0, 0, time.UTC)
	path := "/svc/hyok/xks/tenant-a/kms/xks/v1/keys/key-1/encrypt"
	body := []byte(`{"requestMetadata":{"kmsRequestId":"r1","kmsOperation":"Encrypt"},"plaintext":"AAAA"}`)

	r := signed(t, path, body, now, "kms-xks-proxy", "us-east-1")
	got, err := Verify(r, body, path, "kms-xks-proxy", lookup, now.Add(30*time.Second))
	if err != nil || got.AccessKeyID != keyID || got.Region != "us-east-1" {
		t.Fatalf("a valid signature: %+v %v", got, err)
	}

	cases := map[string]struct {
		req  *http.Request
		body []byte
		path string
		now  time.Time
		want error
	}{
		"body changed":    {signed(t, path, body, now, "kms-xks-proxy", "us-east-1"), []byte(`{"plaintext":"BBBB"}`), path, now, ErrSignature},
		"path changed":    {signed(t, path, body, now, "kms-xks-proxy", "us-east-1"), body, "/svc/hyok/xks/tenant-b/kms/xks/v1/keys/key-1/encrypt", now, ErrSignature},
		"other service":   {signed(t, path, body, now, "kms", "us-east-1"), body, path, now, ErrService},
		"too old":         {signed(t, path, body, now, "kms-xks-proxy", "us-east-1"), body, path, now.Add(6 * time.Minute), ErrSkew},
		"from the future": {signed(t, path, body, now.Add(6*time.Minute), "kms-xks-proxy", "us-east-1"), body, path, now, ErrSkew},
		"unsigned":        {httptest.NewRequest(http.MethodPost, "https://kms.example.com"+path, nil), body, path, now, ErrMissing},
	}
	for name, tc := range cases {
		if _, err := Verify(tc.req, tc.body, tc.path, "kms-xks-proxy", lookup, tc.now); !errors.Is(err, tc.want) {
			t.Fatalf("%s: got %v, want %v", name, err, tc.want)
		}
	}

	wrongKey := signed(t, path, body, now, "kms-xks-proxy", "us-east-1")
	if _, err := Verify(wrongKey, body, path, "kms-xks-proxy", func(string) (string, bool) { return secret + "x", true }, now); !errors.Is(err, ErrSignature) {
		t.Fatalf("another secret: %v", err)
	}
	if _, err := Verify(wrongKey, body, path, "kms-xks-proxy", func(string) (string, bool) { return "", false }, now); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("unknown key: %v", err)
	}
	host := signed(t, path, body, now, "kms-xks-proxy", "us-east-1")
	host.Host = "attacker.example.com"
	if _, err := Verify(host, body, path, "kms-xks-proxy", lookup, now); !errors.Is(err, ErrSignature) {
		t.Fatalf("another host: %v", err)
	}
}
