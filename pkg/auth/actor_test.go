package auth

import (
	"context"
	"testing"
)

func TestActorIsTheVerifiedCaller(t *testing.T) {
	for _, tc := range []struct {
		name   string
		claims *Claims
		want   string
	}{
		{"a user", &Claims{UserID: " usr_1 ", ClientID: "cli_1", Subject: "alice"}, "usr_1"},
		{"an API client", &Claims{ClientID: "cli_1", Subject: "cli_1"}, "cli_1"},
		{"a subject only", &Claims{Subject: "spiffe://corp/app"}, "spiffe://corp/app"},
		{"empty claims", &Claims{}, ""},
		{"nil claims", nil, ""},
	} {
		if got := Actor(ContextWithClaims(context.Background(), tc.claims)); got != tc.want {
			t.Errorf("%s: %q, want %q", tc.name, got, tc.want)
		}
	}
	if Actor(context.Background()) != "" {
		t.Error("a request without a verified token has no actor")
	}
}
