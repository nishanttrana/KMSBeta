package delegation

import (
	"context"
	"net/http"
	"testing"

	pkgauth "vecta-kms/pkg/auth"
)

func request() *http.Request {
	r, _ := http.NewRequest(http.MethodPost, "https://keycore:8010/keys/k/usage/meter", nil)
	return r
}

// A user's verified token is forwarded with the usage; a service's token, or
// a context with no token, forwards nothing.
func TestAttachForwardsOnlyAUser(t *testing.T) {
	user := &pkgauth.Claims{UserID: "alice", TenantID: "t1", Role: "operator"}
	ctx := pkgauth.ContextWithVerifiedToken(pkgauth.ContextWithClaims(context.Background(), user), "user-jwt")
	r := request()
	Attach(ctx, r, "fpe-encrypt")
	if r.Header.Get(HeaderToken) != "user-jwt" || r.Header.Get(HeaderUsage) != "fpe-encrypt" {
		t.Fatalf("user not forwarded: %v", r.Header)
	}

	svc := &pkgauth.Claims{ClientID: "kms-compliance", TenantID: "root", Role: "client-service", Permissions: []string{"service.internal"}}
	svcCtx := pkgauth.ContextWithVerifiedToken(pkgauth.ContextWithClaims(context.Background(), svc), "service-jwt")
	for name, c := range map[string]context.Context{
		"service caller": svcCtx,
		"no token":       pkgauth.ContextWithClaims(context.Background(), user),
		"no identity":    context.Background(),
	} {
		r := request()
		Attach(c, r, "fpe-encrypt")
		if r.Header.Get(HeaderToken) != "" || r.Header.Get(HeaderUsage) != "" {
			t.Fatalf("%s: forwarded %v", name, r.Header)
		}
	}
}

// pkg/auth's middleware keeps the verified token for forwarding, and only
// once it has verified it.
func TestMiddlewareKeepsOnlyAVerifiedToken(t *testing.T) {
	parser := func(raw string) (*pkgauth.Claims, error) {
		if raw != "good" {
			return nil, context.Canceled
		}
		return &pkgauth.Claims{UserID: "alice"}, nil
	}
	var kept string
	h := pkgauth.HTTPMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		kept, _ = pkgauth.VerifiedTokenFromContext(r.Context())
	}), parser)
	r := request()
	r.Header.Set("Authorization", "Bearer good")
	h.ServeHTTP(&discard{}, r)
	if kept != "good" {
		t.Fatalf("verified token not kept: %q", kept)
	}
}

type discard struct{ h http.Header }

func (d *discard) Header() http.Header {
	if d.h == nil {
		d.h = http.Header{}
	}
	return d.h
}
func (d *discard) Write(b []byte) (int, error) { return len(b), nil }
func (d *discard) WriteHeader(int)             {}
