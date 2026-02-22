package auth

import (
	"context"
	"crypto/rsa"
	"errors"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

type ctxKey string

const claimsKey ctxKey = "claims"

type Claims struct {
	TenantID           string   `json:"tenant_id"`
	AzureTenantID      string   `json:"tid,omitempty"`
	Role               string   `json:"role"`
	Permissions        []string `json:"permissions"`
	UserID             string   `json:"user_id"`
	MustChangePassword bool     `json:"must_change_password,omitempty"`
	jwt.RegisteredClaims
}

func ParseRS256(tokenString string, publicKey *rsa.PublicKey) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if token.Method.Alg() != jwt.SigningMethodRS256.Alg() {
			return nil, errors.New("invalid signing method")
		}
		return publicKey, nil
	})
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid claims")
	}
	return claims, nil
}

func ContextWithClaims(ctx context.Context, claims *Claims) context.Context {
	return context.WithValue(ctx, claimsKey, claims)
}

func ClaimsFromContext(ctx context.Context) (*Claims, bool) {
	c, ok := ctx.Value(claimsKey).(*Claims)
	return c, ok
}

func HTTPMiddleware(next http.Handler, parser func(string) (*Claims, error)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer"))
		claims, err := parser(raw)
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r.WithContext(ContextWithClaims(r.Context(), claims)))
	})
}

func UnaryTenantPropagationInterceptor(parser func(string) (*Claims, error)) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		md, _ := metadata.FromIncomingContext(ctx)
		authz := ""
		if vals := md.Get("authorization"); len(vals) > 0 {
			authz = strings.TrimSpace(strings.TrimPrefix(vals[0], "Bearer"))
		}
		if authz != "" {
			if claims, err := parser(authz); err == nil {
				ctx = ContextWithClaims(ctx, claims)
			}
		}
		return handler(ctx, req)
	}
}

func RBACInterceptor(requiredPermission string) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		claims, ok := ClaimsFromContext(ctx)
		if !ok || !hasPermission(claims.Permissions, requiredPermission) {
			return nil, errors.New("forbidden")
		}
		return handler(ctx, req)
	}
}

func hasPermission(perms []string, target string) bool {
	for _, p := range perms {
		if p == target || p == "*" {
			return true
		}
	}
	return false
}
