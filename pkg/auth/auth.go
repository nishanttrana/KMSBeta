package auth

import (
	"context"
	"crypto/rsa"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

type ctxKey string

const claimsKey ctxKey = "claims"

type ConfirmationClaims struct {
	X5TS256 string `json:"x5t#S256,omitempty"`
	JKT     string `json:"jkt,omitempty"`
}

type Claims struct {
	TenantID                  string              `json:"tenant_id"`
	AzureTenantID             string              `json:"tid,omitempty"`
	Role                      string              `json:"role"`
	Permissions               []string            `json:"permissions"`
	UserID                    string              `json:"user_id"`
	ClientID                  string              `json:"client_id,omitempty"`
	AuthMode                  string              `json:"auth_mode,omitempty"`
	WorkloadIdentity          string              `json:"workload_identity,omitempty"`
	WorkloadTrustDomain       string              `json:"workload_trust_domain,omitempty"`
	AllowedKeyIDs             []string            `json:"allowed_key_ids,omitempty"`
	HTTPMessageSignatureKeyID string              `json:"http_message_signature_key_id,omitempty"`
	ReplayProtection          bool                `json:"replay_protection,omitempty"`
	Confirmation              *ConfirmationClaims `json:"cnf,omitempty"`
	MustChangePassword        bool                `json:"must_change_password,omitempty"`
	jwt.RegisteredClaims
}

type ParseOptions struct {
	Issuer   string
	Audience string
	Leeway   time.Duration
}

func ParseRS256(tokenString string, publicKey *rsa.PublicKey) (*Claims, error) {
	return ParseRS256WithOptions(tokenString, publicKey, ParseOptions{})
}

func ParseRS256WithOptions(tokenString string, publicKey *rsa.PublicKey, options ParseOptions) (*Claims, error) {
	return ParseRS256WithClaims(tokenString, &Claims{}, publicKey, options)
}

func ParseRS256WithClaims[T jwt.Claims](tokenString string, claims T, publicKey *rsa.PublicKey, options ParseOptions) (T, error) {
	var zero T
	tokenString = strings.TrimSpace(tokenString)
	if tokenString == "" {
		return zero, errors.New("missing bearer token")
	}
	if publicKey == nil {
		return zero, errors.New("missing rsa public key")
	}
	parserOptions := []jwt.ParserOption{
		jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
	}
	if options.Leeway > 0 {
		parserOptions = append(parserOptions, jwt.WithLeeway(options.Leeway))
	}
	if strings.TrimSpace(options.Issuer) != "" {
		parserOptions = append(parserOptions, jwt.WithIssuer(strings.TrimSpace(options.Issuer)))
	}
	if strings.TrimSpace(options.Audience) != "" {
		parserOptions = append(parserOptions, jwt.WithAudience(strings.TrimSpace(options.Audience)))
	}
	parser := jwt.NewParser(parserOptions...)
	token, err := parser.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		if token.Method.Alg() != jwt.SigningMethodRS256.Alg() {
			return nil, errors.New("invalid signing method")
		}
		return publicKey, nil
	})
	if err != nil {
		return zero, err
	}
	if !token.Valid {
		return zero, errors.New("invalid claims")
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
