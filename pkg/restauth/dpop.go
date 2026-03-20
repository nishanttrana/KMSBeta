package restauth

import (
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type DPoPProof struct {
	JTI       string    `json:"jti"`
	JKT       string    `json:"jkt"`
	HTM       string    `json:"htm"`
	HTU       string    `json:"htu"`
	IssuedAt  time.Time `json:"issued_at"`
	Algorithm string    `json:"algorithm,omitempty"`
}

func VerifyDPoPProof(raw string, method string, allowedHTU []string, accessToken string, maxAge time.Duration) (DPoPProof, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return DPoPProof{}, errors.New("missing DPoP proof")
	}
	if maxAge <= 0 {
		maxAge = 5 * time.Minute
	}
	var selectedJWK map[string]any
	claims := jwt.MapClaims{}
	parser := jwt.NewParser(jwt.WithValidMethods([]string{"ES256", "ES384", "RS256", "EdDSA"}))
	token, err := parser.ParseWithClaims(value, claims, func(token *jwt.Token) (interface{}, error) {
		if !strings.EqualFold(strings.TrimSpace(valueToString(token.Header["typ"])), "dpop+jwt") {
			return nil, errors.New("invalid DPoP typ")
		}
		jwkRaw, ok := token.Header["jwk"].(map[string]any)
		if !ok || len(jwkRaw) == 0 {
			return nil, errors.New("missing DPoP jwk header")
		}
		selectedJWK = jwkRaw
		return JWKPublicKey(jwkRaw)
	})
	if err != nil {
		return DPoPProof{}, err
	}
	if !token.Valid {
		return DPoPProof{}, errors.New("invalid DPoP proof")
	}
	jkt, err := JWKThumbprint(selectedJWK)
	if err != nil {
		return DPoPProof{}, err
	}
	htm := strings.ToUpper(strings.TrimSpace(valueToString(claims["htm"])))
	if htm == "" || htm != strings.ToUpper(strings.TrimSpace(method)) {
		return DPoPProof{}, errors.New("dpop htm mismatch")
	}
	htu := strings.TrimSpace(valueToString(claims["htu"]))
	if htu == "" || !matchesCandidate(htu, allowedHTU) {
		return DPoPProof{}, errors.New("dpop htu mismatch")
	}
	jti := strings.TrimSpace(valueToString(claims["jti"]))
	if jti == "" {
		return DPoPProof{}, errors.New("missing dpop jti")
	}
	iat, err := parseJWTNumericTime(claims["iat"])
	if err != nil {
		return DPoPProof{}, errors.New("invalid dpop iat")
	}
	now := time.Now().UTC()
	if now.Sub(iat) > maxAge || iat.Sub(now) > maxAge {
		return DPoPProof{}, errors.New("dpop proof outside replay window")
	}
	if strings.TrimSpace(accessToken) != "" {
		expectedATH := accessTokenHash(accessToken)
		ath := strings.TrimSpace(valueToString(claims["ath"]))
		if ath == "" || ath != expectedATH {
			return DPoPProof{}, errors.New("dpop ath mismatch")
		}
	}
	return DPoPProof{
		JTI:       jti,
		JKT:       jkt,
		HTM:       htm,
		HTU:       htu,
		IssuedAt:  iat,
		Algorithm: strings.TrimSpace(token.Method.Alg()),
	}, nil
}

func RequestDPoPCandidates(r *http.Request) []string {
	return RequestURLCandidates(r)
}

func parseJWTNumericTime(value any) (time.Time, error) {
	switch v := value.(type) {
	case float64:
		return time.Unix(int64(v), 0).UTC(), nil
	case int64:
		return time.Unix(v, 0).UTC(), nil
	case int:
		return time.Unix(int64(v), 0).UTC(), nil
	case jsonNumber:
		n, err := v.Int64()
		if err != nil {
			return time.Time{}, err
		}
		return time.Unix(n, 0).UTC(), nil
	default:
		return time.Time{}, errors.New("unsupported numeric time")
	}
}

type jsonNumber interface {
	Int64() (int64, error)
}

func accessTokenHash(token string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(token)))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func matchesCandidate(value string, candidates []string) bool {
	target := strings.TrimSpace(value)
	for _, candidate := range candidates {
		if target == strings.TrimSpace(candidate) {
			return true
		}
	}
	return false
}

func ProofKey(publicKey crypto.PublicKey) string {
	switch key := publicKey.(type) {
	case []byte:
		return base64.RawURLEncoding.EncodeToString(key)
	default:
		_ = key
		return ""
	}
}
