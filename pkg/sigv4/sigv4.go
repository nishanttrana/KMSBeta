// Package sigv4 verifies AWS Signature Version 4 on an incoming request.
// AWS KMS signs its calls to an external key store (XKS) proxy this way,
// with the credential the customer configured on both sides, service
// "kms-xks-proxy". The signature is the caller's credential: the HMAC chain
// is computed with pkg/crypto and compared in constant time.
package sigv4

import (
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"vecta-kms/pkg/crypto"
)

const algorithm = "AWS4-HMAC-SHA256"

// MaxSkew is how far x-amz-date may be from the server's clock.
const MaxSkew = 5 * time.Minute

var (
	ErrMissing    = errors.New("sigv4: no AWS4-HMAC-SHA256 authorization")
	ErrMalformed  = errors.New("sigv4: malformed authorization")
	ErrUnknownKey = errors.New("sigv4: unknown access key id")
	ErrService    = errors.New("sigv4: credential scope names another service")
	ErrSkew       = errors.New("sigv4: request time outside the allowed window")
	ErrSignature  = errors.New("sigv4: signature does not match")
)

var reAuth = regexp.MustCompile(`^AWS4-HMAC-SHA256\s+Credential=([^/,\s]+)/(\d{8})/([a-z0-9-]+)/([a-z0-9-]+)/aws4_request,\s*SignedHeaders=([a-z0-9;-]+),\s*Signature=([0-9a-f]{64})$`)

// Verified is what a valid signature proves.
type Verified struct {
	AccessKeyID string
	Region      string
	Time        time.Time
}

// Lookup returns the secret for an access key ID.
type Lookup func(accessKeyID string) (secret string, ok bool)

// Verify checks r's signature. canonicalURI is the path the client signed
// (a proxy in front may have rewritten r.URL.Path); body is the whole
// request body. Only host and x-amz-date must be signed; every signed
// header is canonicalized from the request.
func Verify(r *http.Request, body []byte, canonicalURI, service string, lookup Lookup, now time.Time) (Verified, error) {
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	if !strings.HasPrefix(auth, algorithm) {
		return Verified{}, ErrMissing
	}
	m := reAuth.FindStringSubmatch(auth)
	if m == nil {
		return Verified{}, ErrMalformed
	}
	keyID, date, region, svc, signedList, sig := m[1], m[2], m[3], m[4], m[5], m[6]
	if svc != service {
		return Verified{}, ErrService
	}
	amzDate := r.Header.Get("X-Amz-Date")
	at, err := time.Parse("20060102T150405Z", amzDate)
	if err != nil || !strings.HasPrefix(amzDate, date) {
		return Verified{}, ErrMalformed
	}
	if d := now.Sub(at); d > MaxSkew || d < -MaxSkew {
		return Verified{}, ErrSkew
	}
	signed := strings.Split(signedList, ";")
	if !sort.StringsAreSorted(signed) || !contains(signed, "host") || !contains(signed, "x-amz-date") {
		return Verified{}, ErrMalformed
	}
	secret, ok := lookup(keyID)
	if !ok {
		return Verified{}, ErrUnknownKey
	}
	var ch strings.Builder
	for _, h := range signed {
		v := r.Header.Values(h)
		switch {
		case h == "host":
			v = []string{r.Host}
		case h == "content-length" && len(v) == 0:
			// Go keeps the length out of the header map; it is the body's.
			v = []string{strconv.Itoa(len(body))}
		}
		ch.WriteString(h + ":" + canonicalValue(v) + "\n")
	}
	canonical := strings.Join([]string{
		r.Method, canonicalURI, canonicalQuery(r), ch.String(), signedList, hex.EncodeToString(crypto.SHA256(body)),
	}, "\n")
	scope := date + "/" + region + "/" + service + "/aws4_request"
	toSign := algorithm + "\n" + amzDate + "\n" + scope + "\n" + hex.EncodeToString(crypto.SHA256([]byte(canonical)))
	k := crypto.HMACSHA256([]byte("AWS4"+secret), []byte(date))
	k = crypto.HMACSHA256(k, []byte(region))
	k = crypto.HMACSHA256(k, []byte(service))
	k = crypto.HMACSHA256(k, []byte("aws4_request"))
	want := hex.EncodeToString(crypto.HMACSHA256(k, []byte(toSign)))
	crypto.Zeroize(k)
	if subtle.ConstantTimeCompare([]byte(want), []byte(sig)) != 1 {
		return Verified{}, ErrSignature
	}
	return Verified{AccessKeyID: keyID, Region: region, Time: at}, nil
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// canonicalValue trims each value and collapses inner whitespace runs.
func canonicalValue(values []string) string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		out = append(out, strings.Join(strings.Fields(v), " "))
	}
	return strings.Join(out, ",")
}

// canonicalQuery is the sorted, encoded query (empty for XKS).
func canonicalQuery(r *http.Request) string {
	q := r.URL.Query()
	if len(q) == 0 {
		return ""
	}
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		vs := append([]string(nil), q[k]...)
		sort.Strings(vs)
		for _, v := range vs {
			parts = append(parts, encode(k)+"="+encode(v))
		}
	}
	return strings.Join(parts, "&")
}

// encode is SigV4's URI encoding: unreserved characters stay, the rest are
// %XX in upper case.
func encode(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~' {
			b.WriteByte(c)
			continue
		}
		b.WriteString("%" + strings.ToUpper(hex.EncodeToString([]byte{c})))
	}
	return b.String()
}
