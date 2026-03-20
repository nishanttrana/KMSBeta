package restauth

import (
	"crypto"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type HTTPSignatureResult struct {
	Label      string    `json:"label"`
	KeyID      string    `json:"key_id"`
	Algorithm  string    `json:"algorithm,omitempty"`
	Nonce      string    `json:"nonce,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
	Components []string  `json:"components"`
}

type SignatureInput struct {
	Label          string
	Components     []string
	ComponentInner string
	Params         map[string]string
	ParamOrder     []string
}

func VerifyHTTPMessageSignature(headers http.Header, method string, pathWithQuery string, authority string, body []byte, publicKey crypto.PublicKey, expectedKeyID string, maxAge time.Duration) (HTTPSignatureResult, error) {
	if maxAge <= 0 {
		maxAge = 5 * time.Minute
	}
	inputs, err := parseSignatureInputHeader(headers.Values("Signature-Input"))
	if err != nil {
		return HTTPSignatureResult{}, err
	}
	signatures, err := parseSignatureHeader(headers.Values("Signature"))
	if err != nil {
		return HTTPSignatureResult{}, err
	}
	for _, input := range inputs {
		signature, ok := signatures[input.Label]
		if !ok {
			continue
		}
		keyID := strings.TrimSpace(input.Params["keyid"])
		if strings.TrimSpace(expectedKeyID) != "" && keyID != strings.TrimSpace(expectedKeyID) {
			continue
		}
		createdAt, err := parseSignatureCreated(input.Params["created"])
		if err != nil {
			return HTTPSignatureResult{}, err
		}
		now := time.Now().UTC()
		if now.Sub(createdAt) > maxAge || createdAt.Sub(now) > maxAge {
			return HTTPSignatureResult{}, errors.New("http message signature outside replay window")
		}
		signingBase, err := buildHTTPSignatureBase(input, headers, method, pathWithQuery, authority)
		if err != nil {
			return HTTPSignatureResult{}, err
		}
		if requiresContentDigest(input.Components) {
			if err := verifyContentDigest(headers, body); err != nil {
				return HTTPSignatureResult{}, err
			}
		}
		if err := VerifyAsymmetricSignature(publicKey, input.Params["alg"], []byte(signingBase), signature); err != nil {
			return HTTPSignatureResult{}, err
		}
		return HTTPSignatureResult{
			Label:      input.Label,
			KeyID:      keyID,
			Algorithm:  strings.TrimSpace(input.Params["alg"]),
			Nonce:      strings.TrimSpace(input.Params["nonce"]),
			CreatedAt:  createdAt,
			Components: append([]string{}, input.Components...),
		}, nil
	}
	return HTTPSignatureResult{}, errors.New("no matching http message signature")
}

func parseSignatureInputHeader(values []string) ([]SignatureInput, error) {
	results := make([]SignatureInput, 0)
	for _, raw := range values {
		for _, item := range splitCommaAware(raw) {
			label, body, ok := strings.Cut(strings.TrimSpace(item), "=")
			if !ok {
				continue
			}
			label = strings.TrimSpace(label)
			body = strings.TrimSpace(body)
			if label == "" || !strings.HasPrefix(body, "(") {
				continue
			}
			end := strings.Index(body, ")")
			if end <= 0 {
				return nil, errors.New("invalid signature-input component list")
			}
			componentInner := body[1:end]
			components := parseQuotedComponentList(componentInner)
			if len(components) == 0 {
				return nil, errors.New("signature-input missing covered components")
			}
			params := map[string]string{}
			order := make([]string, 0)
			rest := body[end+1:]
			for _, segment := range strings.Split(rest, ";") {
				entry := strings.TrimSpace(segment)
				if entry == "" {
					continue
				}
				key, value, found := strings.Cut(entry, "=")
				key = strings.TrimSpace(key)
				if !found {
					params[key] = ""
					order = append(order, key)
					continue
				}
				params[key] = strings.Trim(strings.TrimSpace(value), "\"")
				order = append(order, key)
			}
			results = append(results, SignatureInput{Label: label, Components: components, ComponentInner: componentInner, Params: params, ParamOrder: order})
		}
	}
	if len(results) == 0 {
		return nil, errors.New("missing Signature-Input header")
	}
	return results, nil
}

func parseSignatureHeader(values []string) (map[string][]byte, error) {
	out := map[string][]byte{}
	for _, raw := range values {
		for _, item := range splitCommaAware(raw) {
			label, value, ok := strings.Cut(strings.TrimSpace(item), "=")
			if !ok {
				continue
			}
			label = strings.TrimSpace(label)
			value = strings.TrimSpace(value)
			value = strings.TrimPrefix(value, ":")
			value = strings.TrimSuffix(value, ":")
			decoded, err := base64.StdEncoding.DecodeString(value)
			if err != nil {
				decoded, err = base64.RawStdEncoding.DecodeString(value)
			}
			if err != nil {
				return nil, errors.New("invalid Signature header value")
			}
			out[label] = decoded
		}
	}
	if len(out) == 0 {
		return nil, errors.New("missing Signature header")
	}
	return out, nil
}

func buildHTTPSignatureBase(input SignatureInput, headers http.Header, method string, pathWithQuery string, authority string) (string, error) {
	lines := make([]string, 0, len(input.Components)+1)
	for _, component := range input.Components {
		value, err := signatureComponentValue(component, headers, method, pathWithQuery, authority)
		if err != nil {
			return "", err
		}
		lines = append(lines, fmt.Sprintf(`"%s": %s`, component, value))
	}
	lines = append(lines, fmt.Sprintf(`"@signature-params": (%s)%s`, input.ComponentInner, formatSignatureParams(input)))
	return strings.Join(lines, "\n"), nil
}

func signatureComponentValue(component string, headers http.Header, method string, pathWithQuery string, authority string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(component)) {
	case "@method":
		return strings.ToUpper(strings.TrimSpace(method)), nil
	case "@path":
		path := strings.TrimSpace(pathWithQuery)
		if path == "" {
			return "", errors.New("missing request path for http signature")
		}
		if idx := strings.Index(path, "?"); idx >= 0 {
			path = path[:idx]
		}
		return path, nil
	case "@query":
		path := strings.TrimSpace(pathWithQuery)
		if idx := strings.Index(path, "?"); idx >= 0 {
			return path[idx+1:], nil
		}
		return "", nil
	case "@authority":
		value := strings.TrimSpace(authority)
		if value == "" {
			return "", errors.New("missing request authority for http signature")
		}
		return value, nil
	default:
		headerName := http.CanonicalHeaderKey(strings.Trim(strings.TrimSpace(component), "\""))
		value := strings.TrimSpace(headers.Get(headerName))
		if value == "" {
			return "", fmt.Errorf("missing signed header %s", component)
		}
		return value, nil
	}
}

func formatSignatureParams(input SignatureInput) string {
	var parts []string
	for _, key := range input.ParamOrder {
		value := input.Params[key]
		switch key {
		case "created":
			parts = append(parts, ";created="+value)
		default:
			parts = append(parts, fmt.Sprintf(`;%s="%s"`, key, value))
		}
	}
	return strings.Join(parts, "")
}

func parseQuotedComponentList(raw string) []string {
	matches := splitSpaceAware(raw)
	out := make([]string, 0, len(matches))
	for _, match := range matches {
		component := strings.Trim(strings.TrimSpace(match), "\"")
		if component == "" {
			continue
		}
		if strings.HasPrefix(component, "@") {
			out = append(out, component)
		} else {
			out = append(out, strings.ToLower(component))
		}
	}
	return out
}

func splitSpaceAware(raw string) []string {
	out := []string{}
	current := strings.Builder{}
	inQuote := false
	for _, r := range raw {
		switch r {
		case '"':
			inQuote = !inQuote
			current.WriteRune(r)
		case ' ':
			if inQuote {
				current.WriteRune(r)
				continue
			}
			if strings.TrimSpace(current.String()) != "" {
				out = append(out, strings.TrimSpace(current.String()))
			}
			current.Reset()
		default:
			current.WriteRune(r)
		}
	}
	if strings.TrimSpace(current.String()) != "" {
		out = append(out, strings.TrimSpace(current.String()))
	}
	return out
}

func splitCommaAware(raw string) []string {
	out := []string{}
	current := strings.Builder{}
	inQuote := false
	depth := 0
	for _, r := range raw {
		switch r {
		case '"':
			inQuote = !inQuote
			current.WriteRune(r)
		case '(':
			depth++
			current.WriteRune(r)
		case ')':
			if depth > 0 {
				depth--
			}
			current.WriteRune(r)
		case ',':
			if inQuote || depth > 0 {
				current.WriteRune(r)
				continue
			}
			if strings.TrimSpace(current.String()) != "" {
				out = append(out, strings.TrimSpace(current.String()))
			}
			current.Reset()
		default:
			current.WriteRune(r)
		}
	}
	if strings.TrimSpace(current.String()) != "" {
		out = append(out, strings.TrimSpace(current.String()))
	}
	return out
}

func parseSignatureCreated(raw string) (time.Time, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return time.Time{}, errors.New("missing http signature created parameter")
	}
	created, err := time.Parse(time.RFC3339, value)
	if err == nil {
		return created.UTC(), nil
	}
	seconds, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return time.Time{}, errors.New("invalid http signature created parameter")
	}
	return time.Unix(seconds, 0).UTC(), nil
}

func requiresContentDigest(components []string) bool {
	for _, component := range components {
		if strings.EqualFold(strings.TrimSpace(component), "content-digest") {
			return true
		}
	}
	return false
}

func verifyContentDigest(headers http.Header, body []byte) error {
	raw := strings.TrimSpace(headers.Get("Content-Digest"))
	if raw == "" {
		return errors.New("missing Content-Digest header")
	}
	const prefix = "sha-256=:"
	if !strings.HasPrefix(strings.ToLower(raw), prefix) || !strings.HasSuffix(raw, ":") {
		return errors.New("invalid Content-Digest format")
	}
	encoded := raw[len(prefix) : len(raw)-1]
	expected, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return errors.New("invalid Content-Digest value")
	}
	sum := sha256.Sum256(body)
	if subtle.ConstantTimeCompare(expected, sum[:]) != 1 {
		return errors.New("content-digest mismatch")
	}
	return nil
}
