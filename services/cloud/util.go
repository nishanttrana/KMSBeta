package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"
)

func newID(prefix string) string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return prefix + "_" + hex.EncodeToString(b)
}

func defaultString(v string, d string) string {
	if strings.TrimSpace(v) == "" {
		return d
	}
	return strings.TrimSpace(v)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func normalizeProvider(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case ProviderAWS:
		return ProviderAWS
	case ProviderAzure:
		return ProviderAzure
	case ProviderGCP:
		return ProviderGCP
	case ProviderOCI:
		return ProviderOCI
	case ProviderSalesforce:
		return ProviderSalesforce
	default:
		return ""
	}
}

func supportedProvider(v string) bool {
	return normalizeProvider(v) != ""
}

func nowUTC() time.Time {
	return time.Now().UTC()
}

func validJSONOr(v string, fallback string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return fallback
	}
	if json.Valid([]byte(v)) {
		return v
	}
	return fallback
}
