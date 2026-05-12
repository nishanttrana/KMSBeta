package main

import (
	"crypto/x509"
	"strings"
)

// AutoTagHints derives a label set for a newly registered KMIP object
// from the client's TLS identity and the operator's supplied request
// metadata. The output is merged with operator-supplied labels (operator
// wins on conflict) so explicit tags always trump derived ones.
//
// Derivations:
//   - owner:        cert CN if present, else first email SAN
//   - org:          cert O (organization) if present
//   - locality:     cert L
//   - country:      cert C
//   - cert_serial:  full hex serial for traceability
func AutoTagHints(cert *x509.Certificate, operator map[string]string) map[string]string {
	out := make(map[string]string, 8)
	for k, v := range operator {
		if strings.TrimSpace(v) == "" {
			continue
		}
		out[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
	}
	if cert == nil {
		return out
	}
	setIfAbsent(out, "owner", deriveOwner(cert))
	if len(cert.Subject.Organization) > 0 {
		setIfAbsent(out, "org", cert.Subject.Organization[0])
	}
	if len(cert.Subject.Locality) > 0 {
		setIfAbsent(out, "locality", cert.Subject.Locality[0])
	}
	if len(cert.Subject.Country) > 0 {
		setIfAbsent(out, "country", cert.Subject.Country[0])
	}
	if cert.SerialNumber != nil {
		setIfAbsent(out, "cert_serial", cert.SerialNumber.Text(16))
	}
	return out
}

// RequireTagsOrReject reports any required label that is missing from
// the supplied labels. Returns the missing keys; an empty slice means
// the registration may proceed.
func RequireTagsOrReject(labels map[string]string, required []string) []string {
	missing := make([]string, 0)
	for _, r := range required {
		key := strings.ToLower(strings.TrimSpace(r))
		if v, ok := labels[key]; !ok || strings.TrimSpace(v) == "" {
			missing = append(missing, r)
		}
	}
	return missing
}

func deriveOwner(cert *x509.Certificate) string {
	if strings.TrimSpace(cert.Subject.CommonName) != "" {
		return cert.Subject.CommonName
	}
	if len(cert.EmailAddresses) > 0 {
		return cert.EmailAddresses[0]
	}
	if len(cert.URIs) > 0 {
		return cert.URIs[0].String()
	}
	return ""
}

func setIfAbsent(m map[string]string, key, value string) {
	if strings.TrimSpace(value) == "" {
		return
	}
	if _, exists := m[key]; exists {
		return
	}
	m[key] = strings.TrimSpace(value)
}
