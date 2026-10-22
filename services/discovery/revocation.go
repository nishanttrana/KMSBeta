package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	neturl "net/url"
	"time"

	"golang.org/x/crypto/ocsp"

	"vecta-kms/pkg/ssrfguard"
)

// Revocation of a discovered TLS certificate (13.46.0-beta): its OCSP
// responder, named in the certificate, is asked whether the issuer revoked
// it. The answer counts only when it is signed for that issuer
// (ocsp.ParseResponseForCert) and still current. OCSP is plain HTTP by its
// standard: the request carries only the certificate's serial and its
// issuer's hashes, and the answer is signed, so nothing secret crosses it.
// The responder's address is checked where it is dialled (pkg/ssrfguard),
// and redirects are not followed. CRLs are not read; a certificate whose
// issuer offers no OCSP reads "not_offered".

const (
	ocspTimeout = 5 * time.Second
	maxOCSPBody = 64 << 10
)

var errOCSPRedirect = errors.New("OCSP responders are not followed through redirects")

func newOCSPClient() *http.Client {
	return &http.Client{
		Timeout:       ocspTimeout,
		Transport:     &http.Transport{DialContext: ssrfguard.DialContext, Proxy: nil},
		CheckRedirect: func(*http.Request, []*http.Request) error { return errOCSPRedirect },
	}
}

var revocationReasons = map[int]string{
	ocsp.Unspecified: "unspecified", ocsp.KeyCompromise: "key_compromise", ocsp.CACompromise: "ca_compromise",
	ocsp.AffiliationChanged: "affiliation_changed", ocsp.Superseded: "superseded", ocsp.CessationOfOperation: "cessation_of_operation",
	ocsp.CertificateHold: "certificate_hold", ocsp.RemoveFromCRL: "remove_from_crl", ocsp.PrivilegeWithdrawn: "privilege_withdrawn",
	ocsp.AACompromise: "aa_compromise",
}

// checkRevocation answers for the leaf of chain: status "good", "revoked",
// "unknown" (the responder doesn't know it), "unavailable" (no usable
// answer; error says why) or "not_offered".
func (s *Service) checkRevocation(ctx context.Context, chain []*x509.Certificate) map[string]interface{} {
	out := map[string]interface{}{"checked_at": s.now().UTC().Format(time.RFC3339)}
	if len(chain) == 0 || len(chain[0].OCSPServer) == 0 {
		out["status"] = "not_offered"
		return out
	}
	leaf, responder := chain[0], chain[0].OCSPServer[0]
	out["responder"] = responder
	fail := func(why string) map[string]interface{} {
		out["status"], out["error"] = "unavailable", why
		return out
	}
	if len(chain) < 2 {
		return fail("the endpoint did not present the issuing certificate")
	}
	issuer := chain[1]
	if u, err := neturl.Parse(responder); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fail("the certificate's OCSP address is not an http(s) URL")
	}
	req, err := ocsp.CreateRequest(leaf, issuer, &ocsp.RequestOptions{Hash: crypto.SHA256})
	if err != nil {
		return fail("request: " + err.Error())
	}
	hreq, err := http.NewRequestWithContext(ctx, http.MethodPost, responder, bytes.NewReader(req))
	if err != nil {
		return fail("request: " + err.Error())
	}
	hreq.Header.Set("Content-Type", "application/ocsp-request")
	client := s.ocsp
	if client == nil {
		client = newOCSPClient()
	}
	resp, err := client.Do(hreq)
	if err != nil {
		return fail("responder unreachable: " + err.Error())
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		return fail("responder answered HTTP " + resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxOCSPBody))
	if err != nil {
		return fail("responder answer unreadable: " + err.Error())
	}
	ans, err := ocsp.ParseResponseForCert(body, leaf, issuer)
	if err != nil {
		return fail("answer not signed for this issuer: " + err.Error())
	}
	now := s.now()
	if !ans.NextUpdate.IsZero() && now.After(ans.NextUpdate) {
		return fail("the responder's answer is out of date")
	}
	switch ans.Status {
	case ocsp.Good:
		out["status"] = "good"
	case ocsp.Revoked:
		out["status"] = "revoked"
		out["revoked_at"] = ans.RevokedAt.UTC().Format(time.RFC3339)
		out["reason"] = revocationReasons[ans.RevocationReason]
	default:
		out["status"] = "unknown"
	}
	return out
}
