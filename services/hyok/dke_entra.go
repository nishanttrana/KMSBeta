package main

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"vecta-kms/pkg/oidc"
)

// Microsoft Double Key Encryption: Office fetches a DKE key's public part
// without a token and decrypts with an Entra ID access token issued for the
// customer's DKE app registration. The token is verified with pkg/oidc
// against the Entra tenant's signing keys, only for an issuer the endpoint's
// valid_issuers names and an audience its jwt_audiences names, and the user
// must be one the endpoint authorizes by email or app role.

const authModeAnonymous = "anonymous"

var (
	entraVerifier = oidc.NewVerifier()
	// v1 (sts.windows.net) and v2 (login.microsoftonline.com/.../v2.0)
	// issuers of the Entra public cloud.
	entraIssuerRE = regexp.MustCompile(`^https://(?:sts\.windows\.net/([0-9a-f-]{36})/|login\.microsoftonline\.com/([0-9a-f-]{36})/v2\.0)$`)
	entraJWKSURL  = func(entraTenant string) string {
		return "https://login.microsoftonline.com/" + entraTenant + "/discovery/v2.0/keys"
	}
)

// entraTenantOf returns the Entra tenant of an Entra issuer URL.
func entraTenantOf(issuer string) (string, bool) {
	m := entraIssuerRE.FindStringSubmatch(issuer)
	if m == nil {
		return "", false
	}
	return firstNonEmpty(m[1], m[2]), true
}

// isEntraToken reports whether a bearer token claims an Entra issuer. It only
// picks the verifier; nothing else is read from the unverified token.
func isEntraToken(raw string) bool {
	iss, err := oidc.UnverifiedIssuer(raw)
	if err != nil {
		return false
	}
	_, ok := entraTenantOf(iss)
	return ok
}

// resolveDKETenant finds the Vecta tenant of a Microsoft DKE call: the one
// named by tenant_id, or else the only tenant whose enabled DKE endpoint
// matches. Its endpoint metadata is returned.
func (s *Service) resolveDKETenant(ctx context.Context, hint string, match func(DKEEndpointMetadata) bool) (string, DKEEndpointMetadata, error) {
	unauthorized := func(msg string) error { return newServiceError(http.StatusUnauthorized, "unauthorized", msg) }
	var candidates []EndpointConfig
	if hint = strings.TrimSpace(hint); hint != "" {
		cfg, err := s.store.GetEndpoint(ctx, hint, ProtocolDKE)
		if err != nil {
			return "", DKEEndpointMetadata{}, unauthorized("tenant has no DKE endpoint")
		}
		candidates = []EndpointConfig{cfg}
	} else {
		all, err := s.store.ListEnabledEndpointsByProtocol(ctx, ProtocolDKE)
		if err != nil {
			return "", DKEEndpointMetadata{}, err
		}
		candidates = all
	}
	var tenantID string
	var found DKEEndpointMetadata
	for _, cfg := range candidates {
		meta, err := parseDKEEndpointMetadata(cfg.MetadataJSON)
		if err != nil || !match(meta) {
			continue
		}
		if tenantID != "" {
			return "", DKEEndpointMetadata{}, unauthorized("several tenants' DKE endpoints match this call; add tenant_id to the key URI")
		}
		tenantID, found = cfg.TenantID, meta
	}
	if tenantID == "" {
		return "", DKEEndpointMetadata{}, unauthorized("no DKE endpoint trusts this caller")
	}
	return tenantID, found, nil
}

// AuthenticateEntraDKE verifies an Entra ID access token for a DKE endpoint
// and returns the caller and the Vecta tenant it acts in.
func (s *Service) AuthenticateEntraDKE(ctx context.Context, hint, raw, remoteIP string) (AuthIdentity, string, error) {
	unauthorized := func(msg string) error { return newServiceError(http.StatusUnauthorized, "unauthorized", msg) }
	issuer, err := oidc.UnverifiedIssuer(raw)
	if err != nil {
		return AuthIdentity{}, "", unauthorized("invalid bearer token")
	}
	entraTenant, ok := entraTenantOf(issuer)
	if !ok {
		return AuthIdentity{}, "", unauthorized("token issuer is not Entra ID")
	}
	tenantID, meta, err := s.resolveDKETenant(ctx, hint, func(m DKEEndpointMetadata) bool {
		for _, v := range m.ValidIssuers {
			if strings.TrimSpace(v) == issuer {
				return true
			}
		}
		return false
	})
	if err != nil {
		return AuthIdentity{}, "", err
	}
	if len(meta.JWTAudiences) == 0 {
		return AuthIdentity{}, "", unauthorized("the DKE endpoint names no jwt_audiences; Entra tokens are refused until it does")
	}
	if len(meta.AuthorizedEmails) == 0 && len(meta.AuthorizedRoles) == 0 {
		return AuthIdentity{}, "", unauthorized("the DKE endpoint authorizes no emails or roles; Entra tokens are refused until it does")
	}
	var claims map[string]interface{}
	for _, aud := range meta.JWTAudiences {
		if c, verr := entraVerifier.VerifyJWT(ctx, raw, entraJWKSURL(entraTenant), issuer, aud, time.Now()); verr == nil {
			claims = c
			break
		} else {
			err = verr
		}
	}
	if claims == nil {
		return AuthIdentity{}, "", unauthorized("Entra token rejected: " + err.Error())
	}
	str := func(k string) string { v, _ := claims[k].(string); return strings.TrimSpace(v) }
	if !strings.EqualFold(str("tid"), entraTenant) {
		return AuthIdentity{}, "", unauthorized("Entra token tenant does not match its issuer")
	}
	// The user is named by upn / preferred_username. The email claim is not
	// used: Entra lets it be set to an unverified address.
	email := strings.ToLower(firstNonEmpty(str("upn"), str("preferred_username")))
	roles := claimStrings(claims["roles"])
	authorized := email != "" && containsFold(meta.AuthorizedEmails, email)
	for _, role := range roles {
		for _, want := range meta.AuthorizedRoles {
			authorized = authorized || (role != "" && role == strings.TrimSpace(want))
		}
	}
	if !authorized {
		return AuthIdentity{}, "", newServiceError(http.StatusForbidden, "forbidden", "this user is not authorized for the DKE endpoint")
	}
	id := AuthIdentity{
		Mode:          AuthModeJWT,
		Subject:       firstNonEmpty(str("oid"), str("sub")),
		TenantID:      tenantID,
		UserID:        email,
		RemoteIP:      remoteIP,
		JWTIssuer:     issuer,
		EntraTenantID: entraTenant,
	}
	id.JWTAudiences = claimStrings(claims["aud"])
	return id, tenantID, nil
}

// claimStrings reads a JWT claim that is one string or a list of strings,
// verbatim: a value is never split, so "a,b" is not role "a".
func claimStrings(v interface{}) []string {
	switch x := v.(type) {
	case string:
		return []string{x}
	case []interface{}:
		out := make([]string, 0, len(x))
		for _, item := range x {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}
