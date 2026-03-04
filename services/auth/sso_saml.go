package main

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// SSOUserAttributes holds extracted user info from an SSO assertion/token.
type SSOUserAttributes struct {
	ExternalID  string
	Username    string
	Email       string
	DisplayName string
	Provider    string
}

// buildSAMLAuthnRequest generates a SAML 2.0 AuthnRequest redirect URL.
func buildSAMLAuthnRequest(cfg IdentityProviderConfig) (string, error) {
	spEntityID := strings.TrimSpace(identityProviderConfigMapString(cfg.Config, "sp_entity_id", ""))
	acsURL := strings.TrimSpace(identityProviderConfigMapString(cfg.Config, "acs_url", ""))
	idpSSOURL := strings.TrimSpace(identityProviderConfigMapString(cfg.Config, "idp_sso_url", ""))
	nameIDFormat := strings.TrimSpace(identityProviderConfigMapString(cfg.Config, "name_id_format", "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"))

	if spEntityID == "" {
		return "", errors.New("saml sp_entity_id is required")
	}
	if acsURL == "" {
		return "", errors.New("saml acs_url is required")
	}
	if idpSSOURL == "" {
		return "", errors.New("saml idp_sso_url is required")
	}

	requestID := "_" + NewID("saml")
	issueInstant := time.Now().UTC().Format(time.RFC3339)

	authnRequest := fmt.Sprintf(`<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="%s" Version="2.0" IssueInstant="%s" Destination="%s" AssertionConsumerServiceURL="%s" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"><saml:Issuer>%s</saml:Issuer><samlp:NameIDPolicy Format="%s" AllowCreate="true"/></samlp:AuthnRequest>`,
		xmlEscape(requestID),
		xmlEscape(issueInstant),
		xmlEscape(idpSSOURL),
		xmlEscape(acsURL),
		xmlEscape(spEntityID),
		xmlEscape(nameIDFormat),
	)

	// DEFLATE compress then base64 encode
	var buf bytes.Buffer
	w, err := flate.NewWriter(&buf, flate.DefaultCompression)
	if err != nil {
		return "", err
	}
	if _, err := w.Write([]byte(authnRequest)); err != nil {
		return "", err
	}
	if err := w.Close(); err != nil {
		return "", err
	}

	encoded := base64.StdEncoding.EncodeToString(buf.Bytes())
	redirectURL := idpSSOURL + "?" + url.Values{
		"SAMLRequest": {encoded},
	}.Encode()

	return redirectURL, nil
}

// parseSAMLResponse extracts user attributes from a base64-encoded SAMLResponse.
func parseSAMLResponse(cfg IdentityProviderConfig, samlResponse string) (SSOUserAttributes, error) {
	raw, err := base64.StdEncoding.DecodeString(samlResponse)
	if err != nil {
		return SSOUserAttributes{}, fmt.Errorf("saml response base64 decode failed: %w", err)
	}

	attrUsername := strings.TrimSpace(identityProviderConfigMapString(cfg.Config, "attr_username", "username"))
	attrEmail := strings.TrimSpace(identityProviderConfigMapString(cfg.Config, "attr_email", "email"))
	attrDisplayName := strings.TrimSpace(identityProviderConfigMapString(cfg.Config, "attr_display_name", "displayName"))

	// Parse XML to extract NameID and attributes from assertion
	type samlAttribute struct {
		Name   string `xml:"Name,attr"`
		Values []struct {
			Value string `xml:",chardata"`
		} `xml:"AttributeValue"`
	}
	type samlAssertion struct {
		NameID struct {
			Value string `xml:",chardata"`
		} `xml:"Subject>NameID"`
		Conditions struct {
			NotBefore    string `xml:"NotBefore,attr"`
			NotOnOrAfter string `xml:"NotOnOrAfter,attr"`
		} `xml:"Conditions"`
		Attributes []samlAttribute `xml:"AttributeStatement>Attribute"`
	}
	type samlResponseDoc struct {
		XMLName   xml.Name        `xml:"Response"`
		Status    string          `xml:"Status>StatusCode"`
		Assertion []samlAssertion `xml:"Assertion"`
	}

	var doc samlResponseDoc
	if err := xml.Unmarshal(raw, &doc); err != nil {
		return SSOUserAttributes{}, fmt.Errorf("saml response xml parse failed: %w", err)
	}

	if len(doc.Assertion) == 0 {
		return SSOUserAttributes{}, errors.New("saml response contains no assertion")
	}
	assertion := doc.Assertion[0]

	// Validate time conditions if present
	now := time.Now().UTC()
	if nb := strings.TrimSpace(assertion.Conditions.NotBefore); nb != "" {
		if t, err := time.Parse(time.RFC3339, nb); err == nil && now.Before(t.Add(-2*time.Minute)) {
			return SSOUserAttributes{}, errors.New("saml assertion not yet valid")
		}
	}
	if noa := strings.TrimSpace(assertion.Conditions.NotOnOrAfter); noa != "" {
		if t, err := time.Parse(time.RFC3339, noa); err == nil && now.After(t.Add(2*time.Minute)) {
			return SSOUserAttributes{}, errors.New("saml assertion has expired")
		}
	}

	// Extract attributes
	attrMap := map[string]string{}
	for _, attr := range assertion.Attributes {
		name := strings.TrimSpace(attr.Name)
		if name != "" && len(attr.Values) > 0 {
			attrMap[name] = strings.TrimSpace(attr.Values[0].Value)
			// Also store by short name (after last /)
			if idx := strings.LastIndex(name, "/"); idx >= 0 && idx < len(name)-1 {
				attrMap[name[idx+1:]] = strings.TrimSpace(attr.Values[0].Value)
			}
		}
	}

	nameID := strings.TrimSpace(assertion.NameID.Value)

	attrs := SSOUserAttributes{
		ExternalID: nameID,
		Username:   attrMap[attrUsername],
		Email:      attrMap[attrEmail],
		Provider:   identityProviderSAML,
	}
	if v := attrMap[attrDisplayName]; v != "" {
		attrs.DisplayName = v
	}
	// Fallback: use NameID as email/username
	if attrs.Email == "" && strings.Contains(nameID, "@") {
		attrs.Email = nameID
	}
	if attrs.Username == "" && attrs.Email != "" {
		attrs.Username = sanitizeImportedUsername(strings.SplitN(attrs.Email, "@", 2)[0])
	}
	if attrs.Username == "" && nameID != "" {
		attrs.Username = sanitizeImportedUsername(nameID)
	}

	if attrs.Username == "" {
		return SSOUserAttributes{}, errors.New("saml assertion did not contain a usable username")
	}

	return attrs, nil
}

// buildSPMetadata returns SAML SP metadata XML.
func buildSPMetadata(cfg IdentityProviderConfig) (string, error) {
	spEntityID := strings.TrimSpace(identityProviderConfigMapString(cfg.Config, "sp_entity_id", ""))
	acsURL := strings.TrimSpace(identityProviderConfigMapString(cfg.Config, "acs_url", ""))
	if spEntityID == "" || acsURL == "" {
		return "", errors.New("saml sp_entity_id and acs_url are required for metadata")
	}

	metadata := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="%s">
  <md:SPSSODescriptor AuthnRequestsSigned="false" WantAssertionsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
    <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="%s" index="0" isDefault="true"/>
  </md:SPSSODescriptor>
</md:EntityDescriptor>`,
		xmlEscape(spEntityID),
		xmlEscape(acsURL),
	)
	return metadata, nil
}

func xmlEscape(s string) string {
	var buf bytes.Buffer
	_ = xml.EscapeText(&buf, []byte(s))
	return buf.String()
}
