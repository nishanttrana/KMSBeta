package main

import (
	"bytes"
	"compress/flate"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

// SSOUserAttributes holds extracted user info from an SSO assertion/token.
type SSOUserAttributes struct {
	ExternalID  string
	Username    string
	Email       string
	DisplayName string
	Provider    string
}

const (
	samlProtocolNS  = "urn:oasis:names:tc:SAML:2.0:protocol"
	samlAssertionNS = "urn:oasis:names:tc:SAML:2.0:assertion"
	samlStatusOK    = "urn:oasis:names:tc:SAML:2.0:status:Success"
	samlBearer      = "urn:oasis:names:tc:SAML:2.0:cm:bearer"
	samlMaxResponse = 1 << 20
	samlClockSkew   = 2 * time.Minute
)

// Only SHA-2 signature and digest methods are accepted: SHA-1 XML signatures
// are forgeable in practice and are not FIPS 140-3 approved for signatures.
var (
	samlSignatureMethods = map[string]bool{
		"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256":   true,
		"http://www.w3.org/2001/04/xmldsig-more#rsa-sha384":   true,
		"http://www.w3.org/2001/04/xmldsig-more#rsa-sha512":   true,
		"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256": true,
		"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384": true,
		"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512": true,
	}
	samlDigestMethods = map[string]bool{
		"http://www.w3.org/2001/04/xmlenc#sha256":       true,
		"http://www.w3.org/2001/04/xmldsig-more#sha384": true,
		"http://www.w3.org/2001/04/xmlenc#sha512":       true,
	}
)

// buildSAMLAuthnRequest generates a SAML 2.0 AuthnRequest redirect URL. The
// RelayState is a one-time SSO state bound to the request ID, so the callback
// only accepts an assertion issued in response to this request.
func buildSAMLAuthnRequest(cfg IdentityProviderConfig, tenantID string) (string, error) {
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
	if strings.TrimSpace(identityProviderConfigMapString(cfg.Config, "idp_entity_id", "")) == "" {
		return "", errors.New("saml idp_entity_id is required")
	}
	if _, err := samlIdPCertificates(cfg); err != nil {
		return "", err
	}

	requestID := "_" + NewID("saml")
	state, err := generateSSOState(tenantID, identityProviderSAML, requestID)
	if err != nil {
		return "", err
	}
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

	sep := "?"
	if strings.Contains(idpSSOURL, "?") {
		sep = "&"
	}
	return idpSSOURL + sep + url.Values{
		"SAMLRequest": {base64.StdEncoding.EncodeToString(buf.Bytes())},
		"RelayState":  {state},
	}.Encode(), nil
}

// samlIdPCertificates parses the configured IdP signing certificate(s). More
// than one may be given for a certificate rollover.
func samlIdPCertificates(cfg IdentityProviderConfig) ([]*x509.Certificate, error) {
	raw := strings.TrimSpace(identityProviderConfigMapString(cfg.Secrets, "idp_certificate", ""))
	if raw == "" {
		return nil, errors.New("saml idp_certificate is required: assertions cannot be verified without it")
	}
	var certs []*x509.Certificate
	rest := []byte(strings.ReplaceAll(raw, `\n`, "\n"))
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("saml idp_certificate is not a valid certificate: %w", err)
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return nil, errors.New("saml idp_certificate contains no PEM certificate")
	}
	return certs, nil
}

// samlAssertion is what a verified assertion yielded.
type samlAssertion struct {
	ID           string
	NotOnOrAfter time.Time
	Attrs        SSOUserAttributes
}

// parseSAMLResponse verifies a base64-encoded SAMLResponse and extracts the
// user from it. Everything read comes from the element whose XML signature
// verified against the configured IdP certificate, so a signature-wrapping
// payload beside it is never consulted. The assertion must come from the
// configured IdP, be addressed to this SP and ACS, answer expectedRequestID,
// and be inside its validity window.
func parseSAMLResponse(cfg IdentityProviderConfig, samlResponse string, expectedRequestID string, now time.Time) (samlAssertion, error) {
	if len(samlResponse) > samlMaxResponse {
		return samlAssertion{}, errors.New("saml response is too large")
	}
	raw, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(samlResponse), ""))
	if err != nil {
		return samlAssertion{}, fmt.Errorf("saml response base64 decode failed: %w", err)
	}
	certs, err := samlIdPCertificates(cfg)
	if err != nil {
		return samlAssertion{}, err
	}
	idpEntityID := strings.TrimSpace(identityProviderConfigMapString(cfg.Config, "idp_entity_id", ""))
	spEntityID := strings.TrimSpace(identityProviderConfigMapString(cfg.Config, "sp_entity_id", ""))
	acsURL := strings.TrimSpace(identityProviderConfigMapString(cfg.Config, "acs_url", ""))
	if idpEntityID == "" || spEntityID == "" || acsURL == "" {
		return samlAssertion{}, errors.New("saml idp_entity_id, sp_entity_id and acs_url are required")
	}
	if strings.TrimSpace(expectedRequestID) == "" {
		return samlAssertion{}, errors.New("saml login request is unknown or expired")
	}

	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(raw); err != nil {
		return samlAssertion{}, fmt.Errorf("saml response xml parse failed: %w", err)
	}
	root := doc.Root()
	if root == nil || root.Tag != "Response" || root.NamespaceURI() != samlProtocolNS {
		return samlAssertion{}, errors.New("saml document is not a SAML 2.0 Response")
	}
	status := samlChild(samlChild(root, samlProtocolNS, "Status"), samlProtocolNS, "StatusCode")
	if status == nil || status.SelectAttrValue("Value", "") != samlStatusOK {
		return samlAssertion{}, errors.New("saml response status is not Success")
	}
	if d := root.SelectAttrValue("Destination", ""); d != "" && d != acsURL {
		return samlAssertion{}, errors.New("saml response destination does not match acs_url")
	}
	if irt := root.SelectAttrValue("InResponseTo", ""); irt != "" && irt != expectedRequestID {
		return samlAssertion{}, errors.New("saml response does not answer this login request")
	}
	if len(samlChildren(root, samlAssertionNS, "EncryptedAssertion")) > 0 {
		return samlAssertion{}, errors.New("encrypted saml assertions are not supported")
	}
	assertions := samlChildren(root, samlAssertionNS, "Assertion")
	if len(assertions) != 1 {
		return samlAssertion{}, errors.New("saml response must contain exactly one assertion")
	}

	vctx := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{Roots: certs})
	vctx.Clock = dsig.NewRealClock()
	var verified *etree.Element
	switch {
	case samlChild(assertions[0], dsig.Namespace, dsig.SignatureTag) != nil:
		if err := checkSAMLSignatureMethods(assertions[0]); err != nil {
			return samlAssertion{}, err
		}
		if verified, err = vctx.Validate(assertions[0]); err != nil {
			return samlAssertion{}, fmt.Errorf("saml assertion signature invalid: %w", err)
		}
	case samlChild(root, dsig.Namespace, dsig.SignatureTag) != nil:
		if err := checkSAMLSignatureMethods(root); err != nil {
			return samlAssertion{}, err
		}
		resp, verr := vctx.Validate(root)
		if verr != nil {
			return samlAssertion{}, fmt.Errorf("saml response signature invalid: %w", verr)
		}
		signed := samlChildren(resp, samlAssertionNS, "Assertion")
		if len(signed) != 1 {
			return samlAssertion{}, errors.New("signed saml response must contain exactly one assertion")
		}
		verified = signed[0]
	default:
		return samlAssertion{}, errors.New("saml response is not signed")
	}

	if issuer := strings.TrimSpace(samlText(samlChild(verified, samlAssertionNS, "Issuer"))); issuer != idpEntityID {
		return samlAssertion{}, errors.New("saml assertion issuer does not match idp_entity_id")
	}
	id := strings.TrimSpace(verified.SelectAttrValue("ID", ""))
	if id == "" {
		return samlAssertion{}, errors.New("saml assertion has no ID")
	}

	conditions := samlChild(verified, samlAssertionNS, "Conditions")
	if conditions == nil {
		return samlAssertion{}, errors.New("saml assertion has no Conditions")
	}
	if nb := conditions.SelectAttrValue("NotBefore", ""); nb != "" {
		t, err := time.Parse(time.RFC3339, nb)
		if err != nil {
			return samlAssertion{}, errors.New("saml assertion NotBefore is malformed")
		}
		if now.Add(samlClockSkew).Before(t) {
			return samlAssertion{}, errors.New("saml assertion not yet valid")
		}
	}
	notOnOrAfter, err := time.Parse(time.RFC3339, conditions.SelectAttrValue("NotOnOrAfter", ""))
	if err != nil {
		return samlAssertion{}, errors.New("saml assertion NotOnOrAfter is missing or malformed")
	}
	if !now.Add(-samlClockSkew).Before(notOnOrAfter) {
		return samlAssertion{}, errors.New("saml assertion has expired")
	}
	audienceOK := false
	for _, ar := range samlChildren(conditions, samlAssertionNS, "AudienceRestriction") {
		for _, a := range samlChildren(ar, samlAssertionNS, "Audience") {
			if strings.TrimSpace(samlText(a)) == spEntityID {
				audienceOK = true
			}
		}
	}
	if !audienceOK {
		return samlAssertion{}, errors.New("saml assertion audience does not include sp_entity_id")
	}

	subject := samlChild(verified, samlAssertionNS, "Subject")
	if err := checkSAMLBearer(subject, acsURL, expectedRequestID, now); err != nil {
		return samlAssertion{}, err
	}

	attrUsername := strings.TrimSpace(identityProviderConfigMapString(cfg.Config, "attr_username", "username"))
	attrEmail := strings.TrimSpace(identityProviderConfigMapString(cfg.Config, "attr_email", "email"))
	attrDisplayName := strings.TrimSpace(identityProviderConfigMapString(cfg.Config, "attr_display_name", "displayName"))
	attrMap := map[string]string{}
	for _, stmt := range samlChildren(verified, samlAssertionNS, "AttributeStatement") {
		for _, attr := range samlChildren(stmt, samlAssertionNS, "Attribute") {
			name := strings.TrimSpace(attr.SelectAttrValue("Name", ""))
			values := samlChildren(attr, samlAssertionNS, "AttributeValue")
			if name == "" || len(values) == 0 {
				continue
			}
			v := strings.TrimSpace(samlText(values[0]))
			attrMap[name] = v
			if idx := strings.LastIndex(name, "/"); idx >= 0 && idx < len(name)-1 {
				attrMap[name[idx+1:]] = v
			}
		}
	}
	nameID := strings.TrimSpace(samlText(samlChild(subject, samlAssertionNS, "NameID")))
	attrs := SSOUserAttributes{
		ExternalID:  nameID,
		Username:    attrMap[attrUsername],
		Email:       attrMap[attrEmail],
		DisplayName: attrMap[attrDisplayName],
		Provider:    identityProviderSAML,
	}
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
		return samlAssertion{}, errors.New("saml assertion did not contain a usable username")
	}
	return samlAssertion{ID: id, NotOnOrAfter: notOnOrAfter, Attrs: attrs}, nil
}

// checkSAMLBearer requires a bearer SubjectConfirmation for this ACS, this
// request, and the current time (SAML 2.0 Profiles §4.1.4.3).
func checkSAMLBearer(subject *etree.Element, acsURL, expectedRequestID string, now time.Time) error {
	if subject == nil {
		return errors.New("saml assertion has no Subject")
	}
	for _, sc := range samlChildren(subject, samlAssertionNS, "SubjectConfirmation") {
		if sc.SelectAttrValue("Method", "") != samlBearer {
			continue
		}
		data := samlChild(sc, samlAssertionNS, "SubjectConfirmationData")
		if data == nil || data.SelectAttrValue("Recipient", "") != acsURL {
			continue
		}
		if data.SelectAttrValue("InResponseTo", "") != expectedRequestID {
			continue
		}
		t, err := time.Parse(time.RFC3339, data.SelectAttrValue("NotOnOrAfter", ""))
		if err != nil || !now.Add(-samlClockSkew).Before(t) {
			continue
		}
		return nil
	}
	return errors.New("saml assertion has no valid bearer confirmation for this ACS and request")
}

// checkSAMLSignatureMethods refuses SHA-1 (and unknown) signature and digest
// methods before the signature is checked.
func checkSAMLSignatureMethods(el *etree.Element) error {
	sig := samlChild(el, dsig.Namespace, dsig.SignatureTag)
	signedInfo := samlChild(sig, dsig.Namespace, "SignedInfo")
	method := samlChild(signedInfo, dsig.Namespace, "SignatureMethod")
	if method == nil || !samlSignatureMethods[method.SelectAttrValue("Algorithm", "")] {
		return errors.New("saml signature method is not an approved SHA-2 algorithm")
	}
	refs := samlChildren(signedInfo, dsig.Namespace, "Reference")
	if len(refs) != 1 {
		return errors.New("saml signature must have exactly one reference")
	}
	digest := samlChild(refs[0], dsig.Namespace, "DigestMethod")
	if digest == nil || !samlDigestMethods[digest.SelectAttrValue("Algorithm", "")] {
		return errors.New("saml digest method is not an approved SHA-2 algorithm")
	}
	return nil
}

func samlChildren(el *etree.Element, ns, tag string) []*etree.Element {
	if el == nil {
		return nil
	}
	var out []*etree.Element
	for _, c := range el.ChildElements() {
		if c.Tag == tag && c.NamespaceURI() == ns {
			out = append(out, c)
		}
	}
	return out
}

func samlChild(el *etree.Element, ns, tag string) *etree.Element {
	if c := samlChildren(el, ns, tag); len(c) > 0 {
		return c[0]
	}
	return nil
}

func samlText(el *etree.Element) string {
	if el == nil {
		return ""
	}
	return el.Text()
}

// samlSeenAssertions refuses a replayed assertion ID until it expires.
var samlSeenAssertions sync.Map

func consumeSAMLAssertion(id string, notOnOrAfter time.Time) bool {
	now := time.Now()
	samlSeenAssertions.Range(func(k, v any) bool {
		if t, ok := v.(time.Time); ok && now.After(t.Add(samlClockSkew)) {
			samlSeenAssertions.Delete(k)
		}
		return true
	})
	_, loaded := samlSeenAssertions.LoadOrStore(id, notOnOrAfter)
	return !loaded
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
