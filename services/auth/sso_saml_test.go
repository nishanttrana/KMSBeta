package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

type samlIdP struct {
	key  *ecdsa.PrivateKey
	der  []byte
	cert string
}

func newSAMLIdP(t *testing.T) samlIdP {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "idp.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return samlIdP{key: key, der: der, cert: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))}
}

const (
	testSP  = "https://kms.test/saml/metadata"
	testACS = "https://kms.test/auth/sso/saml/callback"
	testIdP = "https://idp.test/metadata"
	testReq = "_saml_req_1"
)

func samlConfig(cert string) IdentityProviderConfig {
	return IdentityProviderConfig{
		Provider: identityProviderSAML,
		Enabled:  true,
		Config: map[string]any{
			"sp_entity_id":  testSP,
			"acs_url":       testACS,
			"idp_entity_id": testIdP,
			"idp_sso_url":   "https://idp.test/sso",
		},
		Secrets: map[string]any{"idp_certificate": cert},
	}
}

type assertionOpts struct {
	issuer, audience, recipient, inResponseTo, nameID string
	notOnOrAfter                                      time.Time
}

func defaultOpts() assertionOpts {
	return assertionOpts{testIdP, testSP, testACS, testReq, "alice@example.com", time.Now().Add(5 * time.Minute)}
}

func assertionXML(o assertionOpts) string {
	noa := o.notOnOrAfter.UTC().Format(time.RFC3339)
	return fmt.Sprintf(`<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a1" Version="2.0" IssueInstant="%s">`+
		`<saml:Issuer>%s</saml:Issuer>`+
		`<saml:Subject><saml:NameID>%s</saml:NameID>`+
		`<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">`+
		`<saml:SubjectConfirmationData Recipient="%s" InResponseTo="%s" NotOnOrAfter="%s"/></saml:SubjectConfirmation></saml:Subject>`+
		`<saml:Conditions NotBefore="%s" NotOnOrAfter="%s"><saml:AudienceRestriction><saml:Audience>%s</saml:Audience></saml:AudienceRestriction></saml:Conditions>`+
		`<saml:AttributeStatement><saml:Attribute Name="email"><saml:AttributeValue>%s</saml:AttributeValue></saml:Attribute></saml:AttributeStatement>`+
		`</saml:Assertion>`,
		time.Now().UTC().Format(time.RFC3339), o.issuer, o.nameID, o.recipient, o.inResponseTo, noa,
		time.Now().Add(-time.Minute).UTC().Format(time.RFC3339), noa, o.audience, o.nameID)
}

func signAssertion(t *testing.T, idp samlIdP, assertion string, method string) string {
	t.Helper()
	doc := etree.NewDocument()
	if err := doc.ReadFromString(assertion); err != nil {
		t.Fatal(err)
	}
	ctx, err := dsig.NewSigningContext(idp.key, [][]byte{idp.der})
	if err != nil {
		t.Fatal(err)
	}
	if err := ctx.SetSignatureMethod(method); err != nil {
		t.Fatal(err)
	}
	signed, err := ctx.SignEnveloped(doc.Root())
	if err != nil {
		t.Fatal(err)
	}
	out := etree.NewDocument()
	out.SetRoot(signed)
	s, err := out.WriteToString()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func wrapResponse(assertions ...string) string {
	return base64.StdEncoding.EncodeToString([]byte(
		`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_r1" Version="2.0" Destination="` + testACS + `" InResponseTo="` + testReq + `">` +
			`<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>` +
			strings.Join(assertions, "") + `</samlp:Response>`))
}

const ecdsaSHA256 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"

func TestSAMLAcceptsSignedAssertionFromConfiguredIdP(t *testing.T) {
	idp := newSAMLIdP(t)
	resp := wrapResponse(signAssertion(t, idp, assertionXML(defaultOpts()), ecdsaSHA256))
	got, err := parseSAMLResponse(samlConfig(idp.cert), resp, testReq, time.Now())
	if err != nil {
		t.Fatalf("valid assertion refused: %v", err)
	}
	if got.Attrs.Email != "alice@example.com" || got.ID != "_a1" {
		t.Fatalf("unexpected attributes: %+v", got)
	}
}

func TestSAMLRefusesForgedAndMisdirectedAssertions(t *testing.T) {
	idp := newSAMLIdP(t)
	other := newSAMLIdP(t)
	signed := signAssertion(t, idp, assertionXML(defaultOpts()), ecdsaSHA256)
	mut := func(f func(*assertionOpts)) string {
		o := defaultOpts()
		f(&o)
		return wrapResponse(signAssertion(t, idp, assertionXML(o), ecdsaSHA256))
	}
	cases := map[string]string{
		"unsigned":            wrapResponse(assertionXML(defaultOpts())),
		"tampered after sign": wrapResponse(strings.Replace(signed, "alice@example.com</saml:NameID>", "admin@example.com</saml:NameID>", 1)),
		"signed by other key": wrapResponse(signAssertion(t, other, assertionXML(defaultOpts()), ecdsaSHA256)),
		"wrapping: two":       wrapResponse(assertionXML(defaultOpts()), signed),
		"wrong issuer":        mut(func(o *assertionOpts) { o.issuer = "https://evil.test" }),
		"wrong audience":      mut(func(o *assertionOpts) { o.audience = "https://other-sp.test" }),
		"wrong recipient":     mut(func(o *assertionOpts) { o.recipient = "https://evil.test/acs" }),
		"other login request": mut(func(o *assertionOpts) { o.inResponseTo = "_someone_else" }),
		"expired":             mut(func(o *assertionOpts) { o.notOnOrAfter = time.Now().Add(-10 * time.Minute) }),
		"sha1 signature":      wrapResponse(strings.Replace(signed, ecdsaSHA256, "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1", 1)),
		"not base64":          "%%%",
		"encrypted assertion": base64.StdEncoding.EncodeToString([]byte(`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status><saml:EncryptedAssertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"/></samlp:Response>`)),
	}
	for name, resp := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := parseSAMLResponse(samlConfig(idp.cert), resp, testReq, time.Now()); err == nil {
				t.Fatal("forged or misdirected assertion was accepted")
			}
		})
	}
	if _, err := parseSAMLResponse(samlConfig(""), wrapResponse(signed), testReq, time.Now()); err == nil {
		t.Fatal("assertion accepted with no IdP certificate configured")
	}
	if _, err := parseSAMLResponse(samlConfig(idp.cert), wrapResponse(signed), "", time.Now()); err == nil {
		t.Fatal("assertion accepted without an outstanding login request")
	}
}

func TestSAMLAssertionIsSingleUse(t *testing.T) {
	id := "_replay_" + NewID("t")
	exp := time.Now().Add(time.Minute)
	if !consumeSAMLAssertion(id, exp) {
		t.Fatal("first use refused")
	}
	if consumeSAMLAssertion(id, exp) {
		t.Fatal("replayed assertion accepted")
	}
}

func TestSAMLAuthnRequestBindsRelayStateToRequest(t *testing.T) {
	idp := newSAMLIdP(t)
	redirect, err := buildSAMLAuthnRequest(samlConfig(idp.cert), "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	i := strings.Index(redirect, "RelayState=")
	if i < 0 {
		t.Fatal("no RelayState in redirect")
	}
	state := strings.SplitN(redirect[i+len("RelayState="):], "&", 2)[0]
	entry, err := validateSSOState(state)
	if err != nil || entry.TenantID != "tenant-a" || entry.Provider != identityProviderSAML || !strings.HasPrefix(entry.Bind, "_saml") {
		t.Fatalf("state not bound: %+v %v", entry, err)
	}
	if _, err := validateSSOState(state); err == nil {
		t.Fatal("RelayState reusable")
	}
	if _, err := buildSAMLAuthnRequest(samlConfig(""), "tenant-a"); err == nil {
		t.Fatal("login started without an IdP certificate to verify against")
	}
}
