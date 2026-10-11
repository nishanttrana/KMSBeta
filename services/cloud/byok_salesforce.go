package main

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	pkgcrypto "vecta-kms/pkg/crypto"
)

// Salesforce Shield Platform Encryption, bring your own key: the org admin
// creates a BYOK-compatible certificate in Setup; the tenant secret is
// wrapped to its public key with RSA-OAEP (SHA-1, as Salesforce requires)
// and uploaded as a TenantSecret with the SHA-256 hash of the secret, which
// Salesforce checks after unwrapping. Each upload is the new active secret.
// Salesforce has no API to verify, revoke or re-upload a secret; those are
// Setup actions, so they are not offered.

const salesforceSecretTypes = "Data,SearchIndex,Analytics,EventBus,DeterministicData"

func (p *salesforceProvider) Capabilities() Capabilities {
	return Capabilities{Rotate: true, Specs: []string{SpecAES256}}
}

// CreateKey records the certificate; Salesforce creates the secret on upload.
func (p *salesforceProvider) CreateKey(_ context.Context, _ cloudKeyCall, k BYOKKey, _ string) (BYOKKey, string, error) {
	if k.KeySpec != SpecAES256 {
		return k, "", fmt.Errorf("Salesforce tenant secrets are 256-bit, not %s", k.KeySpec)
	}
	name, certPEM := k.Settings["certificate_name"], k.Settings["certificate_pem"]
	if name == "" || certPEM == "" {
		return k, "", errors.New("certificate_name and certificate_pem (the BYOK-compatible certificate from Setup) are required")
	}
	if _, err := salesforceCertKey(certPEM); err != nil {
		return k, "", err
	}
	typ := defaultString(k.Settings["secret_type"], "Data")
	if !strings.Contains(","+salesforceSecretTypes+",", ","+typ+",") {
		return k, "", fmt.Errorf("secret_type must be one of %s", salesforceSecretTypes)
	}
	k.Settings["secret_type"] = typ
	k.CloudKeyID, k.Alias, k.CloudState = "TenantSecret:"+typ, name, "pending_import"
	return k, "", nil
}

func salesforceCertKey(certPEM string) ([]byte, error) {
	block, _ := pem.Decode([]byte(strings.TrimSpace(certPEM)))
	if block == nil {
		return nil, errors.New("certificate_pem is not PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("certificate_pem: %w", err)
	}
	return x509.MarshalPKIXPublicKey(cert.PublicKey)
}

func (p *salesforceProvider) ImportParameters(_ context.Context, _ cloudKeyCall, k BYOKKey) (ImportParams, string, error) {
	der, err := salesforceCertKey(k.Settings["certificate_pem"])
	if err != nil {
		return ImportParams{}, "", err
	}
	return ImportParams{WrappingKey: der, Scheme: pkgcrypto.CloudWrapRSAOAEPSHA1, Handle: k.Settings["certificate_name"], WantDigest: true}, "", nil
}

func (p *salesforceProvider) Import(ctx context.Context, c cloudKeyCall, k BYOKKey, in ImportRequest) (BYOKKey, string, string, error) {
	if len(in.Digest) == 0 {
		return k, "", "", errors.New("Salesforce needs the secret's SHA-256 hash")
	}
	token, instance, apiVersion, err := p.resolveConnection(ctx, c.Account, c.Credentials)
	if err != nil {
		return k, "", "", err
	}
	path := "/services/data/" + apiVersion + "/sobjects/TenantSecret"
	cli := "sf data create record --sobject TenantSecret --values \"Type=" + k.Settings["secret_type"] + " SecretValue=<wrapped> SecretValueCertificate=" + in.Params.Handle + " SecretValueHash=<sha256>\""
	out, err := httpJSONRequest(ctx, p.httpClient, http.MethodPost, instance+path, token, map[string]interface{}{
		"Type":                   k.Settings["secret_type"],
		"Description":            in.Description,
		"SecretValue":            base64.StdEncoding.EncodeToString(in.Wrapped),
		"SecretValueCertificate": in.Params.Handle,
		"SecretValueHash":        base64.StdEncoding.EncodeToString(in.Digest),
	}, nil)
	if err != nil {
		return k, "", cli, err
	}
	id := firstString(asObject(out), "id")
	if id == "" {
		return k, "", cli, errors.New("salesforce returned no TenantSecret id")
	}
	k.CloudKeyRef = instance + path + "/" + id
	k.CloudState = "ACTIVE"
	return k, id, cli, nil
}

func (p *salesforceProvider) MakeCurrent(context.Context, cloudKeyCall, BYOKKey, string) (string, error) {
	return "", nil // an uploaded secret is the active one
}

func (p *salesforceProvider) Revoke(context.Context, cloudKeyCall, BYOKKey, string) (string, error) {
	return "", errors.New("Salesforce destroys tenant secrets in Setup only")
}

func (p *salesforceProvider) Unrevoke(context.Context, cloudKeyCall, BYOKKey, string) (bool, string, error) {
	return false, "", nil
}

func (p *salesforceProvider) Describe(ctx context.Context, c cloudKeyCall, k BYOKKey) (BYOKKey, string, error) {
	if k.CurrentMatID == "" {
		return k, "", nil
	}
	token, instance, apiVersion, err := p.resolveConnection(ctx, c.Account, c.Credentials)
	if err != nil {
		return k, "", err
	}
	cli := "sf data get record --sobject TenantSecret --record-id " + k.CurrentMatID
	out, err := httpJSONRequest(ctx, p.httpClient, http.MethodGet,
		instance+"/services/data/"+apiVersion+"/sobjects/TenantSecret/"+url.PathEscape(k.CurrentMatID)+"?fields=Status,Version", token, nil, nil)
	if err != nil {
		return k, cli, err
	}
	k.CloudState = defaultString(firstString(asObject(out), "Status"), k.CloudState)
	return k, cli, nil
}

func (p *salesforceProvider) Verify(context.Context, cloudKeyCall, BYOKKey) (string, string, error) {
	return "", "", errors.New("Salesforce has no API to test a tenant secret")
}

func (p *salesforceProvider) Cleanup(context.Context, cloudKeyCall, BYOKKey, ImportParams) (string, error) {
	return "", nil
}
