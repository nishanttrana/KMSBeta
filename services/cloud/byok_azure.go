package main

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	pkgcrypto "vecta-kms/pkg/crypto"
)

// Azure Key Vault (Premium) and Managed HSM BYOK: a temporary RSA-HSM key
// exchange key (KEK) with only the "import" operation; the material is
// wrapped to it with CKM_RSA_AES_KEY_WRAP (RSA-OAEP with SHA-1 over a fresh
// AES key, then AES key wrap with padding), sent as a transfer blob in
// key_hsm, and the KEK is deleted afterwards. Each import is a new version
// of the key; revoking disables the version (Azure has no way to remove
// material but deleting the whole key).

const azureBYOKEnc = "CKM_RSA_AES_KEY_WRAP"

func (p *azureProvider) Capabilities() Capabilities {
	return Capabilities{Rotate: true, Reimport: true, Revoke: true, RevokeDeletes: false, Expiry: true, Verify: true,
		Specs: []string{SpecAES256, SpecRSA2048, SpecRSA3072, SpecRSA4096, SpecECP256}}
}

type azureCall struct {
	token, vault, apiVersion string
}

func (p *azureProvider) call(ctx context.Context, c cloudKeyCall) (azureCall, error) {
	token, vault, apiVersion, _, err := p.resolveConnection(ctx, c.Region, c.Account, c.Credentials)
	return azureCall{token, vault, apiVersion}, err
}

func (a azureCall) url(path string) string {
	return a.vault + path + "?api-version=" + url.QueryEscape(a.apiVersion)
}

func (p *azureProvider) do(ctx context.Context, a azureCall, method, path string, body interface{}) (map[string]interface{}, error) {
	out, err := httpJSONRequest(ctx, p.httpClient, method, a.url(path), a.token, body, nil)
	return asObject(out), err
}

func azureKeyBody(spec, usage string) (map[string]interface{}, error) {
	switch spec {
	case SpecAES256:
		return map[string]interface{}{"kty": "oct-HSM", "key_ops": []string{"encrypt", "decrypt", "wrapKey", "unwrapKey"}}, nil
	case SpecRSA2048, SpecRSA3072, SpecRSA4096:
		ops := []string{"sign", "verify"}
		if usage == "encrypt" {
			ops = []string{"encrypt", "decrypt", "wrapKey", "unwrapKey"}
		}
		return map[string]interface{}{"kty": "RSA-HSM", "key_ops": ops}, nil
	case SpecECP256:
		return map[string]interface{}{"kty": "EC-HSM", "crv": "P-256", "key_ops": []string{"sign", "verify"}}, nil
	}
	return nil, fmt.Errorf("Azure Key Vault import here supports AES-256 (Managed HSM), RSA and EC-P256 keys, not %s", spec)
}

// CreateKey reserves the name; Azure creates the key on the first import.
func (p *azureProvider) CreateKey(_ context.Context, _ cloudKeyCall, k BYOKKey, _ string) (BYOKKey, string, error) {
	if _, err := azureKeyBody(k.KeySpec, k.Usage); err != nil {
		return k, "", err
	}
	name := sanitizeCloudName(defaultString(strings.TrimPrefix(k.Alias, "alias/"), "vecta-"+k.KeyID))
	k.CloudKeyID, k.Alias, k.CloudState = name, name, "pending_import"
	return k, "", nil
}

func (p *azureProvider) ImportParameters(ctx context.Context, c cloudKeyCall, k BYOKKey) (ImportParams, string, error) {
	a, err := p.call(ctx, c)
	if err != nil {
		return ImportParams{}, "", err
	}
	kek := sanitizeCloudName(k.CloudKeyID + "-kek-" + newID("x"))
	cli := fmt.Sprintf("az keyvault key create --vault-name %s --name %s --kty RSA-HSM --size 4096 --ops import", vaultName(a.vault), kek)
	out, err := p.do(ctx, a, http.MethodPost, "/keys/"+url.PathEscape(kek)+"/create", map[string]interface{}{
		"kty": "RSA-HSM", "key_size": 4096, "key_ops": []string{"import"},
		"attributes": map[string]interface{}{"exp": time.Now().Add(24 * time.Hour).Unix()},
	})
	if err != nil {
		return ImportParams{}, cli, err
	}
	jwk := nestedObject(out, "key")
	pub, err := pkgcrypto.RSAPublicKeyFromJWK(firstString(jwk, "n"), firstString(jwk, "e"))
	if err != nil {
		return ImportParams{}, cli, err
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return ImportParams{}, cli, err
	}
	return ImportParams{WrappingKey: der, Scheme: pkgcrypto.CloudWrapRSAAESKWPSHA1, Handle: firstString(jwk, "kid")}, cli, nil
}

func (p *azureProvider) Import(ctx context.Context, c cloudKeyCall, k BYOKKey, in ImportRequest) (BYOKKey, string, string, error) {
	keyBody, err := azureKeyBody(k.KeySpec, k.Usage)
	if err != nil {
		return k, "", "", err
	}
	a, err := p.call(ctx, c)
	if err != nil {
		return k, "", "", err
	}
	blob, _ := json.Marshal(map[string]interface{}{
		"schema_version": "1.0.0",
		"header":         map[string]string{"kid": in.Params.Handle, "alg": "dir", "enc": azureBYOKEnc},
		"ciphertext":     base64.RawURLEncoding.EncodeToString(in.Wrapped),
		"generator":      "Vecta KMS",
	})
	keyBody["key_hsm"] = base64.RawURLEncoding.EncodeToString(blob)
	attrs := map[string]interface{}{"enabled": true}
	if in.ExpiresAt != nil {
		attrs["exp"] = in.ExpiresAt.Unix()
	}
	cli := fmt.Sprintf("az keyvault key import --vault-name %s --name %s --byok-file transfer.byok", vaultName(a.vault), k.CloudKeyID)
	out, err := p.do(ctx, a, http.MethodPut, "/keys/"+url.PathEscape(k.CloudKeyID), map[string]interface{}{
		"key": keyBody, "hsm": true, "attributes": attrs, "tags": map[string]string{"vecta_key_id": sanitizeLabel(k.KeyID), "vecta_source": k.Source},
	})
	if err != nil {
		return k, "", cli, err
	}
	kid := firstString(nestedObject(out, "key"), "kid")
	if kid == "" {
		return k, "", cli, errors.New("azure import returned no key id")
	}
	k.CloudKeyRef = kid[:strings.LastIndex(kid, "/")]
	k.CloudState = "enabled"
	return k, kid[strings.LastIndex(kid, "/")+1:], cli, nil
}

// MakeCurrent: the newest version is the current one.
func (p *azureProvider) MakeCurrent(context.Context, cloudKeyCall, BYOKKey, string) (string, error) {
	return "", nil
}

func (p *azureProvider) setEnabled(ctx context.Context, c cloudKeyCall, k BYOKKey, version string, enabled bool) (string, error) {
	if version == "" {
		return "", errors.New("no Azure key version recorded for this material")
	}
	a, err := p.call(ctx, c)
	if err != nil {
		return "", err
	}
	cli := fmt.Sprintf("az keyvault key set-attributes --vault-name %s --name %s --version %s --enabled %v", vaultName(a.vault), k.CloudKeyID, version, enabled)
	_, err = p.do(ctx, a, http.MethodPatch, "/keys/"+url.PathEscape(k.CloudKeyID)+"/"+url.PathEscape(version),
		map[string]interface{}{"attributes": map[string]interface{}{"enabled": enabled}})
	return cli, err
}

func (p *azureProvider) Revoke(ctx context.Context, c cloudKeyCall, k BYOKKey, materialID string) (string, error) {
	return p.setEnabled(ctx, c, k, materialID, false)
}

func (p *azureProvider) Unrevoke(ctx context.Context, c cloudKeyCall, k BYOKKey, materialID string) (bool, string, error) {
	cli, err := p.setEnabled(ctx, c, k, materialID, true)
	return err == nil, cli, err
}

func (p *azureProvider) Describe(ctx context.Context, c cloudKeyCall, k BYOKKey) (BYOKKey, string, error) {
	a, err := p.call(ctx, c)
	if err != nil {
		return k, "", err
	}
	cli := fmt.Sprintf("az keyvault key show --vault-name %s --name %s", vaultName(a.vault), k.CloudKeyID)
	out, err := p.do(ctx, a, http.MethodGet, "/keys/"+url.PathEscape(k.CloudKeyID), nil)
	if err != nil {
		return k, cli, err
	}
	attrs := nestedObject(out, "attributes")
	k.CloudState = "disabled"
	if on, ok := boolValue(attrs["enabled"]); ok && on {
		k.CloudState = "enabled"
	}
	if exp, ok := attrs["exp"].(float64); ok && exp > 0 {
		t := time.Unix(int64(exp), 0).UTC()
		k.ExpiresAt = &t
	}
	if kid := firstString(nestedObject(out, "key"), "kid"); kid != "" {
		k.CurrentMatID = kid[strings.LastIndex(kid, "/")+1:]
	}
	return k, cli, nil
}

func (p *azureProvider) Verify(ctx context.Context, c cloudKeyCall, k BYOKKey) (string, string, error) {
	a, err := p.call(ctx, c)
	if err != nil {
		return "", "", err
	}
	base := "/keys/" + url.PathEscape(k.CloudKeyID) + "/" + url.PathEscape(k.CurrentMatID)
	b64 := base64.RawURLEncoding.EncodeToString
	switch {
	case k.KeySpec == SpecAES256 || k.Usage == "encrypt":
		alg := "A256KW"
		if k.KeySpec != SpecAES256 {
			alg = "RSA-OAEP-256"
		}
		probe := pkgcrypto.SHA256(verifyMessage()) // 32 bytes to wrap
		cli := fmt.Sprintf("az keyvault key encrypt/decrypt (wrapkey/unwrapkey, %s) --name %s --version %s", alg, k.CloudKeyID, k.CurrentMatID)
		wrapped, err := p.do(ctx, a, http.MethodPost, base+"/wrapkey", map[string]string{"alg": alg, "value": b64(probe)})
		if err != nil {
			return "", cli, err
		}
		back, err := p.do(ctx, a, http.MethodPost, base+"/unwrapkey", map[string]string{"alg": alg, "value": firstString(wrapped, "value")})
		if err != nil {
			return "", cli, err
		}
		if got, _ := base64.RawURLEncoding.DecodeString(firstString(back, "value")); string(got) != string(probe) {
			return "", cli, errors.New("unwrapkey returned a different value")
		}
		return "wrapkey and unwrapkey round trip with " + alg, cli, nil
	default:
		alg := "PS256"
		if k.KeySpec == SpecECP256 {
			alg = "ES256"
		}
		digest := pkgcrypto.SHA256(verifyMessage())
		cli := fmt.Sprintf("az keyvault key sign/verify --name %s --version %s --algorithm %s", k.CloudKeyID, k.CurrentMatID, alg)
		sig, err := p.do(ctx, a, http.MethodPost, base+"/sign", map[string]string{"alg": alg, "value": b64(digest)})
		if err != nil {
			return "", cli, err
		}
		v, err := p.do(ctx, a, http.MethodPost, base+"/verify", map[string]string{"alg": alg, "digest": b64(digest), "value": firstString(sig, "value")})
		if err != nil {
			return "", cli, err
		}
		if ok, _ := boolValue(v["value"]); !ok {
			return "", cli, errors.New("the signature did not verify")
		}
		return "sign and verify with " + alg, cli, nil
	}
}

func (p *azureProvider) Cleanup(ctx context.Context, c cloudKeyCall, _ BYOKKey, params ImportParams) (string, error) {
	if params.Handle == "" {
		return "", nil
	}
	a, err := p.call(ctx, c)
	if err != nil {
		return "", err
	}
	// .../keys/{name}/{version}: the KEK's name.
	parts := strings.Split(strings.TrimRight(params.Handle, "/"), "/")
	name := parts[len(parts)-2]
	cli := fmt.Sprintf("az keyvault key delete --vault-name %s --name %s", vaultName(a.vault), name)
	_, err = p.do(ctx, a, http.MethodDelete, "/keys/"+url.PathEscape(name), nil)
	return cli, err
}

func vaultName(vaultURL string) string {
	host := strings.TrimPrefix(strings.TrimPrefix(vaultURL, "https://"), "http://")
	if i := strings.IndexByte(host, '.'); i > 0 {
		return host[:i]
	}
	return host
}
