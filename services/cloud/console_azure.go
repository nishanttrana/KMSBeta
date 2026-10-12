package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	pkgcrypto "vecta-kms/pkg/crypto"
)

// Azure Key Vault / Managed HSM console operations. Access is the vault's
// RBAC or access policy, not a per-key policy, and there are no grants or
// aliases. Deletion is the vault's soft delete; cancel recovers the key.

// azureKeyName takes a name or a key URL and returns the name.
func azureKeyRef(key string) string {
	key = strings.TrimRight(strings.TrimSpace(key), "/")
	if i := strings.Index(key, "/keys/"); i >= 0 {
		key = strings.SplitN(key[i+len("/keys/"):], "/", 2)[0]
	}
	return key
}

func (p *azureProvider) Console() map[string]ConsoleFunc {
	type azFn func(ctx context.Context, a azureCall, name string, in ConsoleInput) (interface{}, string, error)
	with := func(f azFn) ConsoleFunc {
		return func(ctx context.Context, c cloudKeyCall, in ConsoleInput) (interface{}, string, error) {
			a, err := p.call(ctx, c)
			if err != nil {
				return nil, "", err
			}
			return f(ctx, a, url.PathEscape(azureKeyRef(in.Key)), in)
		}
	}
	vault := func(a azureCall) string { return vaultName(a.vault) }
	ver := func(in ConsoleInput) string { return url.PathEscape(in.Version) }
	b64u := base64.RawURLEncoding
	std := base64.StdEncoding
	// kty reads the key's type to pick a default algorithm.
	kty := func(ctx context.Context, a azureCall, name string) (string, error) {
		out, err := p.do(ctx, a, http.MethodGet, "/keys/"+name, nil)
		if err != nil {
			return "", err
		}
		return firstString(nestedObject(out, "key"), "kty"), nil
	}
	setEnabled := func(enabled bool) ConsoleFunc {
		return with(func(ctx context.Context, a azureCall, name string, in ConsoleInput) (interface{}, string, error) {
			out, err := p.do(ctx, a, http.MethodPatch, "/keys/"+name+"/"+ver(in), map[string]interface{}{"attributes": map[string]bool{"enabled": enabled}})
			return okOut(out, err), fmt.Sprintf("az keyvault key set-attributes --vault-name %s --name %s --enabled %v", vault(a), name, enabled), err
		})
	}
	setTags := func(change func(map[string]interface{}, ConsoleInput), cli func(string, string, ConsoleInput) string) ConsoleFunc {
		return with(func(ctx context.Context, a azureCall, name string, in ConsoleInput) (interface{}, string, error) {
			cur, err := p.do(ctx, a, http.MethodGet, "/keys/"+name, nil)
			if err != nil {
				return nil, "", err
			}
			tags := nestedObject(cur, "tags")
			change(tags, in)
			out, err := p.do(ctx, a, http.MethodPatch, "/keys/"+name+"/", map[string]interface{}{"tags": tags})
			return okOut(nestedObject(out, "tags"), err), cli(vault(a), name, in), err
		})
	}
	return map[string]ConsoleFunc{
		"list-keys": with(func(ctx context.Context, a azureCall, _ string, _ ConsoleInput) (interface{}, string, error) {
			out, err := p.do(ctx, a, http.MethodGet, "/keys", nil)
			return okOut(out["value"], err), "az keyvault key list --vault-name " + vault(a), err
		}),
		"describe-key": with(func(ctx context.Context, a azureCall, name string, _ ConsoleInput) (interface{}, string, error) {
			out, err := p.do(ctx, a, http.MethodGet, "/keys/"+name, nil)
			return okOut(out, err), fmt.Sprintf("az keyvault key show --vault-name %s --name %s", vault(a), name), err
		}),
		"list-versions": with(func(ctx context.Context, a azureCall, name string, _ ConsoleInput) (interface{}, string, error) {
			out, err := p.do(ctx, a, http.MethodGet, "/keys/"+name+"/versions", nil)
			return okOut(out["value"], err), fmt.Sprintf("az keyvault key list-versions --vault-name %s --name %s", vault(a), name), err
		}),
		"get-public-key": with(func(ctx context.Context, a azureCall, name string, in ConsoleInput) (interface{}, string, error) {
			out, err := p.do(ctx, a, http.MethodGet, "/keys/"+name+"/"+ver(in), nil)
			return okOut(nestedObject(out, "key"), err), fmt.Sprintf("az keyvault key download --vault-name %s --name %s --encoding PEM --file public.pem", vault(a), name), err
		}),
		"enable-key":  setEnabled(true),
		"disable-key": setEnabled(false),
		"schedule-key-deletion": with(func(ctx context.Context, a azureCall, name string, _ ConsoleInput) (interface{}, string, error) {
			out, err := p.do(ctx, a, http.MethodDelete, "/keys/"+name, nil)
			return okOut(map[string]interface{}{"scheduled_purge_date": out["scheduledPurgeDate"], "recovery_id": out["recoveryId"]}, err),
				fmt.Sprintf("az keyvault key delete --vault-name %s --name %s", vault(a), name), err
		}),
		"cancel-key-deletion": with(func(ctx context.Context, a azureCall, name string, _ ConsoleInput) (interface{}, string, error) {
			out, err := p.do(ctx, a, http.MethodPost, "/deletedkeys/"+name+"/recover", nil)
			return okOut(out, err), fmt.Sprintf("az keyvault key recover --vault-name %s --name %s", vault(a), name), err
		}),
		"list-tags": with(func(ctx context.Context, a azureCall, name string, _ ConsoleInput) (interface{}, string, error) {
			out, err := p.do(ctx, a, http.MethodGet, "/keys/"+name, nil)
			return okOut(nestedObject(out, "tags"), err), fmt.Sprintf("az keyvault key show --vault-name %s --name %s --query tags", vault(a), name), err
		}),
		"tag-key": setTags(func(t map[string]interface{}, in ConsoleInput) { t[in.Params["tag_key"]] = in.Params["tag_value"] },
			func(v, n string, in ConsoleInput) string {
				return fmt.Sprintf("az keyvault key set-attributes --vault-name %s --name %s --tags %s=%s", v, n, in.Params["tag_key"], in.Params["tag_value"])
			}),
		"untag-key": setTags(func(t map[string]interface{}, in ConsoleInput) { delete(t, in.Params["tag_key"]) },
			func(v, n string, in ConsoleInput) string {
				return fmt.Sprintf("az keyvault key set-attributes --vault-name %s --name %s --tags (all but %s)", v, n, in.Params["tag_key"])
			}),
		"encrypt": with(func(ctx context.Context, a azureCall, name string, in ConsoleInput) (interface{}, string, error) {
			alg := in.Params["algorithm"]
			if alg == "" {
				t, err := kty(ctx, a, name)
				if err != nil {
					return nil, "", err
				}
				alg = map[bool]string{true: "A256GCM", false: "RSA-OAEP-256"}[strings.HasPrefix(t, "oct")]
			}
			cli := fmt.Sprintf("az keyvault key encrypt --vault-name %s --name %s --algorithm %s --value <base64> --data-type base64", vault(a), name, alg)
			out, err := p.do(ctx, a, http.MethodPost, "/keys/"+name+"/"+ver(in)+"/encrypt", map[string]string{"alg": alg, "value": b64u.EncodeToString(in.bytes("plaintext_b64"))})
			if err != nil {
				return nil, cli, err
			}
			res := map[string]interface{}{"algorithm": alg, "key_version": firstString(out, "kid")}
			for from, to := range map[string]string{"value": "ciphertext_b64", "iv": "iv_b64", "tag": "tag_b64"} {
				if v := firstString(out, from); v != "" {
					raw, _ := b64u.DecodeString(v)
					res[to] = std.EncodeToString(raw)
				}
			}
			return res, cli, nil
		}),
		"decrypt": with(func(ctx context.Context, a azureCall, name string, in ConsoleInput) (interface{}, string, error) {
			alg := in.Params["algorithm"]
			if alg == "" {
				t, err := kty(ctx, a, name)
				if err != nil {
					return nil, "", err
				}
				alg = map[bool]string{true: "A256GCM", false: "RSA-OAEP-256"}[strings.HasPrefix(t, "oct")]
			}
			body := map[string]string{"alg": alg, "value": b64u.EncodeToString(in.bytes("ciphertext_b64"))}
			if iv := in.bytes("iv_b64"); len(iv) > 0 {
				body["iv"] = b64u.EncodeToString(iv)
			}
			if tag := in.bytes("tag_b64"); len(tag) > 0 {
				body["tag"] = b64u.EncodeToString(tag)
			}
			cli := fmt.Sprintf("az keyvault key decrypt --vault-name %s --name %s --algorithm %s --value <base64> --data-type base64", vault(a), name, alg)
			out, err := p.do(ctx, a, http.MethodPost, "/keys/"+name+"/"+ver(in)+"/decrypt", body)
			if err != nil {
				return nil, cli, err
			}
			pt, _ := b64u.DecodeString(firstString(out, "value"))
			return plaintextResult(pt), cli, nil
		}),
		"sign": with(func(ctx context.Context, a azureCall, name string, in ConsoleInput) (interface{}, string, error) {
			alg := defaultString(in.Params["algorithm"], "PS256")
			cli := fmt.Sprintf("az keyvault key sign --vault-name %s --name %s --algorithm %s --digest <sha256 base64>", vault(a), name, alg)
			out, err := p.do(ctx, a, http.MethodPost, "/keys/"+name+"/"+ver(in)+"/sign",
				map[string]string{"alg": alg, "value": b64u.EncodeToString(pkgcrypto.SHA256(in.bytes("message_b64")))})
			if err != nil {
				return nil, cli, err
			}
			sig, _ := b64u.DecodeString(firstString(out, "value"))
			return map[string]string{"signature_b64": std.EncodeToString(sig), "algorithm": alg}, cli, nil
		}),
		"verify": with(func(ctx context.Context, a azureCall, name string, in ConsoleInput) (interface{}, string, error) {
			alg := defaultString(in.Params["algorithm"], "PS256")
			cli := fmt.Sprintf("az keyvault key verify --vault-name %s --name %s --algorithm %s --digest <sha256 base64> --signature <base64>", vault(a), name, alg)
			out, err := p.do(ctx, a, http.MethodPost, "/keys/"+name+"/"+ver(in)+"/verify", map[string]string{"alg": alg,
				"digest": b64u.EncodeToString(pkgcrypto.SHA256(in.bytes("message_b64"))), "value": b64u.EncodeToString(in.bytes("signature_b64"))})
			if err != nil {
				return nil, cli, err
			}
			ok, _ := boolValue(out["value"])
			return map[string]bool{"valid": ok}, cli, nil
		}),
	}
}

func okOut(v interface{}, err error) interface{} {
	if err != nil {
		return nil
	}
	return v
}
