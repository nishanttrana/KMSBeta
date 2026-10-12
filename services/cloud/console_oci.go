package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/keymanagement"
)

// OCI Vault console operations. Access is IAM policy on the compartment, not
// a per-key policy; there are no grants or aliases. Tags are freeform tags.
// Encrypt, decrypt, sign and verify go to the vault's crypto endpoint
// (crypto_endpoint in the credential).

func (p *ociProvider) Console() map[string]ConsoleFunc {
	type mgmtFn func(ctx context.Context, k keymanagement.KmsManagementClient, compartment string, in ConsoleInput) (interface{}, string, error)
	mgmt := func(f mgmtFn) ConsoleFunc {
		return func(ctx context.Context, c cloudKeyCall, in ConsoleInput) (interface{}, string, error) {
			k, _, compartment, err := p.client(c.Region, c.Account, c.Credentials)
			if err != nil {
				return nil, "", err
			}
			return f(ctx, k, compartment, in)
		}
	}
	type cryptoFn func(ctx context.Context, k keymanagement.KmsCryptoClient, m keymanagement.KmsManagementClient, in ConsoleInput) (interface{}, string, error)
	crypto := func(f cryptoFn) ConsoleFunc {
		return func(ctx context.Context, c cloudKeyCall, in ConsoleInput) (interface{}, string, error) {
			endpoint := strings.TrimSpace(anyToString(c.Credentials["crypto_endpoint"]))
			if endpoint == "" {
				return nil, "", errors.New("the OCI credential has no crypto_endpoint (the vault's cryptographic endpoint)")
			}
			m, _, _, err := p.client(c.Region, c.Account, c.Credentials)
			if err != nil {
				return nil, "", err
			}
			k, err := keymanagement.NewKmsCryptoClientWithConfigurationProvider(ociConfig(c), strings.TrimRight(endpoint, "/"))
			if err != nil {
				return nil, "", err
			}
			return f(ctx, k, m, in)
		}
	}
	key := func(in ConsoleInput) *string { return common.String(in.Key) }
	// versionOf is the given version, else the key's current one.
	versionOf := func(ctx context.Context, m keymanagement.KmsManagementClient, in ConsoleInput) (string, error) {
		if in.Version != "" {
			return in.Version, nil
		}
		out, err := m.GetKey(ctx, keymanagement.GetKeyRequest{KeyId: key(in)})
		if err != nil {
			return "", err
		}
		return deref(out.CurrentKeyVersion), nil
	}
	b64 := base64.StdEncoding.EncodeToString
	tags := func(change func(map[string]string, ConsoleInput), cli func(ConsoleInput) string) ConsoleFunc {
		return mgmt(func(ctx context.Context, k keymanagement.KmsManagementClient, _ string, in ConsoleInput) (interface{}, string, error) {
			cur, err := k.GetKey(ctx, keymanagement.GetKeyRequest{KeyId: key(in)})
			if err != nil {
				return nil, "", err
			}
			t := map[string]string{}
			for a, b := range cur.FreeformTags {
				t[a] = b
			}
			change(t, in)
			out, err := k.UpdateKey(ctx, keymanagement.UpdateKeyRequest{KeyId: key(in), UpdateKeyDetails: keymanagement.UpdateKeyDetails{FreeformTags: t}})
			return okOut(out.FreeformTags, err), cli(in), err
		})
	}
	return map[string]ConsoleFunc{
		"list-keys": mgmt(func(ctx context.Context, k keymanagement.KmsManagementClient, compartment string, _ ConsoleInput) (interface{}, string, error) {
			out, err := k.ListKeys(ctx, keymanagement.ListKeysRequest{CompartmentId: common.String(compartment)})
			return okOut(out.Items, err), "oci kms management key list --compartment-id " + compartment, err
		}),
		"describe-key": mgmt(func(ctx context.Context, k keymanagement.KmsManagementClient, _ string, in ConsoleInput) (interface{}, string, error) {
			out, err := k.GetKey(ctx, keymanagement.GetKeyRequest{KeyId: key(in)})
			return okOut(out.Key, err), "oci kms management key get --key-id " + in.Key, err
		}),
		"list-versions": mgmt(func(ctx context.Context, k keymanagement.KmsManagementClient, _ string, in ConsoleInput) (interface{}, string, error) {
			out, err := k.ListKeyVersions(ctx, keymanagement.ListKeyVersionsRequest{KeyId: key(in)})
			return okOut(out.Items, err), "oci kms management key-version list --key-id " + in.Key, err
		}),
		"enable-key": mgmt(func(ctx context.Context, k keymanagement.KmsManagementClient, _ string, in ConsoleInput) (interface{}, string, error) {
			out, err := k.EnableKey(ctx, keymanagement.EnableKeyRequest{KeyId: key(in)})
			return okOut(map[string]interface{}{"lifecycle_state": out.LifecycleState}, err), "oci kms management key enable --key-id " + in.Key, err
		}),
		"disable-key": mgmt(func(ctx context.Context, k keymanagement.KmsManagementClient, _ string, in ConsoleInput) (interface{}, string, error) {
			out, err := k.DisableKey(ctx, keymanagement.DisableKeyRequest{KeyId: key(in)})
			return okOut(map[string]interface{}{"lifecycle_state": out.LifecycleState}, err), "oci kms management key disable --key-id " + in.Key, err
		}),
		"schedule-key-deletion": mgmt(func(ctx context.Context, k keymanagement.KmsManagementClient, _ string, in ConsoleInput) (interface{}, string, error) {
			when := time.Now().UTC().Add(time.Duration(in.int("pending_days", 30)) * 24 * time.Hour)
			out, err := k.ScheduleKeyDeletion(ctx, keymanagement.ScheduleKeyDeletionRequest{KeyId: key(in),
				ScheduleKeyDeletionDetails: keymanagement.ScheduleKeyDeletionDetails{TimeOfDeletion: &common.SDKTime{Time: when}}})
			return okOut(map[string]interface{}{"lifecycle_state": out.LifecycleState, "time_of_deletion": when}, err),
				fmt.Sprintf("oci kms management key schedule-deletion --key-id %s --time-of-deletion %s", in.Key, when.Format(time.RFC3339)), err
		}),
		"cancel-key-deletion": mgmt(func(ctx context.Context, k keymanagement.KmsManagementClient, _ string, in ConsoleInput) (interface{}, string, error) {
			out, err := k.CancelKeyDeletion(ctx, keymanagement.CancelKeyDeletionRequest{KeyId: key(in)})
			return okOut(map[string]interface{}{"lifecycle_state": out.LifecycleState}, err), "oci kms management key cancel-deletion --key-id " + in.Key, err
		}),
		"list-tags": mgmt(func(ctx context.Context, k keymanagement.KmsManagementClient, _ string, in ConsoleInput) (interface{}, string, error) {
			out, err := k.GetKey(ctx, keymanagement.GetKeyRequest{KeyId: key(in)})
			return okOut(out.FreeformTags, err), "oci kms management key get --key-id " + in.Key + " --query data.\"freeform-tags\"", err
		}),
		"tag-key": tags(func(t map[string]string, in ConsoleInput) { t[in.Params["tag_key"]] = in.Params["tag_value"] }, func(in ConsoleInput) string {
			return fmt.Sprintf("oci kms management key update --key-id %s --freeform-tags '{\"%s\":\"%s\"}'", in.Key, in.Params["tag_key"], in.Params["tag_value"])
		}),
		"untag-key": tags(func(t map[string]string, in ConsoleInput) { delete(t, in.Params["tag_key"]) }, func(in ConsoleInput) string {
			return "oci kms management key update --key-id " + in.Key + " --freeform-tags '<all but " + in.Params["tag_key"] + ">'"
		}),
		"encrypt": crypto(func(ctx context.Context, k keymanagement.KmsCryptoClient, _ keymanagement.KmsManagementClient, in ConsoleInput) (interface{}, string, error) {
			out, err := k.Encrypt(ctx, keymanagement.EncryptRequest{EncryptDataDetails: keymanagement.EncryptDataDetails{KeyId: key(in), Plaintext: common.String(b64(in.bytes("plaintext_b64")))}})
			return okOut(map[string]string{"ciphertext_b64": deref(out.Ciphertext)}, err), "oci kms crypto encrypt --key-id " + in.Key + " --plaintext <base64>", err
		}),
		"decrypt": crypto(func(ctx context.Context, k keymanagement.KmsCryptoClient, _ keymanagement.KmsManagementClient, in ConsoleInput) (interface{}, string, error) {
			out, err := k.Decrypt(ctx, keymanagement.DecryptRequest{DecryptDataDetails: keymanagement.DecryptDataDetails{KeyId: key(in), Ciphertext: common.String(in.Params["ciphertext_b64"])}})
			if err != nil {
				return nil, "", err
			}
			pt, _ := base64.StdEncoding.DecodeString(deref(out.Plaintext))
			return plaintextResult(pt), "oci kms crypto decrypt --key-id " + in.Key + " --ciphertext <base64>", nil
		}),
		"sign": crypto(func(ctx context.Context, k keymanagement.KmsCryptoClient, _ keymanagement.KmsManagementClient, in ConsoleInput) (interface{}, string, error) {
			alg := keymanagement.SignDataDetailsSigningAlgorithmEnum(defaultString(in.Params["algorithm"], "SHA_256_RSA_PKCS_PSS"))
			out, err := k.Sign(ctx, keymanagement.SignRequest{SignDataDetails: keymanagement.SignDataDetails{KeyId: key(in), Message: common.String(in.Params["message_b64"]),
				SigningAlgorithm: alg, MessageType: keymanagement.SignDataDetailsMessageTypeRaw}})
			return okOut(map[string]string{"signature_b64": deref(out.Signature), "version": deref(out.KeyVersionId)}, err),
				"oci kms crypto signed-data sign --key-id " + in.Key + " --message <base64> --signing-algorithm " + string(alg), err
		}),
		"verify": crypto(func(ctx context.Context, k keymanagement.KmsCryptoClient, m keymanagement.KmsManagementClient, in ConsoleInput) (interface{}, string, error) {
			v, err := versionOf(ctx, m, in)
			if err != nil {
				return nil, "", err
			}
			alg := keymanagement.VerifyDataDetailsSigningAlgorithmEnum(defaultString(in.Params["algorithm"], "SHA_256_RSA_PKCS_PSS"))
			out, err := k.Verify(ctx, keymanagement.VerifyRequest{VerifyDataDetails: keymanagement.VerifyDataDetails{KeyId: key(in), KeyVersionId: common.String(v),
				Message: common.String(in.Params["message_b64"]), Signature: common.String(in.Params["signature_b64"]), SigningAlgorithm: alg}})
			valid := out.IsSignatureValid != nil && *out.IsSignatureValid
			return okOut(map[string]bool{"valid": valid}, err), "oci kms crypto signed-data verify --key-id " + in.Key + " --key-version-id " + v, err
		}),
	}
}
