package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/keymanagement"

	pkgcrypto "vecta-kms/pkg/crypto"
)

// OCI Vault key import: the vault's RSA wrapping key (one per vault, held in
// its HSM), ImportKey for the first material and ImportKeyVersion for each
// new one (it becomes current). OCI can't remove material from a key;
// revoking disables the key and restoring enables it again.

func (p *ociProvider) Capabilities() Capabilities {
	return Capabilities{Rotate: true, Revoke: true, RevokeDeletes: false, Verify: true, Specs: []string{SpecAES256}}
}

// CreateKey reserves the display name; OCI creates the key on import.
func (p *ociProvider) CreateKey(_ context.Context, _ cloudKeyCall, k BYOKKey, _ string) (BYOKKey, string, error) {
	if k.KeySpec != SpecAES256 {
		return k, "", fmt.Errorf("OCI Vault import here supports AES-256 keys, not %s", k.KeySpec)
	}
	k.Alias = sanitizeCloudName(defaultString(strings.TrimPrefix(k.Alias, "alias/"), "vecta-"+k.KeyID))
	k.CloudState = "pending_import"
	return k, "", nil
}

func (p *ociProvider) ImportParameters(ctx context.Context, c cloudKeyCall, _ BYOKKey) (ImportParams, string, error) {
	client, _, _, err := p.client(c.Region, c.Account, c.Credentials)
	if err != nil {
		return ImportParams{}, "", err
	}
	cli := "oci kms management wrapping-key get --endpoint <management endpoint>"
	out, err := client.GetWrappingKey(ctx, keymanagement.GetWrappingKeyRequest{})
	if err != nil {
		return ImportParams{}, cli, err
	}
	return ImportParams{WrappingKey: []byte(deref(out.PublicKey)), Scheme: pkgcrypto.CloudWrapRSAOAEPSHA256}, cli, nil
}

func ociWrapped(in ImportRequest) *keymanagement.WrappedImportKey {
	return &keymanagement.WrappedImportKey{
		KeyMaterial:       common.String(base64.StdEncoding.EncodeToString(in.Wrapped)),
		WrappingAlgorithm: keymanagement.WrappedImportKeyWrappingAlgorithmSha256,
	}
}

func (p *ociProvider) Import(ctx context.Context, c cloudKeyCall, k BYOKKey, in ImportRequest) (BYOKKey, string, string, error) {
	client, _, compartment, err := p.client(c.Region, c.Account, c.Credentials)
	if err != nil {
		return k, "", "", err
	}
	if k.CloudKeyID != "" {
		cli := "oci kms management key-version import --key-id " + k.CloudKeyID + " --wrapped-import-key file://wrapped.json"
		out, err := client.ImportKeyVersion(ctx, keymanagement.ImportKeyVersionRequest{KeyId: common.String(k.CloudKeyID),
			ImportKeyVersionDetails: keymanagement.ImportKeyVersionDetails{WrappedImportKey: ociWrapped(in)}})
		if err != nil {
			return k, "", cli, err
		}
		return k, deref(out.Id), cli, nil
	}
	cli := fmt.Sprintf("oci kms management key import --compartment-id %s --display-name %s --key-shape '{\"algorithm\":\"AES\",\"length\":32}' --protection-mode HSM --wrapped-import-key file://wrapped.json", compartment, k.Alias)
	out, err := client.ImportKey(ctx, keymanagement.ImportKeyRequest{ImportKeyDetails: keymanagement.ImportKeyDetails{
		CompartmentId: common.String(compartment), DisplayName: common.String(k.Alias),
		KeyShape:         &keymanagement.KeyShape{Algorithm: keymanagement.KeyShapeAlgorithmAes, Length: common.Int(32)},
		WrappedImportKey: ociWrapped(in), ProtectionMode: keymanagement.ImportKeyDetailsProtectionModeHsm,
		FreeformTags:     map[string]string{"vecta_key_id": k.KeyID, "vecta_source": k.Source},
	}})
	if err != nil {
		return k, "", cli, err
	}
	k.CloudKeyID, k.CloudKeyRef = deref(out.Id), deref(out.Id)
	k.CloudState = string(out.LifecycleState)
	return k, deref(out.CurrentKeyVersion), cli, nil
}

// MakeCurrent: an imported key version is the current one.
func (p *ociProvider) MakeCurrent(context.Context, cloudKeyCall, BYOKKey, string) (string, error) {
	return "", nil
}

func (p *ociProvider) Revoke(ctx context.Context, c cloudKeyCall, k BYOKKey, _ string) (string, error) {
	client, _, _, err := p.client(c.Region, c.Account, c.Credentials)
	if err != nil {
		return "", err
	}
	cli := "oci kms management key disable --key-id " + k.CloudKeyID
	_, err = client.DisableKey(ctx, keymanagement.DisableKeyRequest{KeyId: common.String(k.CloudKeyID)})
	return cli, err
}

func (p *ociProvider) Unrevoke(ctx context.Context, c cloudKeyCall, k BYOKKey, _ string) (bool, string, error) {
	client, _, _, err := p.client(c.Region, c.Account, c.Credentials)
	if err != nil {
		return false, "", err
	}
	cli := "oci kms management key enable --key-id " + k.CloudKeyID
	_, err = client.EnableKey(ctx, keymanagement.EnableKeyRequest{KeyId: common.String(k.CloudKeyID)})
	return err == nil, cli, err
}

func (p *ociProvider) Describe(ctx context.Context, c cloudKeyCall, k BYOKKey) (BYOKKey, string, error) {
	client, _, _, err := p.client(c.Region, c.Account, c.Credentials)
	if err != nil {
		return k, "", err
	}
	cli := "oci kms management key get --key-id " + k.CloudKeyID
	out, err := client.GetKey(ctx, keymanagement.GetKeyRequest{KeyId: common.String(k.CloudKeyID)})
	if err != nil {
		return k, cli, err
	}
	k.CloudState = string(out.LifecycleState)
	k.CurrentMatID = defaultString(deref(out.CurrentKeyVersion), k.CurrentMatID)
	return k, cli, nil
}

func (p *ociProvider) Verify(ctx context.Context, c cloudKeyCall, k BYOKKey) (string, string, error) {
	endpoint := strings.TrimSpace(anyToString(c.Credentials["crypto_endpoint"]))
	if endpoint == "" {
		return "", "", errors.New("the OCI credential has no crypto_endpoint; add the vault's cryptographic endpoint to verify")
	}
	_, _, _, err := p.client(c.Region, c.Account, c.Credentials)
	if err != nil {
		return "", "", err
	}
	cfg := ociConfig(c)
	crypto, err := keymanagement.NewKmsCryptoClientWithConfigurationProvider(cfg, strings.TrimRight(endpoint, "/"))
	if err != nil {
		return "", "", err
	}
	msg := base64.StdEncoding.EncodeToString(verifyMessage())
	cli := "oci kms crypto encrypt --key-id " + k.CloudKeyID + " --plaintext ... && oci kms crypto decrypt --key-id " + k.CloudKeyID + " --ciphertext ..."
	enc, err := crypto.Encrypt(ctx, keymanagement.EncryptRequest{EncryptDataDetails: keymanagement.EncryptDataDetails{KeyId: common.String(k.CloudKeyID), Plaintext: common.String(msg)}})
	if err != nil {
		return "", cli, err
	}
	dec, err := crypto.Decrypt(ctx, keymanagement.DecryptRequest{DecryptDataDetails: keymanagement.DecryptDataDetails{KeyId: common.String(k.CloudKeyID), Ciphertext: enc.Ciphertext}})
	if err != nil {
		return "", cli, err
	}
	if deref(dec.Plaintext) != msg {
		return "", cli, errors.New("decrypt returned different plaintext")
	}
	return "encrypt and decrypt round trip on the current version", cli, nil
}

func (p *ociProvider) Cleanup(context.Context, cloudKeyCall, BYOKKey, ImportParams) (string, error) {
	return "", nil // the vault's wrapping key is permanent
}

// ociConfig is the signing configuration the management client uses.
func ociConfig(c cloudKeyCall) common.ConfigurationProvider {
	creds := c.Credentials
	var passphrase *string
	if v := strings.TrimSpace(anyToString(creds["private_key_passphrase"])); v != "" {
		passphrase = common.String(v)
	}
	region := defaultString(c.Region, defaultString(anyToString(creds["region"]), c.Account.DefaultRegion))
	return common.NewRawConfigurationProvider(
		strings.TrimSpace(defaultString(anyToString(creds["tenancy_ocid"]), anyToString(creds["tenancy"]))),
		strings.TrimSpace(defaultString(anyToString(creds["user_ocid"]), anyToString(creds["user"]))),
		region, strings.TrimSpace(anyToString(creds["fingerprint"])),
		strings.ReplaceAll(strings.TrimSpace(defaultString(anyToString(creds["private_key_pem"]), anyToString(creds["private_key"]))), "\\n", "\n"),
		passphrase)
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
