package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awskms "github.com/aws/aws-sdk-go-v2/service/kms"
	awskmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"

	pkgcrypto "vecta-kms/pkg/crypto"
)

// AWS KMS imported key material: a key with origin EXTERNAL, material
// wrapped to a per-import RSA-4096 key with RSAES_OAEP_SHA_256 (symmetric,
// HMAC) or RSA_AES_KEY_WRAP_SHA_256 (private keys), new material through
// NEW_KEY_MATERIAL and RotateKeyOnDemand, and DeleteImportedKeyMaterial as
// the kill switch.

func (p *awsProvider) Capabilities() Capabilities {
	return Capabilities{Rotate: true, Reimport: true, Revoke: true, RevokeDeletes: true, Expiry: true, Verify: true,
		Specs: []string{SpecAES256, SpecHMAC256, SpecRSA2048, SpecRSA3072, SpecRSA4096, SpecECP256, SpecECP384}}
}

func awsSpec(spec, usage string) (awskmstypes.KeySpec, awskmstypes.KeyUsageType, error) {
	switch spec {
	case SpecAES256:
		return awskmstypes.KeySpecSymmetricDefault, awskmstypes.KeyUsageTypeEncryptDecrypt, nil
	case SpecHMAC256:
		return awskmstypes.KeySpecHmac256, awskmstypes.KeyUsageTypeGenerateVerifyMac, nil
	case SpecRSA2048, SpecRSA3072, SpecRSA4096:
		u := awskmstypes.KeyUsageTypeSignVerify
		if usage == "encrypt" {
			u = awskmstypes.KeyUsageTypeEncryptDecrypt
		}
		return awskmstypes.KeySpec("RSA_" + strings.TrimPrefix(spec, "RSA-")), u, nil
	case SpecECP256:
		return awskmstypes.KeySpecEccNistP256, awskmstypes.KeyUsageTypeSignVerify, nil
	case SpecECP384:
		return awskmstypes.KeySpecEccNistP384, awskmstypes.KeyUsageTypeSignVerify, nil
	}
	return "", "", fmt.Errorf("AWS KMS can't import a %s key", spec)
}

func (p *awsProvider) kms(ctx context.Context, c cloudKeyCall) (*awskms.Client, error) {
	client, _, err := p.client(ctx, c.Region, c.Account, c.Credentials)
	return client, err
}

func (p *awsProvider) CreateKey(ctx context.Context, c cloudKeyCall, k BYOKKey, description string) (BYOKKey, string, error) {
	spec, usage, err := awsSpec(k.KeySpec, k.Usage)
	if err != nil {
		return k, "", err
	}
	client, err := p.kms(ctx, c)
	if err != nil {
		return k, "", err
	}
	desc := defaultString(description, "Vecta KMS BYOK key "+k.KeyID)
	cli := fmt.Sprintf("aws kms create-key --origin EXTERNAL --key-spec %s --key-usage %s --description %q --region %s", spec, usage, desc, c.Region)
	out, err := client.CreateKey(ctx, &awskms.CreateKeyInput{
		Origin: awskmstypes.OriginTypeExternal, KeySpec: spec, KeyUsage: usage, Description: aws.String(desc),
		Tags: []awskmstypes.Tag{
			{TagKey: aws.String("vecta:key_id"), TagValue: aws.String(k.KeyID)},
			{TagKey: aws.String("vecta:source"), TagValue: aws.String(k.Source)},
		},
	})
	if err != nil {
		return k, cli, err
	}
	if out.KeyMetadata == nil || out.KeyMetadata.KeyId == nil {
		return k, cli, errors.New("aws create-key returned no key")
	}
	k.CloudKeyID, k.CloudKeyRef = aws.ToString(out.KeyMetadata.KeyId), aws.ToString(out.KeyMetadata.Arn)
	k.CloudState = string(out.KeyMetadata.KeyState)
	if alias := awsAlias(k.Alias); alias != "" {
		if _, err := client.CreateAlias(ctx, &awskms.CreateAliasInput{AliasName: aws.String(alias), TargetKeyId: aws.String(k.CloudKeyID)}); err != nil {
			return k, cli, fmt.Errorf("the key was created (%s) but the alias was refused: %w", k.CloudKeyID, err)
		}
		k.Alias = alias
		cli += fmt.Sprintf(" && aws kms create-alias --alias-name %s --target-key-id %s", alias, k.CloudKeyID)
	}
	return k, cli, nil
}

func (p *awsProvider) ImportParameters(ctx context.Context, c cloudKeyCall, k BYOKKey) (ImportParams, string, error) {
	alg := awskmstypes.AlgorithmSpecRsaesOaepSha256
	scheme := pkgcrypto.CloudWrapRSAOAEPSHA256
	if !specIsSymmetric(k.KeySpec) {
		alg, scheme = awskmstypes.AlgorithmSpecRsaAesKeyWrapSha256, pkgcrypto.CloudWrapRSAAESKWP256
	}
	cli := fmt.Sprintf("aws kms get-parameters-for-import --key-id %s --wrapping-algorithm %s --wrapping-key-spec RSA_4096", k.CloudKeyID, alg)
	client, err := p.kms(ctx, c)
	if err != nil {
		return ImportParams{}, cli, err
	}
	out, err := client.GetParametersForImport(ctx, &awskms.GetParametersForImportInput{
		KeyId: aws.String(k.CloudKeyID), WrappingAlgorithm: alg, WrappingKeySpec: awskmstypes.WrappingKeySpecRsa4096,
	})
	if err != nil {
		return ImportParams{}, cli, err
	}
	params := ImportParams{WrappingKey: out.PublicKey, Token: out.ImportToken, Scheme: scheme}
	if out.ParametersValidTo != nil {
		params.ValidTo = *out.ParametersValidTo
	}
	return params, cli, nil
}

func (p *awsProvider) Import(ctx context.Context, c cloudKeyCall, k BYOKKey, in ImportRequest) (BYOKKey, string, string, error) {
	importType := awskmstypes.ImportTypeExistingKeyMaterial
	if in.NewMaterial {
		importType = awskmstypes.ImportTypeNewKeyMaterial
	}
	input := &awskms.ImportKeyMaterialInput{
		KeyId: aws.String(k.CloudKeyID), ImportToken: in.Params.Token, EncryptedKeyMaterial: in.Wrapped,
		ExpirationModel: awskmstypes.ExpirationModelTypeKeyMaterialDoesNotExpire, ImportType: importType,
		KeyMaterialDescription: aws.String(in.Description),
	}
	expiry := "--expiration-model KEY_MATERIAL_DOES_NOT_EXPIRE"
	if in.ExpiresAt != nil {
		input.ExpirationModel, input.ValidTo = awskmstypes.ExpirationModelTypeKeyMaterialExpires, in.ExpiresAt
		expiry = "--expiration-model KEY_MATERIAL_EXPIRES --valid-to " + in.ExpiresAt.UTC().Format(time.RFC3339)
	}
	cli := fmt.Sprintf("aws kms import-key-material --key-id %s --encrypted-key-material fileb://wrapped.bin --import-token fileb://token.bin %s --import-type %s --key-material-description %q",
		k.CloudKeyID, expiry, importType, in.Description)
	client, err := p.kms(ctx, c)
	if err != nil {
		return k, "", cli, err
	}
	out, err := client.ImportKeyMaterial(ctx, input)
	if err != nil {
		return k, "", cli, err
	}
	return k, aws.ToString(out.KeyMaterialId), cli, nil
}

func (p *awsProvider) MakeCurrent(ctx context.Context, c cloudKeyCall, k BYOKKey, _ string) (string, error) {
	cli := "aws kms rotate-key-on-demand --key-id " + k.CloudKeyID
	client, err := p.kms(ctx, c)
	if err != nil {
		return cli, err
	}
	_, err = client.RotateKeyOnDemand(ctx, &awskms.RotateKeyOnDemandInput{KeyId: aws.String(k.CloudKeyID)})
	return cli, err
}

func (p *awsProvider) Revoke(ctx context.Context, c cloudKeyCall, k BYOKKey, materialID string) (string, error) {
	cli := "aws kms delete-imported-key-material --key-id " + k.CloudKeyID
	in := &awskms.DeleteImportedKeyMaterialInput{KeyId: aws.String(k.CloudKeyID)}
	if materialID != "" {
		in.KeyMaterialId = aws.String(materialID)
		cli += " --key-material-id " + materialID
	}
	client, err := p.kms(ctx, c)
	if err != nil {
		return cli, err
	}
	_, err = client.DeleteImportedKeyMaterial(ctx, in)
	return cli, err
}

// Unrevoke: deleted material comes back only by importing it again.
func (p *awsProvider) Unrevoke(context.Context, cloudKeyCall, BYOKKey, string) (bool, string, error) {
	return false, "", nil
}

func (p *awsProvider) Describe(ctx context.Context, c cloudKeyCall, k BYOKKey) (BYOKKey, string, error) {
	cli := "aws kms describe-key --key-id " + k.CloudKeyID
	client, err := p.kms(ctx, c)
	if err != nil {
		return k, cli, err
	}
	out, err := client.DescribeKey(ctx, &awskms.DescribeKeyInput{KeyId: aws.String(k.CloudKeyID)})
	if err != nil {
		return k, cli, err
	}
	if out.KeyMetadata == nil {
		return k, cli, errors.New("aws describe-key returned no key")
	}
	m := out.KeyMetadata
	k.CloudState = string(m.KeyState)
	k.CloudKeyRef = defaultString(aws.ToString(m.Arn), k.CloudKeyRef)
	k.ExpiresAt = m.ValidTo
	if id := aws.ToString(m.CurrentKeyMaterialId); id != "" {
		k.CurrentMatID = id
	}
	return k, cli, nil
}

// verifyMessage is what a verification round trip encrypts or signs.
func verifyMessage() []byte {
	return []byte("vecta-kms byok verification " + time.Now().UTC().Format(time.RFC3339Nano))
}

func (p *awsProvider) Verify(ctx context.Context, c cloudKeyCall, k BYOKKey) (string, string, error) {
	client, err := p.kms(ctx, c)
	if err != nil {
		return "", "", err
	}
	msg := verifyMessage()
	id := aws.String(k.CloudKeyID)
	switch {
	case k.KeySpec == SpecAES256 || (k.Usage == "encrypt" && !specIsSymmetric(k.KeySpec)):
		alg := awskmstypes.EncryptionAlgorithmSpecSymmetricDefault
		if k.KeySpec != SpecAES256 {
			alg = awskmstypes.EncryptionAlgorithmSpecRsaesOaepSha256
		}
		cli := fmt.Sprintf("aws kms encrypt --key-id %s --encryption-algorithm %s --plaintext ... && aws kms decrypt --key-id %s --encryption-algorithm %s --ciphertext-blob ...", k.CloudKeyID, alg, k.CloudKeyID, alg)
		enc, err := client.Encrypt(ctx, &awskms.EncryptInput{KeyId: id, Plaintext: msg, EncryptionAlgorithm: alg})
		if err != nil {
			return "", cli, err
		}
		dec, err := client.Decrypt(ctx, &awskms.DecryptInput{KeyId: id, CiphertextBlob: enc.CiphertextBlob, EncryptionAlgorithm: alg})
		if err != nil {
			return "", cli, err
		}
		if !bytes.Equal(dec.Plaintext, msg) {
			return "", cli, errors.New("decrypt returned different plaintext")
		}
		return "encrypt and decrypt round trip with " + string(alg), cli, nil
	case k.KeySpec == SpecHMAC256:
		cli := "aws kms generate-mac --key-id " + k.CloudKeyID + " --mac-algorithm HMAC_SHA_256 ... && aws kms verify-mac ..."
		mac, err := client.GenerateMac(ctx, &awskms.GenerateMacInput{KeyId: id, Message: msg, MacAlgorithm: awskmstypes.MacAlgorithmSpecHmacSha256})
		if err != nil {
			return "", cli, err
		}
		v, err := client.VerifyMac(ctx, &awskms.VerifyMacInput{KeyId: id, Message: msg, Mac: mac.Mac, MacAlgorithm: awskmstypes.MacAlgorithmSpecHmacSha256})
		if err != nil {
			return "", cli, err
		}
		if !v.MacValid {
			return "", cli, errors.New("the MAC did not verify")
		}
		return "generate-mac and verify-mac with HMAC_SHA_256", cli, nil
	default:
		alg := awskmstypes.SigningAlgorithmSpecRsassaPssSha256
		if strings.HasPrefix(k.KeySpec, "EC-") {
			alg = awskmstypes.SigningAlgorithmSpecEcdsaSha256
			if k.KeySpec == SpecECP384 {
				alg = awskmstypes.SigningAlgorithmSpecEcdsaSha384
			}
		}
		cli := fmt.Sprintf("aws kms sign --key-id %s --signing-algorithm %s --message ... && aws kms verify ...", k.CloudKeyID, alg)
		sig, err := client.Sign(ctx, &awskms.SignInput{KeyId: id, Message: msg, SigningAlgorithm: alg})
		if err != nil {
			return "", cli, err
		}
		v, err := client.Verify(ctx, &awskms.VerifyInput{KeyId: id, Message: msg, Signature: sig.Signature, SigningAlgorithm: alg})
		if err != nil {
			return "", cli, err
		}
		if !v.SignatureValid {
			return "", cli, errors.New("the signature did not verify")
		}
		return "sign and verify with " + string(alg), cli, nil
	}
}

func (p *awsProvider) Cleanup(context.Context, cloudKeyCall, BYOKKey, ImportParams) (string, error) {
	return "", nil
}
