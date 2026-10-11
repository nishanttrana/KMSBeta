package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"time"

	pkgcrypto "vecta-kms/pkg/crypto"
)

// Alibaba Cloud KMS key import: a key with origin EXTERNAL, material wrapped
// with RSAES_OAEP_SHA_256 to a per-import RSA-2048 key, ImportKeyMaterial
// with an optional expiry, and DeleteKeyMaterial as the kill switch.
// Alibaba can't rotate imported material on a key: a new key is needed.

func (p *alibabaProvider) Capabilities() Capabilities {
	return Capabilities{Reimport: true, Revoke: true, RevokeDeletes: true, Expiry: true, Verify: true, Specs: []string{SpecAES256}}
}

func (p *alibabaProvider) api(ctx context.Context, c cloudKeyCall, params map[string]string) (map[string]interface{}, error) {
	ak, sk, region, err := p.resolveCredentials(c.Region, c.Account, c.Credentials)
	if err != nil {
		return nil, err
	}
	out, err := p.apiRequestAt(ctx, anyToString(c.Credentials["endpoint_url"]), ak, sk, region, params)
	return asObject(out), err
}

func (p *alibabaProvider) CreateKey(ctx context.Context, c cloudKeyCall, k BYOKKey, _ string) (BYOKKey, string, error) {
	if k.KeySpec != SpecAES256 {
		return k, "", fmt.Errorf("Alibaba Cloud KMS import here supports AES-256 keys, not %s", k.KeySpec)
	}
	cli := "aliyun kms CreateKey --Origin EXTERNAL --KeySpec Aliyun_AES_256 --KeyUsage ENCRYPT/DECRYPT --ProtectionLevel HSM"
	out, err := p.api(ctx, c, map[string]string{"Action": "CreateKey", "Origin": "EXTERNAL", "KeySpec": "Aliyun_AES_256",
		"KeyUsage": "ENCRYPT/DECRYPT", "ProtectionLevel": "HSM", "Description": "vecta-byok-" + k.KeyID})
	if err != nil {
		return k, cli, err
	}
	meta := nestedObject(out, "KeyMetadata")
	k.CloudKeyID, k.CloudKeyRef, k.CloudState = firstString(meta, "KeyId"), firstString(meta, "Arn"), firstString(meta, "KeyState")
	if k.CloudKeyID == "" {
		return k, cli, errors.New("alibaba CreateKey returned no key")
	}
	if alias := k.Alias; alias != "" {
		if _, err := p.api(ctx, c, map[string]string{"Action": "CreateAlias", "AliasName": awsAlias(alias), "KeyId": k.CloudKeyID}); err != nil {
			return k, cli, fmt.Errorf("the key was created (%s) but the alias was refused: %w", k.CloudKeyID, err)
		}
		k.Alias = awsAlias(alias)
	}
	return k, cli, nil
}

func (p *alibabaProvider) ImportParameters(ctx context.Context, c cloudKeyCall, k BYOKKey) (ImportParams, string, error) {
	cli := "aliyun kms GetParametersForImport --KeyId " + k.CloudKeyID + " --WrappingAlgorithm RSAES_OAEP_SHA_256 --WrappingKeySpec RSA_2048"
	out, err := p.api(ctx, c, map[string]string{"Action": "GetParametersForImport", "KeyId": k.CloudKeyID,
		"WrappingAlgorithm": "RSAES_OAEP_SHA_256", "WrappingKeySpec": "RSA_2048"})
	if err != nil {
		return ImportParams{}, cli, err
	}
	der, err := base64.StdEncoding.DecodeString(firstString(out, "PublicKey"))
	if err != nil {
		return ImportParams{}, cli, errors.New("alibaba returned a wrapping key that is not base64")
	}
	params := ImportParams{WrappingKey: der, Token: []byte(firstString(out, "ImportToken")), Scheme: pkgcrypto.CloudWrapRSAOAEPSHA256}
	if t, err := time.Parse(time.RFC3339, firstString(out, "TokenExpireTime")); err == nil {
		params.ValidTo = t
	}
	return params, cli, nil
}

func (p *alibabaProvider) Import(ctx context.Context, c cloudKeyCall, k BYOKKey, in ImportRequest) (BYOKKey, string, string, error) {
	if in.NewMaterial {
		return k, "", "", errors.New("Alibaba Cloud KMS can't take new material on a key; create a new BYOK key")
	}
	expire := "0"
	if in.ExpiresAt != nil {
		expire = strconv.FormatInt(in.ExpiresAt.Unix(), 10)
	}
	cli := "aliyun kms ImportKeyMaterial --KeyId " + k.CloudKeyID + " --EncryptedKeyMaterial <wrapped> --ImportToken <token> --KeyMaterialExpireUnix " + expire
	if _, err := p.api(ctx, c, map[string]string{"Action": "ImportKeyMaterial", "KeyId": k.CloudKeyID,
		"EncryptedKeyMaterial": base64.StdEncoding.EncodeToString(in.Wrapped), "ImportToken": string(in.Params.Token),
		"KeyMaterialExpireUnix": expire}); err != nil {
		return k, "", cli, err
	}
	return k, k.CloudKeyID, cli, nil
}

func (p *alibabaProvider) MakeCurrent(context.Context, cloudKeyCall, BYOKKey, string) (string, error) {
	return "", nil
}

func (p *alibabaProvider) Revoke(ctx context.Context, c cloudKeyCall, k BYOKKey, _ string) (string, error) {
	cli := "aliyun kms DeleteKeyMaterial --KeyId " + k.CloudKeyID
	_, err := p.api(ctx, c, map[string]string{"Action": "DeleteKeyMaterial", "KeyId": k.CloudKeyID})
	return cli, err
}

func (p *alibabaProvider) Unrevoke(context.Context, cloudKeyCall, BYOKKey, string) (bool, string, error) {
	return false, "", nil
}

func (p *alibabaProvider) Describe(ctx context.Context, c cloudKeyCall, k BYOKKey) (BYOKKey, string, error) {
	cli := "aliyun kms DescribeKey --KeyId " + k.CloudKeyID
	out, err := p.api(ctx, c, map[string]string{"Action": "DescribeKey", "KeyId": k.CloudKeyID})
	if err != nil {
		return k, cli, err
	}
	meta := nestedObject(out, "KeyMetadata")
	k.CloudState = firstString(meta, "KeyState")
	if t, err := time.Parse(time.RFC3339, firstString(meta, "MaterialExpireTime")); err == nil {
		k.ExpiresAt = &t
	}
	return k, cli, nil
}

func (p *alibabaProvider) Verify(ctx context.Context, c cloudKeyCall, k BYOKKey) (string, string, error) {
	msg := base64.StdEncoding.EncodeToString(verifyMessage())
	cli := "aliyun kms Encrypt --KeyId " + k.CloudKeyID + " --Plaintext ... && aliyun kms Decrypt --CiphertextBlob ..."
	enc, err := p.api(ctx, c, map[string]string{"Action": "Encrypt", "KeyId": k.CloudKeyID, "Plaintext": msg})
	if err != nil {
		return "", cli, err
	}
	dec, err := p.api(ctx, c, map[string]string{"Action": "Decrypt", "CiphertextBlob": firstString(enc, "CiphertextBlob")})
	if err != nil {
		return "", cli, err
	}
	if firstString(dec, "Plaintext") != msg {
		return "", cli, errors.New("decrypt returned different plaintext")
	}
	return "encrypt and decrypt round trip", cli, nil
}

func (p *alibabaProvider) Cleanup(context.Context, cloudKeyCall, BYOKKey, ImportParams) (string, error) {
	return "", nil
}
