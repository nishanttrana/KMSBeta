package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awskms "github.com/aws/aws-sdk-go-v2/service/kms"
	awskmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// AWS KMS console operations: the whole catalogue.
func (p *awsProvider) Console() map[string]ConsoleFunc {
	with := func(f func(ctx context.Context, k *awskms.Client, in ConsoleInput) (interface{}, string, error)) ConsoleFunc {
		return func(ctx context.Context, c cloudKeyCall, in ConsoleInput) (interface{}, string, error) {
			k, err := p.kms(ctx, c)
			if err != nil {
				return nil, "", err
			}
			out, cli, err := f(ctx, k, in)
			if cli != "" && c.Region != "" {
				cli += " --region " + c.Region
			}
			return out, cli, err
		}
	}
	id := func(in ConsoleInput) *string { return aws.String(in.Key) }
	b64 := base64.StdEncoding.EncodeToString
	return map[string]ConsoleFunc{
		"list-keys": with(func(ctx context.Context, k *awskms.Client, _ ConsoleInput) (interface{}, string, error) {
			items := []map[string]string{}
			pg := awskms.NewListKeysPaginator(k, &awskms.ListKeysInput{})
			for pg.HasMorePages() && len(items) < 1000 {
				out, err := pg.NextPage(ctx)
				if err != nil {
					return nil, "aws kms list-keys", err
				}
				for _, e := range out.Keys {
					items = append(items, map[string]string{"key_id": aws.ToString(e.KeyId), "arn": aws.ToString(e.KeyArn)})
				}
			}
			return items, "aws kms list-keys", nil
		}),
		"describe-key": with(func(ctx context.Context, k *awskms.Client, in ConsoleInput) (interface{}, string, error) {
			out, err := k.DescribeKey(ctx, &awskms.DescribeKeyInput{KeyId: id(in)})
			return outOr(out, func() interface{} { return out.KeyMetadata }), "aws kms describe-key --key-id " + in.Key, err
		}),
		"list-versions": with(func(ctx context.Context, k *awskms.Client, in ConsoleInput) (interface{}, string, error) {
			cli := "aws kms list-key-rotations --key-id " + in.Key + " --include-key-material ALL_KEY_MATERIAL"
			out, err := k.ListKeyRotations(ctx, &awskms.ListKeyRotationsInput{KeyId: id(in), IncludeKeyMaterial: awskmstypes.IncludeKeyMaterialAllKeyMaterial})
			return outOr(out, func() interface{} { return out.Rotations }), cli, err
		}),
		"get-public-key": with(func(ctx context.Context, k *awskms.Client, in ConsoleInput) (interface{}, string, error) {
			out, err := k.GetPublicKey(ctx, &awskms.GetPublicKeyInput{KeyId: id(in)})
			return outOr(out, func() interface{} {
				return map[string]interface{}{"public_key_der_b64": b64(out.PublicKey), "key_spec": out.KeySpec, "key_usage": out.KeyUsage}
			}), "aws kms get-public-key --key-id " + in.Key, err
		}),
		"enable-key": with(func(ctx context.Context, k *awskms.Client, in ConsoleInput) (interface{}, string, error) {
			_, err := k.EnableKey(ctx, &awskms.EnableKeyInput{KeyId: id(in)})
			return done(err), "aws kms enable-key --key-id " + in.Key, err
		}),
		"disable-key": with(func(ctx context.Context, k *awskms.Client, in ConsoleInput) (interface{}, string, error) {
			_, err := k.DisableKey(ctx, &awskms.DisableKeyInput{KeyId: id(in)})
			return done(err), "aws kms disable-key --key-id " + in.Key, err
		}),
		"schedule-key-deletion": with(func(ctx context.Context, k *awskms.Client, in ConsoleInput) (interface{}, string, error) {
			days := in.int("pending_days", 30)
			out, err := k.ScheduleKeyDeletion(ctx, &awskms.ScheduleKeyDeletionInput{KeyId: id(in), PendingWindowInDays: aws.Int32(int32(days))})
			return outOr(out, func() interface{} {
					return map[string]interface{}{"deletion_date": out.DeletionDate, "key_state": out.KeyState}
				}),
				fmt.Sprintf("aws kms schedule-key-deletion --key-id %s --pending-window-in-days %d", in.Key, days), err
		}),
		"cancel-key-deletion": with(func(ctx context.Context, k *awskms.Client, in ConsoleInput) (interface{}, string, error) {
			_, err := k.CancelKeyDeletion(ctx, &awskms.CancelKeyDeletionInput{KeyId: id(in)})
			return done(err), "aws kms cancel-key-deletion --key-id " + in.Key, err
		}),
		"get-rotation-status": with(func(ctx context.Context, k *awskms.Client, in ConsoleInput) (interface{}, string, error) {
			out, err := k.GetKeyRotationStatus(ctx, &awskms.GetKeyRotationStatusInput{KeyId: id(in)})
			return outOr(out, func() interface{} {
				return map[string]interface{}{"enabled": out.KeyRotationEnabled, "period_days": out.RotationPeriodInDays, "next_rotation": out.NextRotationDate}
			}), "aws kms get-key-rotation-status --key-id " + in.Key, err
		}),
		"enable-rotation": with(func(ctx context.Context, k *awskms.Client, in ConsoleInput) (interface{}, string, error) {
			req := &awskms.EnableKeyRotationInput{KeyId: id(in)}
			cli := "aws kms enable-key-rotation --key-id " + in.Key
			if d := in.int("period_days", 0); d > 0 {
				req.RotationPeriodInDays = aws.Int32(int32(d))
				cli += fmt.Sprintf(" --rotation-period-in-days %d", d)
			}
			_, err := k.EnableKeyRotation(ctx, req)
			return done(err), cli, err
		}),
		"disable-rotation": with(func(ctx context.Context, k *awskms.Client, in ConsoleInput) (interface{}, string, error) {
			_, err := k.DisableKeyRotation(ctx, &awskms.DisableKeyRotationInput{KeyId: id(in)})
			return done(err), "aws kms disable-key-rotation --key-id " + in.Key, err
		}),
		"get-key-policy": with(func(ctx context.Context, k *awskms.Client, in ConsoleInput) (interface{}, string, error) {
			out, err := k.GetKeyPolicy(ctx, &awskms.GetKeyPolicyInput{KeyId: id(in), PolicyName: aws.String("default")})
			return outOr(out, func() interface{} { return map[string]string{"policy": aws.ToString(out.Policy)} }),
				"aws kms get-key-policy --key-id " + in.Key + " --policy-name default", err
		}),
		"put-key-policy": with(func(ctx context.Context, k *awskms.Client, in ConsoleInput) (interface{}, string, error) {
			// AWS keeps its own lockout check (BypassPolicyLockoutSafetyCheck
			// is never set).
			_, err := k.PutKeyPolicy(ctx, &awskms.PutKeyPolicyInput{KeyId: id(in), PolicyName: aws.String("default"), Policy: aws.String(in.Params["policy"])})
			return done(err), "aws kms put-key-policy --key-id " + in.Key + " --policy-name default --policy file://policy.json", err
		}),
		"list-grants": with(func(ctx context.Context, k *awskms.Client, in ConsoleInput) (interface{}, string, error) {
			out, err := k.ListGrants(ctx, &awskms.ListGrantsInput{KeyId: id(in)})
			return outOr(out, func() interface{} { return out.Grants }), "aws kms list-grants --key-id " + in.Key, err
		}),
		"create-grant": with(func(ctx context.Context, k *awskms.Client, in ConsoleInput) (interface{}, string, error) {
			var ops []awskmstypes.GrantOperation
			for _, o := range strings.Split(in.Params["operations"], ",") {
				if o = strings.TrimSpace(o); o != "" {
					ops = append(ops, awskmstypes.GrantOperation(o))
				}
			}
			req := &awskms.CreateGrantInput{KeyId: id(in), GranteePrincipal: aws.String(in.Params["grantee"]), Operations: ops}
			if n := in.Params["name"]; n != "" {
				req.Name = aws.String(n)
			}
			out, err := k.CreateGrant(ctx, req)
			return outOr(out, func() interface{} { return map[string]string{"grant_id": aws.ToString(out.GrantId)} }),
				fmt.Sprintf("aws kms create-grant --key-id %s --grantee-principal %s --operations %s", in.Key, in.Params["grantee"], strings.ReplaceAll(in.Params["operations"], ",", " ")), err
		}),
		"revoke-grant": with(func(ctx context.Context, k *awskms.Client, in ConsoleInput) (interface{}, string, error) {
			_, err := k.RevokeGrant(ctx, &awskms.RevokeGrantInput{KeyId: id(in), GrantId: aws.String(in.Params["grant_id"])})
			return done(err), "aws kms revoke-grant --key-id " + in.Key + " --grant-id " + in.Params["grant_id"], err
		}),
		"list-aliases": with(func(ctx context.Context, k *awskms.Client, in ConsoleInput) (interface{}, string, error) {
			req := &awskms.ListAliasesInput{}
			cli := "aws kms list-aliases"
			if in.Key != "" {
				req.KeyId, cli = id(in), cli+" --key-id "+in.Key
			}
			out, err := k.ListAliases(ctx, req)
			return outOr(out, func() interface{} { return out.Aliases }), cli, err
		}),
		"create-alias": with(func(ctx context.Context, k *awskms.Client, in ConsoleInput) (interface{}, string, error) {
			alias := awsAlias(in.Params["alias"])
			_, err := k.CreateAlias(ctx, &awskms.CreateAliasInput{AliasName: aws.String(alias), TargetKeyId: id(in)})
			return done(err), "aws kms create-alias --alias-name " + alias + " --target-key-id " + in.Key, err
		}),
		"delete-alias": with(func(ctx context.Context, k *awskms.Client, in ConsoleInput) (interface{}, string, error) {
			alias := awsAlias(in.Params["alias"])
			_, err := k.DeleteAlias(ctx, &awskms.DeleteAliasInput{AliasName: aws.String(alias)})
			return done(err), "aws kms delete-alias --alias-name " + alias, err
		}),
		"list-tags": with(func(ctx context.Context, k *awskms.Client, in ConsoleInput) (interface{}, string, error) {
			out, err := k.ListResourceTags(ctx, &awskms.ListResourceTagsInput{KeyId: id(in)})
			return outOr(out, func() interface{} {
				m := map[string]string{}
				for _, t := range out.Tags {
					m[aws.ToString(t.TagKey)] = aws.ToString(t.TagValue)
				}
				return m
			}), "aws kms list-resource-tags --key-id " + in.Key, err
		}),
		"tag-key": with(func(ctx context.Context, k *awskms.Client, in ConsoleInput) (interface{}, string, error) {
			_, err := k.TagResource(ctx, &awskms.TagResourceInput{KeyId: id(in), Tags: []awskmstypes.Tag{{TagKey: aws.String(in.Params["tag_key"]), TagValue: aws.String(in.Params["tag_value"])}}})
			return done(err), fmt.Sprintf("aws kms tag-resource --key-id %s --tags TagKey=%s,TagValue=%s", in.Key, in.Params["tag_key"], in.Params["tag_value"]), err
		}),
		"untag-key": with(func(ctx context.Context, k *awskms.Client, in ConsoleInput) (interface{}, string, error) {
			_, err := k.UntagResource(ctx, &awskms.UntagResourceInput{KeyId: id(in), TagKeys: []string{in.Params["tag_key"]}})
			return done(err), "aws kms untag-resource --key-id " + in.Key + " --tag-keys " + in.Params["tag_key"], err
		}),
		"encrypt": with(func(ctx context.Context, k *awskms.Client, in ConsoleInput) (interface{}, string, error) {
			req := &awskms.EncryptInput{KeyId: id(in), Plaintext: in.bytes("plaintext_b64")}
			cli := "aws kms encrypt --key-id " + in.Key + " --plaintext fileb://plaintext.bin"
			if a := in.Params["algorithm"]; a != "" {
				req.EncryptionAlgorithm, cli = awskmstypes.EncryptionAlgorithmSpec(a), cli+" --encryption-algorithm "+a
			}
			out, err := k.Encrypt(ctx, req)
			return outOr(out, func() interface{} {
				return map[string]interface{}{"ciphertext_b64": b64(out.CiphertextBlob), "algorithm": out.EncryptionAlgorithm}
			}), cli, err
		}),
		"decrypt": with(func(ctx context.Context, k *awskms.Client, in ConsoleInput) (interface{}, string, error) {
			req := &awskms.DecryptInput{KeyId: id(in), CiphertextBlob: in.bytes("ciphertext_b64")}
			cli := "aws kms decrypt --key-id " + in.Key + " --ciphertext-blob fileb://ciphertext.bin"
			if a := in.Params["algorithm"]; a != "" {
				req.EncryptionAlgorithm, cli = awskmstypes.EncryptionAlgorithmSpec(a), cli+" --encryption-algorithm "+a
			}
			out, err := k.Decrypt(ctx, req)
			return outOr(out, func() interface{} { return plaintextResult(out.Plaintext) }), cli, err
		}),
		"sign": with(func(ctx context.Context, k *awskms.Client, in ConsoleInput) (interface{}, string, error) {
			alg := awskmstypes.SigningAlgorithmSpec(defaultString(in.Params["algorithm"], "RSASSA_PSS_SHA_256"))
			out, err := k.Sign(ctx, &awskms.SignInput{KeyId: id(in), Message: in.bytes("message_b64"), SigningAlgorithm: alg, MessageType: awskmstypes.MessageTypeRaw})
			return outOr(out, func() interface{} {
					return map[string]interface{}{"signature_b64": b64(out.Signature), "algorithm": alg}
				}),
				"aws kms sign --key-id " + in.Key + " --message fileb://message.bin --message-type RAW --signing-algorithm " + string(alg), err
		}),
		"verify": with(func(ctx context.Context, k *awskms.Client, in ConsoleInput) (interface{}, string, error) {
			alg := awskmstypes.SigningAlgorithmSpec(defaultString(in.Params["algorithm"], "RSASSA_PSS_SHA_256"))
			out, err := k.Verify(ctx, &awskms.VerifyInput{KeyId: id(in), Message: in.bytes("message_b64"), Signature: in.bytes("signature_b64"), SigningAlgorithm: alg, MessageType: awskmstypes.MessageTypeRaw})
			return outOr(out, func() interface{} { return map[string]bool{"valid": out.SignatureValid} }),
				"aws kms verify --key-id " + in.Key + " --message fileb://message.bin --signature fileb://signature.bin --signing-algorithm " + string(alg), err
		}),
		"generate-mac": with(func(ctx context.Context, k *awskms.Client, in ConsoleInput) (interface{}, string, error) {
			out, err := k.GenerateMac(ctx, &awskms.GenerateMacInput{KeyId: id(in), Message: in.bytes("message_b64"), MacAlgorithm: awskmstypes.MacAlgorithmSpecHmacSha256})
			return outOr(out, func() interface{} { return map[string]string{"mac_b64": b64(out.Mac)} }),
				"aws kms generate-mac --key-id " + in.Key + " --message fileb://message.bin --mac-algorithm HMAC_SHA_256", err
		}),
		"verify-mac": with(func(ctx context.Context, k *awskms.Client, in ConsoleInput) (interface{}, string, error) {
			out, err := k.VerifyMac(ctx, &awskms.VerifyMacInput{KeyId: id(in), Message: in.bytes("message_b64"), Mac: in.bytes("mac_b64"), MacAlgorithm: awskmstypes.MacAlgorithmSpecHmacSha256})
			return outOr(out, func() interface{} { return map[string]bool{"valid": out.MacValid} }),
				"aws kms verify-mac --key-id " + in.Key + " --message fileb://message.bin --mac fileb://mac.bin --mac-algorithm HMAC_SHA_256", err
		}),
	}
}

// outOr is the result of a call: nothing when it failed.
func outOr[T any](out *T, f func() interface{}) interface{} {
	if out == nil {
		return nil
	}
	return f()
}

func done(err error) interface{} {
	if err != nil {
		return nil
	}
	return map[string]string{"status": "done"}
}
