package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"cloud.google.com/go/iam"
	iampb "cloud.google.com/go/iam/apiv1/iampb"
	cloudkmspb "cloud.google.com/go/kms/apiv1/kmspb"
	"google.golang.org/api/iterator"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	pkgcrypto "vecta-kms/pkg/crypto"
)

// Google Cloud KMS console operations. A key is a CryptoKey name; state
// operations act on a version (the given one, else the primary). Google
// has no grants or aliases; the key's access policy is its IAM policy, and
// its tags are labels.

func pbJSON(m proto.Message) interface{} {
	raw, err := protojson.MarshalOptions{UseProtoNames: true}.Marshal(m)
	if err != nil {
		return nil
	}
	return json.RawMessage(raw)
}

func (p *gcpProvider) Console() map[string]ConsoleFunc {
	with := func(f func(ctx context.Context, s *gcpSession, in ConsoleInput) (interface{}, string, error)) ConsoleFunc {
		return func(ctx context.Context, c cloudKeyCall, in ConsoleInput) (interface{}, string, error) {
			s, err := p.session(ctx, c)
			if err != nil {
				return nil, "", err
			}
			defer s.client.Close() //nolint:errcheck
			return f(ctx, s, in)
		}
	}
	// version is the version an operation acts on.
	version := func(ctx context.Context, s *gcpSession, in ConsoleInput) (string, error) {
		if in.Version != "" {
			if len(in.Version) < 8 { // a number: under the key
				return in.Key + "/cryptoKeyVersions/" + in.Version, nil
			}
			return in.Version, nil
		}
		k, err := s.client.GetCryptoKey(ctx, &cloudkmspb.GetCryptoKeyRequest{Name: in.Key})
		if err != nil {
			return "", err
		}
		if k.GetPrimary() == nil {
			return "", errors.New("this key has no primary version: name the version")
		}
		return k.GetPrimary().GetName(), nil
	}
	setState := func(state cloudkmspb.CryptoKeyVersion_CryptoKeyVersionState, verb string) ConsoleFunc {
		return with(func(ctx context.Context, s *gcpSession, in ConsoleInput) (interface{}, string, error) {
			v, err := version(ctx, s, in)
			if err != nil {
				return nil, "", err
			}
			out, err := s.client.UpdateCryptoKeyVersion(ctx, &cloudkmspb.UpdateCryptoKeyVersionRequest{
				CryptoKeyVersion: &cloudkmspb.CryptoKeyVersion{Name: v, State: state}, UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"state"}}})
			return pbOr(out, err), "gcloud kms keys versions " + verb + " " + v, err
		})
	}
	labels := func(ctx context.Context, s *gcpSession, in ConsoleInput, change func(map[string]string)) (interface{}, string, error) {
		k, err := s.client.GetCryptoKey(ctx, &cloudkmspb.GetCryptoKeyRequest{Name: in.Key})
		if err != nil {
			return nil, "", err
		}
		l := map[string]string{}
		for a, b := range k.GetLabels() {
			l[a] = b
		}
		change(l)
		out, err := s.client.UpdateCryptoKey(ctx, &cloudkmspb.UpdateCryptoKeyRequest{
			CryptoKey: &cloudkmspb.CryptoKey{Name: in.Key, Labels: l}, UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"labels"}}})
		if err != nil {
			return nil, "", err
		}
		return out.GetLabels(), "", nil
	}
	b64 := base64.StdEncoding.EncodeToString
	return map[string]ConsoleFunc{
		"list-keys": with(func(ctx context.Context, s *gcpSession, _ ConsoleInput) (interface{}, string, error) {
			items := []interface{}{}
			it := s.client.ListCryptoKeys(ctx, &cloudkmspb.ListCryptoKeysRequest{Parent: s.ring})
			for len(items) < 1000 {
				k, err := it.Next()
				if errors.Is(err, iterator.Done) {
					break
				}
				if err != nil {
					return nil, "", err
				}
				items = append(items, pbJSON(k))
			}
			return items, fmt.Sprintf("gcloud kms keys list --keyring %s --location %s", s.ringID, s.location), nil
		}),
		"describe-key": with(func(ctx context.Context, s *gcpSession, in ConsoleInput) (interface{}, string, error) {
			k, err := s.client.GetCryptoKey(ctx, &cloudkmspb.GetCryptoKeyRequest{Name: in.Key})
			return pbOr(k, err), "gcloud kms keys describe " + in.Key, err
		}),
		"list-versions": with(func(ctx context.Context, s *gcpSession, in ConsoleInput) (interface{}, string, error) {
			items := []interface{}{}
			it := s.client.ListCryptoKeyVersions(ctx, &cloudkmspb.ListCryptoKeyVersionsRequest{Parent: in.Key})
			for {
				v, err := it.Next()
				if errors.Is(err, iterator.Done) {
					break
				}
				if err != nil {
					return nil, "", err
				}
				items = append(items, pbJSON(v))
			}
			return items, "gcloud kms keys versions list --key " + in.Key, nil
		}),
		"get-public-key": with(func(ctx context.Context, s *gcpSession, in ConsoleInput) (interface{}, string, error) {
			v, err := version(ctx, s, in)
			if err != nil {
				return nil, "", err
			}
			pk, err := s.client.GetPublicKey(ctx, &cloudkmspb.GetPublicKeyRequest{Name: v})
			return pbOr(pk, err), "gcloud kms keys versions get-public-key " + v, err
		}),
		"enable-key":  setState(cloudkmspb.CryptoKeyVersion_ENABLED, "enable"),
		"disable-key": setState(cloudkmspb.CryptoKeyVersion_DISABLED, "disable"),
		"schedule-key-deletion": with(func(ctx context.Context, s *gcpSession, in ConsoleInput) (interface{}, string, error) {
			v, err := version(ctx, s, in)
			if err != nil {
				return nil, "", err
			}
			out, err := s.client.DestroyCryptoKeyVersion(ctx, &cloudkmspb.DestroyCryptoKeyVersionRequest{Name: v})
			return pbOr(out, err), "gcloud kms keys versions destroy " + v, err
		}),
		"cancel-key-deletion": with(func(ctx context.Context, s *gcpSession, in ConsoleInput) (interface{}, string, error) {
			v, err := version(ctx, s, in)
			if err != nil {
				return nil, "", err
			}
			out, err := s.client.RestoreCryptoKeyVersion(ctx, &cloudkmspb.RestoreCryptoKeyVersionRequest{Name: v})
			return pbOr(out, err), "gcloud kms keys versions restore " + v, err
		}),
		"get-key-policy": with(func(ctx context.Context, s *gcpSession, in ConsoleInput) (interface{}, string, error) {
			pol, err := s.client.ResourceIAM(in.Key).Policy(ctx)
			if err != nil {
				return nil, "", err
			}
			return pbJSON(pol.InternalProto), "gcloud kms keys get-iam-policy " + in.Key, nil
		}),
		"put-key-policy": with(func(ctx context.Context, s *gcpSession, in ConsoleInput) (interface{}, string, error) {
			var pol iampb.Policy
			if err := protojson.Unmarshal([]byte(in.Params["policy"]), &pol); err != nil {
				return nil, "", refuseBYOK(400, "bad_request", "policy is not a Google IAM policy: "+err.Error())
			}
			err := s.client.ResourceIAM(in.Key).SetPolicy(ctx, &iam.Policy{InternalProto: &pol})
			return done(err), "gcloud kms keys set-iam-policy " + in.Key + " policy.json", err
		}),
		"list-tags": with(func(ctx context.Context, s *gcpSession, in ConsoleInput) (interface{}, string, error) {
			k, err := s.client.GetCryptoKey(ctx, &cloudkmspb.GetCryptoKeyRequest{Name: in.Key})
			if err != nil {
				return nil, "", err
			}
			return k.GetLabels(), "gcloud kms keys describe " + in.Key + " --format 'value(labels)'", nil
		}),
		"tag-key": with(func(ctx context.Context, s *gcpSession, in ConsoleInput) (interface{}, string, error) {
			out, _, err := labels(ctx, s, in, func(l map[string]string) { l[in.Params["tag_key"]] = in.Params["tag_value"] })
			return out, fmt.Sprintf("gcloud kms keys update %s --update-labels %s=%s", in.Key, in.Params["tag_key"], in.Params["tag_value"]), err
		}),
		"untag-key": with(func(ctx context.Context, s *gcpSession, in ConsoleInput) (interface{}, string, error) {
			out, _, err := labels(ctx, s, in, func(l map[string]string) { delete(l, in.Params["tag_key"]) })
			return out, "gcloud kms keys update " + in.Key + " --remove-labels " + in.Params["tag_key"], err
		}),
		"encrypt": with(func(ctx context.Context, s *gcpSession, in ConsoleInput) (interface{}, string, error) {
			out, err := s.client.Encrypt(ctx, &cloudkmspb.EncryptRequest{Name: in.Key, Plaintext: in.bytes("plaintext_b64")})
			cli := "gcloud kms encrypt --key " + in.Key + " --plaintext-file plaintext.bin --ciphertext-file ciphertext.bin"
			if err != nil {
				return nil, cli, err
			}
			return map[string]string{"ciphertext_b64": b64(out.GetCiphertext()), "version": out.GetName()}, cli, nil
		}),
		"decrypt": with(func(ctx context.Context, s *gcpSession, in ConsoleInput) (interface{}, string, error) {
			out, err := s.client.Decrypt(ctx, &cloudkmspb.DecryptRequest{Name: in.Key, Ciphertext: in.bytes("ciphertext_b64")})
			cli := "gcloud kms decrypt --key " + in.Key + " --ciphertext-file ciphertext.bin --plaintext-file plaintext.bin"
			if err != nil {
				return nil, cli, err
			}
			return plaintextResult(out.GetPlaintext()), cli, nil
		}),
		"sign": with(func(ctx context.Context, s *gcpSession, in ConsoleInput) (interface{}, string, error) {
			v, err := version(ctx, s, in)
			if err != nil {
				return nil, "", err
			}
			cli := "gcloud kms asymmetric-sign --version " + v + " --digest-algorithm sha256 --input-file message.bin --signature-file sig.bin"
			out, err := s.client.AsymmetricSign(ctx, &cloudkmspb.AsymmetricSignRequest{Name: v,
				Digest: &cloudkmspb.Digest{Digest: &cloudkmspb.Digest_Sha256{Sha256: pkgcrypto.SHA256(in.bytes("message_b64"))}}})
			if err != nil {
				return nil, cli, err
			}
			return map[string]string{"signature_b64": b64(out.GetSignature()), "version": v}, cli, nil
		}),
		"verify": with(func(ctx context.Context, s *gcpSession, in ConsoleInput) (interface{}, string, error) {
			// Google verifies nowhere but with the public key.
			v, err := version(ctx, s, in)
			if err != nil {
				return nil, "", err
			}
			pk, err := s.client.GetPublicKey(ctx, &cloudkmspb.GetPublicKeyRequest{Name: v})
			if err != nil {
				return nil, "", err
			}
			pub, err := pkgcrypto.ParsePublicKeyPEM(pk.GetPem())
			if err != nil {
				return nil, "", err
			}
			ok := pkgcrypto.VerifySignatureAny(pub, in.bytes("message_b64"), in.bytes("signature_b64"))
			return map[string]bool{"valid": ok}, "gcloud kms keys versions get-public-key " + v + " (then verify with the public key)", nil
		}),
		"generate-mac": with(func(ctx context.Context, s *gcpSession, in ConsoleInput) (interface{}, string, error) {
			v, err := version(ctx, s, in)
			if err != nil {
				return nil, "", err
			}
			out, err := s.client.MacSign(ctx, &cloudkmspb.MacSignRequest{Name: v, Data: in.bytes("message_b64")})
			cli := "gcloud kms mac-sign --version " + v + " --input-file message.bin --signature-file mac.bin"
			if err != nil {
				return nil, cli, err
			}
			return map[string]string{"mac_b64": b64(out.GetMac())}, cli, nil
		}),
		"verify-mac": with(func(ctx context.Context, s *gcpSession, in ConsoleInput) (interface{}, string, error) {
			v, err := version(ctx, s, in)
			if err != nil {
				return nil, "", err
			}
			out, err := s.client.MacVerify(ctx, &cloudkmspb.MacVerifyRequest{Name: v, Data: in.bytes("message_b64"), Mac: in.bytes("mac_b64")})
			cli := "gcloud kms mac-verify --version " + v + " --input-file message.bin --signature-file mac.bin"
			if err != nil {
				return nil, cli, err
			}
			return map[string]bool{"valid": out.GetSuccess()}, cli, nil
		}),
	}
}

func pbOr(m proto.Message, err error) interface{} {
	if err != nil {
		return nil
	}
	return pbJSON(m)
}
