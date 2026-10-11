package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	gcpkms "cloud.google.com/go/kms/apiv1"
	cloudkmspb "cloud.google.com/go/kms/apiv1/kmspb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	pkgcrypto "vecta-kms/pkg/crypto"
)

// Google Cloud KMS key import: an import-only CryptoKey with no initial
// version, an import job whose RSA-3072 wrapping key Google holds in its
// HSM, and ImportCryptoKeyVersion per material. Revoking destroys the
// version (Google schedules it); restoring cancels that, or imports the
// same material back into the destroyed version.

func (p *gcpProvider) Capabilities() Capabilities {
	return Capabilities{Rotate: true, Reimport: true, Revoke: true, RevokeDeletes: true, Verify: true,
		Specs: []string{SpecAES256, SpecHMAC256, SpecRSA2048, SpecRSA3072, SpecRSA4096, SpecECP256}}
}

func gcpSpec(spec string) (cloudkmspb.CryptoKey_CryptoKeyPurpose, cloudkmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm, error) {
	switch spec {
	case SpecAES256:
		return cloudkmspb.CryptoKey_ENCRYPT_DECRYPT, cloudkmspb.CryptoKeyVersion_GOOGLE_SYMMETRIC_ENCRYPTION, nil
	case SpecHMAC256:
		return cloudkmspb.CryptoKey_MAC, cloudkmspb.CryptoKeyVersion_HMAC_SHA256, nil
	case SpecRSA2048:
		return cloudkmspb.CryptoKey_ASYMMETRIC_SIGN, cloudkmspb.CryptoKeyVersion_RSA_SIGN_PSS_2048_SHA256, nil
	case SpecRSA3072:
		return cloudkmspb.CryptoKey_ASYMMETRIC_SIGN, cloudkmspb.CryptoKeyVersion_RSA_SIGN_PSS_3072_SHA256, nil
	case SpecRSA4096:
		return cloudkmspb.CryptoKey_ASYMMETRIC_SIGN, cloudkmspb.CryptoKeyVersion_RSA_SIGN_PSS_4096_SHA256, nil
	case SpecECP256:
		return cloudkmspb.CryptoKey_ASYMMETRIC_SIGN, cloudkmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256, nil
	}
	return 0, 0, fmt.Errorf("Google Cloud KMS import here supports AES-256, HMAC-256, RSA and EC-P256 signing keys, not %s", spec)
}

type gcpSession struct {
	client                          *gcpkms.KeyManagementClient
	project, location, ring, ringID string
}

func (p *gcpProvider) session(ctx context.Context, c cloudKeyCall) (*gcpSession, error) {
	client, project, location, ring, err := p.client(ctx, c.Region, c.Account, c.Credentials)
	if err != nil {
		return nil, err
	}
	return &gcpSession{client: client, project: project, location: location, ringID: ring,
		ring: fmt.Sprintf("projects/%s/locations/%s/keyRings/%s", project, location, ring)}, nil
}

// pollEvery is how often import jobs and imported versions are re-read.
var gcpPollEvery = 2 * time.Second

func (p *gcpProvider) CreateKey(ctx context.Context, c cloudKeyCall, k BYOKKey, description string) (BYOKKey, string, error) {
	purpose, alg, err := gcpSpec(k.KeySpec)
	if err != nil {
		return k, "", err
	}
	s, err := p.session(ctx, c)
	if err != nil {
		return k, "", err
	}
	defer s.client.Close() //nolint:errcheck
	id := sanitizeCloudName(defaultString(strings.TrimPrefix(k.Alias, "alias/"), "vecta-"+k.KeyID))
	cli := fmt.Sprintf("gcloud kms keys create %s --keyring %s --location %s --purpose %s --default-algorithm %s --protection-level hsm --skip-initial-version-creation --import-only",
		id, s.ringID, s.location, strings.ToLower(strings.ReplaceAll(purpose.String(), "_", "-")), strings.ToLower(strings.ReplaceAll(alg.String(), "_", "-")))
	req := &cloudkmspb.CreateCryptoKeyRequest{
		Parent: s.ring, CryptoKeyId: id, SkipInitialVersionCreation: true,
		CryptoKey: &cloudkmspb.CryptoKey{
			Purpose: purpose, ImportOnly: true,
			VersionTemplate: &cloudkmspb.CryptoKeyVersionTemplate{Algorithm: alg, ProtectionLevel: cloudkmspb.ProtectionLevel_HSM},
			Labels:          map[string]string{"vecta_key_id": sanitizeLabel(k.KeyID), "vecta_source": k.Source},
		},
	}
	key, err := s.client.CreateCryptoKey(ctx, req)
	if status.Code(err) == codes.NotFound {
		// The key ring doesn't exist yet: create it, then the key.
		if _, rerr := s.client.CreateKeyRing(ctx, &cloudkmspb.CreateKeyRingRequest{
			Parent: fmt.Sprintf("projects/%s/locations/%s", s.project, s.location), KeyRingId: s.ringID, KeyRing: &cloudkmspb.KeyRing{},
		}); rerr != nil {
			return k, cli, rerr
		}
		cli = fmt.Sprintf("gcloud kms keyrings create %s --location %s && ", s.ringID, s.location) + cli
		key, err = s.client.CreateCryptoKey(ctx, req)
	}
	if err != nil {
		return k, cli, err
	}
	k.CloudKeyID, k.CloudKeyRef, k.CloudState = key.GetName(), key.GetName(), "PENDING_IMPORT"
	k.Alias = id
	return k, cli, nil
}

func (p *gcpProvider) ImportParameters(ctx context.Context, c cloudKeyCall, k BYOKKey) (ImportParams, string, error) {
	method, scheme := cloudkmspb.ImportJob_RSA_OAEP_3072_SHA256, pkgcrypto.CloudWrapRSAOAEPSHA256
	if !specIsSymmetric(k.KeySpec) {
		method, scheme = cloudkmspb.ImportJob_RSA_OAEP_3072_SHA256_AES_256, pkgcrypto.CloudWrapRSAAESKWP256
	}
	s, err := p.session(ctx, c)
	if err != nil {
		return ImportParams{}, "", err
	}
	defer s.client.Close() //nolint:errcheck
	jobID := sanitizeCloudName(newID("vecta-import"))
	cli := fmt.Sprintf("gcloud kms import-jobs create %s --keyring %s --location %s --import-method %s --protection-level hsm",
		jobID, s.ringID, s.location, strings.ToLower(strings.ReplaceAll(method.String(), "_", "-")))
	job, err := s.client.CreateImportJob(ctx, &cloudkmspb.CreateImportJobRequest{
		Parent: s.ring, ImportJobId: jobID,
		ImportJob: &cloudkmspb.ImportJob{ImportMethod: method, ProtectionLevel: cloudkmspb.ProtectionLevel_HSM},
	})
	if err != nil {
		return ImportParams{}, cli, err
	}
	// Google generates the wrapping key in its HSM; the job turns ACTIVE
	// when it is ready.
	for job.GetState() != cloudkmspb.ImportJob_ACTIVE {
		if job.GetState() == cloudkmspb.ImportJob_EXPIRED {
			return ImportParams{}, cli, errors.New("the import job expired before it became active")
		}
		select {
		case <-ctx.Done():
			return ImportParams{}, cli, ctx.Err()
		case <-time.After(gcpPollEvery):
		}
		if job, err = s.client.GetImportJob(ctx, &cloudkmspb.GetImportJobRequest{Name: job.GetName()}); err != nil {
			return ImportParams{}, cli, err
		}
	}
	params := ImportParams{WrappingKey: []byte(job.GetPublicKey().GetPem()), Scheme: scheme, Handle: job.GetName()}
	if t := job.GetExpireTime(); t != nil {
		params.ValidTo = t.AsTime()
	}
	return params, cli, nil
}

func (p *gcpProvider) Import(ctx context.Context, c cloudKeyCall, k BYOKKey, in ImportRequest) (BYOKKey, string, string, error) {
	_, alg, err := gcpSpec(k.KeySpec)
	if err != nil {
		return k, "", "", err
	}
	s, err := p.session(ctx, c)
	if err != nil {
		return k, "", "", err
	}
	defer s.client.Close() //nolint:errcheck
	cli := fmt.Sprintf("gcloud kms keys versions import --key %s --import-job %s --algorithm %s --wrapped-key-file wrapped.bin",
		k.CloudKeyID, in.Params.Handle, strings.ToLower(strings.ReplaceAll(alg.String(), "_", "-")))
	req := &cloudkmspb.ImportCryptoKeyVersionRequest{Parent: k.CloudKeyID, Algorithm: alg, ImportJob: in.Params.Handle, WrappedKey: in.Wrapped}
	if in.Replace != "" {
		req.CryptoKeyVersion = in.Replace
		cli += " --target-key-version " + in.Replace
	}
	ver, err := s.client.ImportCryptoKeyVersion(ctx, req)
	if err != nil {
		return k, "", cli, err
	}
	for ver.GetState() == cloudkmspb.CryptoKeyVersion_PENDING_IMPORT {
		select {
		case <-ctx.Done():
			return k, ver.GetName(), cli, ctx.Err()
		case <-time.After(gcpPollEvery):
		}
		if ver, err = s.client.GetCryptoKeyVersion(ctx, &cloudkmspb.GetCryptoKeyVersionRequest{Name: ver.GetName()}); err != nil {
			return k, "", cli, err
		}
	}
	if ver.GetState() != cloudkmspb.CryptoKeyVersion_ENABLED {
		return k, ver.GetName(), cli, fmt.Errorf("Google rejected the import (%s): %s", ver.GetState(), ver.GetImportFailureReason())
	}
	return k, ver.GetName(), cli, nil
}

// MakeCurrent sets the primary version, which only symmetric encryption
// keys have; the others use a version by name.
func (p *gcpProvider) MakeCurrent(ctx context.Context, c cloudKeyCall, k BYOKKey, materialID string) (string, error) {
	if k.KeySpec != SpecAES256 {
		return "", nil
	}
	s, err := p.session(ctx, c)
	if err != nil {
		return "", err
	}
	defer s.client.Close() //nolint:errcheck
	versionID := materialID[strings.LastIndex(materialID, "/")+1:]
	cli := fmt.Sprintf("gcloud kms keys update %s --primary-version %s", k.CloudKeyID, versionID)
	_, err = s.client.UpdateCryptoKeyPrimaryVersion(ctx, &cloudkmspb.UpdateCryptoKeyPrimaryVersionRequest{Name: k.CloudKeyID, CryptoKeyVersionId: versionID})
	return cli, err
}

func (p *gcpProvider) Revoke(ctx context.Context, c cloudKeyCall, _ BYOKKey, materialID string) (string, error) {
	if materialID == "" {
		return "", errors.New("no Google key version recorded for this material")
	}
	s, err := p.session(ctx, c)
	if err != nil {
		return "", err
	}
	defer s.client.Close() //nolint:errcheck
	cli := "gcloud kms keys versions destroy " + materialID
	_, err = s.client.DestroyCryptoKeyVersion(ctx, &cloudkmspb.DestroyCryptoKeyVersionRequest{Name: materialID})
	return cli, err
}

// Unrevoke cancels a scheduled destruction; a destroyed version needs its
// material imported again.
func (p *gcpProvider) Unrevoke(ctx context.Context, c cloudKeyCall, _ BYOKKey, materialID string) (bool, string, error) {
	s, err := p.session(ctx, c)
	if err != nil {
		return false, "", err
	}
	defer s.client.Close() //nolint:errcheck
	ver, err := s.client.GetCryptoKeyVersion(ctx, &cloudkmspb.GetCryptoKeyVersionRequest{Name: materialID})
	if err != nil {
		return false, "", err
	}
	if ver.GetState() != cloudkmspb.CryptoKeyVersion_DESTROY_SCHEDULED {
		return false, "", nil
	}
	cli := "gcloud kms keys versions restore " + materialID + " && gcloud kms keys versions enable " + materialID
	if _, err := s.client.RestoreCryptoKeyVersion(ctx, &cloudkmspb.RestoreCryptoKeyVersionRequest{Name: materialID}); err != nil {
		return false, cli, err
	}
	_, err = s.client.UpdateCryptoKeyVersion(ctx, &cloudkmspb.UpdateCryptoKeyVersionRequest{
		CryptoKeyVersion: &cloudkmspb.CryptoKeyVersion{Name: materialID, State: cloudkmspb.CryptoKeyVersion_ENABLED},
		UpdateMask:       &fieldmaskpb.FieldMask{Paths: []string{"state"}},
	})
	return err == nil, cli, err
}

func (p *gcpProvider) Describe(ctx context.Context, c cloudKeyCall, k BYOKKey) (BYOKKey, string, error) {
	s, err := p.session(ctx, c)
	if err != nil {
		return k, "", err
	}
	defer s.client.Close() //nolint:errcheck
	cli := "gcloud kms keys describe " + k.CloudKeyID
	key, err := s.client.GetCryptoKey(ctx, &cloudkmspb.GetCryptoKeyRequest{Name: k.CloudKeyID})
	if err != nil {
		return k, cli, err
	}
	k.CloudState = "ENABLED"
	if pv := key.GetPrimary(); pv != nil {
		k.CloudState = pv.GetState().String()
	} else if k.KeySpec == SpecAES256 {
		k.CloudState = "NO_PRIMARY_VERSION"
	}
	return k, cli, nil
}

func (p *gcpProvider) Verify(ctx context.Context, c cloudKeyCall, k BYOKKey) (string, string, error) {
	s, err := p.session(ctx, c)
	if err != nil {
		return "", "", err
	}
	defer s.client.Close() //nolint:errcheck
	msg := verifyMessage()
	switch k.KeySpec {
	case SpecAES256:
		cli := "gcloud kms encrypt --key " + k.CloudKeyID + " ... && gcloud kms decrypt --key " + k.CloudKeyID + " ..."
		enc, err := s.client.Encrypt(ctx, &cloudkmspb.EncryptRequest{Name: k.CloudKeyID, Plaintext: msg})
		if err != nil {
			return "", cli, err
		}
		dec, err := s.client.Decrypt(ctx, &cloudkmspb.DecryptRequest{Name: k.CloudKeyID, Ciphertext: enc.GetCiphertext()})
		if err != nil {
			return "", cli, err
		}
		if string(dec.GetPlaintext()) != string(msg) {
			return "", cli, errors.New("decrypt returned different plaintext")
		}
		return "encrypt and decrypt round trip on the primary version", cli, nil
	case SpecHMAC256:
		cli := "gcloud kms mac-sign --version " + k.CurrentMatID + " ... && gcloud kms mac-verify ..."
		mac, err := s.client.MacSign(ctx, &cloudkmspb.MacSignRequest{Name: k.CurrentMatID, Data: msg})
		if err != nil {
			return "", cli, err
		}
		v, err := s.client.MacVerify(ctx, &cloudkmspb.MacVerifyRequest{Name: k.CurrentMatID, Data: msg, Mac: mac.GetMac()})
		if err != nil {
			return "", cli, err
		}
		if !v.GetSuccess() {
			return "", cli, errors.New("the MAC did not verify")
		}
		return "mac-sign and mac-verify on " + k.CurrentMatID, cli, nil
	default:
		cli := "gcloud kms asymmetric-sign --version " + k.CurrentMatID + " --digest-algorithm sha256 ... && gcloud kms keys versions get-public-key ..."
		sig, err := s.client.AsymmetricSign(ctx, &cloudkmspb.AsymmetricSignRequest{Name: k.CurrentMatID,
			Digest: &cloudkmspb.Digest{Digest: &cloudkmspb.Digest_Sha256{Sha256: pkgcrypto.SHA256(msg)}}})
		if err != nil {
			return "", cli, err
		}
		pk, err := s.client.GetPublicKey(ctx, &cloudkmspb.GetPublicKeyRequest{Name: k.CurrentMatID})
		if err != nil {
			return "", cli, err
		}
		pub, err := pkgcrypto.ParsePublicKeyPEM(pk.GetPem())
		if err != nil {
			return "", cli, err
		}
		if !pkgcrypto.VerifySignatureAny(pub, msg, sig.GetSignature()) {
			return "", cli, errors.New("the signature did not verify under the version's public key")
		}
		return "asymmetric-sign, verified under the version's public key", cli, nil
	}
}

func (p *gcpProvider) Cleanup(context.Context, cloudKeyCall, BYOKKey, ImportParams) (string, error) {
	return "", nil // import jobs expire on their own after three days
}
