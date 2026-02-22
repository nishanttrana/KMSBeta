package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	gcpkms "cloud.google.com/go/kms/apiv1"
	cloudkmspb "cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/aws/aws-sdk-go-v2/aws"
	awscfg "github.com/aws/aws-sdk-go-v2/config"
	awscreds "github.com/aws/aws-sdk-go-v2/credentials"
	awskms "github.com/aws/aws-sdk-go-v2/service/kms"
	awskmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
)

func newRealProviderRegistry() *ProviderRegistry {
	r := NewProviderRegistry()
	r.Register(newAWSProvider())
	r.Register(newAzureProvider())
	r.Register(newGCPProvider())
	r.Register(newOCIProvider())
	r.Register(newSalesforceProvider())
	return r
}

type unsupportedProvider struct {
	name   string
	reason string
}

func newUnsupportedProvider(name string, reason string) *unsupportedProvider {
	return &unsupportedProvider{name: normalizeProvider(name), reason: strings.TrimSpace(reason)}
}

func (p *unsupportedProvider) Name() string { return p.name }

func (p *unsupportedProvider) DefaultRegion() string { return "global" }

func (p *unsupportedProvider) ImportKey(_ context.Context, _ ImportInput) (ImportResult, error) {
	return ImportResult{}, errors.New(defaultString(p.reason, "provider is not available"))
}

func (p *unsupportedProvider) RotateKey(_ context.Context, _ RotateInput) (ImportResult, error) {
	return ImportResult{}, errors.New(defaultString(p.reason, "provider is not available"))
}

func (p *unsupportedProvider) SyncBinding(_ context.Context, _ SyncInput) (ImportResult, error) {
	return ImportResult{}, errors.New(defaultString(p.reason, "provider is not available"))
}

func (p *unsupportedProvider) Inventory(_ context.Context, _ InventoryInput) ([]InventoryItem, error) {
	return nil, errors.New(defaultString(p.reason, "provider is not available"))
}

type awsProvider struct{}

func newAWSProvider() *awsProvider { return &awsProvider{} }

func (p *awsProvider) Name() string { return ProviderAWS }

func (p *awsProvider) DefaultRegion() string { return "us-east-1" }

func (p *awsProvider) ImportKey(ctx context.Context, in ImportInput) (ImportResult, error) {
	client, region, err := p.client(ctx, in.Region, in.Account, in.Credentials)
	if err != nil {
		return ImportResult{}, err
	}
	keySpec, keyUsage, err := mapAWSKeySpecUsage(in.KeyMeta)
	if err != nil {
		return ImportResult{}, err
	}
	tags := []awskmstypes.Tag{
		{TagKey: aws.String("vecta_tenant"), TagValue: aws.String(in.TenantID)},
		{TagKey: aws.String("vecta_key_id"), TagValue: aws.String(in.KeyID)},
	}
	createOut, err := client.CreateKey(ctx, &awskms.CreateKeyInput{
		Description: aws.String(fmt.Sprintf("Vecta managed key for tenant=%s key_id=%s", in.TenantID, in.KeyID)),
		KeyUsage:    keyUsage,
		KeySpec:     keySpec,
		Tags:        tags,
		MultiRegion: aws.Bool(false),
	})
	if err != nil {
		return ImportResult{}, err
	}
	if createOut == nil || createOut.KeyMetadata == nil || createOut.KeyMetadata.KeyId == nil {
		return ImportResult{}, errors.New("aws create key returned empty metadata")
	}
	cloudKeyID := strings.TrimSpace(aws.ToString(createOut.KeyMetadata.KeyId))
	cloudKeyRef := strings.TrimSpace(aws.ToString(createOut.KeyMetadata.Arn))
	alias := awsAlias(defaultString(anyToString(in.Metadata["alias"]), fmt.Sprintf("alias/vecta-%s", sanitizeCloudName(in.KeyID))))
	if alias != "" {
		_, aliasErr := client.CreateAlias(ctx, &awskms.CreateAliasInput{
			AliasName:   aws.String(alias),
			TargetKeyId: aws.String(cloudKeyID),
		})
		if aliasErr != nil {
			// Keep key imported even if alias creation fails.
			in.Metadata["alias_error"] = aliasErr.Error()
		}
	}
	return ImportResult{
		CloudKeyID:  cloudKeyID,
		CloudKeyRef: cloudKeyRef,
		State:       strings.ToLower(string(createOut.KeyMetadata.KeyState)),
		Metadata: map[string]interface{}{
			"provider":          ProviderAWS,
			"region":            region,
			"key_spec":          string(keySpec),
			"key_usage":         string(keyUsage),
			"native_key_create": true,
			"alias":             alias,
			"imported_at":       time.Now().UTC().Format(time.RFC3339Nano),
		},
	}, nil
}

func (p *awsProvider) RotateKey(ctx context.Context, in RotateInput) (ImportResult, error) {
	client, region, err := p.client(ctx, in.Binding.Region, in.Account, in.Credentials)
	if err != nil {
		return ImportResult{}, err
	}
	keyID := strings.TrimSpace(in.Binding.CloudKeyID)
	if keyID == "" {
		return ImportResult{}, errors.New("cloud key id is required")
	}
	_, _ = client.EnableKeyRotation(ctx, &awskms.EnableKeyRotationInput{KeyId: aws.String(keyID)})
	_, _ = client.UpdateKeyDescription(ctx, &awskms.UpdateKeyDescriptionInput{
		KeyId:       aws.String(keyID),
		Description: aws.String(fmt.Sprintf("Vecta rotated at %s reason=%s", time.Now().UTC().Format(time.RFC3339), defaultString(in.Reason, "manual"))),
	})
	desc, err := client.DescribeKey(ctx, &awskms.DescribeKeyInput{KeyId: aws.String(keyID)})
	if err != nil {
		return ImportResult{}, err
	}
	if desc == nil || desc.KeyMetadata == nil {
		return ImportResult{}, errors.New("aws describe key returned empty metadata")
	}
	return ImportResult{
		CloudKeyID:  keyID,
		CloudKeyRef: strings.TrimSpace(aws.ToString(desc.KeyMetadata.Arn)),
		State:       strings.ToLower(string(desc.KeyMetadata.KeyState)),
		Metadata: map[string]interface{}{
			"provider":      ProviderAWS,
			"region":        region,
			"rotated_at":    time.Now().UTC().Format(time.RFC3339Nano),
			"rotation_mode": "native",
			"reason":        defaultString(in.Reason, "manual"),
		},
	}, nil
}

func (p *awsProvider) SyncBinding(ctx context.Context, in SyncInput) (ImportResult, error) {
	client, region, err := p.client(ctx, in.Binding.Region, in.Account, in.Credentials)
	if err != nil {
		return ImportResult{}, err
	}
	keyID := strings.TrimSpace(in.Binding.CloudKeyID)
	if keyID == "" {
		return ImportResult{}, errors.New("cloud key id is required")
	}
	desc, err := client.DescribeKey(ctx, &awskms.DescribeKeyInput{KeyId: aws.String(keyID)})
	if err != nil {
		return ImportResult{}, err
	}
	if desc == nil || desc.KeyMetadata == nil {
		return ImportResult{}, errors.New("aws describe key returned empty metadata")
	}
	return ImportResult{
		CloudKeyID:  keyID,
		CloudKeyRef: strings.TrimSpace(aws.ToString(desc.KeyMetadata.Arn)),
		State:       strings.ToLower(string(desc.KeyMetadata.KeyState)),
		Metadata: map[string]interface{}{
			"provider":  ProviderAWS,
			"region":    region,
			"synced_at": time.Now().UTC().Format(time.RFC3339Nano),
			"enabled":   desc.KeyMetadata.Enabled,
		},
	}, nil
}

func (p *awsProvider) Inventory(ctx context.Context, in InventoryInput) ([]InventoryItem, error) {
	client, region, err := p.client(ctx, in.Region, in.Account, in.Credentials)
	if err != nil {
		return nil, err
	}
	items := make([]InventoryItem, 0, 64)
	pager := awskms.NewListKeysPaginator(client, &awskms.ListKeysInput{Limit: aws.Int32(50)})
	seen := 0
	for pager.HasMorePages() {
		page, pageErr := pager.NextPage(ctx)
		if pageErr != nil {
			return nil, pageErr
		}
		for _, key := range page.Keys {
			if key.KeyId == nil {
				continue
			}
			keyID := strings.TrimSpace(aws.ToString(key.KeyId))
			if keyID == "" {
				continue
			}
			desc, descErr := client.DescribeKey(ctx, &awskms.DescribeKeyInput{KeyId: aws.String(keyID)})
			if descErr != nil || desc == nil || desc.KeyMetadata == nil {
				continue
			}
			items = append(items, InventoryItem{
				CloudKeyID:     keyID,
				CloudKeyRef:    strings.TrimSpace(aws.ToString(desc.KeyMetadata.Arn)),
				Provider:       ProviderAWS,
				AccountID:      in.Account.ID,
				Region:         region,
				State:          strings.ToLower(string(desc.KeyMetadata.KeyState)),
				Algorithm:      strings.TrimSpace(string(desc.KeyMetadata.KeySpec)),
				ManagedByVecta: false,
			})
			seen++
			if seen >= 200 {
				return items, nil
			}
		}
	}
	return items, nil
}

func (p *awsProvider) client(ctx context.Context, regionHint string, account CloudAccount, creds map[string]interface{}) (*awskms.Client, string, error) {
	region := strings.TrimSpace(regionHint)
	if region == "" {
		region = strings.TrimSpace(anyToString(creds["region"]))
	}
	if region == "" {
		region = defaultString(account.DefaultRegion, p.DefaultRegion())
	}
	loadOpts := []func(*awscfg.LoadOptions) error{awscfg.WithRegion(region)}
	accessKey := defaultString(anyToString(creds["access_key_id"]), anyToString(creds["aws_access_key_id"]))
	secretKey := defaultString(anyToString(creds["secret_access_key"]), anyToString(creds["aws_secret_access_key"]))
	sessionToken := defaultString(anyToString(creds["session_token"]), anyToString(creds["aws_session_token"]))
	if accessKey != "" && secretKey != "" {
		loadOpts = append(loadOpts, awscfg.WithCredentialsProvider(awscreds.NewStaticCredentialsProvider(accessKey, secretKey, sessionToken)))
	}
	cfg, err := awscfg.LoadDefaultConfig(ctx, loadOpts...)
	if err != nil {
		return nil, "", err
	}
	endpoint := strings.TrimSpace(defaultString(anyToString(creds["endpoint_url"]), anyToString(creds["endpoint"])))
	client := awskms.NewFromConfig(cfg, func(o *awskms.Options) {
		if endpoint != "" {
			o.BaseEndpoint = aws.String(endpoint)
		}
	})
	return client, region, nil
}

func mapAWSKeySpecUsage(keyMeta map[string]interface{}) (awskmstypes.KeySpec, awskmstypes.KeyUsageType, error) {
	algorithm := strings.ToUpper(strings.TrimSpace(anyToString(keyMeta["algorithm"])))
	purpose := strings.ToLower(strings.TrimSpace(anyToString(keyMeta["purpose"])))
	if strings.Contains(algorithm, "ML-") || strings.Contains(algorithm, "KYBER") || strings.Contains(algorithm, "DILITHIUM") {
		return "", "", errors.New("aws kms does not support pqc key import in this flow")
	}
	if strings.Contains(algorithm, "RSA-2048") {
		if strings.Contains(purpose, "sign") {
			return awskmstypes.KeySpecRsa2048, awskmstypes.KeyUsageTypeSignVerify, nil
		}
		return awskmstypes.KeySpecRsa2048, awskmstypes.KeyUsageTypeEncryptDecrypt, nil
	}
	if strings.Contains(algorithm, "RSA-3072") {
		if strings.Contains(purpose, "sign") {
			return awskmstypes.KeySpecRsa3072, awskmstypes.KeyUsageTypeSignVerify, nil
		}
		return awskmstypes.KeySpecRsa3072, awskmstypes.KeyUsageTypeEncryptDecrypt, nil
	}
	if strings.Contains(algorithm, "RSA-4096") {
		if strings.Contains(purpose, "sign") {
			return awskmstypes.KeySpecRsa4096, awskmstypes.KeyUsageTypeSignVerify, nil
		}
		return awskmstypes.KeySpecRsa4096, awskmstypes.KeyUsageTypeEncryptDecrypt, nil
	}
	if strings.Contains(algorithm, "ECDSA-P256") || strings.Contains(algorithm, "ECDH-P256") {
		if strings.Contains(purpose, "derive") || strings.Contains(purpose, "agreement") || strings.Contains(algorithm, "ECDH") {
			return awskmstypes.KeySpecEccNistP256, awskmstypes.KeyUsageTypeKeyAgreement, nil
		}
		return awskmstypes.KeySpecEccNistP256, awskmstypes.KeyUsageTypeSignVerify, nil
	}
	if strings.Contains(algorithm, "ECDSA-P384") || strings.Contains(algorithm, "ECDH-P384") {
		if strings.Contains(purpose, "derive") || strings.Contains(purpose, "agreement") || strings.Contains(algorithm, "ECDH") {
			return awskmstypes.KeySpecEccNistP384, awskmstypes.KeyUsageTypeKeyAgreement, nil
		}
		return awskmstypes.KeySpecEccNistP384, awskmstypes.KeyUsageTypeSignVerify, nil
	}
	if strings.Contains(algorithm, "ECDSA-P521") || strings.Contains(algorithm, "ECDH-P521") {
		if strings.Contains(purpose, "derive") || strings.Contains(purpose, "agreement") || strings.Contains(algorithm, "ECDH") {
			return awskmstypes.KeySpecEccNistP521, awskmstypes.KeyUsageTypeKeyAgreement, nil
		}
		return awskmstypes.KeySpecEccNistP521, awskmstypes.KeyUsageTypeSignVerify, nil
	}
	if strings.Contains(algorithm, "ED25519") {
		return "", "", errors.New("aws kms does not support EdDSA key specs in this flow")
	}
	if strings.HasPrefix(algorithm, "AES") || strings.Contains(algorithm, "3DES") || strings.Contains(algorithm, "CAMELLIA") || strings.Contains(algorithm, "CHACHA") {
		return awskmstypes.KeySpecSymmetricDefault, awskmstypes.KeyUsageTypeEncryptDecrypt, nil
	}
	return "", "", fmt.Errorf("unsupported algorithm for aws kms: %s", algorithm)
}

type gcpProvider struct{}

func newGCPProvider() *gcpProvider { return &gcpProvider{} }

func (p *gcpProvider) Name() string { return ProviderGCP }

func (p *gcpProvider) DefaultRegion() string { return "us-central1" }

func (p *gcpProvider) ImportKey(ctx context.Context, in ImportInput) (ImportResult, error) {
	client, projectID, location, keyRing, err := p.client(ctx, in.Region, in.Account, in.Credentials)
	if err != nil {
		return ImportResult{}, err
	}
	defer client.Close() //nolint:errcheck
	keyRingPath := fmt.Sprintf("projects/%s/locations/%s/keyRings/%s", projectID, location, keyRing)
	if _, ringErr := client.GetKeyRing(ctx, &cloudkmspb.GetKeyRingRequest{Name: keyRingPath}); ringErr != nil {
		_, createRingErr := client.CreateKeyRing(ctx, &cloudkmspb.CreateKeyRingRequest{
			Parent:    fmt.Sprintf("projects/%s/locations/%s", projectID, location),
			KeyRingId: keyRing,
			KeyRing:   &cloudkmspb.KeyRing{},
		})
		if createRingErr != nil {
			return ImportResult{}, createRingErr
		}
	}
	purpose, algorithm, err := mapGCPPurposeAlgorithm(in.KeyMeta)
	if err != nil {
		return ImportResult{}, err
	}
	keyID := sanitizeCloudName(defaultString(anyToString(in.Metadata["cloud_key_id"]), in.KeyID))
	if keyID == "" {
		keyID = sanitizeCloudName(newID("gcpkey"))
	}
	create, err := client.CreateCryptoKey(ctx, &cloudkmspb.CreateCryptoKeyRequest{
		Parent:      keyRingPath,
		CryptoKeyId: keyID,
		CryptoKey: &cloudkmspb.CryptoKey{
			Purpose: purpose,
			VersionTemplate: &cloudkmspb.CryptoKeyVersionTemplate{
				Algorithm: algorithm,
			},
			Labels: map[string]string{
				"vecta_tenant": sanitizeLabel(in.TenantID),
				"vecta_key_id": sanitizeLabel(in.KeyID),
			},
		},
	})
	if err != nil {
		return ImportResult{}, err
	}
	name := strings.TrimSpace(create.GetName())
	return ImportResult{
		CloudKeyID:  name,
		CloudKeyRef: name,
		State:       "enabled",
		Metadata: map[string]interface{}{
			"provider":          ProviderGCP,
			"project_id":        projectID,
			"location":          location,
			"key_ring":          keyRing,
			"native_key_create": true,
			"imported_at":       time.Now().UTC().Format(time.RFC3339Nano),
		},
	}, nil
}

func (p *gcpProvider) RotateKey(ctx context.Context, in RotateInput) (ImportResult, error) {
	client, projectID, location, keyRing, err := p.client(ctx, in.Binding.Region, in.Account, in.Credentials)
	if err != nil {
		return ImportResult{}, err
	}
	defer client.Close() //nolint:errcheck
	cryptoKeyName := strings.TrimSpace(in.Binding.CloudKeyID)
	if cryptoKeyName == "" {
		return ImportResult{}, errors.New("cloud key id is required")
	}
	if !strings.Contains(cryptoKeyName, "/cryptoKeys/") {
		cryptoKeyName = fmt.Sprintf("projects/%s/locations/%s/keyRings/%s/cryptoKeys/%s", projectID, location, keyRing, sanitizeCloudName(cryptoKeyName))
	}
	_, err = client.CreateCryptoKeyVersion(ctx, &cloudkmspb.CreateCryptoKeyVersionRequest{
		Parent: cryptoKeyName,
		CryptoKeyVersion: &cloudkmspb.CryptoKeyVersion{
			State: cloudkmspb.CryptoKeyVersion_ENABLED,
		},
	})
	if err != nil {
		return ImportResult{}, err
	}
	return ImportResult{
		CloudKeyID:  cryptoKeyName,
		CloudKeyRef: cryptoKeyName,
		State:       "enabled",
		Metadata: map[string]interface{}{
			"provider":    ProviderGCP,
			"rotated_at":  time.Now().UTC().Format(time.RFC3339Nano),
			"rotation_op": "create_version",
		},
	}, nil
}

func (p *gcpProvider) SyncBinding(ctx context.Context, in SyncInput) (ImportResult, error) {
	client, projectID, location, keyRing, err := p.client(ctx, in.Binding.Region, in.Account, in.Credentials)
	if err != nil {
		return ImportResult{}, err
	}
	defer client.Close() //nolint:errcheck
	cryptoKeyName := strings.TrimSpace(in.Binding.CloudKeyID)
	if cryptoKeyName == "" {
		return ImportResult{}, errors.New("cloud key id is required")
	}
	if !strings.Contains(cryptoKeyName, "/cryptoKeys/") {
		cryptoKeyName = fmt.Sprintf("projects/%s/locations/%s/keyRings/%s/cryptoKeys/%s", projectID, location, keyRing, sanitizeCloudName(cryptoKeyName))
	}
	key, err := client.GetCryptoKey(ctx, &cloudkmspb.GetCryptoKeyRequest{Name: cryptoKeyName})
	if err != nil {
		return ImportResult{}, err
	}
	return ImportResult{
		CloudKeyID:  key.GetName(),
		CloudKeyRef: key.GetName(),
		State:       "enabled",
		Metadata: map[string]interface{}{
			"provider":  ProviderGCP,
			"synced_at": time.Now().UTC().Format(time.RFC3339Nano),
			"purpose":   key.GetPurpose().String(),
		},
	}, nil
}

func (p *gcpProvider) Inventory(ctx context.Context, in InventoryInput) ([]InventoryItem, error) {
	client, projectID, location, keyRing, err := p.client(ctx, in.Region, in.Account, in.Credentials)
	if err != nil {
		return nil, err
	}
	defer client.Close() //nolint:errcheck
	parent := fmt.Sprintf("projects/%s/locations/%s/keyRings/%s", projectID, location, keyRing)
	pager := client.ListCryptoKeys(ctx, &cloudkmspb.ListCryptoKeysRequest{Parent: parent})
	items := make([]InventoryItem, 0, 128)
	for {
		key, pageErr := pager.Next()
		if errors.Is(pageErr, iterator.Done) {
			break
		}
		if pageErr != nil {
			return nil, pageErr
		}
		items = append(items, InventoryItem{
			CloudKeyID:     key.GetName(),
			CloudKeyRef:    key.GetName(),
			Provider:       ProviderGCP,
			AccountID:      in.Account.ID,
			Region:         location,
			State:          "enabled",
			Algorithm:      key.GetPurpose().String(),
			ManagedByVecta: false,
		})
		if len(items) >= 200 {
			break
		}
	}
	return items, nil
}

func (p *gcpProvider) client(ctx context.Context, regionHint string, account CloudAccount, creds map[string]interface{}) (*gcpkms.KeyManagementClient, string, string, string, error) {
	projectID := strings.TrimSpace(defaultString(anyToString(creds["project_id"]), anyToString(creds["project"])))
	if projectID == "" {
		return nil, "", "", "", errors.New("gcp credentials must include project_id")
	}
	location := strings.TrimSpace(regionHint)
	if location == "" {
		location = strings.TrimSpace(anyToString(creds["location"]))
	}
	if location == "" {
		location = defaultString(account.DefaultRegion, p.DefaultRegion())
	}
	keyRing := strings.TrimSpace(defaultString(anyToString(creds["key_ring"]), "vecta"))
	var opts []option.ClientOption
	if rawCreds := strings.TrimSpace(anyToString(creds["_raw_json"])); rawCreds != "" {
		opts = append(opts, option.WithCredentialsJSON([]byte(rawCreds)))
	}
	client, err := gcpkms.NewKeyManagementClient(ctx, opts...)
	if err != nil {
		return nil, "", "", "", err
	}
	return client, projectID, location, keyRing, nil
}

func mapGCPPurposeAlgorithm(keyMeta map[string]interface{}) (cloudkmspb.CryptoKey_CryptoKeyPurpose, cloudkmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm, error) {
	algorithm := strings.ToUpper(strings.TrimSpace(anyToString(keyMeta["algorithm"])))
	purpose := strings.ToLower(strings.TrimSpace(anyToString(keyMeta["purpose"])))
	if strings.HasPrefix(algorithm, "AES") || strings.Contains(algorithm, "CHACHA") || strings.Contains(algorithm, "CAMELLIA") || strings.Contains(algorithm, "3DES") {
		return cloudkmspb.CryptoKey_ENCRYPT_DECRYPT, cloudkmspb.CryptoKeyVersion_GOOGLE_SYMMETRIC_ENCRYPTION, nil
	}
	if strings.Contains(algorithm, "RSA-2048") {
		if strings.Contains(purpose, "sign") {
			return cloudkmspb.CryptoKey_ASYMMETRIC_SIGN, cloudkmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_2048_SHA256, nil
		}
		return cloudkmspb.CryptoKey_ASYMMETRIC_DECRYPT, cloudkmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_2048_SHA256, nil
	}
	if strings.Contains(algorithm, "RSA-3072") {
		if strings.Contains(purpose, "sign") {
			return cloudkmspb.CryptoKey_ASYMMETRIC_SIGN, cloudkmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_3072_SHA256, nil
		}
		return cloudkmspb.CryptoKey_ASYMMETRIC_DECRYPT, cloudkmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_3072_SHA256, nil
	}
	if strings.Contains(algorithm, "RSA-4096") {
		if strings.Contains(purpose, "sign") {
			return cloudkmspb.CryptoKey_ASYMMETRIC_SIGN, cloudkmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA512, nil
		}
		return cloudkmspb.CryptoKey_ASYMMETRIC_DECRYPT, cloudkmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_4096_SHA256, nil
	}
	if strings.Contains(algorithm, "ECDSA-P256") {
		return cloudkmspb.CryptoKey_ASYMMETRIC_SIGN, cloudkmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256, nil
	}
	if strings.Contains(algorithm, "ECDSA-P384") {
		return cloudkmspb.CryptoKey_ASYMMETRIC_SIGN, cloudkmspb.CryptoKeyVersion_EC_SIGN_P384_SHA384, nil
	}
	if strings.Contains(algorithm, "ECDH-") || strings.Contains(purpose, "derive") {
		return 0, 0, errors.New("gcp kms key-agreement mapping is not supported in this flow")
	}
	if strings.Contains(algorithm, "ML-") || strings.Contains(algorithm, "DILITHIUM") {
		return 0, 0, errors.New("gcp kms pqc algorithms are not supported in this flow")
	}
	return 0, 0, fmt.Errorf("unsupported algorithm for gcp kms: %s", algorithm)
}

func awsAlias(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	if !strings.HasPrefix(v, "alias/") {
		v = "alias/" + v
	}
	return sanitizeAlias(v)
}

var nonNameChars = regexp.MustCompile(`[^a-z0-9-]+`)
var nonAliasChars = regexp.MustCompile(`[^a-zA-Z0-9/_-]+`)
var nonLabelChars = regexp.MustCompile(`[^a-z0-9_-]+`)

func sanitizeCloudName(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	if v == "" {
		return ""
	}
	v = nonNameChars.ReplaceAllString(v, "-")
	v = strings.Trim(v, "-")
	if len(v) > 63 {
		v = strings.Trim(v[:63], "-")
	}
	if v == "" {
		return "vecta-key"
	}
	return v
}

func sanitizeAlias(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	v = nonAliasChars.ReplaceAllString(v, "-")
	if !strings.HasPrefix(v, "alias/") {
		v = "alias/" + strings.TrimPrefix(v, "/")
	}
	return v
}

func sanitizeLabel(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	if v == "" {
		return "n-a"
	}
	v = nonLabelChars.ReplaceAllString(v, "_")
	v = strings.Trim(v, "_")
	if len(v) > 63 {
		v = strings.Trim(v[:63], "_")
	}
	if v == "" {
		return "n-a"
	}
	return v
}

func anyToString(v interface{}) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return strings.TrimSpace(t)
	case json.RawMessage:
		return strings.TrimSpace(string(t))
	case []byte:
		return strings.TrimSpace(string(t))
	default:
		return strings.TrimSpace(fmt.Sprint(t))
	}
}
