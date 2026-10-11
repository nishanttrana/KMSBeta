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
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	awskms "github.com/aws/aws-sdk-go-v2/service/kms"
	awssts "github.com/aws/aws-sdk-go-v2/service/sts"
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
	r.Register(newAlibabaProvider())
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
	// With a role_arn the stored access key only calls sts:AssumeRole, and
	// AWS KMS is called with the role's short-lived credentials, which the
	// SDK refreshes before they expire. Nothing but the access key is stored.
	if roleARN := strings.TrimSpace(anyToString(creds["role_arn"])); roleARN != "" {
		externalID := strings.TrimSpace(anyToString(creds["external_id"]))
		cfg.Credentials = aws.NewCredentialsCache(stscreds.NewAssumeRoleProvider(awssts.NewFromConfig(cfg), roleARN, func(o *stscreds.AssumeRoleOptions) {
			o.RoleSessionName = "vecta-kms"
			if externalID != "" {
				o.ExternalID = aws.String(externalID)
			}
		}))
	}
	endpoint := strings.TrimSpace(defaultString(anyToString(creds["endpoint_url"]), anyToString(creds["endpoint"])))
	client := awskms.NewFromConfig(cfg, func(o *awskms.Options) {
		if endpoint != "" {
			o.BaseEndpoint = aws.String(endpoint)
		}
	})
	return client, region, nil
}

type gcpProvider struct {
	// options are extra client options; tests point the client at a local
	// gRPC server with them.
	options []option.ClientOption
}

func newGCPProvider() *gcpProvider { return &gcpProvider{} }

func (p *gcpProvider) Name() string { return ProviderGCP }

func (p *gcpProvider) DefaultRegion() string { return "us-central1" }

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
	if endpoint := strings.TrimSpace(anyToString(creds["endpoint"])); endpoint != "" {
		opts = append(opts, option.WithEndpoint(endpoint)) // a private endpoint
	}
	client, err := gcpkms.NewKeyManagementClient(ctx, append(opts, p.options...)...)
	if err != nil {
		return nil, "", "", "", err
	}
	return client, projectID, location, keyRing, nil
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
