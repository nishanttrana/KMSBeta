package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	pkgcrypto "vecta-kms/pkg/crypto"
)

// ---------------------------------------------------------------------------
// Alibaba Cloud KMS Provider
// ---------------------------------------------------------------------------

type alibabaProvider struct {
	httpClient *http.Client
}

func newAlibabaProvider() *alibabaProvider {
	return &alibabaProvider{
		httpClient: &http.Client{Timeout: 25 * time.Second},
	}
}

func (p *alibabaProvider) Name() string { return ProviderAlibaba }

func (p *alibabaProvider) DefaultRegion() string { return "cn-hangzhou" }

func (p *alibabaProvider) SyncBinding(ctx context.Context, in SyncInput) (ImportResult, error) {
	accessKeyID, accessKeySecret, region, err := p.resolveCredentials(in.Binding.Region, in.Account, in.Credentials)
	if err != nil {
		return ImportResult{}, err
	}
	keyID := strings.TrimSpace(in.Binding.CloudKeyID)
	if keyID == "" {
		return ImportResult{}, fmt.Errorf("cloud key id is required")
	}

	params := map[string]string{
		"Action": "DescribeKey",
		"KeyId":  keyID,
	}
	respRaw, err := p.apiRequest(ctx, accessKeyID, accessKeySecret, region, params)
	if err != nil {
		return ImportResult{}, fmt.Errorf("alibaba kms DescribeKey failed: %w", err)
	}

	resp := asObject(respRaw)
	keyMeta := nestedObject(resp, "KeyMetadata")
	state := strings.ToLower(defaultString(firstString(keyMeta, "KeyState"), "unknown"))
	if state == "pendingdeletion" || state == "pending_deletion" {
		state = "destroy-pending"
	}

	cloudKeyRef := firstString(keyMeta, "Arn")
	if cloudKeyRef == "" {
		cloudKeyRef = in.Binding.CloudKeyRef
	}

	return ImportResult{
		CloudKeyID:  keyID,
		CloudKeyRef: cloudKeyRef,
		State:       state,
		Metadata: map[string]interface{}{
			"provider":         ProviderAlibaba,
			"region":           region,
			"key_usage":        firstString(keyMeta, "KeyUsage"),
			"protection_level": firstString(keyMeta, "ProtectionLevel"),
			"creator":          firstString(keyMeta, "Creator"),
			"synced_at":        time.Now().UTC().Format(time.RFC3339Nano),
		},
	}, nil
}

func (p *alibabaProvider) Inventory(ctx context.Context, in InventoryInput) ([]InventoryItem, error) {
	accessKeyID, accessKeySecret, region, err := p.resolveCredentials(in.Region, in.Account, in.Credentials)
	if err != nil {
		return nil, err
	}

	items := make([]InventoryItem, 0, 128)
	pageNumber := 1
	pageSize := 50

	for len(items) < 200 {
		params := map[string]string{
			"Action":     "ListKeys",
			"PageNumber": fmt.Sprintf("%d", pageNumber),
			"PageSize":   fmt.Sprintf("%d", pageSize),
		}
		respRaw, reqErr := p.apiRequest(ctx, accessKeyID, accessKeySecret, region, params)
		if reqErr != nil {
			return nil, fmt.Errorf("alibaba kms ListKeys failed: %w", reqErr)
		}

		resp := asObject(respRaw)
		keysObj := nestedObject(resp, "Keys")
		keyList := arrayField(keysObj, "Key")

		if len(keyList) == 0 {
			break
		}

		for _, entry := range keyList {
			entryObj := asObject(entry)
			keyID := firstString(entryObj, "KeyId")
			if keyID == "" {
				continue
			}
			arn := firstString(entryObj, "KeyArn")
			if arn == "" {
				arn = fmt.Sprintf("acs:kms:%s:key/%s", region, keyID)
			}
			items = append(items, InventoryItem{
				CloudKeyID:     keyID,
				CloudKeyRef:    arn,
				Provider:       ProviderAlibaba,
				AccountID:      in.Account.ID,
				Region:         region,
				State:          "enabled",
				Algorithm:      "AES-256",
				ManagedByVecta: false,
			})
			if len(items) >= 200 {
				break
			}
		}

		totalCount := 0
		if tc, ok := resp["TotalCount"]; ok {
			if v, ok2 := tc.(float64); ok2 {
				totalCount = int(v)
			}
		}
		if pageNumber*pageSize >= totalCount || len(keyList) < pageSize {
			break
		}
		pageNumber++
	}

	return items, nil
}

// resolveCredentials extracts Alibaba Cloud access credentials and region.
func (p *alibabaProvider) resolveCredentials(regionHint string, account CloudAccount, creds map[string]interface{}) (string, string, string, error) {
	accessKeyID := strings.TrimSpace(defaultString(anyToString(creds["access_key_id"]), anyToString(creds["accessKeyId"])))
	accessKeySecret := strings.TrimSpace(defaultString(anyToString(creds["access_key_secret"]), anyToString(creds["accessKeySecret"])))
	if accessKeyID == "" || accessKeySecret == "" {
		return "", "", "", fmt.Errorf("alibaba credentials require access_key_id and access_key_secret")
	}

	region := strings.TrimSpace(regionHint)
	if region == "" {
		region = strings.TrimSpace(anyToString(creds["region"]))
	}
	if region == "" {
		region = defaultString(account.DefaultRegion, p.DefaultRegion())
	}

	return accessKeyID, accessKeySecret, region, nil
}

// apiRequest performs an Alibaba Cloud KMS API call using Alibaba Cloud signature v1.
// NOTE: Alibaba Cloud API v1 mandates HMAC-SHA1 as the signing algorithm (SignatureMethod=HMAC-SHA1).
// This is an external protocol constraint imposed by the provider — it cannot be changed
// without breaking compatibility. This usage is isolated to outbound API authentication only
// and does not affect internal key material or FIPS 140-3 boundary operations.
// FIPS exception: external third-party protocol mandate (RFC-equivalent external spec).
func (p *alibabaProvider) apiRequest(ctx context.Context, accessKeyID, accessKeySecret, region string, actionParams map[string]string) (interface{}, error) {
	return p.apiRequestAt(ctx, "", accessKeyID, accessKeySecret, region, actionParams)
}

// apiRequestAt is apiRequest at endpoint: the credential's endpoint_url (a
// VPC or private endpoint), or "" for the region's public endpoint.
func (p *alibabaProvider) apiRequestAt(ctx context.Context, endpoint, accessKeyID, accessKeySecret, region string, actionParams map[string]string) (interface{}, error) {
	if endpoint = strings.TrimRight(strings.TrimSpace(endpoint), "/"); endpoint == "" {
		endpoint = fmt.Sprintf("https://kms.%s.aliyuncs.com", region)
	}
	endpoint += "/"

	// Common request parameters per Alibaba Cloud API signature v1 spec
	params := url.Values{}
	params.Set("Format", "JSON")
	params.Set("Version", "2016-01-20")
	params.Set("AccessKeyId", accessKeyID)
	params.Set("SignatureMethod", "HMAC-SHA1")
	params.Set("Timestamp", time.Now().UTC().Format("2006-01-02T15:04:05Z"))
	params.Set("SignatureVersion", "1.0")
	params.Set("SignatureNonce", fmt.Sprintf("%d", time.Now().UnixNano()))

	for k, v := range actionParams {
		params.Set(k, v)
	}

	// Build the string to sign
	sortedKeys := make([]string, 0, len(params))
	for k := range params {
		sortedKeys = append(sortedKeys, k)
	}
	sort.Strings(sortedKeys)

	canonicalized := url.Values{}
	for _, k := range sortedKeys {
		canonicalized.Set(k, params.Get(k))
	}
	canonicalizedQuery := canonicalized.Encode()

	stringToSign := "GET&" + url.QueryEscape("/") + "&" + url.QueryEscape(canonicalizedQuery)

	// HMAC-SHA1 signing (mandated by the Alibaba Cloud API signature protocol)
	mac, err := pkgcrypto.HMACSHA1Interop([]byte(accessKeySecret+"&"), []byte(stringToSign))
	if err != nil {
		return nil, err
	}
	params.Set("Signature", base64.StdEncoding.EncodeToString(mac))

	requestURL := endpoint + "?" + params.Encode()

	respRaw, err := httpJSONRequest(ctx, p.httpClient, http.MethodGet, requestURL, "", nil, nil)
	if err != nil {
		return nil, err
	}

	// Check for Alibaba Cloud error response
	resp := asObject(respRaw)
	if errCode := firstString(resp, "Code"); errCode != "" {
		requestID := firstString(resp, "RequestId")
		message := firstString(resp, "Message")
		return nil, fmt.Errorf("alibaba kms error [%s] RequestId=%s: %s", errCode, requestID, message)
	}

	return respRaw, nil
}
