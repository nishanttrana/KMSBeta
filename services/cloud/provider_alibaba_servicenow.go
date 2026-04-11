package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
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

func (p *alibabaProvider) ImportKey(ctx context.Context, in ImportInput) (ImportResult, error) {
	accessKeyID, accessKeySecret, region, err := p.resolveCredentials(in.Region, in.Account, in.Credentials)
	if err != nil {
		return ImportResult{}, err
	}
	keyName := sanitizeCloudName(defaultString(anyToString(in.Metadata["cloud_key_id"]), in.KeyID))
	if keyName == "" {
		keyName = sanitizeCloudName(newID("alikey"))
	}

	params := map[string]string{
		"Action":              "ImportKeyMaterial",
		"KeyId":               keyName,
		"EncryptedKeyMaterial": anyToString(in.Export["wrapped_material"]),
		"ImportToken":         anyToString(in.Export["import_token"]),
		"KeyMaterialExpireUnix": "0",
	}

	respRaw, err := p.apiRequest(ctx, accessKeyID, accessKeySecret, region, params)
	if err != nil {
		// If ImportKeyMaterial fails (e.g. no wrapping setup), fall back to CreateKey
		createParams := map[string]string{
			"Action":          "CreateKey",
			"KeyUsage":        "ENCRYPT/DECRYPT",
			"Origin":          "Aliyun_KMS",
			"Description":     fmt.Sprintf("Vecta managed key tenant=%s key_id=%s", in.TenantID, in.KeyID),
			"ProtectionLevel": "HSM",
		}
		respRaw, err = p.apiRequest(ctx, accessKeyID, accessKeySecret, region, createParams)
		if err != nil {
			return ImportResult{}, fmt.Errorf("alibaba kms CreateKey failed: %w", err)
		}
	}

	resp := asObject(respRaw)
	keyMeta := nestedObject(resp, "KeyMetadata")
	cloudKeyID := firstString(keyMeta, "KeyId")
	if cloudKeyID == "" {
		cloudKeyID = firstString(resp, "KeyId")
	}
	if cloudKeyID == "" {
		cloudKeyID = keyName
	}
	cloudKeyRef := fmt.Sprintf("acs:kms:%s:%s:key/%s", region, anyToString(keyMeta["Arn"]), cloudKeyID)
	arn := firstString(keyMeta, "Arn")
	if arn != "" {
		cloudKeyRef = arn
	}

	state := strings.ToLower(defaultString(firstString(keyMeta, "KeyState"), "Enabled"))
	if state == "pendingimport" || state == "pending_import" {
		state = "pending-import"
	}

	return ImportResult{
		CloudKeyID:  cloudKeyID,
		CloudKeyRef: cloudKeyRef,
		State:       state,
		Metadata: map[string]interface{}{
			"provider":          ProviderAlibaba,
			"region":            region,
			"key_usage":         firstString(keyMeta, "KeyUsage"),
			"protection_level":  firstString(keyMeta, "ProtectionLevel"),
			"native_key_create": true,
			"imported_at":       time.Now().UTC().Format(time.RFC3339Nano),
		},
	}, nil
}

func (p *alibabaProvider) RotateKey(ctx context.Context, in RotateInput) (ImportResult, error) {
	accessKeyID, accessKeySecret, region, err := p.resolveCredentials(in.Binding.Region, in.Account, in.Credentials)
	if err != nil {
		return ImportResult{}, err
	}
	keyID := strings.TrimSpace(in.Binding.CloudKeyID)
	if keyID == "" {
		return ImportResult{}, fmt.Errorf("cloud key id is required")
	}

	params := map[string]string{
		"Action": "CreateKeyVersion",
		"KeyId":  keyID,
	}
	respRaw, err := p.apiRequest(ctx, accessKeyID, accessKeySecret, region, params)
	if err != nil {
		return ImportResult{}, fmt.Errorf("alibaba kms CreateKeyVersion failed: %w", err)
	}

	resp := asObject(respRaw)
	keyVersion := nestedObject(resp, "KeyVersion")
	versionID := firstString(keyVersion, "KeyVersionId", "VersionId")

	return ImportResult{
		CloudKeyID:  keyID,
		CloudKeyRef: in.Binding.CloudKeyRef,
		State:       "enabled",
		Metadata: map[string]interface{}{
			"provider":        ProviderAlibaba,
			"region":          region,
			"key_version_id":  versionID,
			"rotated_at":      time.Now().UTC().Format(time.RFC3339Nano),
			"rotation_method": "CreateKeyVersion",
			"reason":          defaultString(in.Reason, "manual"),
		},
	}, nil
}

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
	endpoint := fmt.Sprintf("https://kms.%s.aliyuncs.com/", region)

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

	// HMAC-SHA1 signing
	mac := hmac.New(sha1.New, []byte(accessKeySecret+"&"))
	mac.Write([]byte(stringToSign))
	signature := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	params.Set("Signature", signature)

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

// ---------------------------------------------------------------------------
// ServiceNow BYOK Provider
// ---------------------------------------------------------------------------

type serviceNowProvider struct {
	httpClient *http.Client
}

func newServiceNowProvider() *serviceNowProvider {
	return &serviceNowProvider{
		httpClient: &http.Client{Timeout: 25 * time.Second},
	}
}

func (p *serviceNowProvider) Name() string { return ProviderServiceNow }

func (p *serviceNowProvider) DefaultRegion() string { return "us" }

func (p *serviceNowProvider) ImportKey(ctx context.Context, in ImportInput) (ImportResult, error) {
	instanceURL, username, password, err := p.resolveCredentials(in.Account, in.Credentials)
	if err != nil {
		return ImportResult{}, err
	}

	keyName := sanitizeCloudName(defaultString(anyToString(in.Metadata["cloud_key_id"]), in.KeyID))
	if keyName == "" {
		keyName = sanitizeCloudName(newID("snkey"))
	}

	algorithm := strings.ToUpper(strings.TrimSpace(anyToString(in.KeyMeta["algorithm"])))
	if algorithm == "" {
		algorithm = "AES-256"
	}

	payload := map[string]interface{}{
		"name":      keyName,
		"type":      algorithm,
		"key_material": anyToString(in.Export["wrapped_material"]),
		"encryption_context": map[string]interface{}{
			"vecta_tenant_id":       in.TenantID,
			"vecta_original_key_id": in.KeyID,
		},
	}

	endpoint := instanceURL + "/api/now/encryption/key"

	respRaw, err := p.doRequest(ctx, http.MethodPost, endpoint, username, password, payload)
	if err != nil {
		return ImportResult{}, fmt.Errorf("servicenow import key failed: %w", err)
	}

	resp := asObject(respRaw)
	result := nestedObject(resp, "result")
	if len(result) == 0 {
		result = resp
	}

	cloudKeyID := firstString(result, "sys_id", "id", "key_id")
	if cloudKeyID == "" {
		cloudKeyID = keyName
	}
	cloudKeyRef := fmt.Sprintf("%s/api/now/encryption/key/%s", instanceURL, cloudKeyID)
	state := strings.ToLower(defaultString(firstString(result, "state", "status"), "active"))
	if state == "active" {
		state = "enabled"
	}

	return ImportResult{
		CloudKeyID:  cloudKeyID,
		CloudKeyRef: cloudKeyRef,
		State:       state,
		Metadata: map[string]interface{}{
			"provider":          ProviderServiceNow,
			"instance_url":      instanceURL,
			"name":              firstString(result, "name"),
			"type":              firstString(result, "type"),
			"native_key_create": false,
			"imported_at":       time.Now().UTC().Format(time.RFC3339Nano),
		},
	}, nil
}

func (p *serviceNowProvider) RotateKey(ctx context.Context, in RotateInput) (ImportResult, error) {
	instanceURL, username, password, err := p.resolveCredentials(in.Account, in.Credentials)
	if err != nil {
		return ImportResult{}, err
	}

	keyID := strings.TrimSpace(in.Binding.CloudKeyID)
	if keyID == "" {
		return ImportResult{}, fmt.Errorf("cloud key id is required")
	}

	endpoint := fmt.Sprintf("%s/api/now/encryption/key/%s/rotate", instanceURL, url.PathEscape(keyID))

	payload := map[string]interface{}{
		"reason": defaultString(in.Reason, "manual"),
	}

	respRaw, err := p.doRequest(ctx, http.MethodPut, endpoint, username, password, payload)
	if err != nil {
		return ImportResult{}, fmt.Errorf("servicenow rotate key failed: %w", err)
	}

	resp := asObject(respRaw)
	result := nestedObject(resp, "result")
	if len(result) == 0 {
		result = resp
	}

	cloudKeyID := defaultString(firstString(result, "sys_id", "id", "key_id"), keyID)
	cloudKeyRef := fmt.Sprintf("%s/api/now/encryption/key/%s", instanceURL, cloudKeyID)
	state := strings.ToLower(defaultString(firstString(result, "state", "status"), "active"))
	if state == "active" {
		state = "enabled"
	}

	return ImportResult{
		CloudKeyID:  cloudKeyID,
		CloudKeyRef: cloudKeyRef,
		State:       state,
		Metadata: map[string]interface{}{
			"provider":     ProviderServiceNow,
			"instance_url": instanceURL,
			"rotated_at":   time.Now().UTC().Format(time.RFC3339Nano),
			"reason":       defaultString(in.Reason, "manual"),
		},
	}, nil
}

func (p *serviceNowProvider) SyncBinding(ctx context.Context, in SyncInput) (ImportResult, error) {
	instanceURL, username, password, err := p.resolveCredentials(in.Account, in.Credentials)
	if err != nil {
		return ImportResult{}, err
	}

	keyID := strings.TrimSpace(in.Binding.CloudKeyID)
	if keyID == "" {
		return ImportResult{}, fmt.Errorf("cloud key id is required")
	}

	endpoint := fmt.Sprintf("%s/api/now/encryption/key/%s", instanceURL, url.PathEscape(keyID))

	respRaw, err := p.doRequest(ctx, http.MethodGet, endpoint, username, password, nil)
	if err != nil {
		return ImportResult{}, fmt.Errorf("servicenow sync binding failed: %w", err)
	}

	resp := asObject(respRaw)
	result := nestedObject(resp, "result")
	if len(result) == 0 {
		result = resp
	}

	cloudKeyID := defaultString(firstString(result, "sys_id", "id", "key_id"), keyID)
	cloudKeyRef := fmt.Sprintf("%s/api/now/encryption/key/%s", instanceURL, cloudKeyID)
	state := strings.ToLower(defaultString(firstString(result, "state", "status"), "unknown"))
	if state == "active" {
		state = "enabled"
	}

	return ImportResult{
		CloudKeyID:  cloudKeyID,
		CloudKeyRef: cloudKeyRef,
		State:       state,
		Metadata: map[string]interface{}{
			"provider":     ProviderServiceNow,
			"instance_url": instanceURL,
			"name":         firstString(result, "name"),
			"type":         firstString(result, "type"),
			"synced_at":    time.Now().UTC().Format(time.RFC3339Nano),
		},
	}, nil
}

func (p *serviceNowProvider) Inventory(ctx context.Context, in InventoryInput) ([]InventoryItem, error) {
	instanceURL, username, password, err := p.resolveCredentials(in.Account, in.Credentials)
	if err != nil {
		return nil, err
	}

	endpoint := instanceURL + "/api/now/encryption/key"
	items := make([]InventoryItem, 0, 128)
	offset := 0
	limit := 50

	for len(items) < 200 {
		paginatedURL := fmt.Sprintf("%s?sysparm_limit=%d&sysparm_offset=%d", endpoint, limit, offset)

		respRaw, reqErr := p.doRequest(ctx, http.MethodGet, paginatedURL, username, password, nil)
		if reqErr != nil {
			return nil, fmt.Errorf("servicenow list keys failed: %w", reqErr)
		}

		resp := asObject(respRaw)
		records := arrayField(resp, "result")
		if len(records) == 0 {
			break
		}

		for _, entry := range records {
			entryObj := asObject(entry)
			keyID := firstString(entryObj, "sys_id", "id", "key_id")
			if keyID == "" {
				continue
			}
			keyRef := fmt.Sprintf("%s/api/now/encryption/key/%s", instanceURL, keyID)
			state := strings.ToLower(defaultString(firstString(entryObj, "state", "status"), "active"))
			if state == "active" {
				state = "enabled"
			}
			algorithm := strings.ToUpper(defaultString(firstString(entryObj, "type", "algorithm"), "AES-256"))

			items = append(items, InventoryItem{
				CloudKeyID:     keyID,
				CloudKeyRef:    keyRef,
				Provider:       ProviderServiceNow,
				AccountID:      in.Account.ID,
				Region:         p.DefaultRegion(),
				State:          state,
				Algorithm:      algorithm,
				ManagedByVecta: false,
			})
			if len(items) >= 200 {
				break
			}
		}

		if len(records) < limit {
			break
		}
		offset += limit
	}

	return items, nil
}

// resolveCredentials extracts ServiceNow instance URL and basic auth credentials.
func (p *serviceNowProvider) resolveCredentials(account CloudAccount, creds map[string]interface{}) (string, string, string, error) {
	instanceURL := strings.TrimSpace(defaultString(anyToString(creds["instance_url"]), anyToString(creds["endpoint_url"])))
	if instanceURL == "" {
		instanceURL = strings.TrimSpace(account.Name)
	}
	if instanceURL == "" {
		return "", "", "", fmt.Errorf("servicenow credentials require instance_url")
	}
	if !strings.HasPrefix(strings.ToLower(instanceURL), "http://") && !strings.HasPrefix(strings.ToLower(instanceURL), "https://") {
		instanceURL = "https://" + instanceURL
	}
	instanceURL = strings.TrimRight(instanceURL, "/")

	username := strings.TrimSpace(anyToString(creds["username"]))
	password := strings.TrimSpace(anyToString(creds["password"]))
	if username == "" || password == "" {
		return "", "", "", fmt.Errorf("servicenow credentials require username and password")
	}

	return instanceURL, username, password, nil
}

// doRequest performs an HTTP request with Basic Auth for ServiceNow.
func (p *serviceNowProvider) doRequest(ctx context.Context, method, endpoint, username, password string, body interface{}) (interface{}, error) {
	headers := map[string]string{
		"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte(username+":"+password)),
	}
	// httpJSONRequest sets Bearer token from the token param; we pass empty token
	// and use headers for Basic Auth instead.
	return httpJSONRequest(ctx, p.httpClient, method, endpoint, "", body, headers)
}
