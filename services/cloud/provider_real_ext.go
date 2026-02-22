package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/keymanagement"
)

type azureProvider struct {
	httpClient *http.Client
}

func newAzureProvider() *azureProvider {
	return &azureProvider{
		httpClient: &http.Client{Timeout: 25 * time.Second},
	}
}

func (p *azureProvider) Name() string { return ProviderAzure }

func (p *azureProvider) DefaultRegion() string { return "eastus" }

func (p *azureProvider) ImportKey(ctx context.Context, in ImportInput) (ImportResult, error) {
	token, vaultURL, apiVersion, region, err := p.resolveConnection(ctx, in.Region, in.Account, in.Credentials)
	if err != nil {
		return ImportResult{}, err
	}
	spec, err := mapAzureKeySpec(in.KeyMeta)
	if err != nil {
		return ImportResult{}, err
	}
	keyName := sanitizeCloudName(defaultString(anyToString(in.Metadata["cloud_key_id"]), in.KeyID))
	if keyName == "" {
		keyName = sanitizeCloudName(newID("azkey"))
	}
	endpoint := fmt.Sprintf("%s/keys/%s/create?api-version=%s", vaultURL, url.PathEscape(keyName), url.QueryEscape(apiVersion))
	payload := map[string]interface{}{
		"kty": spec.KTY,
		"attributes": map[string]interface{}{
			"enabled": true,
		},
		"key_ops": spec.KeyOps,
		"tags": map[string]string{
			"vecta_tenant": sanitizeLabel(in.TenantID),
			"vecta_key_id": sanitizeLabel(in.KeyID),
		},
	}
	if spec.KeySize > 0 {
		payload["key_size"] = spec.KeySize
	}
	if spec.Curve != "" {
		payload["crv"] = spec.Curve
	}
	respRaw, err := httpJSONRequest(ctx, p.httpClient, http.MethodPost, endpoint, token, payload, nil)
	if err != nil {
		return ImportResult{}, err
	}
	resp := asObject(respRaw)
	keyObj := nestedObject(resp, "key")
	attrObj := nestedObject(resp, "attributes")
	cloudKeyID := firstString(keyObj, "kid")
	if cloudKeyID == "" {
		cloudKeyID = fmt.Sprintf("%s/keys/%s", vaultURL, keyName)
	}
	enabled, hasEnabled := boolValue(attrObj["enabled"])
	state := "unknown"
	if hasEnabled {
		if enabled {
			state = "enabled"
		} else {
			state = "disabled"
		}
	}
	return ImportResult{
		CloudKeyID:  cloudKeyID,
		CloudKeyRef: cloudKeyID,
		State:       state,
		Metadata: map[string]interface{}{
			"provider":          ProviderAzure,
			"region":            region,
			"vault_url":         vaultURL,
			"kty":               spec.KTY,
			"api_version":       apiVersion,
			"native_key_create": true,
			"imported_at":       time.Now().UTC().Format(time.RFC3339Nano),
		},
	}, nil
}

func (p *azureProvider) RotateKey(ctx context.Context, in RotateInput) (ImportResult, error) {
	token, vaultURL, apiVersion, region, err := p.resolveConnection(ctx, in.Binding.Region, in.Account, in.Credentials)
	if err != nil {
		return ImportResult{}, err
	}
	keyName := azureKeyName(in.Binding.CloudKeyID, in.Binding.CloudKeyRef)
	if keyName == "" {
		return ImportResult{}, errors.New("cloud key id is required")
	}
	endpoint := fmt.Sprintf("%s/keys/%s/rotate?api-version=%s", vaultURL, url.PathEscape(keyName), url.QueryEscape(apiVersion))
	respRaw, err := httpJSONRequest(ctx, p.httpClient, http.MethodPost, endpoint, token, map[string]interface{}{}, nil)
	if err != nil {
		return ImportResult{}, err
	}
	resp := asObject(respRaw)
	keyObj := nestedObject(resp, "key")
	attrObj := nestedObject(resp, "attributes")
	cloudKeyID := firstString(keyObj, "kid")
	if cloudKeyID == "" {
		cloudKeyID = fmt.Sprintf("%s/keys/%s", vaultURL, keyName)
	}
	enabled, hasEnabled := boolValue(attrObj["enabled"])
	state := "unknown"
	if hasEnabled {
		if enabled {
			state = "enabled"
		} else {
			state = "disabled"
		}
	}
	return ImportResult{
		CloudKeyID:  cloudKeyID,
		CloudKeyRef: cloudKeyID,
		State:       state,
		Metadata: map[string]interface{}{
			"provider":    ProviderAzure,
			"region":      region,
			"vault_url":   vaultURL,
			"api_version": apiVersion,
			"rotated_at":  time.Now().UTC().Format(time.RFC3339Nano),
			"reason":      defaultString(in.Reason, "manual"),
		},
	}, nil
}

func (p *azureProvider) SyncBinding(ctx context.Context, in SyncInput) (ImportResult, error) {
	token, vaultURL, apiVersion, region, err := p.resolveConnection(ctx, in.Binding.Region, in.Account, in.Credentials)
	if err != nil {
		return ImportResult{}, err
	}
	keyName := azureKeyName(in.Binding.CloudKeyID, in.Binding.CloudKeyRef)
	if keyName == "" {
		return ImportResult{}, errors.New("cloud key id is required")
	}
	endpoint := fmt.Sprintf("%s/keys/%s?api-version=%s", vaultURL, url.PathEscape(keyName), url.QueryEscape(apiVersion))
	respRaw, err := httpJSONRequest(ctx, p.httpClient, http.MethodGet, endpoint, token, nil, nil)
	if err != nil {
		return ImportResult{}, err
	}
	resp := asObject(respRaw)
	keyObj := nestedObject(resp, "key")
	attrObj := nestedObject(resp, "attributes")
	cloudKeyID := firstString(keyObj, "kid")
	if cloudKeyID == "" {
		cloudKeyID = fmt.Sprintf("%s/keys/%s", vaultURL, keyName)
	}
	enabled, hasEnabled := boolValue(attrObj["enabled"])
	state := "unknown"
	if hasEnabled {
		if enabled {
			state = "enabled"
		} else {
			state = "disabled"
		}
	}
	return ImportResult{
		CloudKeyID:  cloudKeyID,
		CloudKeyRef: cloudKeyID,
		State:       state,
		Metadata: map[string]interface{}{
			"provider":    ProviderAzure,
			"region":      region,
			"vault_url":   vaultURL,
			"api_version": apiVersion,
			"kty":         firstString(keyObj, "kty"),
			"synced_at":   time.Now().UTC().Format(time.RFC3339Nano),
		},
	}, nil
}

func (p *azureProvider) Inventory(ctx context.Context, in InventoryInput) ([]InventoryItem, error) {
	token, vaultURL, apiVersion, region, err := p.resolveConnection(ctx, in.Region, in.Account, in.Credentials)
	if err != nil {
		return nil, err
	}
	nextURL := fmt.Sprintf("%s/keys?api-version=%s", vaultURL, url.QueryEscape(apiVersion))
	items := make([]InventoryItem, 0, 128)
	for nextURL != "" && len(items) < 200 {
		respRaw, reqErr := httpJSONRequest(ctx, p.httpClient, http.MethodGet, nextURL, token, nil, nil)
		if reqErr != nil {
			return nil, reqErr
		}
		resp := asObject(respRaw)
		list := arrayField(resp, "value")
		for _, entry := range list {
			entryObj := asObject(entry)
			kid := firstString(entryObj, "kid", "id")
			if kid == "" {
				continue
			}
			state := "unknown"
			if enabled, ok := boolValue(nestedObject(entryObj, "attributes")["enabled"]); ok {
				if enabled {
					state = "enabled"
				} else {
					state = "disabled"
				}
			}
			algorithm := firstString(nestedObject(entryObj, "key"), "kty")
			if algorithm == "" {
				algorithm = firstString(entryObj, "kty")
			}
			items = append(items, InventoryItem{
				CloudKeyID:     kid,
				CloudKeyRef:    kid,
				Provider:       ProviderAzure,
				AccountID:      in.Account.ID,
				Region:         region,
				State:          state,
				Algorithm:      algorithm,
				ManagedByVecta: false,
			})
			if len(items) >= 200 {
				break
			}
		}
		nextURL = strings.TrimSpace(firstString(resp, "nextLink"))
	}
	return items, nil
}

func (p *azureProvider) resolveConnection(ctx context.Context, regionHint string, account CloudAccount, creds map[string]interface{}) (string, string, string, string, error) {
	vaultURL := strings.TrimSpace(defaultString(anyToString(creds["vault_url"]), anyToString(creds["endpoint_url"])))
	if vaultURL == "" {
		vaultName := strings.TrimSpace(defaultString(anyToString(creds["vault_name"]), account.Name))
		if vaultName == "" {
			return "", "", "", "", errors.New("azure credentials must include vault_url or vault_name")
		}
		if strings.Contains(vaultName, "://") {
			vaultURL = vaultName
		} else {
			suffix := strings.TrimSpace(defaultString(anyToString(creds["vault_dns_suffix"]), "vault.azure.net"))
			vaultURL = fmt.Sprintf("https://%s.%s", strings.Trim(vaultName, ". "), strings.Trim(suffix, ". "))
		}
	}
	if !strings.HasPrefix(strings.ToLower(vaultURL), "http://") && !strings.HasPrefix(strings.ToLower(vaultURL), "https://") {
		vaultURL = "https://" + vaultURL
	}
	vaultURL = strings.TrimRight(vaultURL, "/")
	apiVersion := strings.TrimSpace(defaultString(anyToString(creds["api_version"]), "7.4"))
	region := strings.TrimSpace(regionHint)
	if region == "" {
		region = strings.TrimSpace(anyToString(creds["region"]))
	}
	if region == "" {
		region = defaultString(account.DefaultRegion, p.DefaultRegion())
	}
	token, err := p.accessToken(ctx, creds)
	if err != nil {
		return "", "", "", "", err
	}
	return token, vaultURL, apiVersion, region, nil
}

func (p *azureProvider) accessToken(ctx context.Context, creds map[string]interface{}) (string, error) {
	token := strings.TrimSpace(defaultString(anyToString(creds["access_token"]), anyToString(creds["bearer_token"])))
	if token != "" {
		return token, nil
	}
	clientID := strings.TrimSpace(defaultString(anyToString(creds["client_id"]), anyToString(creds["app_id"])))
	clientSecret := strings.TrimSpace(defaultString(anyToString(creds["client_secret"]), anyToString(creds["app_secret"])))
	tenantID := strings.TrimSpace(anyToString(creds["tenant_id"]))
	if clientID == "" || clientSecret == "" || tenantID == "" {
		return "", errors.New("azure credentials require access_token or client_id/client_secret/tenant_id")
	}
	tokenURL := strings.TrimSpace(anyToString(creds["token_url"]))
	if tokenURL == "" {
		tokenURL = fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", url.PathEscape(tenantID))
	}
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", clientID)
	form.Set("client_secret", clientSecret)
	lowerTokenURL := strings.ToLower(tokenURL)
	if strings.Contains(lowerTokenURL, "/oauth2/token") && !strings.Contains(lowerTokenURL, "/v2.0/") {
		form.Set("resource", defaultString(anyToString(creds["resource"]), "https://vault.azure.net"))
	} else {
		form.Set("scope", defaultString(anyToString(creds["scope"]), "https://vault.azure.net/.default"))
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := p.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close() //nolint:errcheck
	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return "", err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("azure token request failed (%d): %s", resp.StatusCode, parseErrorText(body))
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(body, &payload); err != nil {
		return "", err
	}
	token = strings.TrimSpace(anyToString(payload["access_token"]))
	if token == "" {
		return "", errors.New("azure token response missing access_token")
	}
	return token, nil
}

type azureKeySpec struct {
	KTY     string
	KeySize int
	Curve   string
	KeyOps  []string
}

func mapAzureKeySpec(keyMeta map[string]interface{}) (azureKeySpec, error) {
	algorithm := strings.ToUpper(strings.TrimSpace(anyToString(keyMeta["algorithm"])))
	purpose := strings.ToLower(strings.TrimSpace(anyToString(keyMeta["purpose"])))
	if strings.Contains(algorithm, "ML-") || strings.Contains(algorithm, "KYBER") || strings.Contains(algorithm, "DILITHIUM") {
		return azureKeySpec{}, errors.New("azure key vault does not support pqc key creation in this flow")
	}
	if strings.Contains(algorithm, "RSA") {
		bits := parseKeyBits(algorithm, 2048)
		if bits != 2048 && bits != 3072 && bits != 4096 {
			bits = 2048
		}
		spec := azureKeySpec{KTY: "RSA", KeySize: bits}
		if strings.Contains(purpose, "sign") {
			spec.KeyOps = []string{"sign", "verify"}
		} else {
			spec.KeyOps = []string{"encrypt", "decrypt", "wrapKey", "unwrapKey"}
		}
		return spec, nil
	}
	if strings.Contains(algorithm, "ECDSA-P256") || strings.Contains(algorithm, "ECDH-P256") {
		return azureKeySpec{KTY: "EC", Curve: "P-256", KeyOps: ecKeyOpsForPurpose(purpose), KeySize: 0}, nil
	}
	if strings.Contains(algorithm, "ECDSA-P384") || strings.Contains(algorithm, "ECDH-P384") {
		return azureKeySpec{KTY: "EC", Curve: "P-384", KeyOps: ecKeyOpsForPurpose(purpose), KeySize: 0}, nil
	}
	if strings.Contains(algorithm, "ECDSA-P521") || strings.Contains(algorithm, "ECDH-P521") {
		return azureKeySpec{KTY: "EC", Curve: "P-521", KeyOps: ecKeyOpsForPurpose(purpose), KeySize: 0}, nil
	}
	if strings.HasPrefix(algorithm, "AES") || strings.Contains(algorithm, "3DES") || strings.Contains(algorithm, "CHACHA") || strings.Contains(algorithm, "CAMELLIA") {
		bits := parseKeyBits(algorithm, 256)
		if bits != 128 && bits != 192 && bits != 256 {
			bits = 256
		}
		return azureKeySpec{KTY: "oct-HSM", KeySize: bits, KeyOps: []string{"encrypt", "decrypt", "wrapKey", "unwrapKey"}}, nil
	}
	return azureKeySpec{}, fmt.Errorf("unsupported algorithm for azure key vault: %s", algorithm)
}

func ecKeyOpsForPurpose(purpose string) []string {
	if strings.Contains(purpose, "derive") || strings.Contains(purpose, "agreement") {
		return []string{"deriveKey", "deriveBits"}
	}
	return []string{"sign", "verify"}
}

func azureKeyName(id string, ref string) string {
	for _, raw := range []string{strings.TrimSpace(id), strings.TrimSpace(ref)} {
		if raw == "" {
			continue
		}
		if !strings.HasPrefix(strings.ToLower(raw), "http://") && !strings.HasPrefix(strings.ToLower(raw), "https://") {
			return raw
		}
		u, err := url.Parse(raw)
		if err != nil {
			continue
		}
		parts := strings.Split(strings.Trim(u.Path, "/"), "/")
		for i := 0; i < len(parts)-1; i++ {
			if parts[i] == "keys" && i+1 < len(parts) {
				return strings.TrimSpace(parts[i+1])
			}
		}
	}
	return ""
}

type ociProvider struct{}

func newOCIProvider() *ociProvider { return &ociProvider{} }

func (p *ociProvider) Name() string { return ProviderOCI }

func (p *ociProvider) DefaultRegion() string { return "us-ashburn-1" }

func (p *ociProvider) ImportKey(ctx context.Context, in ImportInput) (ImportResult, error) {
	client, region, compartmentID, err := p.client(in.Region, in.Account, in.Credentials)
	if err != nil {
		return ImportResult{}, err
	}
	keyShape, err := mapOCIKeyShape(in.KeyMeta)
	if err != nil {
		return ImportResult{}, err
	}
	keyName := strings.TrimSpace(defaultString(anyToString(in.Metadata["cloud_key_id"]), in.KeyID))
	if keyName == "" {
		keyName = sanitizeCloudName(newID("ocikey"))
	}
	mode := strings.ToUpper(defaultString(anyToString(in.Credentials["protection_mode"]), "HSM"))
	protection, ok := keymanagement.GetMappingCreateKeyDetailsProtectionModeEnum(mode)
	if !ok {
		protection = keymanagement.CreateKeyDetailsProtectionModeHsm
	}
	createResp, err := client.CreateKey(ctx, keymanagement.CreateKeyRequest{
		CreateKeyDetails: keymanagement.CreateKeyDetails{
			CompartmentId: common.String(compartmentID),
			DisplayName:   common.String(keyName),
			KeyShape:      &keyShape,
			FreeformTags: map[string]string{
				"vecta_tenant": sanitizeLabel(in.TenantID),
				"vecta_key_id": sanitizeLabel(in.KeyID),
			},
			ProtectionMode: protection,
		},
	})
	if err != nil {
		return ImportResult{}, err
	}
	cloudKeyID := ptrString(createResp.Id)
	if cloudKeyID == "" {
		return ImportResult{}, errors.New("oci create key returned empty key id")
	}
	return ImportResult{
		CloudKeyID:  cloudKeyID,
		CloudKeyRef: cloudKeyID,
		State:       strings.ToLower(string(createResp.LifecycleState)),
		Metadata: map[string]interface{}{
			"provider":          ProviderOCI,
			"region":            region,
			"compartment_id":    compartmentID,
			"protection_mode":   string(protection),
			"algorithm":         strings.ToUpper(string(keyShape.Algorithm)),
			"native_key_create": true,
			"imported_at":       time.Now().UTC().Format(time.RFC3339Nano),
		},
	}, nil
}

func (p *ociProvider) RotateKey(ctx context.Context, in RotateInput) (ImportResult, error) {
	client, region, compartmentID, err := p.client(in.Binding.Region, in.Account, in.Credentials)
	if err != nil {
		return ImportResult{}, err
	}
	keyID := strings.TrimSpace(in.Binding.CloudKeyID)
	if keyID == "" {
		return ImportResult{}, errors.New("cloud key id is required")
	}
	if _, err := client.CreateKeyVersion(ctx, keymanagement.CreateKeyVersionRequest{
		KeyId: common.String(keyID),
	}); err != nil {
		return ImportResult{}, err
	}
	getResp, err := client.GetKey(ctx, keymanagement.GetKeyRequest{KeyId: common.String(keyID)})
	if err != nil {
		return ImportResult{}, err
	}
	return ImportResult{
		CloudKeyID:  keyID,
		CloudKeyRef: keyID,
		State:       strings.ToLower(string(getResp.LifecycleState)),
		Metadata: map[string]interface{}{
			"provider":          ProviderOCI,
			"region":            region,
			"compartment_id":    compartmentID,
			"current_version":   ptrString(getResp.CurrentKeyVersion),
			"rotated_at":        time.Now().UTC().Format(time.RFC3339Nano),
			"rotation_strategy": "create_key_version",
			"reason":            defaultString(in.Reason, "manual"),
		},
	}, nil
}

func (p *ociProvider) SyncBinding(ctx context.Context, in SyncInput) (ImportResult, error) {
	client, region, compartmentID, err := p.client(in.Binding.Region, in.Account, in.Credentials)
	if err != nil {
		return ImportResult{}, err
	}
	keyID := strings.TrimSpace(in.Binding.CloudKeyID)
	if keyID == "" {
		return ImportResult{}, errors.New("cloud key id is required")
	}
	getResp, err := client.GetKey(ctx, keymanagement.GetKeyRequest{KeyId: common.String(keyID)})
	if err != nil {
		return ImportResult{}, err
	}
	return ImportResult{
		CloudKeyID:  keyID,
		CloudKeyRef: keyID,
		State:       strings.ToLower(string(getResp.LifecycleState)),
		Metadata: map[string]interface{}{
			"provider":        ProviderOCI,
			"region":          region,
			"compartment_id":  compartmentID,
			"current_version": ptrString(getResp.CurrentKeyVersion),
			"algorithm":       strings.ToUpper(string(getResp.KeyShape.Algorithm)),
			"synced_at":       time.Now().UTC().Format(time.RFC3339Nano),
		},
	}, nil
}

func (p *ociProvider) Inventory(ctx context.Context, in InventoryInput) ([]InventoryItem, error) {
	client, region, compartmentID, err := p.client(in.Region, in.Account, in.Credentials)
	if err != nil {
		return nil, err
	}
	items := make([]InventoryItem, 0, 128)
	limit := 50
	var page *string
	for len(items) < 200 {
		resp, listErr := client.ListKeys(ctx, keymanagement.ListKeysRequest{
			CompartmentId: common.String(compartmentID),
			Limit:         &limit,
			Page:          page,
		})
		if listErr != nil {
			return nil, listErr
		}
		for _, entry := range resp.Items {
			keyID := ptrString(entry.Id)
			if keyID == "" {
				continue
			}
			items = append(items, InventoryItem{
				CloudKeyID:     keyID,
				CloudKeyRef:    keyID,
				Provider:       ProviderOCI,
				AccountID:      in.Account.ID,
				Region:         region,
				State:          strings.ToLower(string(entry.LifecycleState)),
				Algorithm:      strings.ToUpper(string(entry.Algorithm)),
				ManagedByVecta: false,
			})
			if len(items) >= 200 {
				break
			}
		}
		if resp.OpcNextPage == nil || strings.TrimSpace(*resp.OpcNextPage) == "" {
			break
		}
		page = resp.OpcNextPage
	}
	return items, nil
}

func (p *ociProvider) client(regionHint string, account CloudAccount, creds map[string]interface{}) (keymanagement.KmsManagementClient, string, string, error) {
	region := strings.TrimSpace(regionHint)
	if region == "" {
		region = strings.TrimSpace(anyToString(creds["region"]))
	}
	if region == "" {
		region = defaultString(account.DefaultRegion, p.DefaultRegion())
	}
	tenancy := strings.TrimSpace(defaultString(anyToString(creds["tenancy_ocid"]), anyToString(creds["tenancy"])))
	user := strings.TrimSpace(defaultString(anyToString(creds["user_ocid"]), anyToString(creds["user"])))
	fingerprint := strings.TrimSpace(anyToString(creds["fingerprint"]))
	privateKey := strings.TrimSpace(defaultString(anyToString(creds["private_key_pem"]), anyToString(creds["private_key"])))
	privateKey = strings.ReplaceAll(privateKey, "\\n", "\n")
	endpoint := strings.TrimSpace(defaultString(anyToString(creds["management_endpoint"]), anyToString(creds["kms_management_endpoint"])))
	if endpoint == "" {
		endpoint = strings.TrimSpace(anyToString(creds["endpoint"]))
	}
	compartmentID := strings.TrimSpace(anyToString(creds["compartment_id"]))
	if tenancy == "" || user == "" || fingerprint == "" || privateKey == "" {
		return keymanagement.KmsManagementClient{}, "", "", errors.New("oci credentials require tenancy_ocid, user_ocid, fingerprint, and private_key_pem")
	}
	if endpoint == "" {
		return keymanagement.KmsManagementClient{}, "", "", errors.New("oci credentials require management_endpoint")
	}
	if compartmentID == "" {
		return keymanagement.KmsManagementClient{}, "", "", errors.New("oci credentials require compartment_id")
	}
	var passphrase *string
	if v := strings.TrimSpace(anyToString(creds["private_key_passphrase"])); v != "" {
		passphrase = common.String(v)
	}
	cfg := common.NewRawConfigurationProvider(tenancy, user, region, fingerprint, privateKey, passphrase)
	client, err := keymanagement.NewKmsManagementClientWithConfigurationProvider(cfg, strings.TrimRight(endpoint, "/"))
	if err != nil {
		return keymanagement.KmsManagementClient{}, "", "", err
	}
	return client, region, compartmentID, nil
}

func mapOCIKeyShape(keyMeta map[string]interface{}) (keymanagement.KeyShape, error) {
	algorithm := strings.ToUpper(strings.TrimSpace(anyToString(keyMeta["algorithm"])))
	if strings.Contains(algorithm, "ML-") || strings.Contains(algorithm, "KYBER") || strings.Contains(algorithm, "DILITHIUM") {
		return keymanagement.KeyShape{}, errors.New("oci vault does not support pqc key creation in this flow")
	}
	if strings.Contains(algorithm, "RSA") {
		bytesLen := 256
		switch parseKeyBits(algorithm, 2048) {
		case 2048:
			bytesLen = 256
		case 3072:
			bytesLen = 384
		case 4096:
			bytesLen = 512
		default:
			bytesLen = 256
		}
		return keymanagement.KeyShape{
			Algorithm: mustMapOCIKeyShapeAlgorithm("RSA"),
			Length:    common.Int(bytesLen),
		}, nil
	}
	if strings.Contains(algorithm, "ECDSA-P256") || strings.Contains(algorithm, "ECDH-P256") {
		return keymanagement.KeyShape{Algorithm: mustMapOCIKeyShapeAlgorithm("ECDSA"), Length: common.Int(32), CurveId: mustMapOCIKeyShapeCurve("NIST_P256")}, nil
	}
	if strings.Contains(algorithm, "ECDSA-P384") || strings.Contains(algorithm, "ECDH-P384") {
		return keymanagement.KeyShape{Algorithm: mustMapOCIKeyShapeAlgorithm("ECDSA"), Length: common.Int(48), CurveId: mustMapOCIKeyShapeCurve("NIST_P384")}, nil
	}
	if strings.Contains(algorithm, "ECDSA-P521") || strings.Contains(algorithm, "ECDH-P521") {
		return keymanagement.KeyShape{Algorithm: mustMapOCIKeyShapeAlgorithm("ECDSA"), Length: common.Int(66), CurveId: mustMapOCIKeyShapeCurve("NIST_P521")}, nil
	}
	if strings.HasPrefix(algorithm, "AES") || strings.Contains(algorithm, "3DES") || strings.Contains(algorithm, "CHACHA") || strings.Contains(algorithm, "CAMELLIA") {
		bits := parseKeyBits(algorithm, 256)
		if bits != 128 && bits != 192 && bits != 256 {
			bits = 256
		}
		return keymanagement.KeyShape{Algorithm: mustMapOCIKeyShapeAlgorithm("AES"), Length: common.Int(bits / 8)}, nil
	}
	return keymanagement.KeyShape{}, fmt.Errorf("unsupported algorithm for oci vault: %s", algorithm)
}

func mustMapOCIKeyShapeAlgorithm(v string) keymanagement.KeyShapeAlgorithmEnum {
	if out, ok := keymanagement.GetMappingKeyShapeAlgorithmEnum(strings.ToUpper(strings.TrimSpace(v))); ok {
		return out
	}
	return keymanagement.KeyShapeAlgorithmAes
}

func mustMapOCIKeyShapeCurve(v string) keymanagement.KeyShapeCurveIdEnum {
	if out, ok := keymanagement.GetMappingKeyShapeCurveIdEnum(strings.ToUpper(strings.TrimSpace(v))); ok {
		return out
	}
	return keymanagement.KeyShapeCurveIdP256
}

type salesforceProvider struct {
	httpClient *http.Client
}

func newSalesforceProvider() *salesforceProvider {
	return &salesforceProvider{
		httpClient: &http.Client{Timeout: 25 * time.Second},
	}
}

func (p *salesforceProvider) Name() string { return ProviderSalesforce }

func (p *salesforceProvider) DefaultRegion() string { return "global" }

func (p *salesforceProvider) ImportKey(ctx context.Context, in ImportInput) (ImportResult, error) {
	token, instanceURL, apiVersion, err := p.resolveConnection(ctx, in.Account, in.Credentials)
	if err != nil {
		return ImportResult{}, err
	}
	keyName := sanitizeCloudName(defaultString(anyToString(in.Metadata["cloud_key_id"]), in.KeyID))
	if keyName == "" {
		keyName = sanitizeCloudName(newID("sfkey"))
	}
	path := p.buildImportPath(anyToString(in.Credentials["import_path"]), apiVersion, keyName)
	payload := map[string]interface{}{
		"name":                  keyName,
		"external_reference":    in.KeyID,
		"algorithm":             strings.ToUpper(strings.TrimSpace(anyToString(in.KeyMeta["algorithm"]))),
		"wrapped_material":      anyToString(in.Export["wrapped_material"]),
		"material_iv":           anyToString(in.Export["material_iv"]),
		"wrapped_dek":           anyToString(in.Export["wrapped_dek"]),
		"vecta_tenant_id":       in.TenantID,
		"vecta_original_key_id": in.KeyID,
	}
	respRaw, err := httpJSONRequest(ctx, p.httpClient, http.MethodPost, instanceURL+path, token, payload, nil)
	if err != nil {
		return ImportResult{}, err
	}
	resp := asObject(respRaw)
	cloudKeyID := firstString(resp, "id", "key_id", "kid", "tenantSecretId", "name")
	if cloudKeyID == "" {
		cloudKeyID = keyName
	}
	cloudKeyRef := firstString(resp, "url", "self", "resourceUrl")
	if cloudKeyRef == "" {
		cloudKeyRef = instanceURL + p.buildPath(anyToString(in.Credentials["sync_path_template"]), apiVersion, cloudKeyID)
	}
	state := strings.ToLower(defaultString(firstString(resp, "status", "state", "lifecycleState"), "enabled"))
	return ImportResult{
		CloudKeyID:  cloudKeyID,
		CloudKeyRef: cloudKeyRef,
		State:       state,
		Metadata: map[string]interface{}{
			"provider":          ProviderSalesforce,
			"instance_url":      instanceURL,
			"api_version":       apiVersion,
			"path":              path,
			"native_key_create": false,
			"imported_at":       time.Now().UTC().Format(time.RFC3339Nano),
		},
	}, nil
}

func (p *salesforceProvider) RotateKey(ctx context.Context, in RotateInput) (ImportResult, error) {
	token, instanceURL, apiVersion, err := p.resolveConnection(ctx, in.Account, in.Credentials)
	if err != nil {
		return ImportResult{}, err
	}
	keyID := strings.TrimSpace(in.Binding.CloudKeyID)
	if keyID == "" {
		return ImportResult{}, errors.New("cloud key id is required")
	}
	path := p.buildPath(anyToString(in.Credentials["rotate_path_template"]), apiVersion, keyID)
	payload := map[string]interface{}{"reason": defaultString(in.Reason, "manual")}
	respRaw, err := httpJSONRequest(ctx, p.httpClient, http.MethodPost, instanceURL+path, token, payload, nil)
	if err != nil {
		return ImportResult{}, err
	}
	resp := asObject(respRaw)
	cloudKeyID := defaultString(firstString(resp, "id", "key_id", "kid", "tenantSecretId"), keyID)
	cloudKeyRef := firstString(resp, "url", "self", "resourceUrl")
	if cloudKeyRef == "" {
		cloudKeyRef = instanceURL + p.buildPath(anyToString(in.Credentials["sync_path_template"]), apiVersion, cloudKeyID)
	}
	return ImportResult{
		CloudKeyID:  cloudKeyID,
		CloudKeyRef: cloudKeyRef,
		State:       strings.ToLower(defaultString(firstString(resp, "status", "state", "lifecycleState"), "enabled")),
		Metadata: map[string]interface{}{
			"provider":     ProviderSalesforce,
			"instance_url": instanceURL,
			"api_version":  apiVersion,
			"path":         path,
			"reason":       defaultString(in.Reason, "manual"),
			"rotated_at":   time.Now().UTC().Format(time.RFC3339Nano),
		},
	}, nil
}

func (p *salesforceProvider) SyncBinding(ctx context.Context, in SyncInput) (ImportResult, error) {
	token, instanceURL, apiVersion, err := p.resolveConnection(ctx, in.Account, in.Credentials)
	if err != nil {
		return ImportResult{}, err
	}
	keyID := strings.TrimSpace(in.Binding.CloudKeyID)
	if keyID == "" {
		return ImportResult{}, errors.New("cloud key id is required")
	}
	path := p.buildPath(anyToString(in.Credentials["sync_path_template"]), apiVersion, keyID)
	respRaw, err := httpJSONRequest(ctx, p.httpClient, http.MethodGet, instanceURL+path, token, nil, nil)
	if err != nil {
		return ImportResult{}, err
	}
	resp := asObject(respRaw)
	cloudKeyID := defaultString(firstString(resp, "id", "key_id", "kid", "tenantSecretId"), keyID)
	cloudKeyRef := firstString(resp, "url", "self", "resourceUrl")
	if cloudKeyRef == "" {
		cloudKeyRef = instanceURL + path
	}
	return ImportResult{
		CloudKeyID:  cloudKeyID,
		CloudKeyRef: cloudKeyRef,
		State:       strings.ToLower(defaultString(firstString(resp, "status", "state", "lifecycleState"), "enabled")),
		Metadata: map[string]interface{}{
			"provider":     ProviderSalesforce,
			"instance_url": instanceURL,
			"api_version":  apiVersion,
			"path":         path,
			"synced_at":    time.Now().UTC().Format(time.RFC3339Nano),
		},
	}, nil
}

func (p *salesforceProvider) Inventory(ctx context.Context, in InventoryInput) ([]InventoryItem, error) {
	token, instanceURL, apiVersion, err := p.resolveConnection(ctx, in.Account, in.Credentials)
	if err != nil {
		return nil, err
	}
	nextURL := instanceURL + p.buildInventoryPath(anyToString(in.Credentials["inventory_path"]), apiVersion)
	items := make([]InventoryItem, 0, 128)
	for nextURL != "" && len(items) < 200 {
		respRaw, reqErr := httpJSONRequest(ctx, p.httpClient, http.MethodGet, nextURL, token, nil, nil)
		if reqErr != nil {
			return nil, reqErr
		}
		records, cursor := parseSalesforceRecords(respRaw)
		for _, record := range records {
			keyID := firstString(record, "id", "key_id", "kid", "tenantSecretId", "name")
			if keyID == "" {
				continue
			}
			cloudRef := firstString(record, "url", "self", "resourceUrl")
			if cloudRef == "" {
				cloudRef = instanceURL + p.buildPath(anyToString(in.Credentials["sync_path_template"]), apiVersion, keyID)
			}
			items = append(items, InventoryItem{
				CloudKeyID:     keyID,
				CloudKeyRef:    cloudRef,
				Provider:       ProviderSalesforce,
				AccountID:      in.Account.ID,
				Region:         p.DefaultRegion(),
				State:          strings.ToLower(defaultString(firstString(record, "status", "state", "lifecycleState"), "enabled")),
				Algorithm:      strings.ToUpper(defaultString(firstString(record, "algorithm", "kty", "type"), "unknown")),
				ManagedByVecta: false,
			})
			if len(items) >= 200 {
				break
			}
		}
		if cursor == "" {
			break
		}
		if strings.HasPrefix(strings.ToLower(cursor), "http://") || strings.HasPrefix(strings.ToLower(cursor), "https://") {
			nextURL = cursor
		} else {
			nextURL = strings.TrimRight(instanceURL, "/") + "/" + strings.TrimLeft(cursor, "/")
		}
	}
	return items, nil
}

func (p *salesforceProvider) resolveConnection(ctx context.Context, account CloudAccount, creds map[string]interface{}) (string, string, string, error) {
	instanceURL := strings.TrimSpace(defaultString(anyToString(creds["instance_url"]), anyToString(creds["endpoint_url"])))
	token := strings.TrimSpace(defaultString(anyToString(creds["access_token"]), anyToString(creds["bearer_token"])))
	if token == "" {
		issuedToken, issuedURL, err := p.issueToken(ctx, creds)
		if err != nil {
			return "", "", "", err
		}
		token = issuedToken
		if instanceURL == "" {
			instanceURL = issuedURL
		}
	}
	if token == "" {
		return "", "", "", errors.New("salesforce credentials require access_token or oauth credentials")
	}
	if instanceURL == "" {
		instanceURL = strings.TrimSpace(account.Name)
	}
	if instanceURL == "" {
		return "", "", "", errors.New("salesforce credentials require instance_url")
	}
	if !strings.HasPrefix(strings.ToLower(instanceURL), "http://") && !strings.HasPrefix(strings.ToLower(instanceURL), "https://") {
		instanceURL = "https://" + instanceURL
	}
	instanceURL = strings.TrimRight(instanceURL, "/")
	apiVersion := strings.TrimSpace(defaultString(anyToString(creds["api_version"]), "v61.0"))
	if !strings.HasPrefix(strings.ToLower(apiVersion), "v") {
		apiVersion = "v" + apiVersion
	}
	return token, instanceURL, apiVersion, nil
}

func (p *salesforceProvider) issueToken(ctx context.Context, creds map[string]interface{}) (string, string, error) {
	clientID := strings.TrimSpace(anyToString(creds["client_id"]))
	clientSecret := strings.TrimSpace(anyToString(creds["client_secret"]))
	if clientID == "" || clientSecret == "" {
		return "", "", errors.New("salesforce oauth requires client_id and client_secret")
	}
	loginURL := strings.TrimSpace(defaultString(anyToString(creds["login_url"]), "https://login.salesforce.com"))
	tokenURL := strings.TrimSpace(anyToString(creds["token_url"]))
	if tokenURL == "" {
		tokenURL = strings.TrimRight(loginURL, "/") + "/services/oauth2/token"
	}
	grantType := strings.TrimSpace(defaultString(anyToString(creds["grant_type"]), "password"))
	form := url.Values{}
	form.Set("grant_type", grantType)
	form.Set("client_id", clientID)
	form.Set("client_secret", clientSecret)
	switch strings.ToLower(grantType) {
	case "password":
		username := strings.TrimSpace(anyToString(creds["username"]))
		password := strings.TrimSpace(anyToString(creds["password"]))
		if username == "" || password == "" {
			return "", "", errors.New("salesforce password grant requires username and password")
		}
		if sec := strings.TrimSpace(anyToString(creds["security_token"])); sec != "" {
			password += sec
		}
		form.Set("username", username)
		form.Set("password", password)
	case "client_credentials":
		if scope := strings.TrimSpace(anyToString(creds["scope"])); scope != "" {
			form.Set("scope", scope)
		}
	default:
		return "", "", fmt.Errorf("unsupported salesforce grant_type: %s", grantType)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := p.httpClient.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close() //nolint:errcheck
	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return "", "", err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", "", fmt.Errorf("salesforce token request failed (%d): %s", resp.StatusCode, parseErrorText(body))
	}
	payload := map[string]interface{}{}
	if err := json.Unmarshal(body, &payload); err != nil {
		return "", "", err
	}
	token := strings.TrimSpace(anyToString(payload["access_token"]))
	if token == "" {
		return "", "", errors.New("salesforce token response missing access_token")
	}
	return token, strings.TrimSpace(anyToString(payload["instance_url"])), nil
}

func (p *salesforceProvider) buildInventoryPath(rawPath string, apiVersion string) string {
	rawPath = strings.TrimSpace(rawPath)
	if rawPath == "" {
		rawPath = fmt.Sprintf("/services/data/%s/platform-encryption/tenant-secrets", apiVersion)
	}
	if strings.Contains(rawPath, "{api_version}") {
		rawPath = strings.ReplaceAll(rawPath, "{api_version}", apiVersion)
	}
	if !strings.HasPrefix(rawPath, "/") {
		rawPath = "/" + rawPath
	}
	return rawPath
}

func (p *salesforceProvider) buildImportPath(rawPath string, apiVersion string, keyID string) string {
	rawPath = strings.TrimSpace(rawPath)
	if rawPath == "" {
		rawPath = fmt.Sprintf("/services/data/%s/platform-encryption/tenant-secrets", apiVersion)
	}
	if strings.Contains(rawPath, "{api_version}") {
		rawPath = strings.ReplaceAll(rawPath, "{api_version}", apiVersion)
	}
	if strings.Contains(rawPath, "{id}") {
		rawPath = strings.ReplaceAll(rawPath, "{id}", url.PathEscape(strings.TrimSpace(keyID)))
	}
	if !strings.HasPrefix(rawPath, "/") {
		rawPath = "/" + rawPath
	}
	return rawPath
}

func (p *salesforceProvider) buildPath(rawPath string, apiVersion string, keyID string) string {
	rawPath = strings.TrimSpace(rawPath)
	if rawPath == "" {
		rawPath = fmt.Sprintf("/services/data/%s/platform-encryption/tenant-secrets/{id}", apiVersion)
	}
	if strings.Contains(rawPath, "{api_version}") {
		rawPath = strings.ReplaceAll(rawPath, "{api_version}", apiVersion)
	}
	if strings.Contains(rawPath, "{id}") {
		rawPath = strings.ReplaceAll(rawPath, "{id}", url.PathEscape(strings.TrimSpace(keyID)))
	}
	if !strings.HasPrefix(rawPath, "/") {
		rawPath = "/" + rawPath
	}
	return rawPath
}

func parseSalesforceRecords(payload interface{}) ([]map[string]interface{}, string) {
	switch typed := payload.(type) {
	case []interface{}:
		out := make([]map[string]interface{}, 0, len(typed))
		for _, item := range typed {
			obj := asObject(item)
			if len(obj) > 0 {
				out = append(out, obj)
			}
		}
		return out, ""
	case map[string]interface{}:
		cursor := firstString(typed, "nextRecordsUrl", "nextLink")
		var arr []interface{}
		if records := arrayField(typed, "records"); len(records) > 0 {
			arr = records
		} else if values := arrayField(typed, "value"); len(values) > 0 {
			arr = values
		} else {
			arr = []interface{}{typed}
		}
		out := make([]map[string]interface{}, 0, len(arr))
		for _, item := range arr {
			obj := asObject(item)
			if len(obj) > 0 {
				out = append(out, obj)
			}
		}
		return out, cursor
	default:
		return nil, ""
	}
}

func httpJSONRequest(ctx context.Context, client *http.Client, method string, endpoint string, bearerToken string, body interface{}, headers map[string]string) (interface{}, error) {
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, reader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if bearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+bearerToken)
	}
	for k, v := range headers {
		if strings.TrimSpace(k) != "" && strings.TrimSpace(v) != "" {
			req.Header.Set(k, v)
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close() //nolint:errcheck
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("http %d: %s", resp.StatusCode, parseErrorText(respBody))
	}
	trimmed := bytes.TrimSpace(respBody)
	if len(trimmed) == 0 {
		return map[string]interface{}{}, nil
	}
	var out interface{}
	if err := json.Unmarshal(trimmed, &out); err != nil {
		return nil, fmt.Errorf("invalid json response: %w", err)
	}
	return out, nil
}

func parseErrorText(raw []byte) string {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return "empty response"
	}
	var payload interface{}
	if err := json.Unmarshal(trimmed, &payload); err != nil {
		return string(trimmed)
	}
	switch typed := payload.(type) {
	case map[string]interface{}:
		for _, key := range []string{"error_description", "error", "message", "detail"} {
			if val := strings.TrimSpace(anyToString(typed[key])); val != "" {
				return val
			}
		}
	case []interface{}:
		for _, entry := range typed {
			obj := asObject(entry)
			for _, key := range []string{"message", "errorCode", "error", "detail"} {
				if val := strings.TrimSpace(anyToString(obj[key])); val != "" {
					return val
				}
			}
		}
	}
	return string(trimmed)
}

func asObject(v interface{}) map[string]interface{} {
	if out, ok := v.(map[string]interface{}); ok {
		return out
	}
	return map[string]interface{}{}
}

func nestedObject(m map[string]interface{}, key string) map[string]interface{} {
	if m == nil {
		return map[string]interface{}{}
	}
	return asObject(m[key])
}

func firstString(m map[string]interface{}, keys ...string) string {
	for _, key := range keys {
		if val := strings.TrimSpace(anyToString(m[key])); val != "" {
			return val
		}
	}
	return ""
}

func arrayField(m map[string]interface{}, key string) []interface{} {
	if m == nil {
		return nil
	}
	raw, ok := m[key]
	if !ok {
		return nil
	}
	switch typed := raw.(type) {
	case []interface{}:
		return typed
	default:
		return nil
	}
}

func boolValue(v interface{}) (bool, bool) {
	switch typed := v.(type) {
	case bool:
		return typed, true
	case string:
		switch strings.ToLower(strings.TrimSpace(typed)) {
		case "true", "1", "yes", "enabled", "active":
			return true, true
		case "false", "0", "no", "disabled", "inactive":
			return false, true
		}
	case float64:
		return typed != 0, true
	case int:
		return typed != 0, true
	case int64:
		return typed != 0, true
	}
	return false, false
}

func parseKeyBits(algorithm string, fallback int) int {
	algorithm = strings.TrimSpace(algorithm)
	if algorithm == "" {
		return fallback
	}
	parts := strings.FieldsFunc(algorithm, func(r rune) bool { return r < '0' || r > '9' })
	for _, p := range parts {
		if p == "" {
			continue
		}
		if val, err := strconv.Atoi(p); err == nil && val > 0 {
			return val
		}
	}
	return fallback
}

func ptrString(v *string) string {
	if v == nil {
		return ""
	}
	return strings.TrimSpace(*v)
}
