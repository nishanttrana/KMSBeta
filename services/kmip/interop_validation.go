package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	kmip "github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/kmipclient"
	"github.com/ovh/kmip-go/payloads"
)

func defaultKMIPInteropVersions() []kmip.ProtocolVersion {
	return []kmip.ProtocolVersion{
		{ProtocolVersionMajor: 3, ProtocolVersionMinor: 2},
		{ProtocolVersionMajor: 3, ProtocolVersionMinor: 1},
		{ProtocolVersionMajor: 3, ProtocolVersionMinor: 0},
		kmip.V2_2,
		kmip.V2_1,
		kmip.V2_0,
		kmip.V1_4,
		kmip.V1_3,
		kmip.V1_2,
		kmip.V1_1,
		kmip.V1_0,
	}
}

func formatKMIPVersion(v kmip.ProtocolVersion) string {
	return fmt.Sprintf("%d.%d", v.ProtocolVersionMajor, v.ProtocolVersionMinor)
}

func parseVersionParts(v string) (int, int, error) {
	parts := strings.Split(strings.TrimSpace(v), ".")
	if len(parts) != 2 {
		return 0, 0, errors.New("invalid version format")
	}
	major, err := strconv.Atoi(strings.TrimSpace(parts[0]))
	if err != nil {
		return 0, 0, err
	}
	minor, err := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err != nil {
		return 0, 0, err
	}
	return major, minor, nil
}

func versionAtLeast(actual string, minimum string) bool {
	if strings.TrimSpace(minimum) == "" {
		return true
	}
	aMajor, aMinor, aErr := parseVersionParts(actual)
	mMajor, mMinor, mErr := parseVersionParts(minimum)
	if aErr != nil || mErr != nil {
		return false
	}
	if aMajor > mMajor {
		return true
	}
	if aMajor < mMajor {
		return false
	}
	return aMinor >= mMinor
}

func normalizeInteropVendor(vendor string) string {
	v := strings.ToLower(strings.TrimSpace(vendor))
	switch v {
	case "mysql", "mongodb", "vmware", "scality", "netapp", "hpe", "dell", "generic":
		return v
	default:
		return "generic"
	}
}

func normalizeInteropEndpoint(endpoint string) string {
	out := strings.TrimSpace(endpoint)
	if out == "" {
		return ""
	}
	if strings.Contains(out, ":") {
		return out
	}
	return out + ":" + KMIPPort
}

func (h *Handler) runInteropValidation(ctx context.Context, target KMIPInteropTarget) KMIPInteropValidationResult {
	start := time.Now()
	result := KMIPInteropValidationResult{
		TargetID: target.ID,
		Vendor:   target.Vendor,
		Endpoint: target.Endpoint,
	}
	defer func() {
		result.CheckedAt = time.Now().UTC()
		result.LatencyMS = time.Since(start).Milliseconds()
		result.Verified = result.HandshakeOK && result.DiscoverVersionsOK && result.QueryOK && result.KeyOperationOK && strings.TrimSpace(result.Error) == ""
	}()

	if strings.TrimSpace(target.Endpoint) == "" {
		result.Error = "target endpoint is required"
		return result
	}
	if strings.TrimSpace(target.CAPEM) == "" {
		result.Error = "ca_pem is required for TLS trust validation"
		return result
	}
	if strings.TrimSpace(target.ClientCertPEM) == "" || strings.TrimSpace(target.ClientKeyPEM) == "" {
		result.Error = "client_cert_pem and client_key_pem are required for mTLS validation"
		return result
	}

	if _, err := tls.X509KeyPair([]byte(target.ClientCertPEM), []byte(target.ClientKeyPEM)); err != nil {
		result.Error = "invalid client certificate/key pair: " + err.Error()
		return result
	}

	dialer := &net.Dialer{Timeout: 8 * time.Second}
	opts := []kmipclient.Option{
		kmipclient.WithRootCAPem([]byte(target.CAPEM)),
		kmipclient.WithClientCertPEM([]byte(target.ClientCertPEM), []byte(target.ClientKeyPEM)),
		kmipclient.WithKmipVersions(defaultKMIPInteropVersions()...),
		kmipclient.WithDialerUnsafe(func(ctx context.Context, addr string) (net.Conn, error) {
			return dialer.DialContext(ctx, "tcp", addr)
		}),
	}
	if strings.TrimSpace(target.ServerName) != "" {
		opts = append(opts, kmipclient.WithServerName(strings.TrimSpace(target.ServerName)))
	}
	client, err := kmipclient.Dial(strings.TrimSpace(target.Endpoint), opts...)
	if err != nil {
		result.Error = "mTLS handshake/dial failed: " + err.Error()
		return result
	}
	defer client.Close()
	result.HandshakeOK = true
	if v := client.Version(); v.ProtocolVersionMajor > 0 {
		result.NegotiatedVersion = formatKMIPVersion(v)
	}

	opCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	discoverAny, err := client.Request(opCtx, &payloads.DiscoverVersionsRequestPayload{
		ProtocolVersion: defaultKMIPInteropVersions(),
	})
	if err != nil {
		result.Error = "DiscoverVersions failed: " + err.Error()
		return result
	}
	discover, ok := discoverAny.(*payloads.DiscoverVersionsResponsePayload)
	if !ok {
		result.Error = "DiscoverVersions response type mismatch"
		return result
	}
	result.DiscoverVersionsOK = true
	if len(discover.ProtocolVersion) > 0 {
		result.DiscoveredVersions = make([]string, 0, len(discover.ProtocolVersion))
		for _, version := range discover.ProtocolVersion {
			result.DiscoveredVersions = append(result.DiscoveredVersions, formatKMIPVersion(version))
		}
		if result.NegotiatedVersion == "" {
			result.NegotiatedVersion = result.DiscoveredVersions[0]
		}
	}
	if strings.TrimSpace(target.ExpectedMinVersion) != "" && !versionAtLeast(result.NegotiatedVersion, target.ExpectedMinVersion) {
		result.Error = fmt.Sprintf("negotiated KMIP version %s is below required minimum %s", result.NegotiatedVersion, target.ExpectedMinVersion)
		return result
	}

	if _, err := client.Request(opCtx, &payloads.QueryRequestPayload{
		QueryFunction: []kmip.QueryFunction{
			kmip.QueryFunctionOperations,
			kmip.QueryFunctionObjects,
			kmip.QueryFunctionCapabilities,
		},
	}); err != nil {
		result.Error = "Query failed: " + err.Error()
		return result
	}
	result.QueryOK = true

	if !target.TestKeyOperation {
		result.KeyOperationOK = true
		result.RoundtripOK = true
		return result
	}

	keyName := fmt.Sprintf("interop-%s-%d", strings.ToLower(strings.TrimSpace(target.Vendor)), time.Now().UnixNano())
	createAny, err := client.Request(opCtx, &payloads.CreateRequestPayload{
		ObjectType: kmip.ObjectTypeSymmetricKey,
		TemplateAttribute: kmip.TemplateAttribute{
			Name: []kmip.Name{
				{NameValue: keyName, NameType: kmip.NameTypeUninterpretedTextString},
			},
			Attribute: []kmip.Attribute{
				{AttributeName: kmip.AttributeNameCryptographicAlgorithm, AttributeValue: kmip.CryptographicAlgorithmAES},
				{AttributeName: kmip.AttributeNameCryptographicLength, AttributeValue: int32(256)},
				{AttributeName: kmip.AttributeNameCryptographicUsageMask, AttributeValue: kmip.CryptographicUsageEncrypt | kmip.CryptographicUsageDecrypt},
			},
		},
	})
	if err != nil {
		result.Error = "Create test key failed: " + err.Error()
		return result
	}
	createResp, ok := createAny.(*payloads.CreateResponsePayload)
	if !ok {
		result.Error = "Create response type mismatch"
		return result
	}
	objectID := strings.TrimSpace(createResp.UniqueIdentifier)
	if objectID == "" {
		result.Error = "Create did not return object identifier"
		return result
	}

	_, _ = client.Request(opCtx, &payloads.ActivateRequestPayload{UniqueIdentifier: objectID})

	plaintext := []byte("kmip-interop-validation")
	encryptAny, err := client.Request(opCtx, &payloads.EncryptRequestPayload{
		UniqueIdentifier: objectID,
		Data:             plaintext,
	})
	if err != nil {
		result.Error = "Encrypt failed: " + err.Error()
		_, _ = client.Request(opCtx, &payloads.DestroyRequestPayload{UniqueIdentifier: objectID})
		return result
	}
	encryptResp, ok := encryptAny.(*payloads.EncryptResponsePayload)
	if !ok {
		result.Error = "Encrypt response type mismatch"
		_, _ = client.Request(opCtx, &payloads.DestroyRequestPayload{UniqueIdentifier: objectID})
		return result
	}

	decryptAny, err := client.Request(opCtx, &payloads.DecryptRequestPayload{
		UniqueIdentifier: objectID,
		Data:             encryptResp.Data,
		IVCounterNonce:   encryptResp.IVCounterNonce,
	})
	if err != nil {
		result.Error = "Decrypt failed: " + err.Error()
		_, _ = client.Request(opCtx, &payloads.DestroyRequestPayload{UniqueIdentifier: objectID})
		return result
	}
	decryptResp, ok := decryptAny.(*payloads.DecryptResponsePayload)
	if !ok {
		result.Error = "Decrypt response type mismatch"
		_, _ = client.Request(opCtx, &payloads.DestroyRequestPayload{UniqueIdentifier: objectID})
		return result
	}
	result.RoundtripOK = string(decryptResp.Data) == string(plaintext)
	if !result.RoundtripOK {
		result.Error = "key operation roundtrip mismatch"
		_, _ = client.Request(opCtx, &payloads.DestroyRequestPayload{UniqueIdentifier: objectID})
		return result
	}

	if _, err := client.Request(opCtx, &payloads.DestroyRequestPayload{UniqueIdentifier: objectID}); err != nil {
		result.Error = "Destroy test key failed: " + err.Error()
		return result
	}

	result.KeyOperationOK = true
	return result
}

func marshalInteropValidationReport(report KMIPInteropValidationResult) string {
	raw, err := json.Marshal(report)
	if err != nil {
		return "{}"
	}
	return string(raw)
}
