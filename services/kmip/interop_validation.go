package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	kmip "github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/payloads"
	"github.com/ovh/kmip-go/ttlv"
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

func (h *Handler) runInteropValidation(ctx context.Context, target KMIPInteropTarget) (result KMIPInteropValidationResult) {
	start := time.Now()
	result = KMIPInteropValidationResult{
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
	// Bound the size of caller-supplied PEM material so a malformed or
	// hostile request cannot stream an unbounded payload into the
	// validator. 8 KiB comfortably fits modern certificate chains.
	const maxInteropPEMBytes = 8 * 1024
	if len(target.CAPEM) > maxInteropPEMBytes ||
		len(target.ClientCertPEM) > maxInteropPEMBytes ||
		len(target.ClientKeyPEM) > maxInteropPEMBytes {
		result.Error = "PEM material exceeds maximum allowed size"
		return result
	}

	pair, err := tls.X509KeyPair([]byte(target.ClientCertPEM), []byte(target.ClientKeyPEM))
	if err != nil {
		result.Error = "invalid client certificate/key pair: " + err.Error()
		return result
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(target.CAPEM)) {
		result.Error = "ca_pem holds no certificate"
		return result
	}

	endpoint := strings.TrimSpace(target.Endpoint)
	serverName := strings.TrimSpace(target.ServerName)
	if serverName == "" {
		if host, _, splitErr := net.SplitHostPort(endpoint); splitErr == nil {
			serverName = host
		}
	}
	// The connection is made here, to the stored endpoint and nowhere else,
	// and it is mutual TLS: the target's CA, this client certificate, the
	// target's name. With a dialer of its own the kmip-go client applies none
	// of its TLS options, so until 13.8.0-beta this dialled plain TCP and
	// sent KMIP in the clear: no TLS server could be validated, and the
	// failure was reported as an "mTLS handshake" that never took place.
	dialer := &tls.Dialer{NetDialer: &net.Dialer{Timeout: 8 * time.Second}, Config: &tls.Config{
		RootCAs: roots, Certificates: []tls.Certificate{pair}, ServerName: serverName,
		MinVersion: tls.VersionTLS12, // FIPS exception: external protocol mandate (KMIP 1.x servers)
	}}
	client, err := dialKMIPSession(ctx, dialer, endpoint)
	if err != nil {
		result.Error = "mTLS handshake/dial failed: " + err.Error()
		return result
	}
	defer client.Close() //nolint:errcheck
	result.HandshakeOK = true
	if v := client.version; v.ProtocolVersionMajor > 0 {
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

// kmipSession is one KMIP connection driven from the caller's goroutine: a
// request is written and its answer read before the next is sent. The
// interop check used the kmip-go client (0.9.2, the newest), whose reader
// goroutine closes the channel its sender writes to when the server hangs
// up: a data race, and a "send on closed channel" panic when the timing is
// unlucky. A customer's KMIP server may hang up whenever it likes.
type kmipSession struct {
	conn    net.Conn
	stream  ttlv.Stream
	version kmip.ProtocolVersion
}

// dialKMIPSession connects with dialer (mutual TLS) and agrees a protocol
// version the way kmip-go's client does: DiscoverVersions under a 1.1
// header, the first version both sides have, 1.0 for a server without it.
func dialKMIPSession(ctx context.Context, dialer *tls.Dialer, endpoint string) (*kmipSession, error) {
	conn, err := dialer.DialContext(ctx, "tcp", endpoint)
	if err != nil {
		return nil, err
	}
	s := &kmipSession{conn: conn, stream: ttlv.NewStream(conn, 1<<20), version: kmip.V1_1}
	resp, err := s.roundTrip(ctx, &payloads.DiscoverVersionsRequestPayload{ProtocolVersion: defaultKMIPInteropVersions()})
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	item := resp.BatchItem[0]
	switch {
	case item.ResultStatus == kmip.ResultStatusOperationFailed && item.ResultReason == kmip.ResultReasonOperationNotSupported:
		s.version = kmip.V1_0
	case item.Err() != nil:
		_ = conn.Close()
		return nil, item.Err()
	default:
		offered, _ := item.ResponsePayload.(*payloads.DiscoverVersionsResponsePayload)
		if offered == nil || len(offered.ProtocolVersion) == 0 {
			_ = conn.Close()
			return nil, errors.New("protocol version negotiation failed: no common version")
		}
		s.version = offered.ProtocolVersion[0]
	}
	return s, nil
}

func (s *kmipSession) roundTrip(ctx context.Context, payload kmip.OperationPayload) (kmip.ResponseMessage, error) {
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(20 * time.Second)
	}
	_ = s.conn.SetDeadline(deadline)
	req := kmip.NewRequestMessage(s.version, payload)
	var resp kmip.ResponseMessage
	if err := s.stream.Send(&req); err != nil {
		return resp, err
	}
	if err := s.stream.Recv(&resp); err != nil {
		return resp, err
	}
	if len(resp.BatchItem) != 1 {
		return resp, fmt.Errorf("%d answers to one request", len(resp.BatchItem))
	}
	return resp, nil
}

// Request sends one operation and returns its answer, or the server's error.
func (s *kmipSession) Request(ctx context.Context, payload kmip.OperationPayload) (kmip.OperationPayload, error) {
	resp, err := s.roundTrip(ctx, payload)
	if err != nil {
		return nil, err
	}
	if err := resp.BatchItem[0].Err(); err != nil {
		return nil, err
	}
	return resp.BatchItem[0].ResponsePayload, nil
}

func (s *kmipSession) Close() error { return s.conn.Close() }
