package siem

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// SentinelExporter sends audit events to Azure Sentinel via the Azure Monitor HTTP Data Collector API.
type SentinelExporter struct {
	workspaceID string
	sharedKey   string
	logType     string
	httpClient  *http.Client
}

// NewSentinelExporter creates an Azure Sentinel destination.
func NewSentinelExporter(workspaceID, sharedKey, logType string, client *http.Client) *SentinelExporter {
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	if logType == "" {
		logType = "VectaKMSAudit"
	}
	return &SentinelExporter{
		workspaceID: workspaceID,
		sharedKey:   sharedKey,
		logType:     logType,
		httpClient:  client,
	}
}

func (s *SentinelExporter) Name() string { return "azure_sentinel" }

// Send posts events to the Azure Monitor HTTP Data Collector API.
// Uses HMAC-SHA256 signature as per:
// https://learn.microsoft.com/en-us/azure/azure-monitor/logs/data-collector-api
func (s *SentinelExporter) Send(ctx context.Context, events []AuditEvent) error {
	if len(events) == 0 {
		return nil
	}

	body, err := json.Marshal(events)
	if err != nil {
		return fmt.Errorf("sentinel: marshal: %w", err)
	}

	dateString := time.Now().UTC().Format(time.RFC1123)
	// Azure expects "GMT" instead of "UTC" in the date
	dateString = strings.Replace(dateString, "UTC", "GMT", 1)

	contentLength := len(body)
	signature, err := s.buildSignature(dateString, contentLength)
	if err != nil {
		return fmt.Errorf("sentinel: build signature: %w", err)
	}

	url := fmt.Sprintf("https://%s.ods.opinsights.azure.com/api/logs?api-version=2016-04-01",
		s.workspaceID)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("sentinel: create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", signature)
	req.Header.Set("Log-Type", s.logType)
	req.Header.Set("x-ms-date", dateString)
	req.Header.Set("time-generated-field", "timestamp")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("sentinel: post: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("sentinel: unexpected status %d: %s", resp.StatusCode, string(respBody))
	}

	return nil
}

// buildSignature creates the HMAC-SHA256 authorization header required by Azure Monitor.
// Signature format: SharedKey {workspaceID}:{base64(HMAC-SHA256(stringToSign))}
func (s *SentinelExporter) buildSignature(dateString string, contentLength int) (string, error) {
	stringToSign := fmt.Sprintf("POST\n%d\napplication/json\nx-ms-date:%s\n/api/logs",
		contentLength, dateString)

	decodedKey, err := base64.StdEncoding.DecodeString(s.sharedKey)
	if err != nil {
		return "", fmt.Errorf("decode shared key: %w", err)
	}

	mac := hmac.New(sha256.New, decodedKey)
	mac.Write([]byte(stringToSign))
	encodedHash := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	return fmt.Sprintf("SharedKey %s:%s", s.workspaceID, encodedHash), nil
}
