package main

import (
	"encoding/base64"
	"strings"
)

// What the request log keeps of a HYOK call. Until 13.29.0-beta it stored
// the request and response whole, so every key a caller wrapped and every
// key unwrapped for it sat in clear in hyok_requests and came back through
// GET /hyok/v1/requests. The log keeps sizes, never the bytes
// (docs/SECURITY/SECRET_HANDLING.md).

type loggedRequest struct {
	TenantID          string   `json:"tenant_id,omitempty"`
	PlaintextBytes    int      `json:"plaintext_bytes,omitempty"`
	CiphertextBytes   int      `json:"ciphertext_bytes,omitempty"`
	IVBytes           int      `json:"iv_bytes,omitempty"`
	ReferenceID       string   `json:"reference_id,omitempty"`
	RequesterID       string   `json:"requester_id,omitempty"`
	RequesterEmail    string   `json:"requester_email,omitempty"`
	JustificationCode string   `json:"justification_code,omitempty"`
	JustificationText string   `json:"justification_text,omitempty"`
	ApproverEmails    []string `json:"approver_emails,omitempty"`
	ApprovalRequestID string   `json:"approval_request_id,omitempty"`
}

type loggedResponse struct {
	Status            string `json:"status"`
	KeyID             string `json:"key_id"`
	Protocol          string `json:"protocol"`
	Operation         string `json:"operation"`
	Version           int    `json:"version,omitempty"`
	PlaintextBytes    int    `json:"plaintext_bytes,omitempty"`
	CiphertextBytes   int    `json:"ciphertext_bytes,omitempty"`
	ApprovalRequestID string `json:"approval_request_id,omitempty"`
}

// encodedLen is the decoded size of a base64 value (standard or URL, padded
// or not); 0 for an empty or undecodable one.
func encodedLen(v string) int {
	v = strings.TrimRight(strings.TrimSpace(v), "=")
	if v == "" {
		return 0
	}
	if n := base64.RawStdEncoding.DecodedLen(len(v)); n > 0 {
		return n
	}
	return 0
}

func logRequestJSON(req ProxyCryptoRequest) string {
	return mustJSON(loggedRequest{
		TenantID:          req.TenantID,
		PlaintextBytes:    encodedLen(req.PlaintextB64),
		CiphertextBytes:   encodedLen(req.CiphertextB64),
		IVBytes:           encodedLen(req.IVB64),
		ReferenceID:       req.ReferenceID,
		RequesterID:       req.RequesterID,
		RequesterEmail:    req.RequesterEmail,
		JustificationCode: req.JustificationCode,
		JustificationText: req.JustificationText,
		ApproverEmails:    req.ApproverEmails,
		ApprovalRequestID: req.ApprovalRequestID,
	})
}

func logResponseJSON(resp ProxyCryptoResponse) string {
	return mustJSON(loggedResponse{
		Status:            resp.Status,
		KeyID:             resp.KeyID,
		Protocol:          resp.Protocol,
		Operation:         resp.Operation,
		Version:           resp.Version,
		PlaintextBytes:    encodedLen(resp.PlaintextB64),
		CiphertextBytes:   encodedLen(resp.CiphertextB64),
		ApprovalRequestID: resp.ApprovalRequestID,
	})
}
