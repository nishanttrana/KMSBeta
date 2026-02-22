package main

import (
	"encoding/json"
	"testing"
)

func TestTTLVEncodeDecodeRoundTrip(t *testing.T) {
	msg := TTLVStructure(tagRequestMessage,
		TTLVStructure(tagRequestHeader,
			TTLVText(tagRequestID, "req-1"),
		),
		TTLVStructure(tagBatchItem,
			TTLVText(tagOperation, "Create"),
			TTLVBytes(tagVendorPayload, []byte(`{"name":"k1","algorithm":"AES-256"}`)),
		),
	)
	raw, err := EncodeTTLV(msg)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeTTLV(raw)
	if err != nil {
		t.Fatal(err)
	}
	req, err := ParseKMIPRequest(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if req.Operation != "Create" || req.RequestID != "req-1" {
		t.Fatalf("unexpected req %+v", req)
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(req.Payload, &payload); err != nil {
		t.Fatal(err)
	}
	if payload["name"] != "k1" {
		t.Fatalf("unexpected payload %+v", payload)
	}
}

func TestBuildKMIPResponse(t *testing.T) {
	req := KMIPMessage{Operation: "Query", RequestID: "req-2", ObjectID: ""}
	_, raw, err := BuildKMIPResponse(req, "success", "OK", map[string]interface{}{
		"kmip_version": "2.1",
	})
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeTTLV(raw)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Tag != tagResponseMessage {
		t.Fatalf("unexpected response tag: 0x%06x", decoded.Tag)
	}
}
