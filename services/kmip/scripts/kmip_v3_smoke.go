package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	kmip "github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/kmipclient"
	"github.com/ovh/kmip-go/payloads"
)

func main() {
	addr := envOr("KMIP_ADDR", "localhost:5696")
	caPath := envOr("KMIP_CA", "infra/certs/out/ca/ca.crt")
	certPath := envOr("KMIP_CERT", "infra/certs/out/kmip-client/tls.crt")
	keyPath := envOr("KMIP_KEY", "infra/certs/out/kmip-client/tls.key")

	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		log.Fatalf("read CA %s: %v", caPath, err)
	}
	client, err := kmipclient.Dial(
		addr,
		kmipclient.WithRootCAPem(caPEM),
		kmipclient.WithClientCertFiles(certPath, keyPath),
		kmipclient.WithKmipVersions(
			kmip.ProtocolVersion{ProtocolVersionMajor: 3, ProtocolVersionMinor: 2},
			kmip.ProtocolVersion{ProtocolVersionMajor: 3, ProtocolVersionMinor: 1},
			kmip.ProtocolVersion{ProtocolVersionMajor: 3, ProtocolVersionMinor: 0},
			kmip.V2_2,
			kmip.V2_1,
			kmip.V1_4,
		),
	)
	if err != nil {
		log.Fatalf("dial kmip: %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	discoverAny, err := client.Request(ctx, &payloads.DiscoverVersionsRequestPayload{
		ProtocolVersion: []kmip.ProtocolVersion{
			{ProtocolVersionMajor: 3, ProtocolVersionMinor: 2},
			{ProtocolVersionMajor: 3, ProtocolVersionMinor: 1},
			{ProtocolVersionMajor: 3, ProtocolVersionMinor: 0},
			kmip.V2_2,
			kmip.V2_1,
			kmip.V1_4,
		},
	})
	if err != nil {
		log.Fatalf("discover versions: %v", err)
	}
	discover := discoverAny.(*payloads.DiscoverVersionsResponsePayload)

	createAny, err := client.Request(ctx, &payloads.CreateRequestPayload{
		ObjectType: kmip.ObjectTypeSymmetricKey,
		TemplateAttribute: kmip.TemplateAttribute{
			Name: []kmip.Name{
				{NameValue: "go-kmip-v3-smoke", NameType: kmip.NameTypeUninterpretedTextString},
			},
			Attribute: []kmip.Attribute{
				{AttributeName: kmip.AttributeNameCryptographicAlgorithm, AttributeValue: kmip.CryptographicAlgorithmAES},
				{AttributeName: kmip.AttributeNameCryptographicLength, AttributeValue: int32(256)},
				{AttributeName: kmip.AttributeNameCryptographicUsageMask, AttributeValue: kmip.CryptographicUsageEncrypt | kmip.CryptographicUsageDecrypt},
			},
		},
	})
	if err != nil {
		log.Fatalf("create: %v", err)
	}
	create := createAny.(*payloads.CreateResponsePayload)

	_, err = client.Request(ctx, &payloads.ActivateRequestPayload{UniqueIdentifier: create.UniqueIdentifier})
	if err != nil {
		log.Fatalf("activate: %v", err)
	}

	encAny, err := client.Request(ctx, &payloads.EncryptRequestPayload{
		UniqueIdentifier: create.UniqueIdentifier,
		Data:             []byte("kmip-v3-roundtrip"),
	})
	if err != nil {
		log.Fatalf("encrypt: %v", err)
	}
	enc := encAny.(*payloads.EncryptResponsePayload)

	decAny, err := client.Request(ctx, &payloads.DecryptRequestPayload{
		UniqueIdentifier: create.UniqueIdentifier,
		Data:             enc.Data,
		IVCounterNonce:   enc.IVCounterNonce,
	})
	if err != nil {
		log.Fatalf("decrypt: %v", err)
	}
	dec := decAny.(*payloads.DecryptResponsePayload)

	fmt.Printf("discover_versions=%v\n", discover.ProtocolVersion)
	fmt.Printf("negotiated_version=%v\n", client.Version())
	fmt.Printf("object_id=%s\n", create.UniqueIdentifier)
	fmt.Printf("ciphertext_len=%d iv_len=%d\n", len(enc.Data), len(enc.IVCounterNonce))
	fmt.Printf("roundtrip_ok=%v\n", string(dec.Data) == "kmip-v3-roundtrip")
}

func envOr(key string, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
