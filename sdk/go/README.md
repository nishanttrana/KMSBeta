# Vecta KMS Go SDK

`github.com/nishanttrana/KMSBeta/sdk/go/vecta`: keys, cryptographic
operations and secrets over the Vecta KMS REST API, standard library only,
Go 1.22 or later.

```bash
go get github.com/nishanttrana/KMSBeta/sdk/go@latest
```

## The identity it uses

The SDK authenticates as a **REST client** (Workbench → REST API): the
client ID (`registration_id`) and the API key shown once at activation. It
exchanges them for short-lived tokens (5 minutes by default) and renews them
itself. To use keys:

1. Grant the client a role with the key permissions it needs, for example
   `key.encrypt`, `key.decrypt`, `key.read`
   ([CI_CD_AUTOMATION.md](../../docs/CI_CD_AUTOMATION.md#a-role-for-a-client-13530-beta)).
2. Assign each key to the client: Key Access Assignments → **REST client**.

Without a role a client reads secrets and signs artifacts only.

## Use

```go
c, err := vecta.New(vecta.Config{
	BaseURL:  "https://kms.example.com",
	TenantID: "acme",
	ClientID: os.Getenv("KMS_CLIENT_ID"),
	APIKey:   os.Getenv("KMS_API_KEY"),
	CAPEM:    caBundle, // when the KMS certificate comes from its own CA
})

ct, err := c.Encrypt(ctx, keyID, []byte("card 4111"), []byte("order-7"))
plain, err := c.Decrypt(ctx, ct, []byte("order-7"))

dk, err := c.GenerateDataKey(ctx, keyID, nil) // envelope encryption
// encrypt locally with dk.Plaintext, keep only dk.Wrapped
key, err := c.Decrypt(ctx, dk.Wrapped, nil)

sig, err := c.Sign(ctx, signingKeyID, digestOrData, "")
ok, err := c.Verify(ctx, sig, digestOrData, "")

err = c.ListKeys(ctx, func(k vecta.Key) bool { fmt.Println(k.ID, k.Name); return true })
v, err := c.GetSecretValue(ctx, secretID)
```

`CreateKey`, `GetKey`, `UpdateKey` (only the fields you set change),
`RotateKey`, `DeactivateKey`, `GetKeyAccess` and `SetKeyAccess` manage keys
when the client's role allows it and the client manages the key.

## Errors

A refused or failed call is an `*vecta.APIError` with the HTTP status, the
KMS's reason (`Code`, for example `no_matching_grant`, `binding_policy`,
`metadata_profile_violation`) and the `RequestID` under which the KMS
audited it. `vecta.IsRefused(err)` is a 401 or 403, `vecta.IsNotFound(err)`
a 404 (the key doesn't exist or the client may not see it).

## Transport

HTTPS only, TLS 1.3, certificates verified against the system roots or
`CAPEM`. The SDK holds no key material beyond what an operation returns to
you (a data key's plaintext).

## Tests

`go test ./...` here runs the SDK's own tests. The platform also runs it
against the real routes of keycore, auth and secrets
(`services/keycore/sdk_contract_test.go`,
`services/auth/sdk_contract_test.go`, `services/secrets/sdk_contract_test.go`),
so a change to either side that breaks the other fails CI.
