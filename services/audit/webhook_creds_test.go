package main

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"testing"

	"vecta-kms/pkg/mek"
)

// The database holds no credential in plaintext: the secret column is empty,
// headers_json has names only, and the envelope doesn't contain the values.
func TestWebhookCredentialsAreSealedAtRest(t *testing.T) {
	h, _, store, srv, _ := webhookRig(t)
	secret, token := "sealed-secret-0123456789", "hec-token-not-in-db"
	_, out := webhookReq(t, h, http.MethodPost, "/webhooks", map[string]any{
		"name": "s", "url": srv.URL, "events": []string{"*"}, "secret": secret,
		"headers": map[string]string{"Authorization": token},
	})
	id := out["webhook"].(map[string]any)["id"].(string)
	var sec, headers string
	var ct, wrapped []byte
	var hasSecret bool
	if err := store.db.SQL().QueryRow(`SELECT secret, headers_json, has_secret, creds_ciphertext, creds_wrapped_dek FROM webhooks WHERE id=$1`, id).
		Scan(&sec, &headers, &hasSecret, &ct, &wrapped); err != nil {
		t.Fatal(err)
	}
	if sec != "" || headers != `{"Authorization":""}` || !hasSecret || len(ct) == 0 || len(wrapped) == 0 {
		t.Fatalf("row: secret=%q headers=%s has_secret=%v ct=%d dek=%d", sec, headers, hasSecret, len(ct), len(wrapped))
	}
	if bytes.Contains(ct, []byte(secret)) || bytes.Contains(ct, []byte(token)) {
		t.Fatal("ciphertext contains a credential")
	}
	// The store refuses plaintext outright.
	if _, err := store.CreateWebhook(context.Background(), Webhook{TenantID: "t1", Name: "x", URL: srv.URL, Secret: "plain-secret-0123456"}); err != errPlaintextCredentials {
		t.Fatalf("store accepted plaintext: %v", err)
	}
}

// A sealed blob copied onto another webhook does not open there.
func TestWebhookCredentialsAreBoundToTheirWebhook(t *testing.T) {
	h, svc, store, srv, _ := webhookRig(t)
	mk := func(name string) string {
		_, out := webhookReq(t, h, http.MethodPost, "/webhooks", map[string]any{"name": name, "url": srv.URL, "events": []string{"*"}, "secret": "secret-for-" + name + "-0123"})
		return out["webhook"].(map[string]any)["id"].(string)
	}
	a, b := mk("a"), mk("b")
	if _, err := store.db.SQL().Exec(`UPDATE webhooks SET creds_ciphertext=(SELECT creds_ciphertext FROM webhooks WHERE id=$1),
		creds_data_iv=(SELECT creds_data_iv FROM webhooks WHERE id=$1), creds_wrapped_dek=(SELECT creds_wrapped_dek FROM webhooks WHERE id=$1),
		creds_wrapped_dek_iv=(SELECT creds_wrapped_dek_iv FROM webhooks WHERE id=$1) WHERE id=$2`, a, b); err != nil {
		t.Fatal(err)
	}
	wb, _ := store.GetWebhook(context.Background(), "t1", b)
	if _, err := svc.creds.Open(wb); err == nil {
		t.Fatal("webhook b opened webhook a's credentials")
	}
}

// Until the master key is open, credentials can't be written (503) and a
// delivery that needs them fails with the reason; webhooks without
// credentials keep working.
func TestWebhookCredentialsFailClosedWithoutKey(t *testing.T) {
	h, svc, _, srv, _ := webhookRig(t)
	_, out := webhookReq(t, h, http.MethodPost, "/webhooks", map[string]any{"name": "sealed", "url": srv.URL, "events": []string{"*"}, "secret": "0123456789abcdef"})
	sealedID := out["webhook"].(map[string]any)["id"].(string)
	svc.creds = &credVault{}
	svc.webhooks.creds = svc.creds
	if rr, res := webhookReq(t, h, http.MethodPost, "/webhooks/"+sealedID+"/test", nil); rr.Code != http.StatusOK || res["success"] != false || res["error"] == "" {
		t.Fatalf("delivery without the key: %d %v", rr.Code, res)
	}
	if rr, _ := webhookReq(t, h, http.MethodPost, "/webhooks", map[string]any{"name": "s", "url": srv.URL, "events": []string{"*"}, "secret": "0123456789abcdef"}); rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("secret stored without the key: %d", rr.Code)
	}
	if rr, _ := webhookReq(t, h, http.MethodPost, "/webhooks", map[string]any{"name": "n", "url": srv.URL, "events": []string{"*"}}); rr.Code != http.StatusCreated {
		t.Fatalf("webhook without credentials refused: %d %s", rr.Code, rr.Body)
	}
}

// A row an earlier release stored in plaintext is sealed on the primary,
// recorded in the exposure register and audited; replacing its credentials
// retires the entry. A member leaves it for the primary.
func TestPlaintextWebhooksAreSealedAndRegistered(t *testing.T) {
	h, svc, store, srv, _ := webhookRig(t)
	ctx := context.Background()
	if _, err := store.db.SQL().Exec(`INSERT INTO webhooks (id, tenant_id, name, url, format, events_json, secret, headers_json)
		VALUES ('wh_legacy', 't1', 'legacy', $1, 'json', '["*"]', 'legacy-plain-secret', '{"DD-API-KEY":"legacy-dd-key"}')`, srv.URL); err != nil {
		t.Fatal(err)
	}
	k, _ := svc.creds.current()
	if n, _ := svc.sealLegacyWebhooks(ctx, k, func(context.Context) bool { return false }, nil); n != 0 {
		t.Fatal("member sealed a replicated row")
	}
	audited := 0
	n, err := svc.sealLegacyWebhooks(ctx, k, func(context.Context) bool { return true }, func(_ context.Context, ev AuditEvent) {
		if ev.Action == "audit.audit.webhook_credentials_sealed" && ev.Details["count"] == 1 {
			audited++
		}
	})
	if err != nil || n != 1 || audited != 1 {
		t.Fatalf("sealed %d (%v), audited %d", n, err, audited)
	}
	var sec, headers string
	_ = store.db.SQL().QueryRow(`SELECT secret, headers_json FROM webhooks WHERE id='wh_legacy'`).Scan(&sec, &headers)
	if sec != "" || headers != `{"DD-API-KEY":""}` {
		t.Fatalf("plaintext left: %q %s", sec, headers)
	}
	wh, _ := store.GetWebhook(ctx, "t1", "wh_legacy")
	if opened, err := svc.creds.Open(wh); err != nil || opened.Secret != "legacy-plain-secret" || opened.Headers["DD-API-KEY"] != "legacy-dd-key" {
		t.Fatalf("sealed values: %v %+v", err, opened)
	}
	open := func() []mek.Exposure { e, _ := k.Exposures(ctx, "t1", true); return e }
	if e := open(); len(e) != 1 || e[0].ItemID != "wh_legacy" || e[0].Source != "plaintext_storage" {
		t.Fatalf("exposure %+v", e)
	}
	// Rotating only the secret leaves the Datadog key exposed.
	webhookReq(t, h, http.MethodPatch, "/webhooks/wh_legacy", map[string]any{"secret": "rotated-secret-012345"})
	if len(open()) != 1 {
		t.Fatal("partial rotation retired the exposure")
	}
	webhookReq(t, h, http.MethodPatch, "/webhooks/wh_legacy", map[string]any{"secret": "rotated-again-012345", "headers": map[string]string{"DD-API-KEY": "new-dd-key"}})
	if len(open()) != 0 {
		t.Fatal("full rotation did not retire the exposure")
	}
}

// A plaintext row that can't be registered and sealed is left alone, the
// sweep fails, and the refusal is audited with the webhook.
func TestPlaintextWebhookSealRefusalAudited(t *testing.T) {
	_, svc, store, srv, _ := webhookRig(t)
	ctx := context.Background()
	if _, err := store.db.SQL().Exec(`INSERT INTO webhooks (id, tenant_id, name, url, format, events_json, secret, headers_json)
		VALUES ('wh_stuck', 't1', 'legacy', $1, 'json', '["*"]', 'legacy-plain-secret', '{}')`, srv.URL); err != nil {
		t.Fatal(err)
	}
	// The exposure register is unavailable, so the row can't be recorded as
	// exposed; it must not be sealed silently either.
	if _, err := store.db.SQL().Exec(`DROP TABLE audit_mek_exposure`); err != nil {
		t.Fatal(err)
	}
	k, _ := svc.creds.current()
	var refused []AuditEvent
	n, err := svc.sealLegacyWebhooks(ctx, k, func(context.Context) bool { return true }, func(_ context.Context, ev AuditEvent) {
		if ev.Action == "audit.audit.webhook_credentials_seal_refused" {
			refused = append(refused, ev)
		}
	})
	if err == nil || n != 0 {
		t.Fatalf("the sweep must fail: sealed %d, %v", n, err)
	}
	if len(refused) != 1 || refused[0].Result != "refused" || refused[0].Details["reason"] != "seal_failed" {
		t.Fatalf("refusal audit: %+v", refused)
	}
	if ids, _ := refused[0].Details["webhook_ids"].([]string); len(ids) != 1 || ids[0] != "wh_stuck" {
		t.Fatalf("refusal must name the webhook: %+v", refused[0].Details)
	}
	var sec string
	_ = store.db.SQL().QueryRow(`SELECT secret FROM webhooks WHERE id='wh_stuck'`).Scan(&sec)
	if sec != "legacy-plain-secret" {
		t.Fatal("a row that couldn't be registered as exposed was changed")
	}
}

// A key that doesn't match the stored data leaves credentials unavailable
// (fail closed) and stops retrying; the audit service itself keeps running.
func TestCredsKeyringMismatchFailsClosed(t *testing.T) {
	svc := &Service{creds: &credVault{}}
	calls := 0
	svc.openCredsKeyring(context.Background(), func(context.Context) (*mek.Keyring, error) {
		calls++
		return nil, mek.ErrMismatch
	}, func(*mek.Keyring) { t.Fatal("opened on a mismatch") }, t.Logf)
	if calls != 1 {
		t.Fatalf("retried a mismatch %d times", calls)
	}
	if _, err := svc.creds.current(); err == nil || !errors.Is(err, errCredsKeyUnavailable) {
		t.Fatalf("credentials available after a mismatch: %v", err)
	}
	if err := svc.creds.Seal(&Webhook{Secret: "0123456789abcdef"}); err == nil {
		t.Fatal("sealed without a key")
	}
}
