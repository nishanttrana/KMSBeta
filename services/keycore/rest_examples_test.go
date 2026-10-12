package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"

	pkgauth "vecta-kms/pkg/auth"
)

// The dashboard's REST API tab shows a hand-written example request and
// response for some routes. Every keycore example is sent here to the real
// handlers: the route must exist, the body must decode (keycore refuses a
// field it does not read), and where the call succeeds every field the
// example response shows must be one the service returned. The examples are
// exported by web/dashboard/scripts/generate-rest-catalog.mjs.
//
// Until 12.3.0-beta most of them named fields keycore never had (message,
// encoding, key_material, status) and answers it never gave (plaintext
// key_material, a "valid" flag), so the playground's examples failed.
func TestRESTExamplesMatchTheService(t *testing.T) {
	raw, err := os.ReadFile("../../web/dashboard/src/generated/restApiExamples.generated.json")
	if err != nil {
		t.Fatal(err)
	}
	var examples []struct {
		ID       string         `json:"id"`
		Service  string         `json:"service"`
		Method   string         `json:"method"`
		Path     string         `json:"pathTemplate"`
		Body     string         `json:"bodyTemplate"`
		Response map[string]any `json:"responseExample"`
	}
	if err := json.Unmarshal(raw, &examples); err != nil {
		t.Fatal(err)
	}

	h, svc, _ := newActorTestHandler(t)
	ctx := adminCtx()
	mk := func(name, algorithm, keyType, purpose string, exportable bool) string {
		t.Helper()
		k, err := svc.CreateKey(ctx, CreateKeyRequest{TenantID: "t1", Name: name, Algorithm: algorithm, KeyType: keyType, Purpose: purpose, CreatedBy: "tester", ExportAllowed: exportable})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		return k.ID
	}
	data := mk("data", "AES-256", "symmetric", "encrypt-decrypt", true)
	keyFor := map[string]string{
		"key-sign": mk("signer", "ECDSA-P256", "asymmetric-private", "sign-verify", false), "keys-mac": mk("mac", "HMAC-SHA256", "symmetric", "mac", false),
		"keys-wrap": mk("kek", "AES-256", "symmetric", "wrap-unwrap", false), "keys-destroy": mk("doomed", "AES-256", "symmetric", "encrypt-decrypt", false),
		"keys-derive": mk("root", "AES-256", "symmetric", "derive", false),
	}
	// Each example that changes a key's state has a key of its own.
	for _, id := range []string{"keys-rotate", "keys-activate", "keys-deactivate", "keys-usage-limit"} {
		keyFor[id] = mk(id, "AES-256", "symmetric", "encrypt-decrypt", false)
	}
	keyFor["key-verify"], keyFor["keys-unwrap"] = keyFor["key-sign"], keyFor["keys-wrap"]
	values := map[string]string{"tenant_id": "t1", "wrapping_key_id": keyFor["keys-wrap"]}
	placeholder := regexp.MustCompile(`\{\{([a-z_]+)\}\}`)
	fill := func(id, text string) string {
		return placeholder.ReplaceAllStringFunc(text, func(m string) string {
			name := m[2 : len(m)-2]
			if name == "key_id" {
				if k := keyFor[id]; k != "" {
					return k
				}
				return data
			}
			if v, ok := values[name]; ok {
				return v
			}
			return name
		})
	}
	admin := &pkgauth.Claims{UserID: "tester", TenantID: "t1", Role: "admin", Permissions: []string{"*"}}

	// An example that needs another's answer says so with a "<...>" value
	// (the ciphertext from encrypt); it is given the real one here, so the
	// producers run first.
	produced := map[string]map[string]any{}
	feeds := map[string]string{"key-decrypt": "key-encrypt", "key-verify": "key-sign", "keys-unwrap": "keys-wrap"}
	first := map[string]bool{"key-encrypt": true, "key-sign": true, "keys-wrap": true}
	sort.SliceStable(examples, func(i, j int) bool { return first[examples[i].ID] && !first[examples[j].ID] })
	withAnswers := func(id, body string) string {
		var fields map[string]any
		if json.Unmarshal([]byte(body), &fields) != nil {
			return body
		}
		for name, v := range fields {
			text, isText := v.(string)
			if !isText || !strings.HasPrefix(text, "<") {
				continue
			}
			if real, ok := produced[feeds[id]][name]; ok {
				fields[name] = real
			} else if name == "confirm_name" {
				fields[name] = "doomed"
			}
		}
		out, _ := json.Marshal(fields)
		return string(out)
	}

	checked, shaped := 0, []string{}
	for _, ex := range examples {
		if ex.Service != "keycore" {
			continue
		}
		checked++
		path := fill(ex.ID, ex.Path)
		if !strings.Contains(path, "tenant_id=") {
			path += map[bool]string{true: "&", false: "?"}[strings.Contains(path, "?")] + "tenant_id=t1"
		}
		req := httptest.NewRequest(ex.Method, path, bytes.NewBufferString(withAnswers(ex.ID, fill(ex.ID, ex.Body))))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req.WithContext(pkgauth.ContextWithClaims(req.Context(), admin)))
		body := w.Body.String()
		if os.Getenv("REST_EXAMPLES_DUMP") != "" { // what the service really answers, to write an example from
			t.Logf("%s -> %d %s", ex.ID, w.Code, strings.TrimSpace(body))
		}
		switch {
		case w.Code == http.StatusNotFound && strings.Contains(body, "404 page not found"), w.Code == http.StatusMethodNotAllowed:
			t.Errorf("%s: %s %s is not a keycore route (%d)", ex.ID, ex.Method, ex.Path, w.Code)
			continue
		case strings.Contains(body, "unknown field"), strings.Contains(body, "cannot unmarshal"), strings.Contains(body, "invalid character"):
			t.Errorf("%s: the example body does not decode: %s", ex.ID, strings.TrimSpace(body))
			continue
		}
		if w.Code < 200 || w.Code > 299 {
			t.Logf("%s: answered %d (%s); response shape not compared", ex.ID, w.Code, strings.TrimSpace(body))
			continue
		}
		var got map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Errorf("%s: response is not a JSON object: %s", ex.ID, body)
			continue
		}
		produced[ex.ID] = got
		var missing []string
		for field := range ex.Response {
			if _, ok := got[field]; !ok {
				missing = append(missing, field)
			}
		}
		if len(missing) > 0 {
			sort.Strings(missing)
			have := make([]string, 0, len(got))
			for k := range got {
				have = append(have, k)
			}
			sort.Strings(have)
			t.Errorf("%s: the example response shows %v, which the service did not return (it returned %v)", ex.ID, missing, have)
			continue
		}
		shaped = append(shaped, ex.ID)
	}
	if checked < 15 {
		t.Fatalf("only %d keycore examples were found", checked)
	}
	t.Logf("%d keycore examples decode; response shape compared for %d: %s", checked, len(shaped), strings.Join(shaped, ", "))
}
