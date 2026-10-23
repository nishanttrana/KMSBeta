package provider

import (
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

// fakeKMS stands in for keycore behind the edge: the paths, bodies and
// answers the Go SDK uses, over TLS 1.3, for one tenant and one token. The
// SDK's own contract tests (services/keycore/sdk_contract_test.go) pin those
// against the real keycore; this pins what Terraform does with them.
type fakeKMS struct {
	mu      sync.Mutex
	n       int
	keys    map[string]map[string]any
	grants  map[string][]any
	patches []map[string]any
	// protected answers deactivations as keycore does for a system key.
	protected bool
}

func (f *fakeKMS) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer tf-token" || r.URL.Query().Get("tenant_id") != "acme" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	reply := func(code int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(v)
	}
	var body map[string]any
	_ = json.NewDecoder(r.Body).Decode(&body)
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/svc/keycore/keys"), "/")
	id := ""
	if len(parts) > 1 {
		id = parts[1]
	}
	k := f.keys[id]
	if id != "" && k == nil {
		reply(http.StatusNotFound, map[string]any{"error": map[string]any{"code": "not_found", "message": "key not found"}})
		return
	}
	switch {
	case r.Method == http.MethodPost && id == "":
		f.n++
		id = fmt.Sprintf("key_%d", f.n)
		labels, _ := body["labels"].(map[string]any)
		if labels == nil {
			labels = map[string]any{}
		}
		if labels["cost-center"] == nil {
			// The tenant's metadata profile fills a default label.
			labels["cost-center"] = "platform"
		}
		keyType := "symmetric"
		if !strings.HasPrefix(body["algorithm"].(string), "AES") {
			keyType = "asymmetric"
		}
		f.keys[id] = map[string]any{
			"id": id, "name": body["name"], "algorithm": body["algorithm"], "purpose": body["purpose"], "key_type": keyType,
			"description": body["description"], "owner": body["owner"], "tags": body["tags"], "labels": labels,
			"status": "active", "current_version": 1, "kcv": "A1B2C3",
		}
		reply(http.StatusCreated, map[string]any{"key_id": id})
	case r.Method == http.MethodGet && len(parts) == 2:
		reply(http.StatusOK, map[string]any{"key": k})
	case r.Method == http.MethodPatch && len(parts) == 2:
		f.patches = append(f.patches, body)
		for name, v := range body {
			k[name] = v
		}
		reply(http.StatusOK, map[string]any{"key": k})
	case r.Method == http.MethodPost && len(parts) == 3 && parts[2] == "deactivate":
		if f.protected {
			reply(http.StatusConflict, map[string]any{"error": map[string]any{"code": "system_key_protected", "message": "system keys can't change status"}})
			return
		}
		if k["status"] == "deactivated" {
			reply(http.StatusConflict, map[string]any{"error": map[string]any{"code": "status_transition_refused", "message": "already deactivated"}})
			return
		}
		k["status"] = "deactivated"
		reply(http.StatusOK, map[string]any{"status": "deactivated"})
	case len(parts) == 3 && parts[2] == "access-policy" && r.Method == http.MethodGet:
		g := f.grants[id]
		if g == nil {
			g = []any{}
		}
		reply(http.StatusOK, map[string]any{"policy": map[string]any{"grants": g}})
	case len(parts) == 3 && parts[2] == "access-policy" && r.Method == http.MethodPut:
		f.grants[id], _ = body["grants"].([]any)
		reply(http.StatusOK, map[string]any{"status": "applied"})
	default:
		reply(http.StatusNotFound, map[string]any{"error": map[string]any{"code": "not_found", "message": r.Method + " " + r.URL.Path}})
	}
}

func startFake(t *testing.T) *fakeKMS {
	t.Helper()
	f := &fakeKMS{keys: map[string]map[string]any{}, grants: map[string][]any{}}
	srv := httptest.NewTLSServer(f)
	t.Cleanup(srv.Close)
	t.Setenv("VECTA_URL", srv.URL)
	t.Setenv("VECTA_TENANT_ID", "acme")
	t.Setenv("VECTA_TOKEN", "tf-token")
	t.Setenv("VECTA_CA_PEM", string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})))
	return f
}

var factories = map[string]func() (tfprotov6.ProviderServer, error){
	"vecta": providerserver.NewProtocol6WithError(New("test")()),
}

func keyConfig(name, algorithm, description string) string {
	return fmt.Sprintf(`
provider "vecta" {}

resource "vecta_key" "payments" {
  name        = %q
  algorithm   = %q
  purpose     = "encrypt"
  description = %q
  tags        = ["pci"]
}

resource "vecta_key_access" "payments" {
  key_id = vecta_key.payments.id
  grant = [{
    subject_type = "client"
    subject_id   = "release-pipeline"
    operations   = ["encrypt", "decrypt"]
  }]
}

data "vecta_key" "payments" {
  id         = vecta_key.payments.id
  depends_on = [vecta_key.payments]
}
`, name, algorithm, description)
}

func TestKeyLifecycle(t *testing.T) {
	f := startFake(t)
	var firstID string
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories,
		Steps: []resource.TestStep{
			{
				Config: keyConfig("payments", "AES-256", "card data"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("vecta_key.payments", "id", "key_1"),
					resource.TestCheckResourceAttr("vecta_key.payments", "key_type", "symmetric"),
					resource.TestCheckResourceAttr("vecta_key.payments", "current_version", "1"),
					resource.TestCheckResourceAttr("vecta_key.payments", "kcv", "A1B2C3"),
					// Left unset, labels show what the tenant's profile filled.
					resource.TestCheckResourceAttr("vecta_key.payments", "labels.cost-center", "platform"),
					resource.TestCheckResourceAttr("vecta_key_access.payments", "grant.#", "1"),
					resource.TestCheckResourceAttr("data.vecta_key.payments", "name", "payments"),
					func(s *terraform.State) error {
						firstID = s.RootModule().Resources["vecta_key.payments"].Primary.ID
						return nil
					},
				),
			},
			{
				// A rename is an update in place, sending only what changed.
				Config: keyConfig("payments-v2", "AES-256", "card data, tokenised"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrPtr("vecta_key.payments", "id", &firstID),
					resource.TestCheckResourceAttr("vecta_key.payments", "name", "payments-v2"),
					func(*terraform.State) error {
						f.mu.Lock()
						defer f.mu.Unlock()
						if len(f.patches) != 1 {
							return fmt.Errorf("want one PATCH, got %v", f.patches)
						}
						p := f.patches[0]
						if len(p) != 2 || p["name"] != "payments-v2" || p["description"] != "card data, tokenised" {
							return fmt.Errorf("PATCH should carry only name and description: %v", p)
						}
						return nil
					},
				),
			},
			{
				// Drift made in the KMS shows in the next plan.
				PreConfig: func() {
					f.mu.Lock()
					f.keys["key_1"]["name"] = "renamed-in-dashboard"
					f.mu.Unlock()
				},
				Config:             keyConfig("payments-v2", "AES-256", "card data, tokenised"),
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
			},
			{
				// A new algorithm is a new key; the old one is deactivated.
				Config: keyConfig("payments-v2", "AES-128", "card data, tokenised"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("vecta_key.payments", "id", "key_2"),
					resource.TestCheckResourceAttr("vecta_key_access.payments", "key_id", "key_2"),
					func(*terraform.State) error {
						f.mu.Lock()
						defer f.mu.Unlock()
						if f.keys["key_1"]["status"] != "deactivated" {
							return fmt.Errorf("the replaced key is %v, want deactivated", f.keys["key_1"]["status"])
						}
						if len(f.grants["key_1"]) != 0 {
							return fmt.Errorf("the replaced key kept grants %v", f.grants["key_1"])
						}
						return nil
					},
				),
			},
			{ResourceName: "vecta_key.payments", ImportState: true, ImportStateVerify: true},
			{ResourceName: "vecta_key_access.payments", ImportState: true, ImportStateId: "key_2", ImportStateVerify: true, ImportStateVerifyIdentifierAttribute: "key_id"},
		},
		CheckDestroy: func(*terraform.State) error {
			f.mu.Lock()
			defer f.mu.Unlock()
			// Destroy deactivates; it never removes a key.
			if len(f.keys) != 2 {
				return fmt.Errorf("want both keys kept, have %d", len(f.keys))
			}
			for id, k := range f.keys {
				if k["status"] != "deactivated" {
					return fmt.Errorf("%s is %v after destroy", id, k["status"])
				}
				if len(f.grants[id]) != 0 {
					return fmt.Errorf("%s kept grants %v", id, f.grants[id])
				}
			}
			return nil
		},
	})
}

const onlyKey = `
provider "vecta" {}

resource "vecta_key" "payments" {
  name      = "payments"
  algorithm = "AES-256"
  purpose   = "encrypt"
}
`

func TestKeyGoneFromKMSIsPlannedAgain(t *testing.T) {
	f := startFake(t)
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories,
		Steps: []resource.TestStep{
			{Config: onlyKey},
			{
				PreConfig: func() {
					f.mu.Lock()
					delete(f.keys, "key_1")
					f.mu.Unlock()
				},
				Config:             onlyKey,
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

func TestProviderRefusesHTTP(t *testing.T) {
	startFake(t)
	t.Setenv("VECTA_URL", "http://kms.example")
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories,
		Steps:                    []resource.TestStep{{Config: keyConfig("payments", "AES-256", ""), ExpectError: regexp.MustCompile("BaseURL is https")}},
	})
}

func TestProfileDefaultLabelIsExplained(t *testing.T) {
	startFake(t)
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories,
		Steps: []resource.TestStep{
			{
				Config: strings.Replace(onlyKey, `purpose   = "encrypt"`, `purpose   = "encrypt"
  labels    = { team = "payments" }`, 1),
				ExpectError: regexp.MustCompile("metadata profile changed the key's labels"),
			},
			{
				// With the default written out, the apply settles. (The
				// first key was left tainted; without an untaint it is
				// replaced, and replacing deactivates it.)
				Config: strings.Replace(onlyKey, `purpose   = "encrypt"`, `purpose   = "encrypt"
  labels    = { team = "payments", cost-center = "platform" }`, 1),
				Check: resource.TestCheckResourceAttr("vecta_key.payments", "labels.%", "2"),
			},
		},
	})
}

func TestRefusedDeactivationFailsTheDestroy(t *testing.T) {
	f := startFake(t)
	protect := func(on bool) func() {
		return func() {
			f.mu.Lock()
			f.protected = on
			f.mu.Unlock()
		}
	}
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories,
		Steps: []resource.TestStep{
			{Config: onlyKey},
			// A refusal is reported; the key stays in state, still active.
			{PreConfig: protect(true), Config: onlyKey, Destroy: true, ExpectError: regexp.MustCompile("system_key_protected")},
			{PreConfig: protect(false), Config: onlyKey, Check: resource.TestCheckResourceAttr("vecta_key.payments", "status", "active")},
		},
	})
}
