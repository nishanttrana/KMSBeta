package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"vecta-kms/pkg/route"
)

// The structured cloud console (13.2.0-beta, docs/SECURITY/CLOUD_BYOK.md):
// a fixed catalogue of key operations in KMS terms, each one route with its
// own permission and audit action, run through the cloud SDK with the
// account's credential. No shell, no free-form commands: an operation and
// its typed parameters are all a caller sends, and a cloud runs only the
// operations its API has. The BYOK key pages use the same routes.

// ConsoleParam is one typed parameter of an operation.
type ConsoleParam struct {
	Name     string `json:"name"`
	Type     string `json:"type"` // string | int | json | base64
	Required bool   `json:"required,omitempty"`
	Help     string `json:"help,omitempty"`
}

// ConsoleOp is an operation of the catalogue.
type ConsoleOp struct {
	Name     string         `json:"name"`
	Label    string         `json:"label"`
	Group    string         `json:"group"`
	Mutating bool           `json:"mutating"`
	Danger   bool           `json:"danger,omitempty"`
	NeedsKey bool           `json:"needs_key"`
	Params   []ConsoleParam `json:"params,omitempty"`
	pattern  string
	action   string
	severity string
}

func param(name, typ string, required bool, help string) ConsoleParam {
	return ConsoleParam{Name: name, Type: typ, Required: required, Help: help}
}

// consoleOps is the catalogue. Patterns are literal so the route index
// names every one.
var consoleOps = []ConsoleOp{
	{Name: "list-keys", Label: "List keys", Group: "Keys", pattern: "POST /cloud/console/list-keys", action: "console_list_keys"},
	{Name: "describe-key", Label: "Describe key", Group: "Keys", NeedsKey: true, pattern: "POST /cloud/console/describe-key", action: "console_describe_key"},
	{Name: "list-versions", Label: "List versions / key material", Group: "Keys", NeedsKey: true, pattern: "POST /cloud/console/list-versions", action: "console_list_versions"},
	{Name: "get-public-key", Label: "Get public key", Group: "Keys", NeedsKey: true, pattern: "POST /cloud/console/get-public-key", action: "console_get_public_key"},
	{Name: "enable-key", Label: "Enable", Group: "State", Mutating: true, NeedsKey: true, pattern: "POST /cloud/console/enable-key", action: "console_enable_key", severity: "warning"},
	{Name: "disable-key", Label: "Disable", Group: "State", Mutating: true, Danger: true, NeedsKey: true, pattern: "POST /cloud/console/disable-key", action: "console_disable_key", severity: "warning"},
	{Name: "schedule-key-deletion", Label: "Schedule deletion", Group: "State", Mutating: true, Danger: true, NeedsKey: true, pattern: "POST /cloud/console/schedule-key-deletion", action: "console_schedule_key_deletion", severity: "critical",
		Params: []ConsoleParam{param("pending_days", "int", false, "waiting period in days (AWS 7-30, Alibaba 7-366, OCI 7-30)")}},
	{Name: "cancel-key-deletion", Label: "Cancel deletion", Group: "State", Mutating: true, NeedsKey: true, pattern: "POST /cloud/console/cancel-key-deletion", action: "console_cancel_key_deletion", severity: "warning"},
	{Name: "get-rotation-status", Label: "Automatic rotation status", Group: "Rotation", NeedsKey: true, pattern: "POST /cloud/console/get-rotation-status", action: "console_get_rotation_status"},
	{Name: "enable-rotation", Label: "Turn on automatic rotation", Group: "Rotation", Mutating: true, NeedsKey: true, pattern: "POST /cloud/console/enable-rotation", action: "console_enable_rotation", severity: "warning",
		Params: []ConsoleParam{param("period_days", "int", false, "rotation period in days (AWS 90-2560)")}},
	{Name: "disable-rotation", Label: "Turn off automatic rotation", Group: "Rotation", Mutating: true, NeedsKey: true, pattern: "POST /cloud/console/disable-rotation", action: "console_disable_rotation", severity: "warning"},
	{Name: "get-key-policy", Label: "Get key policy", Group: "Policy", NeedsKey: true, pattern: "POST /cloud/console/get-key-policy", action: "console_get_key_policy"},
	{Name: "put-key-policy", Label: "Set key policy", Group: "Policy", Mutating: true, Danger: true, NeedsKey: true, pattern: "POST /cloud/console/put-key-policy", action: "console_put_key_policy", severity: "critical",
		Params: []ConsoleParam{param("policy", "json", true, "the whole policy document (AWS key policy, Google IAM policy)")}},
	{Name: "list-grants", Label: "List grants", Group: "Grants", NeedsKey: true, pattern: "POST /cloud/console/list-grants", action: "console_list_grants"},
	{Name: "create-grant", Label: "Create grant", Group: "Grants", Mutating: true, NeedsKey: true, pattern: "POST /cloud/console/create-grant", action: "console_create_grant", severity: "warning",
		Params: []ConsoleParam{param("grantee", "string", true, "grantee principal ARN"), param("operations", "string", true, "comma-separated, e.g. Encrypt,Decrypt"), param("name", "string", false, "")}},
	{Name: "revoke-grant", Label: "Revoke grant", Group: "Grants", Mutating: true, Danger: true, NeedsKey: true, pattern: "POST /cloud/console/revoke-grant", action: "console_revoke_grant", severity: "warning",
		Params: []ConsoleParam{param("grant_id", "string", true, "")}},
	{Name: "list-aliases", Label: "List aliases", Group: "Aliases", pattern: "POST /cloud/console/list-aliases", action: "console_list_aliases"},
	{Name: "create-alias", Label: "Create alias", Group: "Aliases", Mutating: true, NeedsKey: true, pattern: "POST /cloud/console/create-alias", action: "console_create_alias",
		Params: []ConsoleParam{param("alias", "string", true, "alias/name")}},
	{Name: "delete-alias", Label: "Delete alias", Group: "Aliases", Mutating: true, Danger: true, pattern: "POST /cloud/console/delete-alias", action: "console_delete_alias", severity: "warning",
		Params: []ConsoleParam{param("alias", "string", true, "alias/name")}},
	{Name: "list-tags", Label: "List tags", Group: "Tags", NeedsKey: true, pattern: "POST /cloud/console/list-tags", action: "console_list_tags"},
	{Name: "tag-key", Label: "Set tag", Group: "Tags", Mutating: true, NeedsKey: true, pattern: "POST /cloud/console/tag-key", action: "console_tag_key",
		Params: []ConsoleParam{param("tag_key", "string", true, ""), param("tag_value", "string", false, "")}},
	{Name: "untag-key", Label: "Remove tag", Group: "Tags", Mutating: true, NeedsKey: true, pattern: "POST /cloud/console/untag-key", action: "console_untag_key",
		Params: []ConsoleParam{param("tag_key", "string", true, "")}},
	{Name: "encrypt", Label: "Encrypt", Group: "Try it", NeedsKey: true, pattern: "POST /cloud/console/encrypt", action: "console_encrypt",
		Params: []ConsoleParam{param("plaintext_b64", "base64", true, ""), param("algorithm", "string", false, "cloud algorithm name; default per key")}},
	{Name: "decrypt", Label: "Decrypt", Group: "Try it", NeedsKey: true, pattern: "POST /cloud/console/decrypt", action: "console_decrypt",
		Params: []ConsoleParam{param("ciphertext_b64", "base64", true, ""), param("algorithm", "string", false, ""), param("iv_b64", "base64", false, "Azure AES-GCM"), param("tag_b64", "base64", false, "Azure AES-GCM")}},
	{Name: "sign", Label: "Sign", Group: "Try it", NeedsKey: true, pattern: "POST /cloud/console/sign", action: "console_sign",
		Params: []ConsoleParam{param("message_b64", "base64", true, ""), param("algorithm", "string", false, "")}},
	{Name: "verify", Label: "Verify signature", Group: "Try it", NeedsKey: true, pattern: "POST /cloud/console/verify", action: "console_verify",
		Params: []ConsoleParam{param("message_b64", "base64", true, ""), param("signature_b64", "base64", true, ""), param("algorithm", "string", false, "")}},
	{Name: "generate-mac", Label: "Generate MAC", Group: "Try it", NeedsKey: true, pattern: "POST /cloud/console/generate-mac", action: "console_generate_mac",
		Params: []ConsoleParam{param("message_b64", "base64", true, "")}},
	{Name: "verify-mac", Label: "Verify MAC", Group: "Try it", NeedsKey: true, pattern: "POST /cloud/console/verify-mac", action: "console_verify_mac",
		Params: []ConsoleParam{param("message_b64", "base64", true, ""), param("mac_b64", "base64", true, "")}},
}

var consoleOpByName = func() map[string]ConsoleOp {
	m := map[string]ConsoleOp{}
	for _, op := range consoleOps {
		m[op.Name] = op
	}
	return m
}()

// ConsoleInput is what an operation receives: the cloud key, an optional
// version, and its validated parameters.
type ConsoleInput struct {
	Key     string
	Version string
	Params  map[string]string
}

func (in ConsoleInput) bytes(name string) []byte {
	b, _ := base64.StdEncoding.DecodeString(in.Params[name])
	return b
}

func (in ConsoleInput) int(name string, def int) int {
	if n, err := strconv.Atoi(strings.TrimSpace(in.Params[name])); err == nil {
		return n
	}
	return def
}

// ConsoleFunc runs one operation and returns its result and CLI equivalent.
type ConsoleFunc func(ctx context.Context, c cloudKeyCall, in ConsoleInput) (interface{}, string, error)

// consoleProvider is a cloud's implementation of the catalogue.
type consoleProvider interface {
	Console() map[string]ConsoleFunc
}

type consoleRequest struct {
	AccountID string            `json:"account_id"`
	Region    string            `json:"region"`
	Key       string            `json:"key"`
	Version   string            `json:"version"`
	Params    map[string]string `json:"params"`
}

// validate checks the parameters against the operation: unknown names and
// missing or malformed values are refused, so nothing free-form reaches a
// cloud.
func (op ConsoleOp) validate(req consoleRequest) error {
	if op.NeedsKey && strings.TrimSpace(req.Key) == "" {
		return errors.New("key is required")
	}
	known := map[string]ConsoleParam{}
	for _, prm := range op.Params {
		known[prm.Name] = prm
	}
	for name := range req.Params {
		if _, ok := known[name]; !ok {
			return fmt.Errorf("%s takes no parameter %q", op.Name, name)
		}
	}
	for _, prm := range op.Params {
		v := strings.TrimSpace(req.Params[prm.Name])
		if v == "" {
			if prm.Required {
				return fmt.Errorf("%s is required", prm.Name)
			}
			continue
		}
		switch prm.Type {
		case "int":
			if _, err := strconv.Atoi(v); err != nil {
				return fmt.Errorf("%s must be a whole number", prm.Name)
			}
		case "base64":
			if _, err := base64.StdEncoding.DecodeString(v); err != nil {
				return fmt.Errorf("%s must be base64", prm.Name)
			}
		case "json":
			if !json.Valid([]byte(v)) {
				return fmt.Errorf("%s must be JSON", prm.Name)
			}
		}
	}
	return nil
}

// ConsoleOperationsFor lists the catalogue with what the account's cloud
// supports.
type consoleOpView struct {
	ConsoleOp
	Supported bool `json:"supported"`
}

func (s *Service) consoleProviderFor(provider string) (consoleProvider, bool) {
	p, ok := s.byokProviders[provider].(consoleProvider)
	return p, ok
}

// RunConsole runs op for the account. Refusals are byokRefusal.
func (s *Service) RunConsole(ctx context.Context, tenantID string, op ConsoleOp, req consoleRequest) (interface{}, string, string, error) {
	if err := op.validate(req); err != nil {
		return nil, "", "", refuseBYOK(http.StatusBadRequest, "bad_request", err.Error())
	}
	account, _, call, err := s.byokCall(ctx, tenantID, strings.TrimSpace(req.AccountID), strings.TrimSpace(req.Region))
	if err != nil {
		var r *byokRefusal
		if errors.As(err, &r) && r.reason == "byok_not_supported" {
			return nil, "", account.Provider, refuseBYOK(http.StatusConflict, "operation_not_supported", account.Provider+" has no console operations")
		}
		return nil, "", account.Provider, err
	}
	cp, ok := s.consoleProviderFor(account.Provider)
	if !ok {
		return nil, "", account.Provider, refuseBYOK(http.StatusConflict, "operation_not_supported", account.Provider+" has no console operations")
	}
	fn, ok := cp.Console()[op.Name]
	if !ok {
		return nil, "", account.Provider, refuseBYOK(http.StatusConflict, "operation_not_supported", cloudName(account.Provider)+" has no "+op.Label+" operation")
	}
	params := map[string]string{}
	for k, v := range req.Params {
		if v = strings.TrimSpace(v); v != "" {
			params[k] = v
		}
	}
	out, cli, err := fn(ctx, call, ConsoleInput{Key: strings.TrimSpace(req.Key), Version: strings.TrimSpace(req.Version), Params: params})
	return out, cli, account.Provider, err
}

func cloudName(p string) string {
	return map[string]string{ProviderAWS: "AWS KMS", ProviderGCP: "Google Cloud KMS", ProviderAzure: "Azure Key Vault",
		ProviderOCI: "OCI Vault", ProviderAlibaba: "Alibaba Cloud KMS", ProviderSalesforce: "Salesforce"}[p]
}

// plaintextResult returns decrypted data as base64, and as text when it is.
func plaintextResult(b []byte) map[string]interface{} {
	out := map[string]interface{}{"plaintext_b64": base64.StdEncoding.EncodeToString(b)}
	if utf8.Valid(b) {
		out["plaintext_text"] = string(b)
	}
	return out
}

func (h *Handler) consoleRoutes(rt *route.Router) {
	rt.Handle("GET /cloud/console/operations", route.Spec{Action: "console_operations_read", Permission: "cloud.read", Resource: "cloud_account"}, h.consoleOperations)
	for _, op := range consoleOps {
		op := op
		perm := "cloud.read"
		if op.Mutating || op.Group == "Try it" {
			perm = "cloud.write"
		}
		rt.Handle(op.pattern, route.Spec{Action: op.action, Permission: perm, Resource: "cloud_key", Severity: op.severity}, func(c *route.Call) { h.runConsole(c, op) })
	}
}

func (h *Handler) consoleOperations(c *route.Call) {
	supported := map[string]bool{}
	provider := ""
	if id := strings.TrimSpace(c.R.URL.Query().Get("account_id")); id != "" {
		acct, err := h.svc.store.GetAccount(c.R.Context(), c.Tenant, id)
		if err != nil {
			c.Refuse(http.StatusNotFound, "account_not_found", "cloud account "+id+" not found")
			return
		}
		provider = acct.Provider
		if cp, ok := h.svc.consoleProviderFor(provider); ok {
			for name := range cp.Console() {
				supported[name] = true
			}
		}
	}
	items := make([]consoleOpView, 0, len(consoleOps))
	for _, op := range consoleOps {
		items = append(items, consoleOpView{ConsoleOp: op, Supported: supported[op.Name]})
	}
	sort.SliceStable(items, func(i, j int) bool { return items[i].Supported && !items[j].Supported })
	c.JSON(http.StatusOK, map[string]interface{}{"items": items, "provider": provider})
}

func (h *Handler) runConsole(c *route.Call, op ConsoleOp) {
	var req consoleRequest
	if !c.Decode(&req) {
		return
	}
	// Details name the operation and its target, never parameter values:
	// a plaintext, ciphertext or policy stays out of the audit record.
	c.Target(req.Key)
	c.Detail("account_id", req.AccountID)
	c.Detail("operation", op.Name)
	if req.Version != "" {
		c.Detail("version", req.Version)
	}
	out, cli, provider, err := h.svc.RunConsole(c.R.Context(), c.Tenant, op, req)
	if provider != "" {
		c.Detail("provider", provider)
	}
	if err != nil {
		var ref *byokRefusal
		var se serviceError
		switch {
		case errors.As(err, &ref):
			c.Refuse(ref.status, ref.reason, ref.msg)
		case errors.As(err, &se):
			c.Error(se.status, se.code, se.message)
		default:
			c.Detail("error", err.Error())
			c.JSON(http.StatusBadGateway, map[string]interface{}{
				"error": map[string]interface{}{"code": "cloud_error", "message": err.Error(), "request_id": c.RequestID},
				"cli":   cli, "operation": op.Name,
			})
		}
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"result": out, "cli": cli, "operation": op.Name, "provider": provider})
}
