package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"time"

	"vecta-kms/pkg/route"
	"vecta-kms/pkg/svctls"
)

// Key binding policies (13.51.0-beta; docs/KEYS.md "Binding policies"). A
// binding policy says how a key may be reached, whoever is asking:
//
//   - channels: "rest" (a caller using keycore's API directly) and the
//     platform services that may use the key for a caller (kms-kmip,
//     kms-ekm, kms-dataprotect, ...: the verified service identity, or the
//     service a user's request was delegated through);
//   - source_networks: the networks a direct caller must come from (its
//     verified address, pkg/clientip);
//   - workload_identities: patterns a direct caller's workload identity
//     must match.
//
// Every active policy that applies to a key (all keys, listed keys, or keys
// whose labels match) must pass for any operation on it. It is checked in
// keycore's key access decision before grants and before a service
// principal is trusted, and a refusal is audit.key.access_refused with
// reason binding_policy. A grant says who may use a key; a binding says
// how it may be reached.

const (
	permBindingRead  = "key.binding.read"
	permBindingWrite = "key.binding.write"

	bindingChannelREST = "rest"
	bindingActive      = "active"
	bindingDisabled    = "disabled"
	maxBindingEntries  = 64
)

type KeyBindingPolicy struct {
	ID                 string            `json:"id"`
	TenantID           string            `json:"tenant_id"`
	Name               string            `json:"name"`
	AllKeys            bool              `json:"all_keys"`
	KeyIDs             []string          `json:"key_ids"`
	LabelSelector      map[string]string `json:"label_selector"`
	Channels           []string          `json:"channels"`
	SourceNetworks     []string          `json:"source_networks"`
	WorkloadIdentities []string          `json:"workload_identities"`
	Status             string            `json:"status"`
	CreatedBy          string            `json:"created_by"`
	UpdatedBy          string            `json:"updated_by"`
	CreatedAt          time.Time         `json:"created_at"`
	UpdatedAt          time.Time         `json:"updated_at"`
}

var errBindingPolicyInvalid = errors.New("invalid binding policy")

type bindingPolicyError struct{ msg string }

func (e *bindingPolicyError) Error() string { return e.msg }
func (e *bindingPolicyError) Unwrap() error { return errBindingPolicyInvalid }

func invalidBinding(format string, args ...interface{}) error {
	return &bindingPolicyError{msg: fmt.Sprintf(format, args...)}
}

func trimList(in []string) []string {
	out := []string{}
	for _, v := range in {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// normalizeBindingPolicy validates a policy as an administrator wrote it.
func normalizeBindingPolicy(p *KeyBindingPolicy) error {
	p.Name = strings.TrimSpace(p.Name)
	if p.Name == "" || len(p.Name) > 128 {
		return invalidBinding("name is 1 to 128 characters")
	}
	if p.Status == "" {
		p.Status = bindingActive
	}
	if p.Status != bindingActive && p.Status != bindingDisabled {
		return invalidBinding("status is active or disabled")
	}
	p.KeyIDs, p.SourceNetworks, p.WorkloadIdentities = trimList(p.KeyIDs), trimList(p.SourceNetworks), trimList(p.WorkloadIdentities)
	if p.LabelSelector == nil {
		p.LabelSelector = map[string]string{}
	}
	if !p.AllKeys && len(p.KeyIDs) == 0 && len(p.LabelSelector) == 0 {
		return invalidBinding("say which keys it binds: all_keys, key_ids or label_selector")
	}
	if p.AllKeys && (len(p.KeyIDs) > 0 || len(p.LabelSelector) > 0) {
		return invalidBinding("all_keys binds every key; leave key_ids and label_selector empty")
	}
	channels := []string{}
	for _, c := range trimList(p.Channels) {
		c = strings.ToLower(c)
		if _, ok := svctls.Services[c]; c != bindingChannelREST && !ok {
			return invalidBinding("channel %q is \"rest\" or a platform service identity (kms-kmip, kms-ekm, ...)", c)
		}
		channels = append(channels, c)
	}
	p.Channels = channels
	for _, n := range p.SourceNetworks {
		if _, err := parseNetwork(n); err != nil {
			return invalidBinding("source network %q: %v", n, err)
		}
	}
	for _, w := range p.WorkloadIdentities {
		if len(w) > 512 || strings.ContainsAny(w, " \t\r\n") {
			return invalidBinding("workload identity pattern %q is one token of at most 512 characters", w)
		}
	}
	if len(p.Channels) == 0 && len(p.SourceNetworks) == 0 && len(p.WorkloadIdentities) == 0 {
		return invalidBinding("a binding needs at least one condition: channels, source_networks or workload_identities")
	}
	if len(p.KeyIDs) > 1000 || len(p.Channels)+len(p.SourceNetworks)+len(p.WorkloadIdentities) > 3*maxBindingEntries {
		return invalidBinding("too many entries")
	}
	return nil
}

// parseNetwork reads a CIDR or a single address.
func parseNetwork(s string) (netip.Prefix, error) {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, errors.New("not an address or CIDR")
	}
	return netip.PrefixFrom(a, a.BitLen()), nil
}

func (p KeyBindingPolicy) appliesTo(key Key) bool {
	if p.Status != bindingActive {
		return false
	}
	if p.AllKeys {
		return true
	}
	for _, id := range p.KeyIDs {
		if id == key.ID {
			return true
		}
	}
	if len(p.LabelSelector) == 0 {
		return false
	}
	for k, v := range p.LabelSelector {
		if key.Labels[k] != v {
			return false
		}
	}
	return true
}

// bindingChannel is how the request reached the key: the verified service
// identity, the service a user's request was delegated through, or "rest".
func bindingChannel(actor AccessActor) string {
	switch {
	case actorIsServicePrincipal(actor):
		return strings.ToLower(strings.TrimSpace(actor.ClientID))
	case strings.TrimSpace(actor.Via) != "":
		return strings.ToLower(strings.TrimSpace(actor.Via))
	default:
		return bindingChannelREST
	}
}

// bindingProblem says why actor may not reach a key under p, or "".
func bindingProblem(p KeyBindingPolicy, actor AccessActor) string {
	channel := bindingChannel(actor)
	if len(p.Channels) > 0 {
		ok := false
		for _, c := range p.Channels {
			ok = ok || c == channel
		}
		if !ok {
			return fmt.Sprintf("binding %q allows %s, not %s", p.Name, strings.Join(p.Channels, ", "), channel)
		}
	}
	if channel != bindingChannelREST {
		return ""
	}
	if len(p.SourceNetworks) > 0 {
		addr, err := netip.ParseAddr(strings.TrimSpace(actor.SourceIP))
		inside := false
		for _, n := range p.SourceNetworks {
			if pre, perr := parseNetwork(n); err == nil && perr == nil && pre.Contains(addr.Unmap()) {
				inside = true
			}
		}
		if !inside {
			return fmt.Sprintf("binding %q allows %s, not the address %q", p.Name, strings.Join(p.SourceNetworks, ", "), actor.SourceIP)
		}
	}
	if len(p.WorkloadIdentities) > 0 {
		id := strings.TrimSpace(actor.WorkloadIdentity)
		ok := false
		for _, w := range p.WorkloadIdentities {
			ok = ok || (id != "" && globMatch(w, id))
		}
		if !ok {
			return fmt.Sprintf("binding %q allows workloads %s, not %q", p.Name, strings.Join(p.WorkloadIdentities, ", "), id)
		}
	}
	return ""
}

// globMatch matches s against a pattern where * is any run of characters
// and ? any one character.
func globMatch(pattern, s string) bool {
	if pattern == "" {
		return s == ""
	}
	switch pattern[0] {
	case '*':
		for i := 0; i <= len(s); i++ {
			if globMatch(pattern[1:], s[i:]) {
				return true
			}
		}
		return false
	case '?':
		return s != "" && globMatch(pattern[1:], s[1:])
	default:
		return s != "" && s[0] == pattern[0] && globMatch(pattern[1:], s[1:])
	}
}

// checkKeyBindings refuses an operation on key that a binding policy
// doesn't allow for actor.
func (s *Service) checkKeyBindings(ctx context.Context, key Key, actor AccessActor) error {
	policies, err := s.store.ListKeyBindingPolicies(ctx, key.TenantID)
	if err != nil {
		return fmt.Errorf("binding policies: %w", err)
	}
	for _, p := range policies {
		if !p.appliesTo(key) {
			continue
		}
		if problem := bindingProblem(p, actor); problem != "" {
			return refuse("binding_policy", "access denied: "+problem)
		}
	}
	return nil
}

// ---- store ----

const bindingColumns = `id, tenant_id, name, all_keys, key_ids, label_selector, channels, source_networks, workload_identities, status, created_by, updated_by, created_at, updated_at`

func (s *SQLStore) ListKeyBindingPolicies(ctx context.Context, tenantID string) ([]KeyBindingPolicy, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `SELECT `+bindingColumns+` FROM key_binding_policies WHERE tenant_id = $1 ORDER BY name ASC`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := []KeyBindingPolicy{}
	for rows.Next() {
		p, err := scanBindingPolicy(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *SQLStore) GetKeyBindingPolicy(ctx context.Context, tenantID, id string) (KeyBindingPolicy, error) {
	p, err := scanBindingPolicy(s.db.SQL().QueryRowContext(ctx, `SELECT `+bindingColumns+` FROM key_binding_policies WHERE tenant_id = $1 AND id = $2`, tenantID, id))
	if errors.Is(err, sql.ErrNoRows) {
		return KeyBindingPolicy{}, errStoreNotFound
	}
	return p, err
}

func bindingJSON(p KeyBindingPolicy) (keys, sel, ch, nets, wl string) {
	j := func(v any) string { b, _ := json.Marshal(v); return string(b) }
	return j(p.KeyIDs), j(p.LabelSelector), j(p.Channels), j(p.SourceNetworks), j(p.WorkloadIdentities)
}

func (s *SQLStore) CreateKeyBindingPolicy(ctx context.Context, p KeyBindingPolicy) error {
	keys, sel, ch, nets, wl := bindingJSON(p)
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO key_binding_policies (id, tenant_id, name, all_keys, key_ids, label_selector, channels, source_networks, workload_identities, status, created_by, updated_by, created_at, updated_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$11,$12,$12)`, p.ID, p.TenantID, p.Name, p.AllKeys, keys, sel, ch, nets, wl, p.Status, p.CreatedBy, p.CreatedAt.UTC())
	return err
}

func (s *SQLStore) UpdateKeyBindingPolicy(ctx context.Context, p KeyBindingPolicy) error {
	keys, sel, ch, nets, wl := bindingJSON(p)
	res, err := s.db.SQL().ExecContext(ctx, `
UPDATE key_binding_policies SET name = $1, all_keys = $2, key_ids = $3, label_selector = $4, channels = $5, source_networks = $6,
	workload_identities = $7, status = $8, updated_by = $9, updated_at = $10
WHERE tenant_id = $11 AND id = $12`, p.Name, p.AllKeys, keys, sel, ch, nets, wl, p.Status, p.UpdatedBy, time.Now().UTC().Truncate(time.Microsecond), p.TenantID, p.ID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errStoreNotFound
	}
	return nil
}

func (s *SQLStore) DeleteKeyBindingPolicy(ctx context.Context, tenantID, id string) error {
	res, err := s.db.SQL().ExecContext(ctx, `DELETE FROM key_binding_policies WHERE tenant_id = $1 AND id = $2`, tenantID, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errStoreNotFound
	}
	return nil
}

func scanBindingPolicy(sc interface{ Scan(...any) error }) (KeyBindingPolicy, error) {
	var (
		p                       KeyBindingPolicy
		allKeys                 any
		keys, sel, ch, nets, wl string
		created, updated        any
	)
	if err := sc.Scan(&p.ID, &p.TenantID, &p.Name, &allKeys, &keys, &sel, &ch, &nets, &wl, &p.Status, &p.CreatedBy, &p.UpdatedBy, &created, &updated); err != nil {
		return KeyBindingPolicy{}, err
	}
	p.AllKeys = parseDBBool(allKeys)
	_ = json.Unmarshal([]byte(keys), &p.KeyIDs)
	_ = json.Unmarshal([]byte(sel), &p.LabelSelector)
	_ = json.Unmarshal([]byte(ch), &p.Channels)
	_ = json.Unmarshal([]byte(nets), &p.SourceNetworks)
	_ = json.Unmarshal([]byte(wl), &p.WorkloadIdentities)
	if p.LabelSelector == nil {
		p.LabelSelector = map[string]string{}
	}
	for _, l := range []*[]string{&p.KeyIDs, &p.Channels, &p.SourceNetworks, &p.WorkloadIdentities} {
		if *l == nil {
			*l = []string{}
		}
	}
	p.CreatedAt, _ = parseDBTime(created)
	p.UpdatedAt, _ = parseDBTime(updated)
	return p, nil
}

func parseDBBool(v any) bool {
	switch x := v.(type) {
	case bool:
		return x
	case int64:
		return x != 0
	case []byte:
		s := strings.ToLower(string(x))
		return s == "1" || s == "t" || s == "true"
	case string:
		s := strings.ToLower(x)
		return s == "1" || s == "t" || s == "true"
	}
	return false
}

// ---- routes ----

func (h *Handler) bindingPolicyRouter(audit route.Emitter) *route.Router {
	r := route.New("key", audit, nil)
	r.Handle("GET /binding-policies", route.Spec{Action: "binding_policies_listed", Permission: permBindingRead, Resource: "binding_policy"}, h.listBindingPolicies)
	r.Handle("POST /binding-policies", route.Spec{Action: "binding_policy_created", Permission: permBindingWrite, Resource: "binding_policy", Severity: "warning"}, h.createBindingPolicy)
	r.Handle("PUT /binding-policies/{id}", route.Spec{Action: "binding_policy_updated", Permission: permBindingWrite, Resource: "binding_policy", TargetParam: "id", Severity: "warning"}, h.updateBindingPolicy)
	r.Handle("DELETE /binding-policies/{id}", route.Spec{Action: "binding_policy_deleted", Permission: permBindingWrite, Resource: "binding_policy", TargetParam: "id", Severity: "warning"}, h.deleteBindingPolicy)
	r.Handle("POST /binding-policies/check", route.Spec{Action: "binding_policies_checked", Permission: permBindingRead, Resource: "binding_policy"}, h.checkBindingPolicies)
	return r
}

type bindingPolicyInput struct {
	Name               string            `json:"name"`
	AllKeys            bool              `json:"all_keys"`
	KeyIDs             []string          `json:"key_ids"`
	LabelSelector      map[string]string `json:"label_selector"`
	Channels           []string          `json:"channels"`
	SourceNetworks     []string          `json:"source_networks"`
	WorkloadIdentities []string          `json:"workload_identities"`
	Status             string            `json:"status"`
}

func (in bindingPolicyInput) apply(p *KeyBindingPolicy) {
	p.Name, p.AllKeys, p.KeyIDs, p.LabelSelector = in.Name, in.AllKeys, in.KeyIDs, in.LabelSelector
	p.Channels, p.SourceNetworks, p.WorkloadIdentities, p.Status = in.Channels, in.SourceNetworks, in.WorkloadIdentities, in.Status
}

func bindingFail(c *route.Call, err error) {
	switch {
	case errors.Is(err, errBindingPolicyInvalid):
		c.Refuse(http.StatusBadRequest, "invalid_binding_policy", err.Error())
	case errors.Is(err, errStoreNotFound):
		c.Error(http.StatusNotFound, "not_found", "binding policy not found")
	case strings.Contains(strings.ToLower(err.Error()), "unique"):
		c.Refuse(http.StatusConflict, "name_taken", "a binding policy with that name exists")
	default:
		c.Error(http.StatusInternalServerError, "binding_policy_failed", err.Error())
	}
}

func bindingDetails(c *route.Call, p KeyBindingPolicy) {
	c.Detail("name", p.Name)
	c.Detail("status", p.Status)
	c.Detail("all_keys", p.AllKeys)
	c.Detail("key_ids", p.KeyIDs)
	c.Detail("label_selector", p.LabelSelector)
	c.Detail("channels", p.Channels)
	c.Detail("source_networks", p.SourceNetworks)
	c.Detail("workload_identities", p.WorkloadIdentities)
}

func (h *Handler) listBindingPolicies(c *route.Call) {
	items, err := h.svc.store.ListKeyBindingPolicies(c.R.Context(), c.Tenant)
	if err != nil {
		bindingFail(c, err)
		return
	}
	c.Detail("count", len(items))
	c.JSON(http.StatusOK, map[string]any{"items": items})
}

func (h *Handler) createBindingPolicy(c *route.Call) {
	var in bindingPolicyInput
	if !c.Decode(&in) {
		return
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	p := KeyBindingPolicy{ID: newID("kbp"), TenantID: c.Tenant, CreatedBy: c.Actor(), UpdatedBy: c.Actor(), CreatedAt: now, UpdatedAt: now}
	in.apply(&p)
	if err := normalizeBindingPolicy(&p); err != nil {
		bindingFail(c, err)
		return
	}
	if err := h.svc.store.CreateKeyBindingPolicy(c.R.Context(), p); err != nil {
		bindingFail(c, err)
		return
	}
	c.Target(p.ID)
	bindingDetails(c, p)
	c.JSON(http.StatusCreated, map[string]any{"policy": p})
}

func (h *Handler) updateBindingPolicy(c *route.Call) {
	var in bindingPolicyInput
	if !c.Decode(&in) {
		return
	}
	p, err := h.svc.store.GetKeyBindingPolicy(c.R.Context(), c.Tenant, c.R.PathValue("id"))
	if err != nil {
		bindingFail(c, err)
		return
	}
	in.apply(&p)
	p.UpdatedBy = c.Actor()
	if err := normalizeBindingPolicy(&p); err != nil {
		bindingFail(c, err)
		return
	}
	if err := h.svc.store.UpdateKeyBindingPolicy(c.R.Context(), p); err != nil {
		bindingFail(c, err)
		return
	}
	bindingDetails(c, p)
	saved, _ := h.svc.store.GetKeyBindingPolicy(c.R.Context(), c.Tenant, p.ID)
	c.JSON(http.StatusOK, map[string]any{"policy": saved})
}

func (h *Handler) deleteBindingPolicy(c *route.Call) {
	p, err := h.svc.store.GetKeyBindingPolicy(c.R.Context(), c.Tenant, c.R.PathValue("id"))
	if err == nil {
		err = h.svc.store.DeleteKeyBindingPolicy(c.R.Context(), c.Tenant, p.ID)
	}
	if err != nil {
		bindingFail(c, err)
		return
	}
	c.Detail("name", p.Name)
	c.JSON(http.StatusOK, map[string]any{"deleted": p.ID})
}

// checkBindingPolicies answers "would this request reach this key?" before
// a policy is relied on: which policies apply and what each says.
func (h *Handler) checkBindingPolicies(c *route.Call) {
	var in struct {
		KeyID            string `json:"key_id"`
		Channel          string `json:"channel"`
		SourceIP         string `json:"source_ip"`
		WorkloadIdentity string `json:"workload_identity"`
	}
	if !c.Decode(&in) {
		return
	}
	key, err := h.svc.store.GetKey(c.R.Context(), c.Tenant, strings.TrimSpace(in.KeyID))
	if err != nil {
		bindingFail(c, err)
		return
	}
	actor := AccessActor{Authenticated: true, SourceIP: in.SourceIP, WorkloadIdentity: in.WorkloadIdentity}
	if ch := strings.ToLower(strings.TrimSpace(in.Channel)); ch != "" && ch != bindingChannelREST {
		actor.Via = ch
	}
	policies, err := h.svc.store.ListKeyBindingPolicies(c.R.Context(), c.Tenant)
	if err != nil {
		bindingFail(c, err)
		return
	}
	results := []map[string]any{}
	allowed := true
	for _, p := range policies {
		if !p.appliesTo(key) {
			continue
		}
		problem := bindingProblem(p, actor)
		allowed = allowed && problem == ""
		results = append(results, map[string]any{"policy_id": p.ID, "name": p.Name, "allowed": problem == "", "problem": problem})
	}
	sort.Slice(results, func(i, j int) bool { return fmt.Sprint(results[i]["name"]) < fmt.Sprint(results[j]["name"]) })
	c.Target(key.ID)
	c.Detail("allowed", allowed)
	c.Detail("channel", bindingChannel(actor))
	c.JSON(http.StatusOK, map[string]any{"allowed": allowed, "channel": bindingChannel(actor), "policies": results})
}
