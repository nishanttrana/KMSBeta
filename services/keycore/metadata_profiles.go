package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"vecta-kms/pkg/route"
)

// Key metadata profiles (13.50.0-beta; docs/KEYS.md "Metadata profiles").
// A profile says which metadata a tenant's keys must carry: an owner, a
// description, labels (required, from a list of values, matching a
// pattern, or filled from a default) and tags. Every active profile whose
// purposes include the key's (or that names none) applies. A key that
// doesn't meet them is refused when created, imported or updated, with
// every violation listed, and the refusal is audited. Existing keys aren't
// changed; GET /metadata-profiles/{id}/violations lists those that don't
// comply.

const (
	permMetadataRead  = "key.metadata.read"
	permMetadataWrite = "key.metadata.write"

	metadataProfileActive   = "active"
	metadataProfileDisabled = "disabled"

	maxMetadataLabelRules = 64
)

type MetadataLabelRule struct {
	Key      string   `json:"key"`
	Required bool     `json:"required"`
	Allowed  []string `json:"allowed,omitempty"`
	Pattern  string   `json:"pattern,omitempty"`
	Default  string   `json:"default,omitempty"`
}

type MetadataProfileRules struct {
	RequireOwner       bool                `json:"require_owner"`
	RequireDescription bool                `json:"require_description"`
	Labels             []MetadataLabelRule `json:"labels"`
	RequiredTags       []string            `json:"required_tags"`
}

type MetadataProfile struct {
	ID       string   `json:"id"`
	TenantID string   `json:"tenant_id"`
	Name     string   `json:"name"`
	Purposes []string `json:"purposes"`
	MetadataProfileRules
	Status    string    `json:"status"`
	CreatedBy string    `json:"created_by"`
	UpdatedBy string    `json:"updated_by"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// keyMetadata is what a profile checks; labels may be filled with defaults.
type keyMetadata struct {
	Purpose     string
	Owner       string
	Description string
	Labels      map[string]string
	Tags        []string
}

// MetadataViolation lists everything a key lacks. Refused, never partly
// applied.
type MetadataViolation struct {
	Profiles []string `json:"profiles"`
	Problems []string `json:"problems"`
}

func (v *MetadataViolation) Error() string {
	return "the key's metadata doesn't meet the tenant's metadata profiles: " + strings.Join(v.Problems, "; ")
}

var errMetadataProfileInvalid = errors.New("invalid metadata profile")

type metadataProfileError struct{ msg string }

func (e *metadataProfileError) Error() string { return e.msg }
func (e *metadataProfileError) Unwrap() error { return errMetadataProfileInvalid }

func invalidProfile(format string, args ...interface{}) error {
	return &metadataProfileError{msg: fmt.Sprintf(format, args...)}
}

// normalizeMetadataProfile validates a profile as an administrator wrote it.
func normalizeMetadataProfile(p *MetadataProfile) error {
	p.Name = strings.TrimSpace(p.Name)
	if p.Name == "" || len(p.Name) > 128 {
		return invalidProfile("name is 1 to 128 characters")
	}
	if p.Status == "" {
		p.Status = metadataProfileActive
	}
	if p.Status != metadataProfileActive && p.Status != metadataProfileDisabled {
		return invalidProfile("status is active or disabled")
	}
	purposes := []string{}
	for _, v := range p.Purposes {
		if v = strings.ToLower(strings.TrimSpace(v)); v != "" {
			purposes = append(purposes, v)
		}
	}
	p.Purposes = purposes
	if len(p.Labels) > maxMetadataLabelRules {
		return invalidProfile("at most %d label rules", maxMetadataLabelRules)
	}
	seen := map[string]bool{}
	for i := range p.Labels {
		r := &p.Labels[i]
		r.Key = strings.TrimSpace(r.Key)
		if r.Key == "" || len(r.Key) > 64 || strings.HasPrefix(r.Key, "hsm") || strings.ContainsAny(r.Key, " \t\r\n") {
			return invalidProfile("label key %q is 1 to 64 characters without spaces, and not hsm*", r.Key)
		}
		if seen[r.Key] {
			return invalidProfile("label %q has two rules", r.Key)
		}
		seen[r.Key] = true
		if len(r.Pattern) > 256 {
			return invalidProfile("label %q: the pattern is at most 256 characters", r.Key)
		}
		if r.Pattern != "" {
			if _, err := regexp.Compile("^(?:" + r.Pattern + ")$"); err != nil {
				return invalidProfile("label %q: the pattern doesn't compile: %v", r.Key, err)
			}
		}
		if r.Default != "" {
			if problem := labelProblem(*r, r.Default); problem != "" {
				return invalidProfile("label %q: the default %s", r.Key, problem)
			}
		}
	}
	tags := []string{}
	for _, t := range p.RequiredTags {
		if t = strings.TrimSpace(t); t != "" {
			tags = append(tags, t)
		}
	}
	p.RequiredTags = tags
	if p.Labels == nil {
		p.Labels = []MetadataLabelRule{}
	}
	return nil
}

// labelProblem says what is wrong with value under rule, or "".
func labelProblem(rule MetadataLabelRule, value string) string {
	if len(rule.Allowed) > 0 {
		ok := false
		for _, a := range rule.Allowed {
			ok = ok || a == value
		}
		if !ok {
			return fmt.Sprintf("%q is not one of %s", value, strings.Join(rule.Allowed, ", "))
		}
	}
	if rule.Pattern != "" {
		re, err := regexp.Compile("^(?:" + rule.Pattern + ")$")
		if err != nil || !re.MatchString(value) {
			return fmt.Sprintf("%q doesn't match %s", value, rule.Pattern)
		}
	}
	return ""
}

func (p MetadataProfile) appliesTo(purpose string) bool {
	if p.Status != metadataProfileActive {
		return false
	}
	if len(p.Purposes) == 0 {
		return true
	}
	purpose = strings.ToLower(strings.TrimSpace(purpose))
	for _, v := range p.Purposes {
		if v == purpose {
			return true
		}
	}
	return false
}

// checkMetadata applies the profiles to md: defaults fill missing labels,
// and every problem is collected. It changes md.Labels only when there is
// no violation.
func checkMetadata(profiles []MetadataProfile, md *keyMetadata) *MetadataViolation {
	labels := map[string]string{}
	for k, v := range md.Labels {
		labels[k] = v
	}
	v := &MetadataViolation{Profiles: []string{}, Problems: []string{}}
	tags := map[string]bool{}
	for _, t := range md.Tags {
		tags[strings.TrimSpace(t)] = true
	}
	for _, p := range profiles {
		if !p.appliesTo(md.Purpose) {
			continue
		}
		before := len(v.Problems)
		if p.RequireOwner && strings.TrimSpace(md.Owner) == "" {
			v.Problems = append(v.Problems, "an owner is required")
		}
		if p.RequireDescription && strings.TrimSpace(md.Description) == "" {
			v.Problems = append(v.Problems, "a description is required")
		}
		for _, r := range p.Labels {
			value, ok := labels[r.Key]
			value = strings.TrimSpace(value)
			if !ok || value == "" {
				switch {
				case r.Default != "":
					labels[r.Key] = r.Default
				case r.Required:
					v.Problems = append(v.Problems, fmt.Sprintf("label %q is required", r.Key))
				}
				continue
			}
			if problem := labelProblem(r, value); problem != "" {
				v.Problems = append(v.Problems, fmt.Sprintf("label %q: %s", r.Key, problem))
			}
		}
		for _, t := range p.RequiredTags {
			if !tags[t] {
				v.Problems = append(v.Problems, fmt.Sprintf("tag %q is required", t))
			}
		}
		if len(v.Problems) > before {
			v.Profiles = append(v.Profiles, p.Name)
		}
	}
	if len(v.Problems) > 0 {
		return v
	}
	md.Labels = labels
	return nil
}

// enforceMetadataProfiles checks a key being created, imported or updated
// against the tenant's profiles, filling defaults into md.Labels. A
// violation is audited under subject (create_refused, update_refused).
func (s *Service) enforceMetadataProfiles(ctx context.Context, tenantID, subject string, details map[string]any, md *keyMetadata) error {
	profiles, err := s.store.ListMetadataProfiles(ctx, tenantID)
	if err != nil {
		return fmt.Errorf("metadata profiles: %w", err)
	}
	if md.Labels == nil {
		md.Labels = map[string]string{}
	}
	violation := checkMetadata(profiles, md)
	if violation == nil {
		return nil
	}
	details["result"], details["reason"] = "refused", "metadata_profile_violation"
	details["profiles"], details["problems"] = violation.Profiles, violation.Problems
	_ = s.publishAudit(ctx, subject, tenantID, details)
	return violation
}

// applyMetadataProfiles checks a key about to be created or imported and
// fills profile defaults into its labels.
func (s *Service) applyMetadataProfiles(ctx context.Context, req *CreateKeyRequest, operation string) error {
	md := keyMetadata{Purpose: req.Purpose, Owner: req.Owner, Description: req.Description, Labels: req.Labels, Tags: req.Tags}
	if err := s.enforceMetadataProfiles(ctx, req.TenantID, "audit.key.create_refused", map[string]any{"name": req.Name, "operation": operation}, &md); err != nil {
		return err
	}
	req.Labels = md.Labels
	return nil
}

// writeMetadataViolation answers a metadata refusal on a legacy route.
func writeMetadataViolation(w http.ResponseWriter, err error, reqID, tenantID string) bool {
	var v *MetadataViolation
	if !errors.As(err, &v) {
		return false
	}
	writeJSON(w, http.StatusBadRequest, map[string]any{"error": map[string]any{
		"code": "metadata_profile_violation", "message": v.Error(), "profiles": v.Profiles, "problems": v.Problems,
		"request_id": reqID, "tenant_id": tenantID,
	}})
	return true
}

// MetadataProfileViolations lists the tenant's keys that don't meet one
// profile now (keys created before it, or while it was disabled).
func (s *Service) MetadataProfileViolations(ctx context.Context, tenantID string, p MetadataProfile) ([]map[string]any, int, error) {
	keys, err := s.allKeys(ctx, tenantID)
	if err != nil {
		return nil, 0, err
	}
	p.Status = metadataProfileActive
	out := []map[string]any{}
	checked := 0
	for _, k := range keys {
		if k.Status == "destroyed" || !p.appliesTo(k.Purpose) {
			continue
		}
		checked++
		md := keyMetadata{Purpose: k.Purpose, Owner: k.Owner, Description: k.Description, Labels: map[string]string(k.Labels), Tags: k.Tags}
		if v := checkMetadata([]MetadataProfile{p}, &md); v != nil {
			out = append(out, map[string]any{"key_id": k.ID, "name": k.Name, "purpose": k.Purpose, "problems": v.Problems})
		}
	}
	sort.Slice(out, func(i, j int) bool { return fmt.Sprint(out[i]["name"]) < fmt.Sprint(out[j]["name"]) })
	return out, checked, nil
}

// ---- store ----

const metadataProfileColumns = `id, tenant_id, name, purposes, rules, status, created_by, updated_by, created_at, updated_at`

func (s *SQLStore) ListMetadataProfiles(ctx context.Context, tenantID string) ([]MetadataProfile, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `SELECT `+metadataProfileColumns+` FROM key_metadata_profiles WHERE tenant_id = $1 ORDER BY name ASC`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := []MetadataProfile{}
	for rows.Next() {
		p, err := scanMetadataProfile(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *SQLStore) GetMetadataProfile(ctx context.Context, tenantID, id string) (MetadataProfile, error) {
	p, err := scanMetadataProfile(s.db.SQL().QueryRowContext(ctx, `SELECT `+metadataProfileColumns+` FROM key_metadata_profiles WHERE tenant_id = $1 AND id = $2`, tenantID, id))
	if errors.Is(err, sql.ErrNoRows) {
		return MetadataProfile{}, errStoreNotFound
	}
	return p, err
}

func (s *SQLStore) CreateMetadataProfile(ctx context.Context, p MetadataProfile) error {
	purposes, _ := json.Marshal(p.Purposes)
	rules, _ := json.Marshal(p.MetadataProfileRules)
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO key_metadata_profiles (id, tenant_id, name, purposes, rules, status, created_by, updated_by, created_at, updated_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$7,$8,$8)`, p.ID, p.TenantID, p.Name, string(purposes), string(rules), p.Status, p.CreatedBy, p.CreatedAt.UTC())
	return err
}

func (s *SQLStore) UpdateMetadataProfile(ctx context.Context, p MetadataProfile) error {
	purposes, _ := json.Marshal(p.Purposes)
	rules, _ := json.Marshal(p.MetadataProfileRules)
	res, err := s.db.SQL().ExecContext(ctx, `
UPDATE key_metadata_profiles SET name = $1, purposes = $2, rules = $3, status = $4, updated_by = $5, updated_at = $6
WHERE tenant_id = $7 AND id = $8`, p.Name, string(purposes), string(rules), p.Status, p.UpdatedBy, time.Now().UTC().Truncate(time.Microsecond), p.TenantID, p.ID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errStoreNotFound
	}
	return nil
}

func (s *SQLStore) DeleteMetadataProfile(ctx context.Context, tenantID, id string) error {
	res, err := s.db.SQL().ExecContext(ctx, `DELETE FROM key_metadata_profiles WHERE tenant_id = $1 AND id = $2`, tenantID, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errStoreNotFound
	}
	return nil
}

func scanMetadataProfile(sc interface{ Scan(...any) error }) (MetadataProfile, error) {
	var (
		p                MetadataProfile
		purposes, rules  string
		created, updated any
	)
	if err := sc.Scan(&p.ID, &p.TenantID, &p.Name, &purposes, &rules, &p.Status, &p.CreatedBy, &p.UpdatedBy, &created, &updated); err != nil {
		return MetadataProfile{}, err
	}
	_ = json.Unmarshal([]byte(purposes), &p.Purposes)
	_ = json.Unmarshal([]byte(rules), &p.MetadataProfileRules)
	if p.Purposes == nil {
		p.Purposes = []string{}
	}
	if p.Labels == nil {
		p.Labels = []MetadataLabelRule{}
	}
	if p.RequiredTags == nil {
		p.RequiredTags = []string{}
	}
	p.CreatedAt, _ = parseDBTime(created)
	p.UpdatedAt, _ = parseDBTime(updated)
	return p, nil
}

// ---- routes ----

func (h *Handler) metadataProfileRouter(audit route.Emitter) *route.Router {
	r := route.New("key", audit, nil)
	r.Handle("GET /metadata-profiles", route.Spec{Action: "metadata_profiles_listed", Permission: permMetadataRead, Resource: "metadata_profile"}, h.listMetadataProfiles)
	r.Handle("POST /metadata-profiles", route.Spec{Action: "metadata_profile_created", Permission: permMetadataWrite, Resource: "metadata_profile", Severity: "warning"}, h.createMetadataProfile)
	r.Handle("PUT /metadata-profiles/{id}", route.Spec{Action: "metadata_profile_updated", Permission: permMetadataWrite, Resource: "metadata_profile", TargetParam: "id", Severity: "warning"}, h.updateMetadataProfile)
	r.Handle("DELETE /metadata-profiles/{id}", route.Spec{Action: "metadata_profile_deleted", Permission: permMetadataWrite, Resource: "metadata_profile", TargetParam: "id", Severity: "warning"}, h.deleteMetadataProfile)
	r.Handle("GET /metadata-profiles/{id}/violations", route.Spec{Action: "metadata_profile_violations_listed", Permission: permMetadataRead, Resource: "metadata_profile", TargetParam: "id"}, h.metadataProfileViolations)
	return r
}

type metadataProfileInput struct {
	Name     string   `json:"name"`
	Purposes []string `json:"purposes"`
	Status   string   `json:"status"`
	MetadataProfileRules
}

func metadataFail(c *route.Call, err error) {
	switch {
	case errors.Is(err, errMetadataProfileInvalid):
		c.Refuse(http.StatusBadRequest, "invalid_metadata_profile", err.Error())
	case errors.Is(err, errStoreNotFound):
		c.Error(http.StatusNotFound, "not_found", "metadata profile not found")
	case strings.Contains(strings.ToLower(err.Error()), "unique"):
		c.Refuse(http.StatusConflict, "name_taken", "a metadata profile with that name exists")
	default:
		c.Error(http.StatusInternalServerError, "metadata_profile_failed", err.Error())
	}
}

func profileDetails(c *route.Call, p MetadataProfile) {
	c.Detail("name", p.Name)
	c.Detail("purposes", p.Purposes)
	c.Detail("status", p.Status)
	c.Detail("require_owner", p.RequireOwner)
	c.Detail("require_description", p.RequireDescription)
	keys := []string{}
	for _, l := range p.Labels {
		keys = append(keys, l.Key)
	}
	c.Detail("labels", keys)
	c.Detail("required_tags", p.RequiredTags)
}

func (h *Handler) listMetadataProfiles(c *route.Call) {
	items, err := h.svc.store.ListMetadataProfiles(c.R.Context(), c.Tenant)
	if err != nil {
		metadataFail(c, err)
		return
	}
	c.Detail("count", len(items))
	c.JSON(http.StatusOK, map[string]any{"items": items})
}

func (h *Handler) createMetadataProfile(c *route.Call) {
	var in metadataProfileInput
	if !c.Decode(&in) {
		return
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	p := MetadataProfile{ID: newID("mdp"), TenantID: c.Tenant, Name: in.Name, Purposes: in.Purposes, Status: in.Status,
		MetadataProfileRules: in.MetadataProfileRules, CreatedBy: c.Actor(), UpdatedBy: c.Actor(), CreatedAt: now, UpdatedAt: now}
	if err := normalizeMetadataProfile(&p); err != nil {
		metadataFail(c, err)
		return
	}
	if err := h.svc.store.CreateMetadataProfile(c.R.Context(), p); err != nil {
		metadataFail(c, err)
		return
	}
	c.Target(p.ID)
	profileDetails(c, p)
	c.JSON(http.StatusCreated, map[string]any{"profile": p})
}

func (h *Handler) updateMetadataProfile(c *route.Call) {
	var in metadataProfileInput
	if !c.Decode(&in) {
		return
	}
	cur, err := h.svc.store.GetMetadataProfile(c.R.Context(), c.Tenant, c.R.PathValue("id"))
	if err != nil {
		metadataFail(c, err)
		return
	}
	p := cur
	p.Name, p.Purposes, p.Status, p.MetadataProfileRules, p.UpdatedBy = in.Name, in.Purposes, in.Status, in.MetadataProfileRules, c.Actor()
	if err := normalizeMetadataProfile(&p); err != nil {
		metadataFail(c, err)
		return
	}
	if err := h.svc.store.UpdateMetadataProfile(c.R.Context(), p); err != nil {
		metadataFail(c, err)
		return
	}
	profileDetails(c, p)
	saved, _ := h.svc.store.GetMetadataProfile(c.R.Context(), c.Tenant, p.ID)
	c.JSON(http.StatusOK, map[string]any{"profile": saved})
}

func (h *Handler) deleteMetadataProfile(c *route.Call) {
	cur, err := h.svc.store.GetMetadataProfile(c.R.Context(), c.Tenant, c.R.PathValue("id"))
	if err == nil {
		err = h.svc.store.DeleteMetadataProfile(c.R.Context(), c.Tenant, cur.ID)
	}
	if err != nil {
		metadataFail(c, err)
		return
	}
	c.Detail("name", cur.Name)
	c.JSON(http.StatusOK, map[string]any{"deleted": cur.ID})
}

func (h *Handler) metadataProfileViolations(c *route.Call) {
	p, err := h.svc.store.GetMetadataProfile(c.R.Context(), c.Tenant, c.R.PathValue("id"))
	if err != nil {
		metadataFail(c, err)
		return
	}
	items, checked, err := h.svc.MetadataProfileViolations(c.R.Context(), c.Tenant, p)
	if err != nil {
		metadataFail(c, err)
		return
	}
	c.Detail("checked", checked)
	c.Detail("violations", len(items))
	c.JSON(http.StatusOK, map[string]any{"items": items, "checked": checked})
}
