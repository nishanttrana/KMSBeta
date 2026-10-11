package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	pkgkeyaccess "vecta-kms/pkg/keyaccess"
)

// The BYOK engine runs each operation as named steps, records every step
// with the call it made and its command-line equivalent, and keeps custody:
// which KMS key version is behind which material in the cloud. A step that
// fails stops the run; what was done before it stays recorded.

// byokRefusal is a refusal before or during a run, with its reason.
type byokRefusal struct {
	status      int
	reason, msg string
}

func (e *byokRefusal) Error() string { return e.msg }

func refuseBYOK(status int, reason, msg string) error {
	return &byokRefusal{status: status, reason: reason, msg: msg}
}

// SetBYOK wires the engine: its store, keycore and the cloud protocols.
func (s *Service) SetBYOK(store BYOKStore, kc BYOKKeycore, providers map[string]BYOKProvider) {
	s.byokStore, s.byokKeycore, s.byokProviders = store, kc, providers
}

func defaultBYOKProviders() map[string]BYOKProvider {
	return map[string]BYOKProvider{
		ProviderAWS: newAWSProvider(), ProviderGCP: newGCPProvider(), ProviderAzure: newAzureProvider(),
		ProviderOCI: newOCIProvider(), ProviderAlibaba: newAlibabaProvider(), ProviderSalesforce: newSalesforceProvider(),
	}
}

// BYOKProviderInfo is what the dashboard shows per cloud.
type BYOKProviderInfo struct {
	Provider     string       `json:"provider"`
	Capabilities Capabilities `json:"capabilities"`
}

func (s *Service) BYOKProviders() []BYOKProviderInfo {
	out := []BYOKProviderInfo{}
	for _, name := range []string{ProviderAWS, ProviderAzure, ProviderGCP, ProviderOCI, ProviderAlibaba, ProviderSalesforce} {
		if p, ok := s.byokProviders[name]; ok {
			out = append(out, BYOKProviderInfo{Provider: name, Capabilities: p.Capabilities()})
		}
	}
	return out
}

type byokRun struct {
	s   *Service
	ctx context.Context
	run BYOKRun
}

// step runs fn as a named step and records it.
func (r *byokRun) step(name, call string, fn func() (cli, detail string, err error)) error {
	st := BYOKStep{Name: name, Call: call, StartedAt: time.Now().UTC()}
	cli, detail, err := fn()
	st.CLI, st.Detail, st.FinishedAt = cli, detail, time.Now().UTC()
	switch {
	case err != nil:
		st.Status, st.Error = "failed", err.Error()
	case cli == "" && detail == "":
		st.Status = "skipped"
	default:
		st.Status = "succeeded"
	}
	r.run.Steps = append(r.run.Steps, st)
	if err != nil {
		r.run.Status, r.run.Error = "failed", name+": "+err.Error()
	}
	return err
}

func (r *byokRun) finish() BYOKRun {
	if r.run.Status == "" {
		r.run.Status = "succeeded"
	}
	r.run.FinishedAt = time.Now().UTC()
	if r.run.BYOKID != "" {
		_ = r.s.byokStore.PutBYOKRun(r.ctx, r.run)
	}
	return r.run
}

// target is a BYOK key with what every cloud call needs.
type byokTarget struct {
	key      BYOKKey
	provider BYOKProvider
	call     cloudKeyCall
}

func (s *Service) byokReady() error {
	if s.byokStore == nil || s.byokKeycore == nil {
		return refuseBYOK(http.StatusServiceUnavailable, "byok_unavailable", "the BYOK engine is not configured")
	}
	return nil
}

func (s *Service) byokCall(ctx context.Context, tenantID, accountID, region string) (CloudAccount, BYOKProvider, cloudKeyCall, error) {
	account, err := s.store.GetAccount(ctx, tenantID, accountID)
	if err != nil {
		if errors.Is(err, errNotFound) {
			return CloudAccount{}, nil, cloudKeyCall{}, refuseBYOK(http.StatusNotFound, "account_not_found", "cloud account "+accountID+" not found")
		}
		return CloudAccount{}, nil, cloudKeyCall{}, err
	}
	p, ok := s.byokProviders[account.Provider]
	if !ok {
		return account, nil, cloudKeyCall{}, refuseBYOK(http.StatusConflict, "byok_not_supported", account.Provider+" has no key import this KMS can drive")
	}
	creds, err := s.accountCredentials(ctx, account)
	if err != nil {
		return account, p, cloudKeyCall{}, err
	}
	return account, p, cloudKeyCall{Account: account, Credentials: creds, Region: defaultString(region, account.DefaultRegion)}, nil
}

func (s *Service) byokTarget(ctx context.Context, tenantID, id string) (byokTarget, error) {
	if err := s.byokReady(); err != nil {
		return byokTarget{}, err
	}
	k, err := s.byokStore.GetBYOKKey(ctx, tenantID, id)
	if errors.Is(err, errNotFound) {
		return byokTarget{}, refuseBYOK(http.StatusNotFound, "not_found", "BYOK key "+id+" not found")
	}
	if err != nil {
		return byokTarget{}, err
	}
	_, p, call, err := s.byokCall(ctx, tenantID, k.AccountID, k.Region)
	return byokTarget{key: k, provider: p, call: call}, err
}

// gateMaterial applies the tenant's key access justification policy before
// material leaves for a cloud.
func (s *Service) gateMaterial(ctx context.Context, tenantID, keyID, provider, accountID, op string) error {
	res, err := s.evaluateKeyAccess(ctx, pkgkeyaccess.EvaluateRequest{
		TenantID: tenantID, Service: "cloud", Connector: provider, Operation: "import", KeyID: keyID,
		ResourceID: accountID, TargetType: "cloud_byok_key", RequestID: newID("byokreq"),
		Metadata: map[string]interface{}{"provider": provider, "account_id": accountID, "byok_operation": op},
	})
	if err != nil {
		return err
	}
	if strings.EqualFold(res.Action, "deny") {
		return refuseBYOK(http.StatusForbidden, "key_access_denied", firstNonEmpty(res.Reason, "blocked by key access justification policy"))
	}
	if res.ApprovalRequired {
		return refuseBYOK(http.StatusConflict, "approval_required", "this import needs approval "+res.ApprovalRequestID+"; run it again once approved")
	}
	return nil
}

func usageFromKey(spec string, info map[string]interface{}) string {
	purpose := strings.ToLower(anyToString(info["purpose"]))
	switch {
	case spec == SpecHMAC256:
		return "mac"
	case spec == SpecAES256:
		return "encrypt"
	case strings.Contains(purpose, "encrypt") || strings.Contains(purpose, "wrap"):
		return "encrypt"
	}
	return "sign"
}

func expiryFrom(days int, caps Capabilities) (*time.Time, error) {
	if days <= 0 {
		return nil, nil
	}
	if !caps.Expiry {
		return nil, refuseBYOK(http.StatusBadRequest, "expiry_not_supported", "this cloud has no expiry for imported material")
	}
	if days > 365 {
		return nil, refuseBYOK(http.StatusBadRequest, "bad_request", "imported material can be valid for at most 365 days")
	}
	t := time.Now().UTC().Add(time.Duration(days) * 24 * time.Hour).Truncate(time.Second)
	return &t, nil
}

// importMaterial is the shared sequence: wrapping key, wrap in the KMS or
// HSM, import, remove the temporary wrapping key. It returns the material
// record (not yet stored) and the key as the cloud now describes it.
func (s *Service) importMaterial(r *byokRun, t *byokTarget, version int, in ImportRequest) (BYOKMaterial, error) {
	var params ImportParams
	if err := r.step("Get the cloud's wrapping key", "GetParametersForImport", func() (string, string, error) {
		p, cli, err := t.provider.ImportParameters(r.ctx, t.call, t.key)
		params = p
		return cli, "scheme " + p.Scheme, err
	}); err != nil {
		return BYOKMaterial{}, err
	}
	where := map[string]string{SourceKMS: "in the KMS", SourceHSM: "inside the HSM"}[t.key.Source]
	var wrapped CloudWrapResult
	if err := r.step("Wrap the key material "+where, "keycore cloud-wrap", func() (string, string, error) {
		res, blob, digest, err := s.byokKeycore.CloudWrap(r.ctx, t.key.TenantID, t.key.KeyID, params.WrappingKey, params.Scheme, version, params.WantDigest)
		if err != nil {
			return "", "", err
		}
		wrapped, in.Wrapped, in.Digest = res, blob, digest
		return "", fmt.Sprintf("version %d (KCV %s) wrapped %s with %s to the cloud key %s", res.Version, res.KCV, where, res.Scheme, shortFP(res.WrappingKeySHA256)), nil
	}); err != nil {
		return BYOKMaterial{}, err
	}
	in.Params = params
	in.Description = fmt.Sprintf("vecta:%s:v%d", t.key.KeyID, wrapped.Version)
	var materialID string
	importErr := r.step("Import the wrapped material", "ImportKeyMaterial", func() (string, string, error) {
		k, id, cli, err := t.provider.Import(r.ctx, t.call, t.key, in)
		if err == nil {
			t.key, materialID = k, id
		}
		return cli, "material " + id, err
	})
	// The temporary wrapping key goes whatever the import did.
	_ = r.step("Remove the temporary wrapping key", "Cleanup", func() (string, string, error) {
		cli, err := t.provider.Cleanup(r.ctx, t.call, t.key, params)
		return cli, "", err
	})
	if importErr != nil {
		return BYOKMaterial{}, importErr
	}
	if r.run.Status == "failed" { // cleanup failed: recorded, not fatal
		r.run.Status, r.run.Error = "", ""
	}
	return BYOKMaterial{
		ID: newID("bmat"), TenantID: t.key.TenantID, BYOKID: t.key.ID, KMSVersion: wrapped.Version, KCV: wrapped.KCV,
		CloudMaterialID: materialID, State: MaterialCurrent, Scheme: wrapped.Scheme, Source: wrapped.Source,
		WrappingKeySHA256: wrapped.WrappingKeySHA256, ImportedAt: time.Now().UTC(), ExpiresAt: in.ExpiresAt,
	}, nil
}

func shortFP(fp string) string {
	if len(fp) > 16 {
		return fp[:16] + "…"
	}
	return fp
}

func (s *Service) verifyStep(r *byokRun, t *byokTarget) {
	if !t.provider.Capabilities().Verify {
		return
	}
	_ = r.step("Verify the key in the cloud", "Verify", func() (string, string, error) {
		detail, cli, err := t.provider.Verify(r.ctx, t.call, t.key)
		return cli, detail, err
	})
}

// CreateBYOK creates the cloud key and imports the KMS key's current
// version into it.
func (s *Service) CreateBYOK(ctx context.Context, tenantID, actor string, req CreateBYOKRequest) (BYOKRun, BYOKKey, error) {
	if err := s.byokReady(); err != nil {
		return BYOKRun{}, BYOKKey{}, err
	}
	req.KeyID, req.AccountID = strings.TrimSpace(req.KeyID), strings.TrimSpace(req.AccountID)
	if req.KeyID == "" || req.AccountID == "" {
		return BYOKRun{}, BYOKKey{}, refuseBYOK(http.StatusBadRequest, "bad_request", "account_id and key_id are required")
	}
	account, p, call, err := s.byokCall(ctx, tenantID, req.AccountID, req.Region)
	if err != nil {
		return BYOKRun{}, BYOKKey{}, err
	}
	info, err := s.byokKeycore.KeyInfo(ctx, tenantID, req.KeyID)
	if err != nil {
		return BYOKRun{}, BYOKKey{}, err
	}
	if ok, _ := boolValue(info["export_allowed"]); !ok {
		return BYOKRun{}, BYOKKey{}, refuseBYOK(http.StatusConflict, "key_not_exportable",
			"this KMS key does not allow cloud import; create it with export (KMS) or cloud import (HSM) allowed")
	}
	spec := specFromKMS(anyToString(info["algorithm"]))
	caps := p.Capabilities()
	if spec == "" || !containsString(caps.Specs, spec) {
		return BYOKRun{}, BYOKKey{}, refuseBYOK(http.StatusBadRequest, "spec_not_supported",
			fmt.Sprintf("%s can import %s; this key is %s", account.Provider, strings.Join(caps.Specs, ", "), anyToString(info["algorithm"])))
	}
	expires, err := expiryFrom(req.ValidityDays, caps)
	if err != nil {
		return BYOKRun{}, BYOKKey{}, err
	}
	if err := s.gateMaterial(ctx, tenantID, req.KeyID, account.Provider, account.ID, OpCreate); err != nil {
		return BYOKRun{}, BYOKKey{}, err
	}
	source := SourceKMS
	if labels, _ := info["labels"].(map[string]interface{}); anyToString(labels["hsm"]) == "resident" {
		source = SourceHSM
	}
	key := BYOKKey{
		ID: newID("byok"), TenantID: tenantID, AccountID: account.ID, Provider: account.Provider, Region: call.Region,
		KeyID: req.KeyID, Source: source, Origin: OriginBYOK, KeySpec: spec, Usage: usageFromKey(spec, info),
		Alias: strings.TrimSpace(req.Alias), MaterialState: MaterialPending, CreatedBy: actor,
		Settings: map[string]string{},
	}
	for k, v := range map[string]string{"certificate_name": req.CertificateName, "certificate_pem": req.CertificatePEM, "secret_type": req.SecretType} {
		if strings.TrimSpace(v) != "" {
			key.Settings[k] = strings.TrimSpace(v)
		}
	}
	r := &byokRun{s: s, ctx: ctx, run: BYOKRun{ID: newID("brun"), TenantID: tenantID, Operation: OpCreate, Actor: actor, StartedAt: time.Now().UTC()}}
	t := &byokTarget{key: key, provider: p, call: call}
	if err := r.step("Create the cloud key, waiting for material", "CreateKey", func() (string, string, error) {
		k, cli, err := p.CreateKey(ctx, call, t.key, req.Description)
		t.key = k
		if cli == "" && err == nil {
			return "", "the cloud creates the key on import", nil
		}
		return cli, k.CloudKeyID, err
	}); err != nil {
		return r.finish(), BYOKKey{}, err
	}
	if err := s.byokStore.CreateBYOKKey(ctx, t.key); err != nil {
		return r.finish(), BYOKKey{}, err
	}
	r.run.BYOKID = t.key.ID
	mat, err := s.importMaterial(r, t, 0, ImportRequest{ExpiresAt: expires})
	if err != nil {
		t.key.MaterialState = MaterialFailed
		_ = s.byokStore.UpdateBYOKKey(ctx, t.key)
		return r.finish(), t.key, err
	}
	t.key.MaterialState, t.key.CurrentMatID, t.key.ExpiresAt = MaterialCurrent, mat.CloudMaterialID, expires
	if t.key.CloudState == "" || strings.EqualFold(t.key.CloudState, "PendingImport") {
		if k, _, err := p.Describe(ctx, call, t.key); err == nil {
			t.key.CloudState = k.CloudState
		}
	}
	if err := s.byokStore.PutBYOKMaterial(ctx, mat); err != nil {
		return r.finish(), t.key, err
	}
	if err := s.byokStore.UpdateBYOKKey(ctx, t.key); err != nil {
		return r.finish(), t.key, err
	}
	s.verifyStep(r, t)
	return r.finish(), t.key, nil
}

func (s *Service) materials(ctx context.Context, k BYOKKey) ([]BYOKMaterial, BYOKMaterial) {
	all, _ := s.byokStore.ListBYOKMaterials(ctx, k.TenantID, k.ID)
	for _, m := range all {
		if m.State == MaterialCurrent {
			return all, m
		}
	}
	return all, BYOKMaterial{}
}

// RunBYOK performs op on an existing BYOK key.
func (s *Service) RunBYOK(ctx context.Context, tenantID, id, op, actor string, req BYOKOperationRequest) (BYOKRun, BYOKKey, error) {
	t, err := s.byokTarget(ctx, tenantID, id)
	if err != nil {
		return BYOKRun{}, BYOKKey{}, err
	}
	if t.key.Origin != OriginBYOK {
		return BYOKRun{}, t.key, refuseBYOK(http.StatusConflict, "cloud_generated", "this key's material was generated by the cloud; it is listed read-only")
	}
	caps := t.provider.Capabilities()
	r := &byokRun{s: s, ctx: ctx, run: BYOKRun{ID: newID("brun"), TenantID: tenantID, BYOKID: id, Operation: op, Actor: actor, StartedAt: time.Now().UTC()}}
	all, current := s.materials(ctx, t.key)
	unsupported := func() (BYOKRun, BYOKKey, error) {
		return BYOKRun{}, t.key, refuseBYOK(http.StatusConflict, "operation_not_supported", t.key.Provider+" does not support "+op+" for imported material")
	}
	switch op {
	case OpRotate:
		if !caps.Rotate {
			return unsupported()
		}
		if t.key.MaterialState != MaterialCurrent {
			return BYOKRun{}, t.key, refuseBYOK(http.StatusConflict, "no_current_material", "import or restore material before rotating")
		}
		expires, err := expiryFrom(req.ValidityDays, caps)
		if err != nil {
			return BYOKRun{}, t.key, err
		}
		if err := s.gateMaterial(ctx, tenantID, t.key.KeyID, t.key.Provider, t.key.AccountID, op); err != nil {
			return BYOKRun{}, t.key, err
		}
		var version int
		if err := r.step("Rotate the KMS key", "keycore rotate", func() (string, string, error) {
			v, err := s.byokKeycore.RotateForBYOK(ctx, tenantID, t.key.KeyID, req.Reason)
			version = v
			return "", fmt.Sprintf("new version %d", v), err
		}); err != nil {
			return r.finish(), t.key, err
		}
		mat, err := s.importMaterial(r, &t, version, ImportRequest{NewMaterial: true, ExpiresAt: expires})
		if err != nil {
			return r.finish(), t.key, err
		}
		if err := r.step("Make the new material current", "MakeCurrent", func() (string, string, error) {
			cli, err := t.provider.MakeCurrent(ctx, t.call, t.key, mat.CloudMaterialID)
			return cli, "", err
		}); err != nil {
			mat.State = MaterialPrevious // imported but not current
			_ = s.byokStore.PutBYOKMaterial(ctx, mat)
			return r.finish(), t.key, err
		}
		if current.ID != "" {
			current.State = MaterialPrevious
			_ = s.byokStore.PutBYOKMaterial(ctx, current)
		}
		_ = s.byokStore.PutBYOKMaterial(ctx, mat)
		t.key.CurrentMatID, t.key.ExpiresAt, t.key.MaterialState = mat.CloudMaterialID, expires, MaterialCurrent
	case OpReimport:
		pending := t.key.MaterialState == MaterialPending || t.key.MaterialState == MaterialFailed
		if !caps.Reimport && !pending {
			return unsupported()
		}
		expires, err := expiryFrom(req.ValidityDays, caps)
		if err != nil {
			return BYOKRun{}, t.key, err
		}
		if err := s.gateMaterial(ctx, tenantID, t.key.KeyID, t.key.Provider, t.key.AccountID, op); err != nil {
			return BYOKRun{}, t.key, err
		}
		mat, err := s.importMaterial(r, &t, current.KMSVersion, ImportRequest{ExpiresAt: expires})
		if err != nil {
			return r.finish(), t.key, err
		}
		if current.ID != "" && current.CloudMaterialID == mat.CloudMaterialID {
			mat.ID, mat.ImportedAt = current.ID, current.ImportedAt // same material, renewed
		} else if current.ID != "" {
			current.State = MaterialPrevious
			_ = s.byokStore.PutBYOKMaterial(ctx, current)
		}
		_ = s.byokStore.PutBYOKMaterial(ctx, mat)
		t.key.CurrentMatID, t.key.ExpiresAt, t.key.MaterialState = mat.CloudMaterialID, expires, MaterialCurrent
	case OpRevoke:
		if !caps.Revoke {
			return unsupported()
		}
		target := current
		if req.MaterialID != "" {
			target = findMaterial(all, req.MaterialID)
		}
		if target.ID == "" {
			return BYOKRun{}, t.key, refuseBYOK(http.StatusConflict, "no_material", "there is no imported material to revoke")
		}
		name := "Delete the key material in the cloud"
		if !caps.RevokeDeletes {
			name = "Disable the key in the cloud"
		}
		if err := r.step(name, "Revoke", func() (string, string, error) {
			cli, err := t.provider.Revoke(ctx, t.call, t.key, target.CloudMaterialID)
			return cli, fmt.Sprintf("KMS version %d stays in the KMS; restore brings it back", target.KMSVersion), err
		}); err != nil {
			return r.finish(), t.key, err
		}
		now := time.Now().UTC()
		target.State, target.RevokedAt = MaterialRevoked, &now
		_ = s.byokStore.PutBYOKMaterial(ctx, target)
		if target.ID == current.ID {
			t.key.MaterialState = MaterialRevoked
		}
	case OpRestore:
		target := BYOKMaterial{}
		for _, m := range all {
			if m.State == MaterialRevoked && (req.MaterialID == "" || m.CloudMaterialID == req.MaterialID || m.ID == req.MaterialID) {
				target = m
				break
			}
		}
		if target.ID == "" {
			return BYOKRun{}, t.key, refuseBYOK(http.StatusConflict, "no_revoked_material", "there is no revoked material to restore")
		}
		var undone bool
		if err := r.step("Re-enable the material in the cloud", "Unrevoke", func() (string, string, error) {
			ok, cli, err := t.provider.Unrevoke(ctx, t.call, t.key, target.CloudMaterialID)
			undone = ok
			if !ok && err == nil {
				return "", "", nil // needs a re-import
			}
			return cli, "", err
		}); err != nil {
			return r.finish(), t.key, err
		}
		if !undone {
			if err := s.gateMaterial(ctx, tenantID, t.key.KeyID, t.key.Provider, t.key.AccountID, op); err != nil {
				r.run.Status, r.run.Error = "failed", err.Error()
				return r.finish(), t.key, err
			}
			in := ImportRequest{ExpiresAt: target.ExpiresAt}
			if t.key.Provider == ProviderGCP {
				in.Replace = target.CloudMaterialID
			}
			if in.ExpiresAt != nil && in.ExpiresAt.Before(time.Now()) {
				in.ExpiresAt = nil
				if days := req.ValidityDays; days > 0 {
					if in.ExpiresAt, err = expiryFrom(days, caps); err != nil {
						return r.finish(), t.key, err
					}
				}
			}
			mat, err := s.importMaterial(r, &t, target.KMSVersion, in)
			if err != nil {
				return r.finish(), t.key, err
			}
			target.CloudMaterialID, target.ExpiresAt = defaultString(mat.CloudMaterialID, target.CloudMaterialID), in.ExpiresAt
		}
		if current.ID != "" && current.ID != target.ID {
			current.State = MaterialPrevious
			_ = s.byokStore.PutBYOKMaterial(ctx, current)
		}
		target.State, target.RevokedAt = MaterialCurrent, nil
		_ = s.byokStore.PutBYOKMaterial(ctx, target)
		t.key.MaterialState, t.key.CurrentMatID = MaterialCurrent, target.CloudMaterialID
	case OpVerify:
		if !caps.Verify {
			return unsupported()
		}
		s.verifyStep(r, &t)
		return r.finish(), t.key, runError(r.run)
	case OpSync:
	default:
		return BYOKRun{}, t.key, refuseBYOK(http.StatusBadRequest, "bad_request", "unknown operation "+op)
	}
	_ = r.step("Read the key's state in the cloud", "DescribeKey", func() (string, string, error) {
		k, cli, err := t.provider.Describe(ctx, t.call, t.key)
		if err == nil {
			t.key.CloudState = k.CloudState
			if op == OpSync {
				t.key.ExpiresAt = k.ExpiresAt
			}
		}
		return cli, t.key.CloudState, err
	})
	if err := s.byokStore.UpdateBYOKKey(ctx, t.key); err != nil {
		return r.finish(), t.key, err
	}
	if op == OpRotate || op == OpRestore || op == OpReimport {
		s.verifyStep(r, &t)
	}
	return r.finish(), t.key, runError(r.run)
}

func runError(run BYOKRun) error {
	if run.Status == "failed" {
		return errors.New(run.Error)
	}
	return nil
}

func findMaterial(all []BYOKMaterial, id string) BYOKMaterial {
	for _, m := range all {
		if m.ID == id || m.CloudMaterialID == id {
			return m
		}
	}
	return BYOKMaterial{}
}

func containsString(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// ListBYOK lists the tenant's BYOK keys, and the cloud keys an earlier
// release created natively, read-only, as origin cloud-generated.
func (s *Service) ListBYOK(ctx context.Context, tenantID string) ([]BYOKKey, error) {
	if err := s.byokReady(); err != nil {
		return nil, err
	}
	out, err := s.byokStore.ListBYOKKeys(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	legacy, err := s.store.ListBindings(ctx, tenantID, "", "", "", 500, 0)
	if err != nil {
		return nil, err
	}
	for _, b := range legacy {
		out = append(out, BYOKKey{
			ID: b.ID, TenantID: b.TenantID, AccountID: b.AccountID, Provider: b.Provider, Region: b.Region, KeyID: b.KeyID,
			Origin: OriginCloudGenerated, CloudKeyID: b.CloudKeyID, CloudKeyRef: b.CloudKeyRef, CloudState: b.SyncStatus,
			CreatedAt: b.CreatedAt, UpdatedAt: b.UpdatedAt,
		})
	}
	return out, nil
}

// BYOKDetail is a key with its custody and recent runs.
type BYOKDetail struct {
	Key       BYOKKey        `json:"key"`
	Materials []BYOKMaterial `json:"materials"`
	Runs      []BYOKRun      `json:"runs"`
}

func (s *Service) GetBYOK(ctx context.Context, tenantID, id string) (BYOKDetail, error) {
	if err := s.byokReady(); err != nil {
		return BYOKDetail{}, err
	}
	k, err := s.byokStore.GetBYOKKey(ctx, tenantID, id)
	if errors.Is(err, errNotFound) {
		return BYOKDetail{}, refuseBYOK(http.StatusNotFound, "not_found", "BYOK key "+id+" not found")
	}
	if err != nil {
		return BYOKDetail{}, err
	}
	mats, err := s.byokStore.ListBYOKMaterials(ctx, tenantID, id)
	if err != nil {
		return BYOKDetail{}, err
	}
	runs, err := s.byokStore.ListBYOKRuns(ctx, tenantID, id, 50)
	return BYOKDetail{Key: k, Materials: mats, Runs: runs}, err
}
