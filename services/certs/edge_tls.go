package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	pkgaudit "vecta-kms/pkg/audit"
	"vecta-kms/pkg/route"
	"vecta-kms/pkg/svctls"
)

// External edge key exchange (docs/SECURITY/INTERNAL_TLS.md). One node-wide
// profile for the KMS's two external listeners: Envoy's HTTPS edge and the
// KMIP listener. It is stored as the svctls.EdgeIdentity row of the Service
// mTLS policy table (replicated: every node applies it), published in
// mtls-policy.json (KMIP reads it on every handshake) and as the Envoy group
// list in edge-ecdh-curves (infra/envoy/entry.sh hot-restarts Envoy with
// it). Whether it is in force is measured, never assumed: certs completes a
// TLS 1.3 handshake with each listener, one group at a time.

// edgeListener is one external listener certs measures.
type edgeListener struct {
	Name, Address, ServerName string
	envoy                     bool // Envoy can only name some groups (svctls.EnvoyGroups)
}

// edgeListeners are the listeners to measure, from CERTS_EDGE_PROBE_TARGETS
// ("name=host:port,..."; a name starting with "envoy" is an Envoy listener).
func edgeListeners() []edgeListener {
	var out []edgeListener
	for _, item := range splitCSV(envOr("CERTS_EDGE_PROBE_TARGETS", "envoy=envoy:443,kmip=kmip:5696")) {
		name, addr, ok := strings.Cut(item, "=")
		host, _, herr := strings.Cut(addr, ":")
		if !ok || !herr || name == "" || host == "" {
			continue
		}
		out = append(out, edgeListener{Name: name, Address: addr, ServerName: host, envoy: strings.HasPrefix(name, "envoy")})
	}
	return out
}

// expected is the groups the listener must accept under profile.
func (l edgeListener) expected(profile string) []tls.CurveID {
	if l.envoy {
		return svctls.EnvoyGroups(profile)
	}
	return svctls.ServerGroups(profile)
}

// edgePolicy is the stored edge profile, or the default.
func edgePolicy(rows map[string]mtlsPolicyRow) (svctls.EdgePolicy, *mtlsPolicyRow) {
	r, ok := rows[svctls.EdgeIdentity]
	if !ok || !containsString(svctls.KXProfiles, r.KXProfile) {
		return svctls.DefaultEdgePolicy(), nil
	}
	return svctls.EdgePolicy{KXProfile: r.KXProfile, Generation: r.Generation}, &r
}

// publishEdgeCurves writes Envoy's group list for p next to the policy file.
func publishEdgeCurves(dir string, p svctls.EdgePolicy) error {
	raw := []byte(strings.Join(svctls.EnvoyCurves(p.KXProfile), ",") + "\n")
	path := filepath.Join(dir, svctls.EdgeCurvesFileName)
	if cur, err := os.ReadFile(path); err == nil && string(cur) == string(raw) {
		return nil
	}
	return writeFileAtomically(path, raw, 0o644)
}

type edgeChangeResult struct {
	Policy   svctls.EdgePolicy `json:"policy"`
	Previous svctls.EdgePolicy `json:"previous_policy"`
}

// SetEdgeKX changes the edge profile and publishes it.
func (s *Service) SetEdgeKX(ctx context.Context, profile, reason, actor string) (edgeChangeResult, error) {
	st, err := s.mtls()
	if err != nil {
		return edgeChangeResult{}, err
	}
	rows, err := st.ListMTLSPolicies(ctx)
	if err != nil {
		return edgeChangeResult{}, err
	}
	prev, _ := edgePolicy(rows)
	if !containsString(svctls.KXProfiles, profile) {
		return edgeChangeResult{}, mtlsRefusal{"invalid_policy", fmt.Sprintf("key-exchange profile %q is not one of %s", profile, strings.Join(svctls.KXProfiles, ", "))}
	}
	if profile == prev.KXProfile {
		return edgeChangeResult{}, mtlsRefusal{"unchanged", "the edge already uses " + profile}
	}
	next := svctls.EdgePolicy{KXProfile: profile, Generation: prev.Generation + 1}
	if err := st.UpsertMTLSPolicy(ctx, mtlsPolicyRow{
		Identity: svctls.EdgeIdentity, KeyAlgorithm: "", KXProfile: next.KXProfile, Generation: next.Generation,
		RestartMode: svctls.RestartGraceful, Reason: reason, UpdatedBy: actor,
	}); err != nil {
		return edgeChangeResult{}, err
	}
	if dir := strings.TrimSpace(s.trustDir); dir != "" {
		if err := s.PublishMTLSPolicy(ctx, dir); err != nil {
			return edgeChangeResult{}, fmt.Errorf("publish the policy: %w", err)
		}
	}
	return edgeChangeResult{Policy: next, Previous: prev}, nil
}

// edgeObservedInstance names a listener's row in platform_mtls_observed.
func edgeObservedInstance(l edgeListener) string { return "edge:" + l.Name }

// ProbeEdge measures every external listener and records what it accepts.
// The recorded profile and generation are the policy's only when the
// accepted groups are exactly the ones it requires.
func (s *Service) ProbeEdge(ctx context.Context) error {
	st, err := s.mtls()
	if err != nil {
		return err
	}
	rows, err := st.ListMTLSPolicies(ctx)
	if err != nil {
		return err
	}
	policy, _ := edgePolicy(rows)
	all := svctls.ProbeGroupsAll()
	var errs []error
	for _, l := range edgeListeners() {
		// Pinned to the certificate certs installed for the listener.
		pin, _, err := installedLeaf(s.listenerCertDir(l))
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: installed certificate: %w", l.Name, err))
			continue
		}
		res, err := svctls.ProbeGroups(ctx, l.Address, l.ServerName, pin, all)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		row := mtlsObservedRow{
			Identity: svctls.EdgeIdentity, Instance: edgeObservedInstance(l),
			ServerGroups: groupList(res.Accepted), LastHandshakeGroup: svctls.GroupName(res.Negotiated),
			LastHandshakeAt: time.Now().UTC(), StartedAt: time.Now().UTC(),
		}
		if res.Leaf != nil {
			row.Serial, row.NotAfter, row.KeyAlgorithm = res.Leaf.SerialNumber.Text(16), res.Leaf.NotAfter, leafKeyAlgorithm(res.Leaf)
		}
		row.KXProfile = measuredProfile(l, res)
		if row.KXProfile == policy.KXProfile {
			row.Generation = policy.Generation
		}
		if err := st.UpsertMTLSObserved(ctx, row); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// measuredProfile is the profile whose groups the listener accepted, or
// "unrecognised".
func measuredProfile(l edgeListener, res svctls.ProbeResult) string {
	for _, p := range svctls.KXProfiles {
		if reflect.DeepEqual(onlyProbed(l.expected(p), res.Probed), res.Accepted) {
			return p
		}
	}
	return "unrecognised"
}

func onlyProbed(want, probed []tls.CurveID) []tls.CurveID {
	var out []tls.CurveID
	for _, g := range want {
		for _, p := range probed {
			if g == p {
				out = append(out, g)
				break
			}
		}
	}
	return out
}

func groupList(ids []tls.CurveID) []string {
	out := []string{}
	for _, g := range ids {
		out = append(out, svctls.GroupName(g))
	}
	return out
}

func leafKeyAlgorithm(c *x509.Certificate) string {
	return c.PublicKeyAlgorithm.String()
}

// listenerCertDir holds the certificate the listener serves.
func (s *Service) listenerCertDir(l edgeListener) string {
	if l.envoy {
		return s.edgeDir()
	}
	return filepath.Join(s.runtimeCfg.MaterializeDir, "kmip")
}

// edgeListenerView is one listener on the Service mTLS page.
type edgeListenerView struct {
	Name     string           `json:"name"`
	Address  string           `json:"address"`
	Expected []string         `json:"expected_groups"`
	Observed *mtlsObservedRow `json:"observed,omitempty"`
	Applied  bool             `json:"applied"`
}

type edgeView struct {
	Certificate  edgeCertView        `json:"certificate"`
	Policy       svctls.EdgePolicy   `json:"policy"`
	PolicyRecord *mtlsPolicyRow      `json:"policy_record,omitempty"`
	Listeners    []edgeListenerView  `json:"listeners"`
	Applied      bool                `json:"applied"`
	KXProfiles   []string            `json:"kx_profiles"`
	Groups       map[string][]string `json:"groups"`
}

// EdgeInventory is the edge policy with what each listener was measured to
// accept. Applied means every listener was measured under this generation.
func (s *Service) EdgeInventory(ctx context.Context) (edgeView, error) {
	st, err := s.mtls()
	if err != nil {
		return edgeView{}, err
	}
	rows, err := st.ListMTLSPolicies(ctx)
	if err != nil {
		return edgeView{}, err
	}
	observed, err := st.ListMTLSObserved(ctx)
	if err != nil {
		return edgeView{}, err
	}
	p, rec := edgePolicy(rows)
	listeners := edgeListeners()
	v := edgeView{Policy: p, PolicyRecord: rec, Applied: len(listeners) > 0, KXProfiles: svctls.KXProfiles, Groups: map[string][]string{}}
	for _, prof := range svctls.KXProfiles {
		v.Groups[prof] = groupNames(prof)
	}
	for _, l := range listeners {
		lv := edgeListenerView{Name: l.Name, Address: l.Address, Expected: groupList(l.expected(p.KXProfile))}
		for _, o := range observed {
			if o.Identity == svctls.EdgeIdentity && o.Instance == edgeObservedInstance(l) {
				oo := o
				lv.Observed = &oo
			}
		}
		lv.Applied = lv.Observed != nil && lv.Observed.KXProfile == p.KXProfile && lv.Observed.Generation == p.Generation
		v.Applied = v.Applied && lv.Applied
		v.Listeners = append(v.Listeners, lv)
	}
	served := ""
	for _, l := range v.Listeners {
		if strings.HasPrefix(l.Name, "envoy") && l.Observed != nil {
			served = l.Observed.Serial
		}
	}
	v.Certificate = s.edgeCertificateView(ctx, s.internalTenant(), served)
	return v, nil
}

// AuditAppliedEdge emits audit.certs.edge_tls_applied once per generation,
// when every listener was measured accepting exactly the new groups.
// Primary only: the audited marker is replicated.
func (s *Service) AuditAppliedEdge(ctx context.Context, emit route.Emitter) error {
	v, err := s.EdgeInventory(ctx)
	if err != nil {
		return err
	}
	rec := v.PolicyRecord
	if rec == nil || !v.Applied || rec.AuditedGeneration >= rec.Generation {
		return nil
	}
	details := map[string]interface{}{"kx_profile": v.Policy.KXProfile, "generation": v.Policy.Generation, "tenant_scope": "platform"}
	for _, l := range v.Listeners {
		details[l.Name+"_groups"] = l.Observed.ServerGroups
		details[l.Name+"_negotiated"] = l.Observed.LastHandshakeGroup
	}
	if emit != nil {
		_ = emit.Emit(ctx, "edge_tls_applied", pkgaudit.Event{
			TenantID: "root", ActorID: "kms-certs", ActorType: "service", TargetType: "edge_tls",
			TargetID: svctls.EdgeIdentity, Result: "success", Details: details,
		})
	}
	st, err := s.mtls()
	if err != nil {
		return err
	}
	return st.MarkMTLSPolicyAudited(ctx, svctls.EdgeIdentity, v.Policy.Generation)
}
