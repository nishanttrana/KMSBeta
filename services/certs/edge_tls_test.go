package main

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"vecta-kms/pkg/route/routetest"
	"vecta-kms/pkg/svctls"
)

// The edge profile is changed by a root administrator only, published for
// both external listeners (the policy file for KMIP, Envoy's group list),
// and every change and refusal is audited.
func TestEdgeTLSRoutesPublishAndAudit(t *testing.T) {
	f := newMTLSFixture(t)
	rec := &routetest.Recorder{}
	router := mtlsRouter(t, f.svc, rec)
	ctx := context.Background()
	if err := f.svc.PublishMTLSPolicy(ctx, f.trust); err != nil {
		t.Fatal(err)
	}
	curves := func() string {
		raw, err := os.ReadFile(filepath.Join(f.trust, svctls.EdgeCurvesFileName))
		if err != nil {
			t.Fatal(err)
		}
		return strings.TrimSpace(string(raw))
	}
	if got, want := curves(), strings.Join(svctls.EnvoyCurves(svctls.KXPQCPreferred), ","); got != want {
		t.Fatalf("before any choice Envoy gets the default: %q, want %q", got, want)
	}

	for _, tc := range []struct {
		tenant, profile string
		status          int
		reason          string
	}{
		{"acme", svctls.KXPQCRequired, http.StatusForbidden, "not_root_tenant"},
		{"root", "pqc-only", http.StatusBadRequest, "invalid_policy"},
		{"root", svctls.KXPQCPreferred, http.StatusConflict, "unchanged"},
	} {
		w := mtlsCall(router, http.MethodPut, "/certs/edge-tls", tc.tenant, map[string]string{"kx_profile": tc.profile})
		last := rec.Last(t)
		if w.Code != tc.status || last.Action != "edge_tls_policy_updated" || last.Event.Result != "refused" || last.Event.Details["reason"] != tc.reason {
			t.Fatalf("%s/%s: %d, audited %s %s %+v", tc.tenant, tc.profile, w.Code, last.Action, last.Event.Result, last.Event.Details)
		}
	}
	if curves() != strings.Join(svctls.EnvoyCurves(svctls.KXPQCPreferred), ",") {
		t.Fatal("a refused change must not be published")
	}

	w := mtlsCall(router, http.MethodPut, "/certs/edge-tls", "root", map[string]string{"kx_profile": svctls.KXPQCRequired, "reason": "quantum"})
	last := rec.Last(t)
	if w.Code != http.StatusOK || last.Event.Result != "success" || last.Event.TargetID != svctls.EdgeIdentity ||
		last.Event.Details["kx_profile"] != svctls.KXPQCRequired || last.Event.Details["previous_kx_profile"] != svctls.KXPQCPreferred ||
		last.Event.Details["generation"] != int64(1) {
		t.Fatalf("the change must be audited with old and new values: %d %s %+v", w.Code, w.Body, last.Event)
	}
	if curves() != "X25519MLKEM768" {
		t.Fatalf("Envoy must get only the hybrid group: %q", curves())
	}
	p, err := svctls.ReadEdgePolicy(filepath.Join(f.trust, svctls.PolicyFileName))
	if err != nil || p.KXProfile != svctls.KXPQCRequired || p.Generation != 1 {
		t.Fatalf("KMIP reads the policy file: %+v %v", p, err)
	}
	if _, err := svctls.ReadPolicy(filepath.Join(f.trust, svctls.PolicyFileName), svctls.EdgeIdentity); err != nil {
		t.Fatalf("service readers still parse the file: %v", err)
	}

	w = mtlsCall(router, http.MethodGet, "/certs/edge-tls", "root", nil)
	if last := rec.Last(t); w.Code != http.StatusOK || last.Action != "edge_tls_read" || last.Event.Details["applied"] != false {
		t.Fatalf("reading is audited and nothing is measured yet: %d %+v", w.Code, last.Event)
	}
}

// edgeServer serves TLS 1.3 with the runtime edge certificate and the
// groups config returns for each handshake.
func edgeServer(t *testing.T, dir string, config func(base *tls.Config) *tls.Config) string {
	t.Helper()
	cert, err := tls.LoadX509KeyPair(filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key"))
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", config(&tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { _ = c.(*tls.Conn).Handshake(); _ = c.Close() }(c)
		}
	}()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	return "localhost:" + port
}

// "Applied" and audit.certs.edge_tls_applied come only from handshakes:
// a listener still accepting classical groups keeps the change pending; once
// both accept exactly the hybrid group it is applied and audited once.
func TestEdgeTLSAppliedOnlyWhenMeasured(t *testing.T) {
	f := newMTLSFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	cfg := f.cfg
	cfg.Enabled, cfg.TenantID, cfg.RootCAName = true, "root", "vecta-runtime-root"
	if err := f.svc.MaterializeRuntimeCerts(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.SetEdgeKX(ctx, svctls.KXPQCRequired, "test", "admin"); err != nil {
		t.Fatal(err)
	}
	// KMIP's path: the published policy, applied per handshake.
	watch := svctls.WatchEdge(ctx, filepath.Join(f.trust, svctls.PolicyFileName), t.Logf)
	kmip := edgeServer(t, filepath.Join(cfg.MaterializeDir, "kmip"), watch.ServerConfig)
	// An Envoy still on the classical groups.
	envoyGroups := []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384}
	lagging := func(base *tls.Config) *tls.Config {
		c := base.Clone()
		c.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) {
			cc := base.Clone()
			cc.CurvePreferences = envoyGroups
			return cc, nil
		}
		return c
	}
	envoy := edgeServer(t, filepath.Join(cfg.MaterializeDir, "envoy"), lagging)
	t.Setenv("CERTS_EDGE_PROBE_TARGETS", "envoy="+envoy+",kmip="+kmip)

	rec := &routetest.Recorder{}
	if err := f.svc.ProbeEdge(ctx); err != nil {
		t.Fatal(err)
	}
	v, err := f.svc.EdgeInventory(ctx)
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]edgeListenerView{}
	for _, l := range v.Listeners {
		byName[l.Name] = l
	}
	if !byName["kmip"].Applied || byName["envoy"].Applied || v.Applied {
		t.Fatalf("kmip applied, envoy not: %+v", v.Listeners)
	}
	if got := byName["kmip"].Observed.ServerGroups; !reflect.DeepEqual(got, groupList(svctls.ServerGroups(svctls.KXPQCRequired))) {
		t.Fatalf("kmip measured %v", got)
	}
	if byName["envoy"].Observed.KXProfile != svctls.KXClassical || byName["kmip"].Observed.Serial == "" ||
		byName["kmip"].Observed.LastHandshakeAt.IsZero() || !strings.Contains(byName["kmip"].Observed.LastHandshakeGroup, "MLKEM") {
		t.Fatalf("the lagging listener is measured as classical: %+v", byName["envoy"].Observed)
	}
	if err := f.svc.AuditAppliedEdge(ctx, rec); err != nil || len(rec.Events()) != 0 {
		t.Fatalf("no applied event while a listener lags: %+v %v", rec.Events(), err)
	}

	envoyGroups = svctls.EnvoyGroups(svctls.KXPQCRequired)
	if err := f.svc.ProbeEdge(ctx); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := f.svc.AuditAppliedEdge(ctx, rec); err != nil {
			t.Fatal(err)
		}
	}
	ev := rec.Events()
	if len(ev) != 1 || ev[0].Action != "edge_tls_applied" || ev[0].Event.Details["kx_profile"] != svctls.KXPQCRequired ||
		!reflect.DeepEqual(ev[0].Event.Details["envoy_groups"], []string{"X25519MLKEM768"}) {
		t.Fatalf("exactly one applied event with the measured groups: %+v", ev)
	}
}

// An unreachable listener is an error, never "applied".
func TestEdgeProbeUnreachableIsNotApplied(t *testing.T) {
	f := newMTLSFixture(t)
	ctx := context.Background()
	cfg := f.cfg
	cfg.Enabled, cfg.TenantID, cfg.RootCAName = true, "root", "vecta-runtime-root"
	if err := f.svc.MaterializeRuntimeCerts(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	_ = ln.Close()
	t.Setenv("CERTS_EDGE_PROBE_TARGETS", "kmip="+addr)
	if err := f.svc.ProbeEdge(ctx); err == nil {
		t.Fatal("an unreachable listener must be reported")
	}
	if v, _ := f.svc.EdgeInventory(ctx); v.Applied || v.Listeners[0].Observed != nil {
		t.Fatalf("nothing measured, nothing applied: %+v", v)
	}
}
