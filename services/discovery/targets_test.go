package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"testing"

	pkgaudit "vecta-kms/pkg/audit"
	pkgauth "vecta-kms/pkg/auth"
	"vecta-kms/pkg/route"
	"vecta-kms/pkg/route/routetest"
)

func TestNormalizeTarget(t *testing.T) {
	for in, want := range map[string]string{"Scan.Example.COM": "scan.example.com", "[2001:db8::1]": "2001:db8::1", "10.1.2.3": "10.1.2.3", "host.": "host"} {
		if got, err := normalizeTarget(in, 443); err != nil || got != want {
			t.Errorf("normalizeTarget(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"", "https://x.example", "x.example/path", "x.example:443", "localhost", "a.localhost", "127.0.0.1", "::1", "169.254.169.254", "fd00:ec2::254", "0.0.0.0", "224.0.0.1"} {
		if _, err := normalizeTarget(in, 443); !errors.Is(err, errInvalidTarget) {
			t.Errorf("normalizeTarget(%q) accepted: %v", in, err)
		}
	}
	for _, port := range []int{0, -1, 65536} {
		if _, err := normalizeTarget("x.example", port); !errors.Is(err, errInvalidTarget) {
			t.Errorf("port %d accepted", port)
		}
	}
}

// The dial guard checks the resolved address, so a name that resolves to
// loopback or metadata is refused at connect time.
func TestRefuseReservedAddr(t *testing.T) {
	for _, a := range []string{"127.0.0.1:443", "[::1]:443", "169.254.169.254:80", "[fe80::1]:443", "[::ffff:127.0.0.1]:443"} {
		if err := refuseReservedAddr("tcp", a, nil); !errors.Is(err, errReservedTarget) {
			t.Errorf("%s allowed: %v", a, err)
		}
	}
	for _, a := range []string{"10.0.0.5:443", "192.168.1.10:8443", "[2001:db8::1]:443"} {
		if err := refuseReservedAddr("tcp", a, nil); err != nil {
			t.Errorf("%s refused: %v", a, err)
		}
	}
}

// A tenant-added target is handshaken like an operator endpoint, and only
// for its own tenant.
func TestTenantTargetIsScanned(t *testing.T) {
	svc, _, _ := newDiscoveryService(t)
	ctx := context.Background()
	srv := httptest.NewTLSServer(http.NotFoundHandler())
	defer srv.Close()
	t.Setenv("DISCOVERY_TLS_ENDPOINTS", "")
	port, _ := strconv.Atoi(srv.URL[strings.LastIndex(srv.URL, ":")+1:])
	if err := svc.store.CreateTarget(ctx, ScanTarget{ID: "target_1", TenantID: "t1", Host: "127.0.0.1", Port: port}); err != nil {
		t.Fatal(err)
	}
	assets, err := svc.scanNetwork(ctx, "t1", "s")
	if err != nil || len(assets) != 2 {
		t.Fatalf("tenant target: %d assets, %v", len(assets), err)
	}
	if a, err := svc.scanNetwork(ctx, "t2", "s"); !errors.Is(err, errScanNotConfigured) || len(a) != 0 {
		t.Fatalf("another tenant's target scanned: %d assets, %v", len(a), err)
	}
}

// A stored target that resolves to a reserved address is refused when
// dialled, not handshaken, and so is an operator endpoint.
func TestTenantTargetDialGuard(t *testing.T) {
	svc, _, _ := newDiscoveryService(t)
	ctx := context.Background()
	srv := httptest.NewTLSServer(http.NotFoundHandler())
	defer srv.Close()
	t.Setenv("DISCOVERY_TLS_ENDPOINTS", "")
	svc.targetGuard = newTargetGuard
	port, _ := strconv.Atoi(srv.URL[strings.LastIndex(srv.URL, ":")+1:])
	if err := svc.store.CreateTarget(ctx, ScanTarget{ID: "target_1", TenantID: "t1", Host: "127.0.0.1", Port: port}); err != nil {
		t.Fatal(err)
	}
	a, err := svc.scanNetwork(ctx, "t1", "s")
	if err == nil || !strings.Contains(err.Error(), errReservedTarget.Error()) || len(a) != 0 {
		t.Fatalf("loopback target: %d assets, %v", len(a), err)
	}
	t.Setenv("DISCOVERY_TLS_ENDPOINTS", strings.TrimPrefix(srv.URL, "https://"))
	if a, err := svc.scanNetwork(ctx, "t2", "s"); err == nil || !strings.Contains(err.Error(), errReservedTarget.Error()) || len(a) != 0 {
		t.Fatalf("loopback operator endpoint: %d assets, %v", len(a), err)
	}
}

// A target naming a KMS platform host is refused when added; customer hosts
// that share a label with one (auth.example.com) are not.
func TestPlatformHostTargetRefused(t *testing.T) {
	for _, h := range []string{"keycore", "Postgres", "nats.", "envoy", "hsm-integration", "discovery"} {
		if _, err := normalizeTarget(h, 443); !errors.Is(err, errPlatformTarget) {
			t.Errorf("%s: %v, want errPlatformTarget", h, err)
		}
	}
	for _, h := range []string{"auth.example.com", "certs.corp.internal", "keycore-backup"} {
		if _, err := normalizeTarget(h, 443); err != nil {
			t.Errorf("%s refused: %v", h, err)
		}
	}
}

// At dial time the guard refuses every address a platform host resolves to
// and this container's own, whatever name the target used.
func TestPlatformAddrsRefusedAtDial(t *testing.T) {
	lookup := func(_ context.Context, h string) ([]netip.Addr, error) {
		switch h {
		case "keycore":
			return []netip.Addr{netip.MustParseAddr("172.20.0.11")}, nil
		case "postgres":
			return []netip.Addr{netip.MustParseAddr("::ffff:172.20.0.5")}, nil
		}
		return nil, errors.New("no such host")
	}
	own := func() ([]net.Addr, error) {
		return []net.Addr{&net.IPNet{IP: net.ParseIP("172.20.0.30"), Mask: net.CIDRMask(16, 32)}}, nil
	}
	guard := guardAddrs(platformAddrs(context.Background(), lookup, own))
	for _, a := range []string{"172.20.0.11:8010", "172.20.0.5:5432", "172.20.0.30:8100"} {
		if err := guard("tcp", a, nil); !errors.Is(err, errPlatformTarget) {
			t.Errorf("%s: %v, want errPlatformTarget", a, err)
		}
	}
	if err := guard("tcp", "169.254.169.254:80", nil); !errors.Is(err, errReservedTarget) {
		t.Errorf("metadata: %v", err)
	}
	for _, a := range []string{"172.20.0.99:443", "10.0.0.5:443"} {
		if err := guard("tcp", a, nil); err != nil {
			t.Errorf("%s refused: %v", a, err)
		}
	}
}

// The certs source skips the platform's internal service certificates.
func TestCertsScanSkipsInternalServiceCerts(t *testing.T) {
	svc, _, _ := newDiscoveryService(t)
	assets, err := svc.scanCertificates(context.Background(), "t1", "s")
	if err != nil || len(assets) != 2 {
		t.Fatalf("assets %d, %v", len(assets), err)
	}
	for _, a := range assets {
		if a.Metadata["cert_id"] == "c3" {
			t.Fatalf("internal mTLS certificate inventoried: %+v", a)
		}
	}
}

// Assets a pre-7.13.0-beta scan stored for platform services are hidden.
func TestStoredPlatformAssetsHidden(t *testing.T) {
	svc, store, _ := newDiscoveryService(t)
	ctx := context.Background()
	for _, a := range []CryptoAsset{
		{ID: "p1", Source: "certs", AssetType: "certificate", Name: "kms-keycore", Algorithm: "ECDSA-P256"},
		{ID: "p2", Source: "network", AssetType: "tls_endpoint", Name: "postgres:5432", Location: "postgres:5432", Algorithm: "X25519"},
		{ID: "c1", Source: "network", AssetType: "tls_endpoint", Name: "auth.example.com:443", Location: "auth.example.com:443", Algorithm: "X25519"},
	} {
		a.TenantID, a.Status = "t1", "active"
		if err := store.UpsertAsset(ctx, a); err != nil {
			t.Fatal(err)
		}
	}
	got, _ := svc.ListAssets(ctx, "t1", 10, 0, "", "", "")
	if len(got) != 1 || got[0].ID != "c1" {
		t.Fatalf("listed %+v", got)
	}
	if _, err := svc.GetAsset(ctx, "t1", "p1"); !errors.Is(err, errNotFound) {
		t.Fatalf("platform asset readable: %v", err)
	}
	if sum, _ := svc.Summary(ctx, "t1"); sum.TotalAssets != 1 {
		t.Fatalf("summary counts platform assets: %+v", sum)
	}
}

// Rows stored with the pre-7.11.0-beta "vulnerable" are read as what the
// catalogue says now; ECDSA-P256 is quantum-vulnerable, not weak.
func TestStoredVulnerableIsReclassifiedOnRead(t *testing.T) {
	svc, store, _ := newDiscoveryService(t)
	ctx := context.Background()
	for id, alg := range map[string]string{"a1": "ECDSA-P256", "a2": "RSA-1024"} {
		if err := store.UpsertAsset(ctx, CryptoAsset{ID: id, TenantID: "t1", AssetType: "tls_certificate", Name: id, Source: "network", Algorithm: alg, Status: "active", Classification: "vulnerable"}); err != nil {
			t.Fatal(err)
		}
	}
	if a, _ := svc.GetAsset(ctx, "t1", "a1"); a.Classification != "quantum_vulnerable" {
		t.Fatalf("ECDSA-P256 read as %q", a.Classification)
	}
	if got, _ := svc.ListAssets(ctx, "t1", 10, 0, "", "", "weak"); len(got) != 1 || got[0].ID != "a2" {
		t.Fatalf("weak filter: %+v", got)
	}
	if got, _ := svc.ListAssets(ctx, "t1", 10, 0, "", "", "vulnerable"); len(got) != 0 {
		t.Fatalf("stale class still matches: %+v", got)
	}
	sum, _ := svc.Summary(ctx, "t1")
	if sum.ClassificationCounts["quantum_vulnerable"] != 1 || sum.ClassificationCounts["weak"] != 1 || sum.ClassificationCounts["vulnerable"] != 0 {
		t.Fatalf("summary counts: %+v", sum.ClassificationCounts)
	}
}

// Adding and removing a target are audited as their own actions, and each
// refusal carries its reason.
func TestTargetRoutesAudited(t *testing.T) {
	svc, _, _ := newDiscoveryService(t)
	rec := &routetest.Recorder{}
	h := NewHandler(svc, rec, nil)
	writer := &pkgauth.Claims{UserID: "w", TenantID: "t1", Permissions: []string{"discovery.write", "discovery.read"}}
	readonly := &pkgauth.Claims{UserID: "ro", TenantID: "t1", Permissions: []string{"discovery.read"}}

	expect := func(action, result, reason string) pkgaudit.Event {
		t.Helper()
		ev := rec.Last(t)
		if ev.Action != action || ev.Event.Result != result || (reason != "" && ev.Event.Details["reason"] != reason) {
			t.Fatalf("audited %s %s %+v, want %s %s %s", ev.Action, ev.Event.Result, ev.Event.Details, action, result, reason)
		}
		return ev.Event
	}

	if rr := serveAs(h, readonly, http.MethodPost, "/discovery/targets", `{"host":"scan.example.com","port":443}`); rr.Code != http.StatusForbidden {
		t.Fatalf("add as discovery.read: %d", rr.Code)
	}
	expect("target_add", route.ResultRefused, route.ReasonPermissionDenied)

	for body, reason := range map[string]string{
		`{"host":"169.254.169.254","port":80}`:    "invalid_target",
		`{"host":"https://x.example","port":443}`: "invalid_target",
		`{"host":"x.example","port":0}`:           "invalid_target",
	} {
		if rr := serveAs(h, writer, http.MethodPost, "/discovery/targets", body); rr.Code != http.StatusBadRequest {
			t.Fatalf("add %s: %d %s", body, rr.Code, rr.Body)
		}
		expect("target_add", route.ResultRefused, reason)
	}

	rr := serveAs(h, writer, http.MethodPost, "/discovery/targets", `{"host":"Scan.Example.com","port":8443}`)
	if rr.Code != http.StatusCreated {
		t.Fatalf("add: %d %s", rr.Code, rr.Body)
	}
	var created struct{ Target ScanTarget }
	_ = json.Unmarshal(rr.Body.Bytes(), &created)
	if created.Target.Host != "scan.example.com" || created.Target.CreatedBy != "w" {
		t.Fatalf("created %+v", created.Target)
	}
	if ev := expect("target_add", route.ResultSuccess, ""); ev.Details["host"] != "Scan.Example.com" {
		t.Fatalf("add details %+v", ev.Details)
	}

	if rr := serveAs(h, writer, http.MethodPost, "/discovery/targets", `{"host":"scan.example.com","port":8443}`); rr.Code != http.StatusConflict {
		t.Fatalf("duplicate: %d", rr.Code)
	}
	expect("target_add", route.ResultRefused, "target_exists")

	if rr := serveAs(h, writer, http.MethodGet, "/discovery/targets", ""); rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), created.Target.ID) {
		t.Fatalf("list: %d %s", rr.Code, rr.Body)
	}

	if rr := serveAs(h, readonly, http.MethodDelete, "/discovery/targets/"+created.Target.ID, ""); rr.Code != http.StatusForbidden {
		t.Fatalf("remove as discovery.read: %d", rr.Code)
	}
	expect("target_remove", route.ResultRefused, route.ReasonPermissionDenied)

	other := &pkgauth.Claims{UserID: "o", TenantID: "t2", Permissions: []string{"discovery.write"}}
	if rr := serveAs(h, other, http.MethodDelete, "/discovery/targets/"+created.Target.ID, ""); rr.Code != http.StatusNotFound {
		t.Fatalf("remove another tenant's target: %d", rr.Code)
	}

	if rr := serveAs(h, writer, http.MethodDelete, "/discovery/targets/"+created.Target.ID, ""); rr.Code != http.StatusOK {
		t.Fatalf("remove: %d %s", rr.Code, rr.Body)
	}
	expect("target_remove", route.ResultSuccess, "")
	if items, _ := svc.ListTargets(context.Background(), "t1"); len(items) != 0 {
		t.Fatalf("target still listed: %+v", items)
	}
}
