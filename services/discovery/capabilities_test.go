package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	pkgaudit "vecta-kms/pkg/audit"
	pkgauth "vecta-kms/pkg/auth"
	"vecta-kms/pkg/route"
	"vecta-kms/pkg/route/routetest"
)

var (
	testWriter   = &pkgauth.Claims{UserID: "w", TenantID: "t1", Permissions: []string{"discovery.write", "discovery.read"}}
	testReadonly = &pkgauth.Claims{UserID: "ro", TenantID: "t1", Permissions: []string{"discovery.read"}}
)

func expectAudit(t *testing.T, rec *routetest.Recorder, action, result, reason string) pkgaudit.Event {
	t.Helper()
	ev := rec.Last(t)
	if ev.Action != action || ev.Event.Result != result || (reason != "" && ev.Event.Details["reason"] != reason) {
		t.Fatalf("audited %s %s %+v, want %s %s %s", ev.Action, ev.Event.Result, ev.Event.Details, action, result, reason)
	}
	return ev.Event
}

func testCertDER(t *testing.T, notAfter time.Time) []byte {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "api.example.com"}, DNSNames: []string{"api.example.com"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: notAfter}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// An upload is inventoried by the keys it holds; secrets are recorded by
// fingerprint only and nothing of the file reaches the response, the store
// or the audit event.
func TestUploadInventoriesWithoutStoringSecrets(t *testing.T) {
	svc, _, pub := newDiscoveryService(t)
	rec := &routetest.Recorder{}
	h := NewHandler(svc, rec, nil)
	svcAudit := &routetest.Recorder{}
	svc.audit = svcAudit

	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	p8, _ := x509.MarshalPKCS8PrivateKey(rsaKey)
	_, edPriv, _ := ed25519.GenerateKey(rand.Reader)
	sshBlock, err := ssh.MarshalPrivateKey(edPriv, "deploy")
	if err != nil {
		t.Fatal(err)
	}
	sshPub, _ := ssh.NewPublicKey(edPriv.Public())
	const akia = "AKIAABCDEFGHIJKLMNOP"
	var buf bytes.Buffer
	_ = pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: testCertDER(t, time.Now().Add(10*24*time.Hour))})
	_ = pem.Encode(&buf, &pem.Block{Type: "PRIVATE KEY", Bytes: p8})
	_ = pem.Encode(&buf, sshBlock)
	buf.WriteString(strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub))) + " alice@laptop\naws_access_key_id = " + akia + "\n")
	body, _ := json.Marshal(map[string]string{"name": "../bundle.pem", "content": base64.StdEncoding.EncodeToString(buf.Bytes())})

	if rr := serveAs(h, testReadonly, http.MethodPost, "/discovery/upload", string(body)); rr.Code != http.StatusForbidden {
		t.Fatalf("upload as discovery.read: %d", rr.Code)
	}
	expectAudit(t, rec, "upload_scan", route.ResultRefused, route.ReasonPermissionDenied)

	rr := serveAs(h, testWriter, http.MethodPost, "/discovery/upload", string(body))
	if rr.Code != http.StatusOK {
		t.Fatalf("upload: %d %s", rr.Code, rr.Body)
	}
	var resp struct {
		Scan   DiscoveryScan
		Assets []CryptoAsset
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	var got []string
	for _, a := range resp.Assets {
		got = append(got, a.AssetType+"|"+a.Algorithm+"|"+a.Classification+"|"+a.Name)
	}
	sort.Strings(got)
	want := []string{
		"certificate|ECDSA-P256|quantum_vulnerable|api.example.com",
		"cloud_access_key||exposed|bundle.pem",
		"private_key_material|ED25519|exposed|bundle.pem",
		"private_key_material|RSA-2048|exposed|bundle.pem",
		"ssh_public_key|ED25519|quantum_vulnerable|alice@laptop",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("assets\n got %v\nwant %v", got, want)
	}
	stored, _ := svc.ListAssets(context.Background(), "t1", 100, 0, "upload", "", "")
	ev := expectAudit(t, rec, "upload_scan", route.ResultSuccess, "")
	evRaw, _ := json.Marshal(ev)
	storedRaw, _ := json.Marshal(stored)
	secretPEM := base64.StdEncoding.EncodeToString(p8)[:40]
	for _, raw := range [][]byte{rr.Body.Bytes(), storedRaw, evRaw} {
		if s := string(raw); strings.Contains(s, akia) || strings.Contains(s, secretPEM) || strings.Contains(s, "BEGIN") {
			t.Fatalf("file content leaked: %s", s)
		}
	}
	if len(stored) != 5 || ev.Details["file"] != "bundle.pem" || ev.Details["assets"] != float64(5) && ev.Details["assets"] != 5 {
		t.Fatalf("stored %d, audit %+v", len(stored), ev.Details)
	}
	// Each newly found secret raises secret_exposed once, without the secret.
	var exposed []pkgaudit.Event
	for _, e := range svcAudit.Events() {
		if e.Action == "secret_exposed" {
			exposed = append(exposed, e.Event)
		}
	}
	exposedRaw, _ := json.Marshal(exposed)
	if len(exposed) != 3 || exposed[0].TenantID != "t1" || exposed[0].TargetType != "crypto_asset" || strings.Contains(string(exposedRaw), akia) {
		t.Fatalf("secret_exposed events: %s", exposedRaw)
	}
	if rr := serveAs(h, testWriter, http.MethodPost, "/discovery/upload", string(body)); rr.Code != http.StatusOK {
		t.Fatalf("second upload: %d", rr.Code)
	}
	for n, e := 0, svcAudit.Events(); ; {
		for _, x := range e {
			if x.Action == "secret_exposed" {
				n++
			}
		}
		if n != 3 {
			t.Fatalf("re-uploading the same file raised secret_exposed again: %d events", n)
		}
		break
	}
	if pub.Count("audit.discovery.asset_found") != 10 {
		t.Fatalf("asset_found events: %d", pub.Count("audit.discovery.asset_found"))
	}
	if resp.Scan.ScanType != "upload" || resp.Scan.Status != "completed" {
		t.Fatalf("upload scan: %+v", resp.Scan)
	}
	if sum, _ := svc.Summary(context.Background(), "t1"); sum.ClassificationCounts["exposed"] != 3 || sum.ClassificationCounts["quantum_vulnerable"] != 2 {
		t.Fatalf("summary: %+v", sum)
	}

	for body, reason := range map[string]string{
		`{"name":"x.pem","content":"%%%"}`:                                             "invalid_upload",
		`{"name":"x.pem","content":""}`:                                                "invalid_upload",
		`{"name":"x.pem","content":"` + strings.Repeat("A", int(maxUploadBody)) + `"}`: "upload_too_large",
	} {
		if rr := serveAs(h, testWriter, http.MethodPost, "/discovery/upload", body); rr.Code != map[string]int{"invalid_upload": 400, "upload_too_large": 413}[reason] {
			t.Fatalf("%s: %d %s", reason, rr.Code, rr.Body)
		}
		expectAudit(t, rec, "upload_scan", route.ResultRefused, reason)
	}
}

// Formats a code scan or upload recognises beyond PEM bundles.
func TestFindMaterialFormats(t *testing.T) {
	der := testCertDER(t, time.Now().Add(-time.Hour))
	if f := findMaterial("server.cer", der); len(f) != 1 || f[0].kind != "certificate" || f[0].algorithm != "ECDSA-P256" {
		t.Fatalf("DER certificate: %+v", f)
	}
	if f := findMaterial("store.p12", []byte{0x30, 0x82, 1, 2}); len(f) != 1 || f[0].kind != "keystore" || !secretKinds["keystore"] {
		t.Fatalf("keystore: %+v", f)
	}
	k, _ := rsa.GenerateKey(rand.Reader, 2048)
	sshPub, _ := ssh.NewPublicKey(&k.PublicKey)
	known := "git.example.com,10.0.0.9 " + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub))) + "\n"
	if f := findMaterial("known_hosts", []byte(known)); len(f) != 1 || f[0].algorithm != "RSA-2048" || f[0].name != "git.example.com,10.0.0.9" || f[0].fingerprint != ssh.FingerprintSHA256(sshPub) {
		t.Fatalf("known_hosts: %+v", f)
	}
	pkix, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	two := append(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pkix}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	f := findMaterial("chain.pem", two)
	if len(f) != 2 || f[0].kind != "public_key" || f[0].line != 1 || f[1].kind != "certificate" || f[1].line <= 1 {
		t.Fatalf("PEM lines: %+v", f)
	}
	svc, _, _ := newDiscoveryService(t)
	if a := svc.materialAssets("t1", "s", "upload", "server.cer", findMaterial("server.cer", der)); len(a) != 1 || a[0].Status != "expired" || a[0].Location != "server.cer" {
		t.Fatalf("expired certificate asset: %+v", a)
	}
}

// A scan runs in the background, reports each source as it finishes, and a
// second scan for the tenant is refused and audited while one runs.
func TestScanRunsInBackgroundOneAtATime(t *testing.T) {
	svc, _, _ := newDiscoveryService(t)
	block := make(chan struct{})
	svc.cloud = &testCloud{block: block}
	rec := &routetest.Recorder{}
	h := NewHandler(svc, rec, nil)

	rr := serveAs(h, testWriter, http.MethodPost, "/discovery/scan", `{"scan_types":["cloud","certs"]}`)
	if rr.Code != http.StatusAccepted {
		t.Fatalf("scan: %d %s", rr.Code, rr.Body)
	}
	var started struct{ Scan DiscoveryScan }
	_ = json.Unmarshal(rr.Body.Bytes(), &started)
	if started.Scan.Status != "running" {
		t.Fatalf("started %+v", started.Scan)
	}
	if rr := serveAs(h, testWriter, http.MethodPost, "/discovery/scan", `{"scan_types":["certs"]}`); rr.Code != http.StatusConflict {
		t.Fatalf("second scan: %d %s", rr.Code, rr.Body)
	}
	if ev := expectAudit(t, rec, "scan_start", route.ResultRefused, "scan_running"); ev.Details["running_scan_id"] != started.Scan.ID {
		t.Fatalf("refusal details %+v", ev.Details)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		sc, _ := svc.GetScan(context.Background(), "t1", started.Scan.ID)
		if done, _ := sc.Stats["sources_done"].([]interface{}); len(done) == 1 && done[0] == "certs" && sc.Status == "running" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no progress recorded: %+v", sc)
		}
		time.Sleep(20 * time.Millisecond)
	}
	close(block)
	if sc := finishScan(t, svc, started.Scan); sc.Status != "completed" || extractInt(sc.Stats["cloud_assets"]) != 1 || extractInt(sc.Stats["assets_discovered"]) != 3 {
		t.Fatalf("finished %+v", sc)
	}
	if rr := serveAs(h, testWriter, http.MethodPost, "/discovery/scan", `{"scan_types":["certs"]}`); rr.Code != http.StatusAccepted {
		t.Fatalf("scan after the first finished: %d", rr.Code)
	}
	svc.scans.Wait()
}

// A scan left running past its deadline (the service restarted) reads as
// interrupted.
func TestAbandonedScanReadsInterrupted(t *testing.T) {
	svc, store, _ := newDiscoveryService(t)
	ctx := context.Background()
	if err := store.CreateScan(ctx, DiscoveryScan{ID: "scan_old", TenantID: "t1", ScanType: "network", Status: "running", Trigger: "manual", Stats: map[string]interface{}{}, StartedAt: time.Now().Add(-time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if sc, _ := svc.GetScan(ctx, "t1", "scan_old"); sc.Status != "interrupted" {
		t.Fatalf("get: %s", sc.Status)
	}
	if items, _ := svc.ListScans(ctx, "t1", 10, 0); len(items) != 1 || items[0].Status != "interrupted" {
		t.Fatalf("list: %+v", items)
	}
}

// Sources says what each source has to read and how its last scan went.
func TestSourcesReportSetupAndLastScan(t *testing.T) {
	svc, _, _ := newDiscoveryService(t)
	ctx := context.Background()
	svc.root = ""
	if _, err := svc.AddTarget(ctx, "t1", "10.0.4.0/28", 22, "ssh", "w"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.AddTarget(ctx, "t1", "api.example.com", 443, "", "w"); err != nil {
		t.Fatal(err)
	}
	rec := &routetest.Recorder{}
	h := NewHandler(svc, rec, nil)
	read := func() map[string]SourceStatus {
		t.Helper()
		rr := serveAs(h, testReadonly, http.MethodGet, "/discovery/sources", "")
		if rr.Code != http.StatusOK {
			t.Fatalf("sources: %d %s", rr.Code, rr.Body)
		}
		expectAudit(t, rec, "sources_read", route.ResultSuccess, "")
		var resp struct{ Items []SourceStatus }
		_ = json.Unmarshal(rr.Body.Bytes(), &resp)
		out := map[string]SourceStatus{}
		for _, s := range resp.Items {
			out[s.ID] = s
		}
		return out
	}
	src := read()
	if n := src["network"]; !n.Configured || n.Detail["ranges"] != float64(1) || n.Detail["hosts"] != float64(1) || n.Detail["ssh"] != float64(1) || n.Detail["addresses"] != float64(1+14+1) {
		t.Fatalf("network: %+v", n)
	}
	if c := src["cloud"]; !c.Configured || c.Detail["accounts"] != float64(1) {
		t.Fatalf("cloud: %+v", c)
	}
	if c := src["certs"]; !c.Configured || c.Detail["certificates"] != float64(2) || c.LastScan != nil {
		t.Fatalf("certs: %+v", c)
	}
	if src["code"].Configured || !src["upload"].Configured || len(src) != 5 {
		t.Fatalf("code/upload: %+v", src)
	}
	scan, _ := svc.StartScan(ctx, ScanRequest{TenantID: "t1", ScanTypes: []string{"certs", "code"}})
	finishScan(t, svc, scan)
	src = read()
	if l := src["certs"].LastScan; l == nil || l.Assets != 2 || l.Error != "" || l.ScanID != scan.ID {
		t.Fatalf("certs last scan: %+v", l)
	}
	if l := src["code"].LastScan; l == nil || !strings.Contains(l.Error, "WORKSPACE_ROOT") {
		t.Fatalf("code last scan: %+v", l)
	}
}

// Ranges and SSH targets: at most 256 addresses a range, none reserved,
// 4096 addresses a tenant; the protocol is tls or ssh.
func TestTargetRangesAndProtocol(t *testing.T) {
	for in, want := range map[string]string{"10.0.4.7/24": "10.0.4.0/24", "192.168.1.16/28": "192.168.1.16/28", "2001:DB8::/120": "2001:db8::/120"} {
		if got, err := normalizeTarget(in, 22); err != nil || got != want {
			t.Errorf("normalizeTarget(%q) = %q, %v", in, got, err)
		}
	}
	for _, in := range []string{"10.0.0.0/23", "2001:db8::/119", "127.0.0.0/24", "169.254.169.0/24", "0.0.0.0/30", "10.0.0.0/33", "a.example/24"} {
		if _, err := normalizeTarget(in, 22); !errors.Is(err, errInvalidTarget) {
			t.Errorf("normalizeTarget(%q) accepted: %v", in, err)
		}
	}
	for in, n := range map[string]int{"10.0.0.0/24": 254, "10.0.0.0/30": 2, "10.0.0.0/31": 2, "10.0.0.5/32": 1, "2001:db8::/120": 256} {
		if got := len(prefixHosts(netipMustPrefix(in))); got != n {
			t.Errorf("prefixHosts(%s) = %d, want %d", in, got, n)
		}
	}
	svc, _, _ := newDiscoveryService(t)
	ctx := context.Background()
	if _, err := svc.AddTarget(ctx, "t1", "git.example.com", 22, "ftp", "w"); !errors.Is(err, errInvalidTarget) {
		t.Fatalf("protocol ftp: %v", err)
	}
	for i := 0; i < 16; i++ { // 16 x 254 = 4064 addresses
		if _, err := svc.AddTarget(ctx, "t1", "10."+itoa(i)+".0.0/24", 443, "tls", "w"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := svc.AddTarget(ctx, "t1", "10.99.0.0/24", 443, "tls", "w"); !errors.Is(err, errTargetLimit) {
		t.Fatalf("address budget: %v", err)
	}

	rec := &routetest.Recorder{}
	h := NewHandler(svc, rec, nil)
	rr := serveAs(h, testWriter, http.MethodPost, "/discovery/targets", `{"host":"git.example.com","port":22,"protocol":"ssh"}`)
	if rr.Code != http.StatusCreated || !strings.Contains(rr.Body.String(), `"protocol":"ssh"`) {
		t.Fatalf("ssh target: %d %s", rr.Code, rr.Body)
	}
	if ev := expectAudit(t, rec, "target_add", route.ResultSuccess, ""); ev.Details["protocol"] != "ssh" {
		t.Fatalf("details %+v", ev.Details)
	}
	for _, body := range []string{`{"host":"git.example.com","port":2222,"protocol":"ftp"}`, `{"host":"10.1.0.0/16","port":443}`} {
		if rr := serveAs(h, testWriter, http.MethodPost, "/discovery/targets", body); rr.Code != http.StatusBadRequest {
			t.Fatalf("%s: %d", body, rr.Code)
		}
		expectAudit(t, rec, "target_add", route.ResultRefused, "invalid_target")
	}
}

// Removing an asset needs discovery.write and the asset's own tenant.
func TestRemoveAssetAudited(t *testing.T) {
	svc, store, _ := newDiscoveryService(t)
	ctx := context.Background()
	if err := store.UpsertAsset(ctx, CryptoAsset{ID: "a1", TenantID: "t1", Source: "network", AssetType: "tls_endpoint", Name: "old.example.com:443", Location: "old.example.com:443", Algorithm: "X25519", Status: "active"}); err != nil {
		t.Fatal(err)
	}
	rec := &routetest.Recorder{}
	h := NewHandler(svc, rec, nil)
	if rr := serveAs(h, testReadonly, http.MethodDelete, "/discovery/assets/a1", ""); rr.Code != http.StatusForbidden {
		t.Fatalf("remove as discovery.read: %d", rr.Code)
	}
	expectAudit(t, rec, "asset_remove", route.ResultRefused, route.ReasonPermissionDenied)
	other := &pkgauth.Claims{UserID: "o", TenantID: "t2", Permissions: []string{"discovery.write"}}
	if rr := serveAs(h, other, http.MethodDelete, "/discovery/assets/a1", ""); rr.Code != http.StatusNotFound {
		t.Fatalf("remove another tenant's asset: %d", rr.Code)
	}
	if rr := serveAs(h, testWriter, http.MethodDelete, "/discovery/assets/a1", ""); rr.Code != http.StatusOK {
		t.Fatalf("remove: %d %s", rr.Code, rr.Body)
	}
	expectAudit(t, rec, "asset_remove", route.ResultSuccess, "")
	if _, err := svc.GetAsset(ctx, "t1", "a1"); !errors.Is(err, errNotFound) {
		t.Fatalf("asset still there: %v", err)
	}
}

// A review is kept across rescans, which rewrite only what they observe;
// a review a row stored in status before 7.18.0-beta still reads.
func TestReviewSurvivesRescan(t *testing.T) {
	svc, store, _ := newDiscoveryService(t)
	ctx := context.Background()
	scan, _ := svc.StartScan(ctx, ScanRequest{TenantID: "t1", ScanTypes: []string{"certs"}})
	finishScan(t, svc, scan)
	assets, _ := svc.ListAssets(ctx, "t1", 10, 0, "certs", "", "")
	if len(assets) == 0 {
		t.Fatal("no assets")
	}
	if _, err := svc.ClassifyAsset(ctx, "t1", assets[0].ID, ClassifyRequest{Status: "accepted_risk", Notes: "legacy partner"}, "alice"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ClassifyAsset(ctx, "t1", assets[0].ID, ClassifyRequest{Status: "ignored"}, "alice"); httpStatusForErr(err) != http.StatusBadRequest {
		t.Fatalf("unknown review status: %v", err)
	}
	scan, _ = svc.StartScan(ctx, ScanRequest{TenantID: "t1", ScanTypes: []string{"certs"}})
	finishScan(t, svc, scan)
	got, _ := svc.GetAsset(ctx, "t1", assets[0].ID)
	if got.Metadata["review_status"] != "accepted_risk" || got.Metadata["review_notes"] != "legacy partner" || got.Metadata["reviewed_by"] != "alice" || got.Status != "active" {
		t.Fatalf("after rescan: status %q metadata %+v", got.Status, got.Metadata)
	}
	if err := store.UpsertAsset(ctx, CryptoAsset{ID: "old", TenantID: "t1", Source: "network", AssetType: "tls_endpoint", Name: "x", Algorithm: "X25519", Status: "remediated",
		Metadata: map[string]interface{}{"classification_notes": "rotated"}}); err != nil {
		t.Fatal(err)
	}
	if old, _ := svc.GetAsset(ctx, "t1", "old"); old.Metadata["review_status"] != "remediated" || old.Metadata["review_notes"] != "rotated" {
		t.Fatalf("legacy review: %+v", old.Metadata)
	}
}

// Every number the summary reports is the total the asset list returns for
// the same filter, so a chart bar and its drill-down list always agree.
func TestSummaryCountsEqualFilteredLists(t *testing.T) {
	svc, store, _ := newDiscoveryService(t)
	ctx := context.Background()
	now := time.Now().UTC()
	soon := map[string]interface{}{"not_after": now.Add(10 * 24 * time.Hour).Format(time.RFC3339)}
	past := map[string]interface{}{"not_after": now.Add(-time.Hour).Format(time.RFC3339)}
	for _, a := range []CryptoAsset{
		{ID: "a1", Source: "network", AssetType: "tls_certificate", Algorithm: "RSA-1024", Metadata: past},
		{ID: "a2", Source: "certs", AssetType: "certificate", Algorithm: "ECDSA-P256", Metadata: soon},
		{ID: "a3", Source: "certs", AssetType: "certificate", Algorithm: "ECDSA-P256"},
		{ID: "a4", Source: "code", AssetType: "private_key_material", Algorithm: "RSA-2048"},
		{ID: "a5", Source: "upload", AssetType: "cloud_access_key", Algorithm: ""},
		{ID: "a6", Source: "network", AssetType: "tls_endpoint", Algorithm: "X25519-ML-KEM-768-HYBRID", PQCReady: true},
	} {
		a.TenantID, a.Name, a.Status, a.LastSeen = "t1", a.ID, "active", now
		if err := store.UpsertAsset(ctx, a); err != nil {
			t.Fatal(err)
		}
	}
	sum, err := svc.Summary(ctx, "t1")
	if err != nil {
		t.Fatal(err)
	}
	total := func(f AssetFilter) int {
		t.Helper()
		items, n, err := svc.FindAssets(ctx, "t1", 100, 0, f)
		if err != nil || len(items) != n {
			t.Fatalf("filter %+v: %d items, total %d, %v", f, len(items), n, err)
		}
		return n
	}
	if sum.TotalAssets != 6 || total(AssetFilter{}) != 6 {
		t.Fatalf("total %d", sum.TotalAssets)
	}
	for class, n := range sum.ClassificationCounts {
		if got := total(AssetFilter{Classes: []string{class}}); got != n {
			t.Errorf("class %s: summary %d, list %d", class, n, got)
		}
	}
	for alg, classes := range sum.AlgorithmClasses {
		alg := alg
		for class, n := range classes {
			if got := total(AssetFilter{Algorithm: &alg, Classes: []string{class}}); got != n {
				t.Errorf("algorithm %q class %s: summary %d, list %d", alg, class, n, got)
			}
		}
		if got := total(AssetFilter{Algorithm: &alg}); got != sum.AlgorithmDistribution[alg] {
			t.Errorf("algorithm %q: summary %d, list %d", alg, sum.AlgorithmDistribution[alg], got)
		}
	}
	for src, classes := range sum.SourceClassification {
		for class, n := range classes {
			if got := total(AssetFilter{Source: src, Classes: []string{class}}); got != n {
				t.Errorf("source %s class %s: summary %d, list %d", src, class, n, got)
			}
		}
	}
	if got := total(AssetFilter{PQCReady: true}); got != sum.PQCReadyCount || got != 1 {
		t.Errorf("post-quantum: summary %d, list %d", sum.PQCReadyCount, got)
	}
	if got := total(AssetFilter{ExpiringDays: 30}); got != sum.Expiring30 || got != 2 {
		t.Errorf("expiring: summary %d, list %d", sum.Expiring30, got)
	}
	// The no-algorithm bucket (a cloud access key) is its own filter, and
	// "weak or exposed" is two classes in one.
	none := ""
	if total(AssetFilter{Algorithm: &none}) != 1 || total(AssetFilter{Classes: []string{"weak", "exposed"}}) != 3 || total(AssetFilter{Query: "ml-kem"}) != 1 {
		t.Errorf("filters: summary %+v", sum)
	}

	// The route takes the same filters and reports the total with a page.
	rec := &routetest.Recorder{}
	rr := serveAs(NewHandler(svc, rec, nil), testReadonly, http.MethodGet, "/discovery/assets?classification=weak,exposed&limit=2&offset=2", "")
	var page struct {
		Items []CryptoAsset
		Total int
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &page)
	if rr.Code != http.StatusOK || page.Total != 3 || len(page.Items) != 1 {
		t.Fatalf("paged list: %d total %d items %d", rr.Code, page.Total, len(page.Items))
	}
	if rr := serveAs(NewHandler(svc, rec, nil), testReadonly, http.MethodGet, "/discovery/assets?algorithm=", ""); !strings.Contains(rr.Body.String(), `"total":1`) {
		t.Fatalf("no-algorithm filter: %s", rr.Body)
	}
}

// The inventory is counted and paged in full, however large: before
// 7.18.0-beta the summary and the list read the newest 10000 rows.
func TestInventoryIsNeverASample(t *testing.T) {
	svc, store, _ := newDiscoveryService(t)
	ctx := context.Background()
	const n = 10250
	for i := 0; i < n; i++ {
		if err := store.UpsertAsset(ctx, CryptoAsset{ID: "a" + itoa(i), TenantID: "t1", Source: "cloud", AssetType: "kms_key", Name: "k", Algorithm: "RSA-2048", Status: "active"}); err != nil {
			t.Fatal(err)
		}
	}
	sum, err := svc.Summary(ctx, "t1")
	if err != nil || sum.TotalAssets != n || sum.ClassificationCounts["quantum_vulnerable"] != n {
		t.Fatalf("summary counted %d of %d: %v", sum.TotalAssets, n, err)
	}
	items, total, err := svc.FindAssets(ctx, "t1", 25, n-10, AssetFilter{Classes: []string{"quantum_vulnerable"}})
	if err != nil || total != n || len(items) != 10 {
		t.Fatalf("last page: %d items, total %d, %v", len(items), total, err)
	}
}

// "Not seen" lists the assets of a scanned source that its last scan didn't
// observe; uploads, which are never rescanned, are not flagged.
func TestNotSeenFilter(t *testing.T) {
	svc, store, _ := newDiscoveryService(t)
	ctx := context.Background()
	old := time.Now().UTC().Add(-48 * time.Hour)
	for _, a := range []CryptoAsset{
		{ID: "gone", Source: "certs", AssetType: "certificate", Algorithm: "RSA-2048", LastSeen: old},
		{ID: "file", Source: "upload", AssetType: "certificate", Algorithm: "RSA-2048", LastSeen: old},
	} {
		a.TenantID, a.Name, a.Status = "t1", a.ID, "active"
		if err := store.UpsertAsset(ctx, a); err != nil {
			t.Fatal(err)
		}
	}
	if _, n, _ := svc.FindAssets(ctx, "t1", 10, 0, AssetFilter{NotSeen: true}); n != 0 {
		t.Fatalf("flagged %d assets before any scan", n)
	}
	scan, _ := svc.StartScan(ctx, ScanRequest{TenantID: "t1", ScanTypes: []string{"certs"}})
	finishScan(t, svc, scan)
	_, _, _ = svc.ScanUpload(ctx, "t1", "x.pem", []byte("nothing"))
	items, n, err := svc.FindAssets(ctx, "t1", 10, 0, AssetFilter{NotSeen: true})
	if err != nil || n != 1 || items[0].ID != "gone" {
		t.Fatalf("not seen: %+v, %v", items, err)
	}
}
