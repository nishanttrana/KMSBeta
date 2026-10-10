package main

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"vecta-kms/pkg/route"
	"vecta-kms/pkg/route/routetest"
)

func testPrivatePEM(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p8, _ := x509.MarshalPKCS8PrivateKey(key)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: p8}))
}

var (
	jksBytes = append([]byte{0xfe, 0xed, 0xfe, 0xed, 0, 0, 0, 2}, bytes.Repeat([]byte{7}, 64)...)
	// PKCS#12 starts SEQUENCE { INTEGER 3, ... }.
	p12Bytes = append([]byte{0x30, 0x82, 0x0a, 0x00, 0x02, 0x01, 0x03, 0x30, 0x82}, bytes.Repeat([]byte{9}, 64)...)
	pngBytes = append([]byte("\x89PNG\r\n\x1a\n"), bytes.Repeat([]byte{1}, 64)...)
)

func zipOf(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		w, err := zw.Create(n)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = w.Write([]byte(files[n]))
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func tarGzOf(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for n, body := range files {
		_ = tw.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: n, Mode: 0o644, Size: int64(len(body))})
		_, _ = tw.Write([]byte(body))
	}
	_ = tw.Close()
	_ = gz.Close()
	return buf.Bytes()
}

// A keystore, key or certificate is recognised by what it holds, whatever
// the file is called; an image or prose is not.
func TestKeyMaterialByContent(t *testing.T) {
	priv := testPrivatePEM(t)
	for name, c := range map[string]struct {
		raw  []byte
		kind string
		meta string
	}{
		"backup.bin":    {jksBytes, "keystore", "jks"},
		"store.dat":     {p12Bytes, "keystore", "p12"},
		"release.jceks": {append([]byte{0xce, 0xce, 0xce, 0xce}, 1, 2, 3, 4, 5, 6), "keystore", "jceks"},
		"notes":         {[]byte(priv), "private_key_material", ""},
		"cert.blob":     {testCertDER(t, time.Now().Add(time.Hour)), "certificate", ""},
	} {
		got := findMaterial(name, c.raw)
		if len(got) != 1 || got[0].kind != c.kind || (c.meta != "" && got[0].meta["format"] != c.meta) {
			t.Errorf("%s: %+v, want one %s %s", name, got, c.kind, c.meta)
		}
		if !looksLikeKeyMaterial(c.raw[:min(len(c.raw), sniffBytes)]) {
			t.Errorf("%s: its first bytes were not recognised", name)
		}
	}
	for name, raw := range map[string][]byte{
		"png": pngBytes, "prose": []byte("The key to good documentation is brevity.\n"), "empty": nil,
		"json": []byte(`{"a": 1}`), "short der": {0x30, 0x03, 0x02, 0x01, 0x03},
	} {
		if looksLikeKeyMaterial(raw) {
			t.Errorf("%s recognised as key material", name)
		}
	}
	if !looksLikeKeyMaterial(zipOf(t, map[string]string{"a.txt": "x"})) || !looksLikeKeyMaterial([]byte("ssh-ed25519 AAAAC3Nza user@host")) {
		t.Error("an archive or an SSH public key was not recognised")
	}
}

// An archive is opened in memory and its members read like files beside
// it: by name, or by content when the name says nothing. Dependencies and
// archives inside it are left alone.
func TestArchivesAreScannedInMemory(t *testing.T) {
	svc, _, _ := newDiscoveryService(t)
	priv := testPrivatePEM(t)
	files := map[string]string{
		"deploy/id_rsa":            priv,
		"conf/nginx.conf":          "ssl_protocols TLSv1;\n",
		"data/blob.bin":            priv, // by content
		"data/store":               string(jksBytes),
		"node_modules/dep/key.pem": priv,
		"img/logo.png":             string(pngBytes),
		"docs/README.md":           "nothing here",
		"nested/inner.zip":         string(zipOf(t, map[string]string{"id_rsa": priv})),
	}
	want := []string{
		"crypto_usage|TLS-1.0|weak|conf/nginx.conf:1",
		"keystore||exposed|data/store",
		"private_key_material|RSA-2048|exposed|data/blob.bin:1",
		"private_key_material|RSA-2048|exposed|deploy/id_rsa:1",
	}
	for name, raw := range map[string][]byte{"release.zip": zipOf(t, files), "app.jar": zipOf(t, files), "backup.tar.gz": tarGzOf(t, files), "renamed.dat": zipOf(t, files)} {
		assets, err := svc.fileAssets("t1", "s", "upload", name, name, raw)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got := assetLines(assets, name+"!"); !reflect.DeepEqual(got, want) {
			t.Fatalf("%s\n got %q\nwant %q", name, got, want)
		}
		for _, a := range assets {
			if a.Metadata["archive"] != name || !strings.HasPrefix(a.Location, name+"!/"+a.Metadata["member"].(string)) {
				t.Fatalf("%s: asset %+v", name, a)
			}
		}
	}

	// Over the cap: what was read, and the reason.
	old := maxArchiveExpanded
	maxArchiveExpanded = 2500
	assets, err := svc.fileAssets("t1", "s", "upload", "release.zip", "release.zip", zipOf(t, files))
	maxArchiveExpanded = old
	if !errors.Is(err, errArchiveTooLarge) || len(assets) == 0 || len(assets) >= 4 {
		t.Fatalf("over the cap: %d assets, %v", len(assets), err)
	}
	// A member that claims a small size and holds a large one is not read.
	bomb := zipOf(t, map[string]string{"big.pem": priv + strings.Repeat("A", maxUploadBytes)})
	if assets, err := svc.fileAssets("t1", "s", "upload", "bomb.zip", "bomb.zip", bomb); err != nil || len(assets) != 0 {
		t.Fatalf("an oversized member: %d assets, %v", len(assets), err)
	}
	damaged := zipOf(t, files)
	if _, err := svc.fileAssets("t1", "s", "upload", "bad.zip", "bad.zip", damaged[:len(damaged)/2]); err == nil {
		t.Fatal("a truncated zip read as complete")
	}
	// A gzip that is not a tar, and a keystore that happens to be zip-like,
	// are files, not archives.
	var gz bytes.Buffer
	w := gzip.NewWriter(&gz)
	_, _ = w.Write([]byte("plain text"))
	_ = w.Close()
	if assets, err := svc.fileAssets("t1", "s", "upload", "notes.gz", "notes.gz", gz.Bytes()); err != nil || len(assets) != 0 {
		t.Fatalf("gzip of text: %d assets, %v", len(assets), err)
	}
}

// An uploaded archive is inventoried member by member, and no member's
// content reaches the response or the audit event.
func TestUploadedArchive(t *testing.T) {
	svc, _, _ := newDiscoveryService(t)
	rec := &routetest.Recorder{}
	h := NewHandler(svc, rec, nil)
	priv := testPrivatePEM(t)
	body, _ := json.Marshal(map[string]string{"name": "release.zip", "content": base64.StdEncoding.EncodeToString(zipOf(t, map[string]string{"deploy/id_rsa": priv, "store.bin": string(jksBytes)}))})
	rr := serveAs(h, testWriter, http.MethodPost, "/discovery/upload", string(body))
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "release.zip!/deploy/id_rsa:1") || !strings.Contains(rr.Body.String(), "release.zip!/store.bin") {
		t.Fatalf("upload: %d %s", rr.Code, rr.Body)
	}
	if strings.Contains(rr.Body.String(), "BEGIN") {
		t.Fatal("a member's content is in the response")
	}
	if ev := expectAudit(t, rec, "upload_scan", route.ResultSuccess, ""); ev.Details["assets"] != 2 {
		t.Fatalf("details %+v", ev.Details)
	}
}

// A deep scan reads the first kilobyte of an object whose name says
// nothing and scans it only if that holds key material; without it such
// objects are never requested.
func TestDeepScanReadsByContent(t *testing.T) {
	priv := testPrivatePEM(t)
	objects := map[string]string{
		"backups/store.dat":    string(jksBytes),
		"backups/key.bak":      strings.Repeat("# comment line\n", 10) + priv,
		"backups/late.bak":     strings.Repeat("x", sniffBytes+10) + priv, // nothing in its first kilobyte
		"media/logo.png":       string(pngBytes) + strings.Repeat("\x00", 4096),
		"media/renamed.dat":    string(zipOf(t, map[string]string{"id_rsa": priv})),
		"node_modules/a/k.bak": priv,
		"conf/id_rsa":          priv, // by name, deep or not
	}
	for _, deep := range []bool{false, true} {
		svc, _, _ := newDiscoveryService(t)
		srv := newS3Server(t, objects, true)
		trust(t, svc, srv)
		svc.conns = stubConnections{"c1": s3Connection(srvHost(srv))}
		b := Bucket{ID: "b1", TenantID: "t1", Provider: "s3", Endpoint: srv.URL, Name: "acme-artifacts", Region: "eu-west-1", ConnectionID: "c1", Deep: deep}
		res, err := svc.scanBucket(context.Background(), svc.storageClient(nil), b, "s", false)
		if err != nil {
			t.Fatalf("deep %v: %v", deep, err)
		}
		got := assetLines(res.assets, b.label())
		want := []string{"private_key_material|RSA-2048|exposed|conf/id_rsa:1"}
		if deep {
			want = []string{
				"keystore||exposed|backups/store.dat",
				"private_key_material|RSA-2048|exposed|backups/key.bak:11",
				"private_key_material|RSA-2048|exposed|conf/id_rsa:1",
				"private_key_material|RSA-2048|exposed|media/renamed.dat!/id_rsa:1",
			}
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("deep %v\n got %q\nwant %q", deep, got, want)
		}
		srv.mu.Lock()
		ranged := append([]string(nil), srv.ranged...)
		srv.mu.Unlock()
		sort.Strings(ranged)
		wantRanged := []string(nil)
		wantSniffed, wantFiles := 0, 1
		if deep {
			// The dependency folder is not looked into; everything else
			// without a telling name is, by its first kilobyte only.
			wantRanged = []string{
				"/acme-artifacts/backups/key.bak bytes=0-1023", "/acme-artifacts/backups/late.bak bytes=0-1023",
				"/acme-artifacts/backups/store.dat bytes=0-1023", "/acme-artifacts/media/logo.png bytes=0-1023", "/acme-artifacts/media/renamed.dat bytes=0-1023",
			}
			wantSniffed, wantFiles = 5, 4
		}
		if !reflect.DeepEqual(ranged, wantRanged) || res.sniffed != wantSniffed || res.files != wantFiles {
			t.Fatalf("deep %v: ranged %q, sniffed %d, files %d", deep, ranged, res.sniffed, res.files)
		}
		// The image and the file with nothing up front were asked for once
		// (their first kilobyte) and never downloaded; the dependency never.
		count := map[string]int{}
		for _, r := range srv.requests() {
			uri, _, _ := strings.Cut(r, " | ")
			count[uri]++
		}
		once := 0
		if deep {
			once = 1
		}
		if count["/acme-artifacts/media/logo.png"] != once || count["/acme-artifacts/backups/late.bak"] != once || count["/acme-artifacts/node_modules/a/k.bak"] != 0 {
			t.Fatalf("deep %v: requests %v", deep, count)
		}
		// Key material found by its first bytes is then read in full.
		if deep && count["/acme-artifacts/backups/key.bak"] != 2 {
			t.Fatalf("key.bak requested %d times, want 2", count["/acme-artifacts/backups/key.bak"])
		}
	}
}
