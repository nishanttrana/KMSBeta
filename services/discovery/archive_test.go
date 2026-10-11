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
// it: by name, or by content when the name says nothing. Dependencies are
// left alone; an archive inside it is opened in its place.
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
		"private_key_material|RSA-2048|exposed|nested/inner.zip!/id_rsa:1",
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
	if !errors.Is(err, errArchiveTooLarge) || len(assets) == 0 || len(assets) >= 5 {
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
	// A gzip of one file is read as that file: text holds nothing, a key is
	// found under the name without ".gz".
	gzOf := func(body string) []byte {
		var gz bytes.Buffer
		w := gzip.NewWriter(&gz)
		_, _ = w.Write([]byte(body))
		_ = w.Close()
		return gz.Bytes()
	}
	if assets, err := svc.fileAssets("t1", "s", "upload", "notes.gz", "notes.gz", gzOf("plain text")); err != nil || len(assets) != 0 {
		t.Fatalf("gzip of text: %d assets, %v", len(assets), err)
	}
	assets, err = svc.fileAssets("t1", "s", "upload", "backup/server.key.gz", "backup/server.key.gz", gzOf(priv))
	if got := assetLines(assets, "backup/server.key.gz!"); err != nil || !reflect.DeepEqual(got, []string{"private_key_material|RSA-2048|exposed|server.key:1"}) {
		t.Fatalf("gzipped key: %q %v", got, err)
	}
}

// Archives inside archives are opened (8.1.0-beta), whatever mix of zip, tar
// and gzip they are, down to maxArchiveDepth. One allowance of entries and
// bytes covers the whole tree, so nesting can't multiply what is unpacked,
// and an archive nested deeper is reported, not opened.
func TestArchivesInsideArchives(t *testing.T) {
	svc, _, _ := newDiscoveryService(t)
	priv := testPrivatePEM(t)
	level3 := tarGzOf(t, map[string]string{"etc/ssl/server.key": priv})
	level2 := zipOf(t, map[string]string{"layers/base.tar.gz": string(level3), "conf/nginx.conf": "ssl_protocols TLSv1;\n"})
	level1 := zipOf(t, map[string]string{"release/app.war": string(level2), "top.pem": priv})
	assets, err := svc.fileAssets("t1", "s", "upload", "bundle.zip", "bundle.zip", level1)
	want := []string{
		"crypto_usage|TLS-1.0|weak|release/app.war!/conf/nginx.conf:1",
		"private_key_material|RSA-2048|exposed|release/app.war!/layers/base.tar.gz!/etc/ssl/server.key:1",
		"private_key_material|RSA-2048|exposed|top.pem:1",
	}
	if got := assetLines(assets, "bundle.zip!"); err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("nested archives: %v\n got %q\nwant %q", err, got, want)
	}
	for _, a := range assets {
		if a.Metadata["archive"] != "bundle.zip" || a.Location != "bundle.zip!/"+a.Metadata["member"].(string)+":1" {
			t.Fatalf("asset %s member %v", a.Location, a.Metadata["member"])
		}
	}

	// Deeper than the limit: the archive at the limit is not opened, the
	// scan says so, and everything above it is still read.
	deep := zipOf(t, map[string]string{"id_rsa": priv})
	for i := 0; i < maxArchiveDepth; i++ {
		deep = zipOf(t, map[string]string{"inner.zip": string(deep), "level.pem": priv})
	}
	assets, err = svc.fileAssets("t1", "s", "upload", "deep.zip", "deep.zip", deep)
	if !errors.Is(err, errArchiveTooDeep) || len(assets) != maxArchiveDepth {
		t.Fatalf("too deep: %d assets, %v", len(assets), err)
	}
	for _, a := range assets {
		if strings.HasSuffix(a.Location, "/id_rsa:1") {
			t.Fatalf("the archive below the limit was opened: %s", a.Location)
		}
	}

	// The byte allowance is the tree's: three levels that each fit alone
	// do not fit together.
	pad := strings.Repeat("# padding\n", 200) // 2000 bytes of a file the parser reads
	c := zipOf(t, map[string]string{"c.conf": pad, "c.pem": priv})
	b := zipOf(t, map[string]string{"b.conf": pad, "c.zip": string(c)})
	a := zipOf(t, map[string]string{"a.conf": pad, "b.zip": string(b)})
	old := maxArchiveExpanded
	maxArchiveExpanded = int64(len(b)) + 2500 // the outer level alone fits
	_, err = svc.fileAssets("t1", "s", "upload", "a.zip", "a.zip", a)
	maxArchiveExpanded = old
	if !errors.Is(err, errArchiveTooLarge) {
		t.Fatalf("nested archives drew on separate allowances: %v", err)
	}
	if assets, err := svc.fileAssets("t1", "s", "upload", "a.zip", "a.zip", a); err != nil || len(assets) != 1 {
		t.Fatalf("within the allowance: %d assets, %v", len(assets), err)
	}
	// So is the entry allowance.
	many := map[string]string{}
	for i := 0; i < 40; i++ {
		many["f"+itoa(i)+".txt"] = "x"
	}
	inner := zipOf(t, many)
	outer := zipOf(t, map[string]string{"one.zip": string(inner), "two.zip": string(inner)})
	oldEntries := maxArchiveEntries
	maxArchiveEntries = 60
	_, err = svc.fileAssets("t1", "s", "upload", "outer.zip", "outer.zip", outer)
	maxArchiveEntries = oldEntries
	if !errors.Is(err, errArchiveTooLarge) {
		t.Fatalf("entries were counted per archive: %v", err)
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
		"backups/late.bak":     strings.Repeat("x", sniffBytes+10) + "\n" + priv,    // nothing in its first kilobyte
		"backups/firmware.img": strings.Repeat("\x00", 9000) + "\n" + priv,          // binary, a key further in
		"backups/blob.img":     strings.Repeat("\x00\x01", 6000),                    // binary, nothing in it
		"media/huge.dat":       strings.Repeat("x", maxUploadBytes+1) + "\n" + priv, // too large to hold: read through
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
		res, err := svc.scanBucket(context.Background(), nil, b, "s", false)
		if err != nil {
			t.Fatalf("deep %v: %v", deep, err)
		}
		got := assetLines(res.assets, b.label())
		want := []string{"private_key_material|RSA-2048|exposed|conf/id_rsa:1"}
		if deep {
			want = []string{
				"keystore||exposed|backups/store.dat",
				"private_key_material|RSA-2048|exposed|backups/firmware.img:2",
				"private_key_material|RSA-2048|exposed|backups/key.bak:11",
				"private_key_material|RSA-2048|exposed|backups/late.bak:2",
				"private_key_material|RSA-2048|exposed|conf/id_rsa:1",
				"private_key_material|RSA-2048|exposed|media/huge.dat:2",
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
			// The dependency folder is not looked into. Everything else
			// without a telling name is read: whole when it is small,
			// through from start to end when it is too large to hold (so a
			// key anywhere in it is found), and by its first kilobyte only
			// when it is an image.
			wantRanged = []string{"/acme-artifacts/media/logo.png bytes=0-1023"}
			// Parsed: all but the image and the empty binary.
			wantSniffed, wantFiles = 8, 7
		}
		if !reflect.DeepEqual(ranged, wantRanged) || res.sniffed != wantSniffed || res.files != wantFiles {
			t.Fatalf("deep %v: ranged %q, sniffed %d, files %d", deep, ranged, res.sniffed, res.files)
		}
		// Each object was asked for once: the image by its first kilobyte,
		// never downloaded; the dependency never.
		count := map[string]int{}
		for _, r := range srv.requests() {
			uri, _, _ := strings.Cut(r, " | ")
			count[uri]++
		}
		once := 0
		if deep {
			once = 1
		}
		if count["/acme-artifacts/media/logo.png"] != once || count["/acme-artifacts/media/huge.dat"] != once || count["/acme-artifacts/backups/late.bak"] != once || count["/acme-artifacts/node_modules/a/k.bak"] != 0 {
			t.Fatalf("deep %v: requests %v", deep, count)
		}
		// A small object is one request, whatever it holds.
		if deep && (count["/acme-artifacts/backups/key.bak"] != 1 || count["/acme-artifacts/backups/blob.img"] != 1) {
			t.Fatalf("small objects: %v", count)
		}
	}
}
