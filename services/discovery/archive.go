package main

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"path"
	"strconv"
	"strings"
)

// Reading by content, and inside archives (7.37.0-beta). Until now a file
// was read only if its name said what it was, so a keystore called
// backup.bin or a key inside release.zip was never seen.
//
//   - A keystore is recognised by its first bytes (JKS, JCEKS, PKCS#12),
//     whatever it is called.
//   - A zip (jar, war, ear), tar, gzipped tar or gzipped file is opened in
//     memory and each member is read by the same rules as a file beside it.
//     Members are named archive!/member.
//   - An archive inside an archive is opened too (8.1.0-beta), down to
//     maxArchiveDepth, and named outer!/inner!/member. The entry and byte
//     caps are for the whole tree, not for each level, so nesting can't
//     multiply what one archive makes the scan unpack.
//   - looksLikeKeyMaterial is the test a bucket's deep scan applies to an
//     object whose name says nothing.
//
// Nothing is written to disk. The caps bound what a crafted archive can
// make the scan hold or do.

const (
	maxArchiveBytes = 32 << 20 // an archive's own size
	sniffBytes      = 1024
)

// What is read out of one archive and every archive inside it (variables so
// a test can lower them).
var (
	maxArchiveExpanded int64 = 256 << 20
	maxArchiveEntries        = 20000
)

// maxArchiveDepth: an archive and three inside one another. Deeper ones are
// reported, not opened.
const maxArchiveDepth = 4

var (
	errArchiveTooLarge = errors.New("the archive holds more entries or bytes than the scan limit")
	errArchiveTooDeep  = errors.New("an archive nested more than 4 deep was not opened")
)

var archiveExt = map[string]bool{".zip": true, ".jar": true, ".war": true, ".ear": true, ".tar": true, ".tgz": true, ".gz": true}

func archiveName(name string) bool {
	return archiveExt[strings.ToLower(path.Ext(strings.ReplaceAll(name, "\\", "/")))]
}

// fileSizeOK: a file the scan holds in memory: 2 MiB, or 32 MiB for an
// archive.
func fileSizeOK(name string, size int64) bool {
	return size > 0 && (size <= maxUploadBytes || (archiveName(name) && size <= maxArchiveBytes))
}

// archiveKind names the container raw is, by its first bytes: "zip", "gzip",
// "tar" or "".
func archiveKind(raw []byte) string {
	switch {
	case bytes.HasPrefix(raw, []byte("PK\x03\x04")):
		return "zip"
	case bytes.HasPrefix(raw, []byte{0x1f, 0x8b}):
		return "gzip"
	case len(raw) > 262 && string(raw[257:262]) == "ustar":
		return "tar"
	}
	return ""
}

// keystoreFormat recognises a keystore by its first bytes: "jks", "jceks",
// "p12" or "".
func keystoreFormat(raw []byte) string {
	switch {
	case bytes.HasPrefix(raw, []byte{0xfe, 0xed, 0xfe, 0xed}):
		return "jks"
	case bytes.HasPrefix(raw, []byte{0xce, 0xce, 0xce, 0xce}):
		return "jceks"
	}
	// PKCS#12: SEQUENCE { INTEGER 3, ... } in BER or DER.
	if len(raw) > 8 && raw[0] == 0x30 {
		body := raw[2:]
		switch {
		case raw[1] == 0x80: // indefinite length
		case raw[1]&0x80 != 0:
			n := int(raw[1] & 0x7f)
			if n > 4 || len(raw) < 2+n+3 {
				return ""
			}
			body = raw[2+n:]
		}
		if bytes.HasPrefix(body, []byte{0x02, 0x01, 0x03}) {
			return "p12"
		}
	}
	return ""
}

var keyMarkers = [][]byte{
	[]byte("-----BEGIN "), []byte("openssh-key-v1"), []byte("PuTTY-User-Key-File"),
	[]byte("ssh-rsa AAAA"), []byte("ssh-ed25519 AAAA"), []byte("ecdsa-sha2-nistp"), []byte("ssh-dss AAAA"),
}

// looksLikeKeyMaterial: the start of a file that may hold keys or
// certificates, or is an archive that may: worth reading in full.
func looksLikeKeyMaterial(head []byte) bool {
	if keystoreFormat(head) != "" || archiveKind(head) != "" {
		return true
	}
	for _, m := range keyMarkers {
		if bytes.Contains(head, m) {
			return true
		}
	}
	// A DER certificate or key: SEQUENCE of SEQUENCE, long form.
	return len(head) > 8 && head[0] == 0x30 && head[1] == 0x82 && head[4] == 0x30
}

// member is one file read out of an archive. name is its path from the
// outermost archive: inner.zip!/keys/server.key.
type member struct {
	name string
	raw  []byte
}

// memberWanted: an archive member small enough to hold: 2 MiB, or 32 MiB
// when its name says it is an archive itself. What is kept of it is decided
// once it is read (keepMember).
func memberWanted(name string, size int64) bool {
	return fileSizeOK(name, size) && !strings.HasSuffix(name, "/") && !skippedPath(name)
}

// keepMember: read by name, or holding key material by content.
func keepMember(name string, raw []byte) bool {
	return (codeScanFile(path.Base(name)) && !archiveName(name)) || looksLikeKeyMaterial(raw[:min(len(raw), sniffBytes)])
}

// expansion is one outermost archive being opened. Its counts cover the
// whole tree, so an archive inside an archive draws on the same allowance
// as its parent and nesting can't multiply what is unpacked.
type expansion struct {
	out     []member
	entries int
	bytes   int64 // read out of archives, at every level
	full    bool  // a cap was reached: stop
	err     error // the first problem, or errArchiveTooLarge
}

func (x *expansion) fail(err error) {
	if x.err == nil || err == errArchiveTooLarge {
		x.err = err
	}
	x.full = x.full || err == errArchiveTooLarge
}

// take counts n more bytes read and one more entry when entry is set.
func (x *expansion) take(n int64, entry bool) bool {
	if entry {
		x.entries++
	}
	if x.bytes += n; x.bytes > maxArchiveExpanded || x.entries > maxArchiveEntries {
		x.fail(errArchiveTooLarge)
	}
	return !x.full
}

// budgetReader counts what is read through it against the expansion.
type budgetReader struct {
	r io.Reader
	x *expansion
}

func (b budgetReader) Read(p []byte) (int, error) {
	n, err := b.r.Read(p)
	if n > 0 && !b.x.take(int64(n), false) {
		return n, errArchiveTooLarge
	}
	return n, err
}

// expandArchive reads the members of a zip, tar, gzipped tar or gzipped
// file that the parser reads, opening archives inside it down to
// maxArchiveDepth. raw that is not an archive returns nil, nil. Over a cap,
// or with a damaged or too deeply nested archive inside, it returns what it
// read and the error.
func expandArchive(name string, raw []byte) ([]member, error) {
	x := &expansion{}
	x.open("", name, raw, 1)
	return x.out, x.err
}

func (x *expansion) open(prefix, name string, raw []byte, depth int) {
	switch archiveKind(raw) {
	case "zip":
		x.zip(prefix, raw, depth)
	case "gzip":
		x.gzip(prefix, name, raw, depth)
	case "tar":
		x.tar(prefix, bytes.NewReader(raw), depth)
	}
}

// add takes one member read at depth: an archive is opened in its place,
// anything else is kept if the parser reads it.
func (x *expansion) add(prefix, name string, body []byte, depth int) {
	if archiveKind(body) != "" && keystoreFormat(body) == "" {
		if depth >= maxArchiveDepth {
			x.fail(errArchiveTooDeep)
			return
		}
		x.open(prefix+name+"!/", name, body, depth+1)
		return
	}
	if len(body) <= maxUploadBytes && keepMember(name, body) {
		x.out = append(x.out, member{prefix + name, body})
	}
}

func (x *expansion) zip(prefix string, raw []byte, depth int) {
	zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		x.fail(errors.New("the zip archive is damaged"))
		return
	}
	for _, f := range zr.File {
		if x.full {
			return
		}
		name := path.Clean(strings.ReplaceAll(f.Name, "\\", "/"))
		if !x.take(0, true) {
			return
		}
		if f.FileInfo().IsDir() || !memberWanted(name, int64(f.UncompressedSize64)) {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			continue // an encrypted or unsupported member
		}
		// The header's size is the archive's claim; read no more than the
		// limit for its name, whatever it says.
		limit := int64(maxUploadBytes)
		if archiveName(name) {
			limit = maxArchiveBytes
		}
		body, err := io.ReadAll(io.LimitReader(budgetReader{rc, x}, limit+1))
		rc.Close() //nolint:errcheck
		if x.full {
			return
		}
		if err != nil || int64(len(body)) > limit {
			continue
		}
		x.add(prefix, name, body, depth)
	}
}

// tarHeader: a 512-byte block that is a tar header, by its checksum (the
// "ustar" magic is absent from old archives).
func tarHeader(block []byte) bool {
	if len(block) < 512 {
		return false
	}
	want, err := strconv.ParseInt(strings.Trim(string(block[148:156]), " \x00"), 8, 64)
	if err != nil {
		return false
	}
	var sum int64
	for i, c := range block[:512] {
		if i >= 148 && i < 156 {
			c = ' '
		}
		sum += int64(c)
	}
	return sum == want
}

// gzip opens a gzipped tar, or a single gzipped file (server.key.gz), which
// is read as the file its name says without ".gz".
func (x *expansion) gzip(prefix, name string, raw []byte, depth int) {
	gz, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		return
	}
	defer gz.Close() //nolint:errcheck
	br := bufio.NewReaderSize(budgetReader{gz, x}, 4096)
	if head, _ := br.Peek(512); tarHeader(head) {
		x.tar(prefix, br, depth)
		return
	}
	body, err := io.ReadAll(io.LimitReader(br, maxArchiveBytes+1))
	if err != nil || x.full || len(body) == 0 || len(body) > maxArchiveBytes || !x.take(0, true) {
		return
	}
	inner := strings.TrimSuffix(path.Base(strings.ReplaceAll(name, "\\", "/")), path.Ext(name))
	if inner == "" || inner == "." || inner == "/" {
		inner = "content"
	}
	x.add(prefix, inner, body, depth)
}

func (x *expansion) tar(prefix string, r io.Reader, depth int) {
	if _, counted := r.(*bufio.Reader); !counted {
		r = budgetReader{r, x}
	}
	tr := tar.NewReader(r)
	for first := true; ; first = false {
		h, err := tr.Next()
		if err == io.EOF || x.full {
			return
		}
		if err != nil {
			if !first {
				x.fail(errors.New("the tar archive ended early or is damaged"))
			}
			return
		}
		if !x.take(0, true) {
			return
		}
		name := path.Clean(h.Name)
		if h.Typeflag != tar.TypeReg || !memberWanted(name, h.Size) {
			continue
		}
		body := make([]byte, h.Size)
		if _, err := io.ReadFull(tr, body); err != nil {
			if !x.full {
				x.fail(errors.New("the tar archive ended early or is damaged"))
			}
			return
		}
		x.add(prefix, name, body, depth)
	}
}

// fileAssets inventories one file: the file itself, or, when it is an
// archive, each member the parser reads. file names it in asset locations.
// An archive over its caps yields what was read and the error.
func (s *Service) fileAssets(tenantID, scanID, source, file, name string, raw []byte) ([]CryptoAsset, error) {
	out, _, err := s.fileAssetsIn(fileRef{}, tenantID, scanID, source, file, name, raw)
	return out, err
}

// fileAssetsIn is fileAssets for a file of a scan unit (usage_unit.go). On
// its own (no unit) an archive is its own unit: its members can read each
// other's constants.
func (s *Service) fileAssetsIn(ref fileRef, tenantID, scanID, source, file, name string, raw []byte) ([]CryptoAsset, fileUsage, error) {
	if archiveKind(raw) == "" || keystoreFormat(raw) != "" {
		found, usage := findMaterialIn(ref, file, name, raw)
		return s.materialAssets(tenantID, scanID, source, file, found), usage, nil
	}
	own := ref.unit == nil
	if own {
		ref.unit = newUsageUnit()
	}
	members, err := expandArchive(name, raw)
	var (
		out   []CryptoAsset
		usage fileUsage
	)
	outer := ref.tag
	for _, m := range members {
		member := ref
		member.tag = func(a CryptoAsset) {
			if outer != nil {
				outer(a)
			}
			a.Metadata["archive"], a.Metadata["member"] = file, m.name
		}
		found, u := findMaterialIn(member, file+"!/"+m.name, m.name, m.raw)
		usage.merge(u)
		for _, a := range s.materialAssets(tenantID, scanID, source, file+"!/"+m.name, found) {
			a.Metadata["archive"], a.Metadata["member"] = file, m.name
			out = append(out, a)
		}
	}
	if own {
		late, _ := s.unitAssets(ref.unit, tenantID, scanID, source)
		out = append(out, late...)
	}
	return out, usage, err
}
