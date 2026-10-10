package main

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"path"
	"strings"
)

// Reading by content, and inside archives (7.37.0-beta). Until now a file
// was read only if its name said what it was, so a keystore called
// backup.bin or a key inside release.zip was never seen.
//
//   - A keystore is recognised by its first bytes (JKS, JCEKS, PKCS#12),
//     whatever it is called.
//   - A zip (jar, war, ear), tar or gzipped tar is opened in memory and each
//     member is read by the same rules as a file beside it. Members are
//     named archive!/member. An archive inside an archive is not opened.
//   - looksLikeKeyMaterial is the test a bucket's deep scan applies to the
//     first kilobyte of an object whose name says nothing.
//
// Nothing is written to disk. The caps bound what a crafted archive can
// make the scan hold or do.

const (
	maxArchiveBytes   = 32 << 20 // an archive's own size
	maxArchiveEntries = 20000
	sniffBytes        = 1024
)

// maxArchiveExpanded caps the bytes read out of one archive (a variable so
// a test can lower it).
var maxArchiveExpanded int64 = 256 << 20

var errArchiveTooLarge = errors.New("the archive holds more entries or bytes than the scan limit")

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

// member is one file read out of an archive.
type member struct {
	name string
	raw  []byte
}

// memberWanted: an archive member the parser reads, by name; a member
// whose name says nothing is decided by its content once read.
func memberWanted(name string, size int64) bool {
	return size > 0 && size <= maxUploadBytes && !strings.HasSuffix(name, "/") && !skippedPath(name)
}

// keepMember: read by name, or holding key material by content.
func keepMember(name string, raw []byte) bool {
	return (codeScanFile(path.Base(name)) && !archiveName(name)) || looksLikeKeyMaterial(raw[:min(len(raw), sniffBytes)])
}

// expandArchive reads the members of a zip, tar or gzipped tar that the
// parser reads. raw that is not an archive returns nil, nil. Over the caps
// it returns what it read and errArchiveTooLarge.
func expandArchive(raw []byte) ([]member, error) {
	switch archiveKind(raw) {
	case "zip":
		return expandZip(raw)
	case "gzip":
		gz, err := gzip.NewReader(bytes.NewReader(raw))
		if err != nil {
			return nil, nil
		}
		defer gz.Close() //nolint:errcheck
		return expandTar(gz)
	case "tar":
		return expandTar(bytes.NewReader(raw))
	}
	return nil, nil
}

func expandZip(raw []byte) ([]member, error) {
	zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		return nil, errors.New("the zip archive is damaged")
	}
	var (
		out  []member
		used int64
	)
	for i, f := range zr.File {
		if i >= maxArchiveEntries {
			return out, errArchiveTooLarge
		}
		name := path.Clean(strings.ReplaceAll(f.Name, "\\", "/"))
		if f.FileInfo().IsDir() || !memberWanted(name, int64(f.UncompressedSize64)) {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			continue // an encrypted or unsupported member
		}
		// The header's size is the archive's claim; read no more than the
		// limit whatever it says.
		body, err := io.ReadAll(io.LimitReader(rc, maxUploadBytes+1))
		rc.Close() //nolint:errcheck
		if err != nil || len(body) > maxUploadBytes {
			continue
		}
		if used += int64(len(body)); used > maxArchiveExpanded {
			return out, errArchiveTooLarge
		}
		if keepMember(name, body) {
			out = append(out, member{name, body})
		}
	}
	return out, nil
}

func expandTar(r io.Reader) ([]member, error) {
	counted := &io.LimitedReader{R: r, N: maxArchiveExpanded + 1}
	tr := tar.NewReader(counted)
	var out []member
	for entries := 0; ; entries++ {
		h, err := tr.Next()
		if err == io.EOF {
			return out, nil
		}
		if counted.N <= 0 || entries >= maxArchiveEntries {
			return out, errArchiveTooLarge
		}
		if err != nil {
			if len(out) == 0 && entries == 0 {
				return nil, nil // gzip of something that is not a tar
			}
			return out, errors.New("the tar archive ended early or is damaged")
		}
		name := path.Clean(h.Name)
		if h.Typeflag != tar.TypeReg || !memberWanted(name, h.Size) {
			continue
		}
		body := make([]byte, h.Size)
		if _, err := io.ReadFull(tr, body); err != nil {
			if counted.N <= 0 {
				return out, errArchiveTooLarge
			}
			return out, errors.New("the tar archive ended early or is damaged")
		}
		if keepMember(name, body) {
			out = append(out, member{name, body})
		}
	}
}

// fileAssets inventories one file: the file itself, or, when it is an
// archive, each member the parser reads. file names it in asset locations.
// An archive over its caps yields what was read and the error.
func (s *Service) fileAssets(tenantID, scanID, source, file, name string, raw []byte) ([]CryptoAsset, error) {
	if archiveKind(raw) == "" || keystoreFormat(raw) != "" {
		return s.materialAssets(tenantID, scanID, source, file, findMaterial(name, raw)), nil
	}
	members, err := expandArchive(raw)
	var out []CryptoAsset
	for _, m := range members {
		for _, a := range s.materialAssets(tenantID, scanID, source, file+"!/"+m.name, findMaterial(m.name, m.raw)) {
			a.Metadata["archive"], a.Metadata["member"] = file, m.name
			out = append(out, a)
		}
	}
	return out, err
}
