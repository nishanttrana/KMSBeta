package main

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// Content sourcing for the leak scanner. Two safe sources only: content
// submitted inline with the scan request, and files under an operator-
// configured root (LEAK_SCAN_ROOT). There is deliberately no network fetch —
// pulling remote git repos, container images, S3 objects or log streams needs
// credentialed fetchers that are an explicit future integration, not silent
// fabrication. Target types without a usable source fail the job honestly.

const (
	maxScanFileBytes = 5 << 20 // 5 MiB per file
	maxScanFiles     = 5000
)

type scanItem struct {
	path string
	data []byte
}

// gatherScanContent resolves a target (plus optional inline content) into the
// set of (path, bytes) items to run detectors over.
func gatherScanContent(target LeakScanTarget, inlineContent, inlineName string) ([]scanItem, error) {
	if strings.TrimSpace(inlineContent) != "" {
		name := firstNonEmptyStr(strings.TrimSpace(inlineName), target.Name, "submitted-content")
		return []scanItem{{path: name, data: []byte(inlineContent)}}, nil
	}
	return gatherLocalContent(target)
}

func gatherLocalContent(target LeakScanTarget) ([]scanItem, error) {
	root := strings.TrimSpace(os.Getenv("LEAK_SCAN_ROOT"))
	if root == "" {
		return nil, fmt.Errorf("no content source available for %s target %q: submit inline content, or set LEAK_SCAN_ROOT to scan mounted paths", target.Type, target.Name)
	}
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}

	rel := strings.TrimPrefix(target.URI, "file://")
	if strings.Contains(target.URI, "://") && !strings.HasPrefix(target.URI, "file://") {
		return nil, fmt.Errorf("remote %s fetching is not configured; only file:// and mounted paths under LEAK_SCAN_ROOT are scanned", target.Type)
	}
	var p string
	if filepath.IsAbs(rel) {
		p = filepath.Clean(rel)
	} else {
		p = filepath.Join(rootAbs, filepath.Clean("/"+rel))
	}
	pAbs, err := filepath.Abs(p)
	if err != nil {
		return nil, err
	}
	// Containment: the resolved path must be the root itself or under it.
	if pAbs != rootAbs && !strings.HasPrefix(pAbs, rootAbs+string(os.PathSeparator)) {
		return nil, fmt.Errorf("target path escapes the configured scan root")
	}

	info, err := os.Stat(pAbs)
	if err != nil {
		return nil, fmt.Errorf("cannot access target path: %w", err)
	}
	if !info.IsDir() {
		data, err := readScanFile(pAbs)
		if err != nil {
			return nil, err
		}
		return []scanItem{{path: relPath(rootAbs, pAbs), data: data}}, nil
	}

	var items []scanItem
	count := 0
	walkErr := filepath.WalkDir(pAbs, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if skipScanDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if count >= maxScanFiles {
			return filepath.SkipAll
		}
		if !d.Type().IsRegular() {
			return nil
		}
		data, rerr := readScanFile(path)
		if rerr != nil {
			return nil // unreadable/oversized files are skipped, not fatal
		}
		if looksBinary(data) {
			return nil
		}
		items = append(items, scanItem{path: relPath(rootAbs, path), data: data})
		count++
		return nil
	})
	if walkErr != nil {
		return nil, walkErr
	}
	return items, nil
}

func readScanFile(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.Size() > maxScanFileBytes {
		return nil, fmt.Errorf("file exceeds scan size limit")
	}
	return os.ReadFile(path) //nolint:gosec // path is contained under the configured scan root
}

func skipScanDir(name string) bool {
	switch name {
	case ".git", ".hg", ".svn", "node_modules", "vendor", "dist", "build",
		".terraform", ".venv", "__pycache__", ".idea", ".gradle", "target":
		return true
	}
	return false
}

// looksBinary reports whether the leading bytes contain a NUL, a cheap and
// effective binary-file heuristic.
func looksBinary(data []byte) bool {
	n := len(data)
	if n > 512 {
		n = 512
	}
	return bytes.IndexByte(data[:n], 0) >= 0
}

func relPath(root, path string) string {
	if rel, err := filepath.Rel(root, path); err == nil {
		return rel
	}
	return path
}

func firstNonEmptyStr(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
