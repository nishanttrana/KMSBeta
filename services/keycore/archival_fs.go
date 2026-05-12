package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Put writes a versioned archive blob into the filesystem store.
func (s *FilesystemArchiveStore) Put(ctx context.Context, tenantID, keyID string, version int, blob []byte) error {
	dir := s.dir(tenantID, keyID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp := filepath.Join(dir, fmt.Sprintf(".v%d.tmp", version))
	if err := os.WriteFile(tmp, blob, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(dir, fmt.Sprintf("v%d.bin", version)))
}

// Get reads a versioned archive blob.
func (s *FilesystemArchiveStore) Get(ctx context.Context, tenantID, keyID string, version int) ([]byte, error) {
	return os.ReadFile(filepath.Join(s.dir(tenantID, keyID), fmt.Sprintf("v%d.bin", version)))
}

// Delete removes a versioned archive blob. Missing files are not an error;
// the call is idempotent so reconciler retries are safe.
func (s *FilesystemArchiveStore) Delete(ctx context.Context, tenantID, keyID string, version int) error {
	err := os.Remove(filepath.Join(s.dir(tenantID, keyID), fmt.Sprintf("v%d.bin", version)))
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// List enumerates the archived versions for a key.
func (s *FilesystemArchiveStore) List(ctx context.Context, tenantID, keyID string) ([]int, error) {
	entries, err := os.ReadDir(s.dir(tenantID, keyID))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	out := make([]int, 0, len(entries))
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, "v") || !strings.HasSuffix(name, ".bin") {
			continue
		}
		v, err := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(name, "v"), ".bin"))
		if err != nil || v <= 0 {
			continue
		}
		out = append(out, v)
	}
	return out, nil
}

func (s *FilesystemArchiveStore) dir(tenantID, keyID string) string {
	// Path components are sanitised to prevent traversal: tenant and key
	// IDs are restricted to alnum + "-_" by the store.
	tID := safeFsComponent(tenantID)
	kID := safeFsComponent(keyID)
	return filepath.Join(s.Root, tID, kID)
}

func safeFsComponent(in string) string {
	var b strings.Builder
	for _, r := range in {
		switch {
		case r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9',
			r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	return b.String()
}
