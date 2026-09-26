package hsmconnector

import (
	"context"
	"encoding/hex"
	"io"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	pkgaudit "vecta-kms/pkg/audit"
	pkgcrypto "vecta-kms/pkg/crypto"
	"vecta-kms/pkg/route"
)

// Files uploaded over SSH/SFTP to hsm-integration can't pass through the
// audit pipeline where they arrive (a plain sshd). This process is the one
// that loads them, so it records what is there: an inventory at start, then
// every file added, changed or removed, with its SHA-256
// (docs/SECURITY/HSM_INTEGRATION.md). Subjects: audit.hsm.provider_library_*.

type libFile struct {
	size    int64
	modTime time.Time
	sha256  string
}

type libraryWatcher struct {
	roots []string
	emit  route.Emitter
	logf  func(string, ...interface{})
	seen  map[string]libFile
}

// WatchLibraries audits the provider workspaces under the library roots
// until ctx ends, rescanning every interval.
func WatchLibraries(ctx context.Context, emit route.Emitter, interval time.Duration, logger *log.Logger) {
	w := &libraryWatcher{roots: libraryRoots(), emit: emit, logf: logger.Printf}
	w.scan(ctx)
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			w.scan(ctx)
		}
	}
}

func (w *libraryWatcher) scan(ctx context.Context) {
	now := map[string]libFile{}
	for _, root := range w.roots {
		_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				w.logf("hsm library scan: %v", err)
				return nil
			}
			if d.IsDir() {
				return nil
			}
			info, err := os.Stat(path) // follows a symlink, as loading would
			if err != nil || !info.Mode().IsRegular() {
				return nil
			}
			f := libFile{size: info.Size(), modTime: info.ModTime()}
			if prev, ok := w.seen[path]; ok && prev.size == f.size && prev.modTime.Equal(f.modTime) {
				f.sha256 = prev.sha256
			} else {
				f.sha256 = fileSHA256(path)
			}
			now[path] = f
			return nil
		})
	}
	if w.seen == nil {
		w.inventory(ctx, now)
	} else {
		w.diff(ctx, now)
	}
	w.seen = now
}

// inventory is emitted once per start: a change made while the connector
// was down shows as a difference between two inventories.
func (w *libraryWatcher) inventory(ctx context.Context, files map[string]libFile) {
	byTenant := map[string][]map[string]interface{}{}
	for path, f := range files {
		tenant := w.tenantOf(path)
		byTenant[tenant] = append(byTenant[tenant], map[string]interface{}{"path": path, "sha256": f.sha256, "size": f.size})
	}
	tenants := make([]string, 0, len(byTenant))
	for t := range byTenant {
		tenants = append(tenants, t)
	}
	sort.Strings(tenants)
	for _, t := range tenants {
		w.event(ctx, "provider_library_inventory", t, "", map[string]interface{}{"files": byTenant[t], "file_count": len(byTenant[t])})
	}
}

func (w *libraryWatcher) diff(ctx context.Context, now map[string]libFile) {
	for path, f := range now {
		prev, ok := w.seen[path]
		switch {
		case !ok:
			w.event(ctx, "provider_library_added", w.tenantOf(path), path, map[string]interface{}{"sha256": f.sha256, "size": f.size})
		case prev.sha256 != f.sha256:
			w.event(ctx, "provider_library_changed", w.tenantOf(path), path, map[string]interface{}{"sha256": f.sha256, "previous_sha256": prev.sha256, "size": f.size})
		}
	}
	for path, prev := range w.seen {
		if _, ok := now[path]; !ok {
			w.event(ctx, "provider_library_removed", w.tenantOf(path), path, map[string]interface{}{"previous_sha256": prev.sha256})
		}
	}
}

func (w *libraryWatcher) event(ctx context.Context, action, tenant, path string, details map[string]interface{}) {
	if w.emit == nil {
		return
	}
	details["tenant_slug"] = tenant
	details["channel"] = "hsm-integration ssh/sftp"
	_ = w.emit.Emit(ctx, action, pkgaudit.Event{
		TenantID: tenant, ActorID: "kms-hsm", ActorType: "service",
		TargetType: "pkcs11_library", TargetID: path, Result: "success", Details: details,
	})
}

// tenantOf: <root>/<tenant-slug>/..., the layout install-provider.sh uses.
func (w *libraryWatcher) tenantOf(path string) string {
	for _, root := range w.roots {
		if rel, err := filepath.Rel(root, path); err == nil && !strings.HasPrefix(rel, "..") {
			if first, _, found := strings.Cut(filepath.ToSlash(rel), "/"); found && first != "" {
				return first
			}
		}
	}
	return "root"
}

// maxHashedLibrary bounds the memory a scan uses; vendor PKCS#11 libraries
// and client files are far smaller.
const maxHashedLibrary = 256 << 20

func fileSHA256(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return "unreadable"
	}
	defer f.Close() //nolint:errcheck
	data, err := io.ReadAll(io.LimitReader(f, maxHashedLibrary+1))
	if err != nil {
		return "unreadable"
	}
	if len(data) > maxHashedLibrary {
		return "too_large"
	}
	return hex.EncodeToString(pkgcrypto.SHA256(data))
}
