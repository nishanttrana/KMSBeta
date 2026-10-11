package main

import (
	"encoding/hex"
	"sort"
	"strings"
	"sync"

	pkgcrypto "vecta-kms/pkg/crypto"
)

// usageUnit is what the files of one scan share (9.2.0-beta): a repository,
// the workspace, an archive, or a bucket. A constant one file defines can
// name the algorithm in a call in another, so each file's exported
// constants go into the unit, and the statements that read a constant the
// file itself does not define are kept, in memory only, until the unit has
// seen every file. resolve then reads them again with the whole table.
//
// Nothing here is stored: a bucket, whose objects are read over many scans,
// records only each object's constants and the names it could not resolve
// (types.go BucketObject), and reads an object again when what those names
// stand for has changed.
type usageUnit struct {
	mu      sync.Mutex
	exports map[string][]constValue // each with the file that defines it
	byFile  map[string][]string     // the names each file exports
	pending []pendingStatement
	held    int // bytes of pending statements
}

// maxPendingBytes bounds the statements a unit holds for its second look.
// Beyond it, later files resolve only against their own names.
const maxPendingBytes = 8 << 20

type pendingStatement struct {
	ref   fileRef
	file  string // as in asset locations
	ext   string
	st    statement
	local map[string][]constValue
}

// fileRef says which unit a file belongs to and how its assets are marked.
// The zero value is a file on its own.
type fileRef struct {
	unit  *usageUnit
	owner string            // what the file belongs to in the unit (a bucket's object key)
	tag   func(CryptoAsset) // the caller's own metadata, applied to assets found later too
}

// fileUsage is what a file contributes to its unit.
type fileUsage struct {
	exports map[string][]string // constants other files may read
	needs   []string            // constant names it reads and does not define
}

func (u *fileUsage) merge(v fileUsage) {
	for name, lits := range v.exports {
		if u.exports == nil {
			u.exports = map[string][]string{}
		}
		u.exports[name] = append(u.exports[name], lits...)
	}
	u.needs = append(u.needs, v.needs...)
}

func newUsageUnit() *usageUnit {
	return &usageUnit{exports: map[string][]constValue{}, byFile: map[string][]string{}}
}

// define records the constants file exports, replacing what it exported
// when it was last read.
func (u *usageUnit) define(file string, exports map[string][]string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	for _, name := range u.byFile[file] {
		kept := u.exports[name][:0]
		for _, v := range u.exports[name] {
			if v.file != file {
				kept = append(kept, v)
			}
		}
		if len(kept) == 0 {
			delete(u.exports, name)
		} else {
			u.exports[name] = kept
		}
	}
	delete(u.byFile, file)
	u.add(file, exports)
}

func (u *usageUnit) add(file string, exports map[string][]string) {
	for name, lits := range exports {
		u.byFile[file] = append(u.byFile[file], name)
		for _, lit := range lits {
			u.exports[name] = append(u.exports[name], constValue{lit: lit, file: file})
		}
	}
}

// seed adds constants a file exported when it was read in an earlier scan.
func (u *usageUnit) seed(file string, exports map[string][]string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.add(file, exports)
}

// visible is what names stand for to file: every other file's constants,
// one entry per distinct value.
func (u *usageUnit) visible(file string, names []string) map[string][]constValue {
	u.mu.Lock()
	defer u.mu.Unlock()
	out := map[string][]constValue{}
	for _, name := range names {
		seen := map[string]bool{}
		for _, v := range u.exports[name] {
			// Not its own: the file, or a member of it when it is an archive.
			if v.file != file && !strings.HasPrefix(v.file, file+"!/") && !seen[v.lit] {
				seen[v.lit] = true
				out[name] = append(out[name], v)
			}
		}
		sort.Slice(out[name], func(i, j int) bool { return out[name][i].lit < out[name][j].lit })
	}
	return out
}

// needsHash names what file's unresolved constants stand for now. A bucket
// object is read again when it changes.
func (u *usageUnit) needsHash(file string, needs []string) string {
	if u == nil || len(needs) == 0 {
		return ""
	}
	sorted := append([]string(nil), needs...)
	sort.Strings(sorted)
	var sb strings.Builder
	table := u.visible(file, sorted)
	for _, name := range sorted {
		sb.WriteString(name + "=")
		for _, v := range table[name] {
			sb.WriteString(v.lit + ",")
		}
		sb.WriteByte(';')
	}
	return hex.EncodeToString(pkgcrypto.SHA256([]byte(sb.String()))[:8])
}

// usageScan applies the usage rules to a file with the names it defines
// itself. In a unit it also hands over its constants and keeps the
// statements another file's constant might complete.
func usageScan(ext string, raw []byte, ref fileRef, file string) ([]finding, fileUsage) {
	sts := statements(ext, raw)
	local, exported := fileConsts(ext, sts, raw)
	var (
		out   []finding
		usage fileUsage
		needs = map[string]bool{}
	)
	for _, st := range sts {
		l := &lookup{ext: ext, local: local, needs: map[string]bool{}}
		out = append(out, scanStatement(ext, st, l, map[string]bool{})...)
		if len(l.needs) == 0 {
			continue
		}
		for name := range l.needs {
			needs[name] = true
		}
		if u := ref.unit; u != nil {
			u.mu.Lock()
			if u.held+len(st.text) <= maxPendingBytes {
				u.held += len(st.text)
				u.pending = append(u.pending, pendingStatement{ref: ref, file: file, ext: ext, st: st, local: local})
			}
			u.mu.Unlock()
		}
	}
	for name := range exported {
		for _, v := range local[name] {
			if usage.exports == nil {
				usage.exports = map[string][]string{}
			}
			usage.exports[name] = append(usage.exports[name], v.lit)
		}
	}
	for name := range needs {
		usage.needs = append(usage.needs, name)
	}
	sort.Strings(usage.needs)
	if ref.unit != nil {
		ref.unit.define(file, usage.exports)
	}
	return out, usage
}

// resolved is a finding a statement gave once the unit knew every file.
type resolved struct {
	ref  fileRef
	file string
	f    finding
}

// resolve reads the kept statements again with the constants of the whole
// unit, and returns only what that adds. It empties the unit's statements.
func (u *usageUnit) resolve() []resolved {
	u.mu.Lock()
	pending := u.pending
	u.pending, u.held = nil, 0
	u.mu.Unlock()
	var out []resolved
	for _, p := range pending {
		// What the statement gave on its own is already reported.
		seen := map[string]bool{}
		first := &lookup{ext: p.ext, local: p.local, needs: map[string]bool{}}
		scanStatement(p.ext, p.st, first, seen)
		names := make([]string, 0, len(first.needs))
		for name := range first.needs {
			names = append(names, name)
		}
		shared := u.visible(p.file, names)
		if len(shared) == 0 {
			continue
		}
		for _, f := range scanStatement(p.ext, p.st, &lookup{ext: p.ext, local: p.local, shared: shared}, seen) {
			out = append(out, resolved{ref: p.ref, file: p.file, f: f})
		}
	}
	return out
}

// unitAssets turns what resolve found into assets, marked as their files'
// other assets are.
func (s *Service) unitAssets(u *usageUnit, tenantID, scanID, source string) ([]CryptoAsset, map[string][]string) {
	var out []CryptoAsset
	byOwner := map[string][]string{}
	for _, r := range u.resolve() {
		for _, a := range s.materialAssets(tenantID, scanID, source, r.file, []finding{r.f}) {
			if r.ref.tag != nil {
				r.ref.tag(a)
			}
			out = append(out, a)
			byOwner[r.ref.owner] = append(byOwner[r.ref.owner], a.ID)
		}
	}
	return out, byOwner
}
