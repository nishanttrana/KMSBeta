package main

import (
	"strconv"
	"strings"
)

// KeyVersionRef is a parsed reference to a specific generation of a key.
// Callers can address `key.id` for "current" or `key.id@N` for "version N";
// the API endpoint and KMIP layer both normalise to this struct so the
// rest of the keycore code doesn't care about the syntax.
type KeyVersionRef struct {
	KeyID   string
	Version int  // 0 = current
	Explicit bool // true when caller named a specific version
}

// ParseKeyRef splits "key.id" or "key.id@N" into a KeyVersionRef. Invalid
// suffixes degrade to "current" rather than erroring so callers can use
// the function defensively.
func ParseKeyRef(raw string) KeyVersionRef {
	s := strings.TrimSpace(raw)
	if s == "" {
		return KeyVersionRef{}
	}
	idx := strings.LastIndex(s, "@")
	if idx == -1 {
		return KeyVersionRef{KeyID: s}
	}
	id := s[:idx]
	suffix := strings.TrimSpace(s[idx+1:])
	if suffix == "" {
		return KeyVersionRef{KeyID: id}
	}
	n, err := strconv.Atoi(suffix)
	if err != nil || n <= 0 {
		return KeyVersionRef{KeyID: id}
	}
	return KeyVersionRef{KeyID: id, Version: n, Explicit: true}
}

// Render emits the canonical string form. Used by audit so log lines and
// API responses stay consistent.
func (r KeyVersionRef) Render() string {
	if r.KeyID == "" {
		return ""
	}
	if !r.Explicit {
		return r.KeyID
	}
	return r.KeyID + "@" + strconv.Itoa(r.Version)
}

// VersionPolicy controls how many historical versions a key retains for
// decrypt-only use after rotation. RetainCount=2 means "current + 2
// previous"; older generations are auto-archived by the reconciler.
type VersionPolicy struct {
	RetainCount int
}

// DefaultVersionPolicy keeps the current version plus three predecessors,
// which covers most rolling-deploy windows without growing the hot cache
// indefinitely.
func DefaultVersionPolicy() VersionPolicy {
	return VersionPolicy{RetainCount: 3}
}

// IsArchivable returns true when a non-current version is old enough to
// move to cold storage.
func (p VersionPolicy) IsArchivable(version, currentVersion int) bool {
	if version <= 0 || currentVersion <= 0 || version >= currentVersion {
		return false
	}
	return currentVersion-version > p.RetainCount
}
