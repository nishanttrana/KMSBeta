package main

// KeyVersionRef is a parsed reference to a specific generation of a key.
// Callers can address `key.id` for "current" or `key.id@N` for "version N";
// the API endpoint and KMIP layer both normalise to this struct so the
// rest of the keycore code doesn't care about the syntax.
type KeyVersionRef struct {
	KeyID    string
	Version  int  // 0 = current
	Explicit bool // true when caller named a specific version
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
