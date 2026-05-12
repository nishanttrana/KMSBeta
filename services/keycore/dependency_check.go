package main

import (
	"context"
	"errors"
	"strings"
)

// KeyDependency represents one downstream consumer of a key. Destroying
// a key while dependencies still exist would silently break those
// consumers; the destroy handler rejects with the list so the operator
// can revoke or migrate them first.
type KeyDependency struct {
	Kind        string `json:"kind"`         // "kmip_client", "ekm_connector", "escrow_holder", "audit_webhook"
	ID          string `json:"id"`
	Description string `json:"description,omitempty"`
}

// DependencyChecker resolves a key's live dependencies. The handler
// surfaces them in the 409 response when destroy is rejected; the
// reconciler uses them to refuse the auto-promote-to-destroyed step
// when dependencies still exist.
type DependencyChecker interface {
	Dependencies(ctx context.Context, tenantID, keyID string) ([]KeyDependency, error)
}

// ErrKeyHasDependencies is returned by destroy paths when downstream
// consumers still reference the key. It carries the list so the caller
// can render a helpful error.
type ErrKeyHasDependencies struct {
	Deps []KeyDependency
}

func (e ErrKeyHasDependencies) Error() string {
	if len(e.Deps) == 0 {
		return "key has unresolved dependencies"
	}
	parts := make([]string, 0, len(e.Deps))
	for _, d := range e.Deps {
		parts = append(parts, d.Kind+":"+d.ID)
	}
	return "key has unresolved dependencies: " + strings.Join(parts, ", ")
}

// CheckDependencies is the helper used by handler code to enforce the
// dependency check uniformly. Returns ErrKeyHasDependencies if any
// dependency is found; nil if the key is safe to destroy.
func CheckDependencies(ctx context.Context, checker DependencyChecker, tenantID, keyID string) error {
	if checker == nil {
		return nil
	}
	deps, err := checker.Dependencies(ctx, tenantID, keyID)
	if err != nil {
		return err
	}
	if len(deps) == 0 {
		return nil
	}
	return ErrKeyHasDependencies{Deps: deps}
}

// NoopDependencyChecker is the default when no live registry is wired up.
// It returns no dependencies and is safe to use during development —
// production deployments wire in a real checker via SetDependencyChecker.
type NoopDependencyChecker struct{}

func (NoopDependencyChecker) Dependencies(_ context.Context, _ string, _ string) ([]KeyDependency, error) {
	return nil, nil
}

// IsDependencyErr unwraps the sentinel for callers that need to switch on
// the type without depending on errors.As semantics.
func IsDependencyErr(err error) (ErrKeyHasDependencies, bool) {
	var e ErrKeyHasDependencies
	if errors.As(err, &e) {
		return e, true
	}
	return ErrKeyHasDependencies{}, false
}
