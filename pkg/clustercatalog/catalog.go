// Package clustercatalog classifies every database table for KMS clustering
// (docs/CLUSTERING.md): replicated per component from the primary to the
// members assigned that component, node-local (never replicated), or
// shared-append (audit chains, written on every node).
package clustercatalog

import (
	"fmt"
	"sort"
	"strings"
)

// Core components are replicated to every member: without them no other
// feature works (identity, keys, policy, governance).
var Core = []string{"auth", "keycore", "policy", "governance"}

type Class string

const (
	ClassReplicated   Class = "replicated"
	ClassNodeLocal    Class = "node-local"
	ClassSharedAppend Class = "shared-append"
	ClassUnknown      Class = "unknown"
)

// RowFilters restrict a replicated table to its shared rows: rows flagged
// node_local (the node's own admin and CLI accounts, internal service
// identities) never leave the node. Each filter column is in the table's
// replica identity (auth migration 011).
var RowFilters = map[string]string{
	"auth_users":                "NOT node_local",
	"auth_client_registrations": "NOT node_local",
	"auth_api_keys":             "NOT node_local",
}

// Components returns every component that owns replicated tables, sorted.
func Components() []string {
	out := make([]string, 0, len(Replicated))
	for c := range Replicated {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

// WithCore returns components plus the core components, de-duplicated and
// sorted. Profiles may name components that own no tables (features that moved
// to the KMS Extension); they are kept and simply replicate nothing.
func WithCore(components []string) []string {
	set := map[string]bool{}
	for _, c := range append(append([]string{}, Core...), components...) {
		if c = strings.TrimSpace(c); c != "" {
			set[c] = true
		}
	}
	out := make([]string, 0, len(set))
	for c := range set {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

// Tables returns the replicated tables of a component (nil if it owns none).
func Tables(component string) []string {
	return Replicated[component]
}

// PublicationName is the Postgres publication that carries a component.
func PublicationName(component string) string {
	return "vecta_pub_" + strings.ReplaceAll(strings.TrimSpace(component), "-", "_")
}

// Ident turns a node id or component into a safe lower-case identifier part.
func Ident(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else {
			b.WriteRune('_')
		}
	}
	return b.String()
}

// SubscriptionName is the subscription a member uses for a component.
func SubscriptionName(nodeID, component string) string {
	return fmt.Sprintf("vecta_sub_%s_%s", Ident(nodeID), Ident(component))
}

// Classify returns a table's class and, for replicated tables, its component.
func Classify(table string) (Class, string) {
	table = strings.ToLower(strings.TrimSpace(table))
	for c, ts := range Replicated {
		for _, t := range ts {
			if t == table {
				return ClassReplicated, c
			}
		}
	}
	if _, ok := NodeLocal[table]; ok {
		return ClassNodeLocal, ""
	}
	if _, ok := SharedAppend[table]; ok {
		return ClassSharedAppend, ""
	}
	if strings.HasPrefix(table, "audit_events_") {
		return ClassSharedAppend, "" // monthly partitions of audit_events
	}
	return ClassUnknown, ""
}
