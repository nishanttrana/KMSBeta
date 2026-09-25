// Package clusterrepl drives Postgres logical replication for KMS clustering
// (docs/CLUSTERING.md). The primary publishes one publication per component
// (pkg/clustercatalog); a member subscribes only to the components it was
// assigned. Node-local tables are never published because only catalogue
// tables of a component are ever added to its publication.
package clusterrepl

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"vecta-kms/pkg/clustercatalog"
)

type Engine struct {
	db *sql.DB
}

func New(db *sql.DB) *Engine { return &Engine{db: db} }

// quoteIdent quotes a Postgres identifier.
func quoteIdent(s string) string { return `"` + strings.ReplaceAll(s, `"`, `""`) + `"` }

// quoteLiteral quotes a Postgres string literal.
func quoteLiteral(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

func knownComponent(c string) bool {
	_, ok := clustercatalog.Replicated[c]
	return ok
}

// existingTables returns which of the given tables exist in schema public.
func (e *Engine) existingTables(ctx context.Context, tables []string) ([]string, error) {
	if len(tables) == 0 {
		return nil, nil
	}
	rows, err := e.db.QueryContext(ctx, `SELECT tablename FROM pg_tables WHERE schemaname = 'public'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	have := map[string]bool{}
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		have[n] = true
	}
	out := []string{}
	for _, t := range tables {
		if have[t] {
			out = append(out, t)
		}
	}
	sort.Strings(out)
	return out, rows.Err()
}

func (e *Engine) publicationTables(ctx context.Context, pub string) ([]string, error) {
	rows, err := e.db.QueryContext(ctx, `SELECT tablename FROM pg_publication_tables WHERE pubname = $1 ORDER BY tablename`, pub)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := []string{}
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// Publications lists the vecta_pub_* publications and their tables.
func (e *Engine) Publications(ctx context.Context) ([]PublicationStatus, error) {
	rows, err := e.db.QueryContext(ctx, `
SELECT p.pubname, COALESCE(pt.tablename, '')
FROM pg_publication p LEFT JOIN pg_publication_tables pt ON pt.pubname = p.pubname
WHERE p.pubname LIKE 'vecta_pub_%'
ORDER BY p.pubname, pt.tablename`)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := []PublicationStatus{}
	for rows.Next() {
		var pub, table string
		if err := rows.Scan(&pub, &table); err != nil {
			return nil, err
		}
		if len(out) == 0 || out[len(out)-1].Publication != pub {
			out = append(out, PublicationStatus{Publication: pub, Component: strings.TrimPrefix(pub, "vecta_pub_"), Tables: []string{}})
		}
		if table != "" {
			out[len(out)-1].Tables = append(out[len(out)-1].Tables, table)
		}
	}
	return out, rows.Err()
}

type PublicationStatus struct {
	Component   string   `json:"component"`
	Publication string   `json:"publication"`
	Tables      []string `json:"tables"`
	// Changed is set by EnsurePublications when it created the publication or
	// changed its table set (callers audit it).
	Changed bool `json:"-"`
}

// EnsurePublications creates or updates one publication per component with
// the component's tables that exist on this node. Safe to run repeatedly
// (services create their tables at their own startup).
func (e *Engine) EnsurePublications(ctx context.Context, components []string) ([]PublicationStatus, error) {
	out := []PublicationStatus{}
	for _, c := range components {
		if !knownComponent(c) {
			continue // component owns no tables
		}
		tables, err := e.existingTables(ctx, clustercatalog.Tables(c))
		if err != nil {
			return nil, err
		}
		pub := clustercatalog.PublicationName(c)
		if len(tables) == 0 {
			continue
		}
		quoted := make([]string, len(tables))
		for i, t := range tables {
			quoted[i] = quoteIdent(t)
		}
		var exists bool
		if err := e.db.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM pg_publication WHERE pubname = $1)`, pub).Scan(&exists); err != nil {
			return nil, err
		}
		current, err := e.publicationTables(ctx, pub)
		if err != nil {
			return nil, err
		}
		changed := !exists || strings.Join(current, ",") != strings.Join(tables, ",")
		if changed {
			stmt := fmt.Sprintf("CREATE PUBLICATION %s FOR TABLE %s WITH (publish_via_partition_root = true)", quoteIdent(pub), strings.Join(quoted, ", "))
			if exists {
				stmt = fmt.Sprintf("ALTER PUBLICATION %s SET TABLE %s", quoteIdent(pub), strings.Join(quoted, ", "))
			}
			if _, err := e.db.ExecContext(ctx, stmt); err != nil {
				return nil, fmt.Errorf("publication %s: %w", pub, err)
			}
		}
		out = append(out, PublicationStatus{Component: c, Publication: pub, Tables: tables, Changed: changed})
	}
	return out, nil
}

// SubscribeOptions controls how a member subscribes to a component.
type SubscribeOptions struct {
	// ResetLocalData truncates the member's copy of the component's tables
	// before the initial copy. Required on a freshly installed member, whose
	// bootstrap rows (e.g. the root tenant) would otherwise collide with the
	// primary's. Never set it on a node that holds data you need.
	ResetLocalData bool
}

// Subscribe makes this node receive a component from the primary described by
// conninfo (a libpq connection string to the primary's database).
func (e *Engine) Subscribe(ctx context.Context, nodeID, component, conninfo string, opts SubscribeOptions) error {
	if !knownComponent(component) {
		return fmt.Errorf("component %q owns no replicated tables", component)
	}
	want := clustercatalog.Tables(component)
	tables, err := e.existingTables(ctx, want)
	if err != nil {
		return err
	}
	if len(tables) == 0 {
		return fmt.Errorf("component %s: none of its tables exist on this node; start its service first", component)
	}
	if opts.ResetLocalData {
		quoted := make([]string, len(tables))
		for i, t := range tables {
			quoted[i] = quoteIdent(t)
		}
		if _, err := e.db.ExecContext(ctx, "TRUNCATE "+strings.Join(quoted, ", ")+" CASCADE"); err != nil {
			return fmt.Errorf("reset %s: %w", component, err)
		}
	}
	sub := clustercatalog.SubscriptionName(nodeID, component)
	stmt := fmt.Sprintf("CREATE SUBSCRIPTION %s CONNECTION %s PUBLICATION %s WITH (copy_data = true, slot_name = %s)",
		quoteIdent(sub), quoteLiteral(conninfo), quoteIdent(clustercatalog.PublicationName(component)), quoteLiteral(sub))
	if _, err := e.db.ExecContext(ctx, stmt); err != nil {
		return fmt.Errorf("subscription %s: %w", sub, err)
	}
	return nil
}

// Unsubscribe stops receiving a component and drops the replication slot on
// the primary.
func (e *Engine) Unsubscribe(ctx context.Context, nodeID, component string) error {
	sub := clustercatalog.SubscriptionName(nodeID, component)
	_, err := e.db.ExecContext(ctx, "DROP SUBSCRIPTION IF EXISTS "+quoteIdent(sub))
	return err
}

type TableSyncState struct {
	Table string `json:"table"`
	// State: initializing, copying, syncing, ready (pg_subscription_rel.srsubstate).
	State string `json:"state"`
}

type SubscriptionStatus struct {
	Subscription  string           `json:"subscription"`
	Component     string           `json:"component"`
	Enabled       bool             `json:"enabled"`
	WorkerRunning bool             `json:"worker_running"`
	LastMessageAt time.Time        `json:"last_message_at,omitempty"`
	LagSeconds    float64          `json:"lag_seconds"`
	Tables        []TableSyncState `json:"tables"`
	Ready         bool             `json:"ready"`
}

func syncStateName(code string) string {
	switch code {
	case "i":
		return "initializing"
	case "d":
		return "copying"
	case "f", "s":
		return "syncing"
	case "r":
		return "ready"
	}
	return code
}

// SubscriptionStatuses reports the real state of this node's subscriptions:
// whether the apply worker runs, per-table copy state and apply lag.
func (e *Engine) SubscriptionStatuses(ctx context.Context, nodeID string) ([]SubscriptionStatus, error) {
	prefix := strings.TrimSuffix(clustercatalog.SubscriptionName(nodeID, "x"), "x")
	rows, err := e.db.QueryContext(ctx, `
SELECT s.subname, s.subenabled, st.pid IS NOT NULL, st.last_msg_receipt_time,
       COALESCE(EXTRACT(EPOCH FROM (now() - st.latest_end_time)), 0)
FROM pg_subscription s
LEFT JOIN pg_stat_subscription st ON st.subid = s.oid AND st.relid IS NULL
WHERE s.subname LIKE $1
ORDER BY s.subname`, prefix+"%")
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := []SubscriptionStatus{}
	for rows.Next() {
		var (
			st   SubscriptionStatus
			last sql.NullTime
		)
		if err := rows.Scan(&st.Subscription, &st.Enabled, &st.WorkerRunning, &last, &st.LagSeconds); err != nil {
			return nil, err
		}
		if last.Valid {
			st.LastMessageAt = last.Time
		}
		st.Component = strings.TrimPrefix(st.Subscription, prefix)
		out = append(out, st)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		trows, err := e.db.QueryContext(ctx, `
SELECT c.relname, r.srsubstate
FROM pg_subscription_rel r
JOIN pg_subscription s ON s.oid = r.srsubid
JOIN pg_class c ON c.oid = r.srrelid
WHERE s.subname = $1 ORDER BY c.relname`, out[i].Subscription)
		if err != nil {
			return nil, err
		}
		ready := true
		for trows.Next() {
			var ts TableSyncState
			var code string
			if err := trows.Scan(&ts.Table, &code); err != nil {
				trows.Close() //nolint:errcheck
				return nil, err
			}
			ts.State = syncStateName(code)
			ready = ready && code == "r"
			out[i].Tables = append(out[i].Tables, ts)
		}
		trows.Close() //nolint:errcheck
		out[i].Ready = ready && len(out[i].Tables) > 0 && out[i].WorkerRunning
	}
	return out, nil
}

// WaitReady blocks until every subscription of nodeID is ready or ctx ends.
func (e *Engine) WaitReady(ctx context.Context, nodeID string) error {
	for {
		sts, err := e.SubscriptionStatuses(ctx, nodeID)
		if err != nil {
			return err
		}
		ready := len(sts) > 0
		for _, s := range sts {
			ready = ready && s.Ready
		}
		if ready {
			return nil
		}
		select {
		case <-ctx.Done():
			return errors.New("replication did not become ready: " + ctx.Err().Error())
		case <-time.After(500 * time.Millisecond):
		}
	}
}

// WALLevel reports the server's wal_level; logical replication needs "logical".
func (e *Engine) WALLevel(ctx context.Context) (string, error) {
	var v string
	err := e.db.QueryRowContext(ctx, `SHOW wal_level`).Scan(&v)
	return v, err
}
