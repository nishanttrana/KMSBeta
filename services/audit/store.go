package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	pkgdb "vecta-kms/pkg/db"
)

var errNotFound = errors.New("not found")

type Store interface {
	PersistEvent(ctx context.Context, event AuditEvent) (AuditEvent, error)
	QueryEvents(ctx context.Context, tenantID string, q EventQuery) ([]AuditEvent, error)
	GetEvent(ctx context.Context, tenantID string, id string) (AuditEvent, error)
	VerifyChain(ctx context.Context, tenantID string) (bool, []map[string]interface{}, error)
	VerifyTarget(ctx context.Context, tenantID, targetID string, limit int) (TargetIntegrity, error)
	ListCheckpoints(ctx context.Context, tenantID string, limit int) ([]CheckpointStatus, error)

	CountDistinctIPsForTarget(ctx context.Context, tenantID string, targetID string, since time.Time) (int, error)

	// Webhook operations
	ListWebhooks(ctx context.Context, tenantID string) ([]Webhook, error)
	CreateWebhook(ctx context.Context, w Webhook) (Webhook, error)
	UpdateWebhook(ctx context.Context, tenantID string, id string, w Webhook) (Webhook, error)
	DeleteWebhook(ctx context.Context, tenantID string, id string) error
	GetWebhook(ctx context.Context, tenantID string, id string) (Webhook, error)
	RecordDelivery(ctx context.Context, d WebhookDelivery) error
	ListDeliveries(ctx context.Context, tenantID string, webhookID string, limit int) ([]WebhookDelivery, error)
	IncrementFailureCount(ctx context.Context, tenantID string, id string) error
	UpdateLastDelivery(ctx context.Context, tenantID string, id string, status string, at time.Time) error
	ListPlaintextWebhooks(ctx context.Context) ([]Webhook, error)
	ListLegacyWebhooks(ctx context.Context) ([]Webhook, error)
	SealPlaintextWebhook(ctx context.Context, w Webhook) (bool, error)

	// Ops metrics operations
	RecordOp(ctx context.Context, op OpSample) error
	GetOpsOverview(ctx context.Context, tenantID string, window string) (OpsOverview, error)
	GetOpsTimeSeries(ctx context.Context, tenantID string, window string) ([]OpsTimeSeries, error)
	GetLatencyPercentiles(ctx context.Context, tenantID string, window string) ([]LatencyPercentiles, error)
	GetServiceStats(ctx context.Context, tenantID string, window string) ([]ServiceOpsStats, error)
	GetErrorBreakdown(ctx context.Context, tenantID string, window string) ([]ErrorBreakdown, error)
	// GetAllServiceStats returns cross-tenant per-service/op-type aggregates for Prometheus.
	GetAllServiceStats(ctx context.Context) ([]PrometheusMetricRow, error)

	// CBOMSamples returns algorithm/parameter aggregates derived from the
	// immutable audit chain. Used by the CBOM inventory/diff endpoints.
	CBOMSamples(ctx context.Context, tenantID string) ([]CBOMSample, error)
}

type SQLStore struct {
	db         *pkgdb.DB
	isPostgres bool
	keys       *signingKeys    // HMAC-SHA256 keys for per-event signatures
	cpKeys     *checkpointKeys // trusted checkpoint public keys (checkpoint.go)
	// chainNode returns the chain this node appends to (clusterstate
	// ChainNode): "" while standalone.
	chainNode func(context.Context) string
}

func NewSQLStore(db *pkgdb.DB) *SQLStore {
	return &SQLStore{
		db:         db,
		isPostgres: detectPostgresDriver(db),
		keys:       &signingKeys{},
		cpKeys:     &checkpointKeys{},
		chainNode:  func(context.Context) string { return "" },
	}
}

// SetEventSigningKey installs the node's configured signing key.
func (s *SQLStore) SetEventSigningKey(key []byte) {
	s.keys.install(key)
}

// SetChainNode sets how the store learns its chain id.
func (s *SQLStore) SetChainNode(f func(context.Context) string) { s.chainNode = f }

type EventQuery struct {
	Action string
	// ActionPrefixes match events whose action starts with any of them
	// (for example "audit.hsm." and "audit.key.hsm_"); at most 5.
	ActionPrefixes []string
	ActorID        string
	Result         string
	TargetID       string
	SessionID      string
	CorrelationID  string
	RiskMin        int
	From           time.Time
	To             time.Time
	Limit          int
	Offset         int
}

func (s *SQLStore) PersistEvent(ctx context.Context, event AuditEvent) (AuditEvent, error) {
	tx, err := s.db.SQL().BeginTx(ctx, nil)
	if err != nil {
		return AuditEvent{}, err
	}
	defer tx.Rollback() //nolint:errcheck

	tenantID := event.TenantID
	previousHash := "GENESIS"
	sequence := int64(1)
	// This node's chain: its pre-cluster rows ('') continue into its
	// clustered rows; other nodes' replicated chains are never extended here.
	self := s.chainNode(ctx)
	event.ChainNode = self

	var prevSeq int64
	var prevHash string
	err = tx.QueryRowContext(ctx, `
SELECT sequence, chain_hash FROM audit_events
WHERE tenant_id=$1 AND chain_node IN ('', $2) ORDER BY sequence DESC LIMIT 1
`, tenantID, self).Scan(&prevSeq, &prevHash)
	if err == nil {
		sequence = prevSeq + 1
		previousHash = prevHash
	} else if !errors.Is(err, sql.ErrNoRows) {
		return AuditEvent{}, err
	}
	if event.ID == "" {
		event.ID = newID("evt")
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}
	if event.ActorType == "" {
		event.ActorType = "system"
	}
	if event.Result == "" {
		event.Result = "success"
	}
	event.SourceIP = normalizeSourceIP(event.SourceIP)
	event.Sequence = sequence
	event.PreviousHash = previousHash
	event.ChainHash = chainHash(previousHash, eventHashInput(event))
	// Compute per-event HMAC for authenticity (FIPS 140-3 integrity + authenticity).
	event.HMACSig, event.HMACKeyID = s.keys.sign(event.ChainHash)
	// Populate FIPS category group if not already set by service layer.
	if event.CategoryGroup == "" {
		event.CategoryGroup = categoryGroupForService(event.Service)
	}

	if err := s.ensureAuditPartition(ctx, tx, event.Timestamp); err != nil {
		return AuditEvent{}, err
	}

	tags, _ := json.Marshal(event.Tags)
	details, _ := json.Marshal(event.Details)
	_, err = tx.ExecContext(ctx, `
INSERT INTO audit_events (
    id, tenant_id, sequence, chain_hash, previous_hash, hmac_sig, category_group,
    timestamp, service, action, actor_id, actor_type,
    target_type, target_id, method, endpoint, source_ip, user_agent, request_hash, correlation_id, parent_event_id,
    session_id, result, status_code, error_message, duration_ms, fips_compliant, approval_id, risk_score, tags, node_id, details,
    chain_node, hmac_key_id, created_at
) VALUES (
    $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30,$31,$32,$33,$34,CURRENT_TIMESTAMP
)
`, event.ID, event.TenantID, event.Sequence, event.ChainHash, event.PreviousHash,
		nullable(event.HMACSig), nullable(event.CategoryGroup),
		event.Timestamp, event.Service, event.Action, event.ActorID, event.ActorType,
		event.TargetType, event.TargetID, event.Method, event.Endpoint, nullable(event.SourceIP), nullable(event.UserAgent), nullable(event.RequestHash),
		nullable(event.CorrelationID), nullable(event.ParentEventID), nullable(event.SessionID), event.Result, event.StatusCode, nullable(event.ErrorMessage),
		event.DurationMS, event.FIPSCompliant, nullable(event.ApprovalID), event.RiskScore, tags, nullable(event.NodeID), details,
		event.ChainNode, nullable(event.HMACKeyID),
	)
	if err != nil {
		return AuditEvent{}, err
	}

	if err := tx.Commit(); err != nil {
		return AuditEvent{}, err
	}
	return event, nil
}

func (s *SQLStore) QueryEvents(ctx context.Context, tenantID string, q EventQuery) ([]AuditEvent, error) {
	if q.Limit <= 0 || q.Limit > 1000 {
		q.Limit = 200
	}
	args := []interface{}{tenantID, q.Action, q.ActorID, q.Result, q.TargetID, q.SessionID, q.CorrelationID, q.RiskMin, nullableTime(q.From), nullableTime(q.To), q.Limit, q.Offset}
	prefixClause := ""
	var likes []string
	for _, p := range q.ActionPrefixes {
		p = strings.TrimSpace(p)
		if p == "" || len(likes) == 5 {
			continue
		}
		args = append(args, likePrefix(p))
		likes = append(likes, fmt.Sprintf(`action LIKE $%d ESCAPE '\'`, len(args)))
	}
	if len(likes) > 0 {
		prefixClause = "  AND (" + strings.Join(likes, " OR ") + ")"
	}
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT id, tenant_id, sequence, chain_hash, previous_hash,
       COALESCE(hmac_sig,''), COALESCE(category_group,''),
       timestamp, service, action, actor_id, actor_type,
       COALESCE(target_type,''), COALESCE(target_id,''), COALESCE(method,''), COALESCE(endpoint,''), COALESCE(CAST(source_ip AS TEXT),''), COALESCE(user_agent,''),
       COALESCE(request_hash,''), COALESCE(correlation_id,''), COALESCE(parent_event_id,''), COALESCE(session_id,''),
       result, COALESCE(status_code,0), COALESCE(error_message,''), COALESCE(duration_ms,0), COALESCE(fips_compliant,false), COALESCE(approval_id,''),
       COALESCE(risk_score,0), COALESCE(tags,'[]'), COALESCE(node_id,''), COALESCE(details,'{}'), created_at
FROM audit_events
WHERE tenant_id=$1
  AND ($2='' OR action=$2)
  AND ($3='' OR actor_id=$3)
  AND ($4='' OR result=$4)
  AND ($5='' OR target_id=$5)
  AND ($6='' OR session_id=$6)
  AND ($7='' OR correlation_id=$7)
  AND ($8=0 OR risk_score >= $8)
  AND timestamp >= COALESCE($9, timestamp)
  AND timestamp <= COALESCE($10, timestamp)
`+prefixClause+`
ORDER BY timestamp DESC
LIMIT $11 OFFSET $12
`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	var out []AuditEvent
	for rows.Next() {
		ev, err := scanEvent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, ev)
	}
	return out, rows.Err()
}

func (s *SQLStore) GetEvent(ctx context.Context, tenantID string, id string) (AuditEvent, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT id, tenant_id, sequence, chain_hash, previous_hash,
       COALESCE(hmac_sig,''), COALESCE(category_group,''),
       timestamp, service, action, actor_id, actor_type,
       COALESCE(target_type,''), COALESCE(target_id,''), COALESCE(method,''), COALESCE(endpoint,''), COALESCE(CAST(source_ip AS TEXT),''), COALESCE(user_agent,''),
       COALESCE(request_hash,''), COALESCE(correlation_id,''), COALESCE(parent_event_id,''), COALESCE(session_id,''),
       result, COALESCE(status_code,0), COALESCE(error_message,''), COALESCE(duration_ms,0), COALESCE(fips_compliant,false), COALESCE(approval_id,''),
       COALESCE(risk_score,0), COALESCE(tags,'[]'), COALESCE(node_id,''), COALESCE(details,'{}'), created_at
FROM audit_events WHERE tenant_id=$1 AND id=$2
`, tenantID, id)
	ev, err := scanEvent(row)
	if errors.Is(err, sql.ErrNoRows) {
		return AuditEvent{}, errNotFound
	}
	return ev, err
}

// chainRowColumns selects every field eventHashInput covers, plus the chain
// and signature fields, in the order scanChainRow reads them.
const chainRowColumns = `id, sequence, previous_hash, chain_hash, timestamp, service, action, actor_id, actor_type,
       COALESCE(target_type,''), COALESCE(target_id,''), COALESCE(method,''), COALESCE(endpoint,''), COALESCE(CAST(source_ip AS TEXT),''), COALESCE(user_agent,''),
       COALESCE(request_hash,''), COALESCE(correlation_id,''), COALESCE(parent_event_id,''), COALESCE(session_id,''),
       result, COALESCE(status_code,0), COALESCE(error_message,''), COALESCE(duration_ms,0), COALESCE(fips_compliant,false), COALESCE(approval_id,''),
       COALESCE(risk_score,0), tags, COALESCE(node_id,''), details,
       chain_node, COALESCE(hmac_sig,''), COALESCE(hmac_key_id,'')`

// scanChainRow reads one chainRowColumns row as stored, so a recomputed hash
// covers exactly what is in the database now.
func scanChainRow(rows interface {
	Scan(dest ...interface{}) error
}, tenantID string) (AuditEvent, error) {
	var (
		ev                  AuditEvent
		timestampRaw        interface{}
		tagsRaw, detailsRaw []byte
	)
	if err := rows.Scan(&ev.ID, &ev.Sequence, &ev.PreviousHash, &ev.ChainHash, &timestampRaw, &ev.Service, &ev.Action, &ev.ActorID, &ev.ActorType,
		&ev.TargetType, &ev.TargetID, &ev.Method, &ev.Endpoint, &ev.SourceIP, &ev.UserAgent, &ev.RequestHash, &ev.CorrelationID, &ev.ParentEventID, &ev.SessionID,
		&ev.Result, &ev.StatusCode, &ev.ErrorMessage, &ev.DurationMS, &ev.FIPSCompliant, &ev.ApprovalID, &ev.RiskScore, &tagsRaw, &ev.NodeID, &detailsRaw,
		&ev.ChainNode, &ev.HMACSig, &ev.HMACKeyID); err != nil {
		return AuditEvent{}, err
	}
	ev.TenantID = tenantID
	ev.Timestamp = parseTimeValue(timestampRaw)
	_ = json.Unmarshal(tagsRaw, &ev.Tags)
	_ = json.Unmarshal(detailsRaw, &ev.Details)
	return ev, nil
}

func (s *SQLStore) VerifyChain(ctx context.Context, tenantID string) (bool, []map[string]interface{}, error) {
	self := s.chainNode(ctx)
	chainOf := func(node string) string {
		if node == "" {
			return self
		}
		return node
	}
	var breaks []map[string]interface{}
	brk := func(seq int64, id, node, reason string) {
		breaks = append(breaks, map[string]interface{}{"sequence": seq, "event_id": id, "chain_node": node, "reason": reason})
	}

	// Every checkpoint must verify under a trusted key, and the row at the
	// head it signed must still carry the signed chain hash (checked in the
	// walk below). A rewrite that recomputes every later hash and HMAC still
	// changes that row.
	cps, err := s.loadCheckpoints(ctx, tenantID, 0)
	if err != nil {
		return false, nil, err
	}
	heads := map[string]checkpoint{}
	for _, cp := range cps {
		status, err := s.verifyCheckpointSignature(ctx, cp)
		if err != nil {
			return false, nil, err
		}
		if status != checkpointVerified {
			brk(cp.Head.Sequence, cp.EventID, cp.Head.ChainNode, "checkpoint_"+status)
			continue
		}
		heads[fmt.Sprintf("%s|%d", chainOf(cp.Head.ChainNode), cp.Head.Sequence)] = cp
	}

	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT `+chainRowColumns+`
FROM audit_events
WHERE tenant_id=$1
ORDER BY sequence ASC
`, tenantID)
	if err != nil {
		return false, nil, err
	}
	defer rows.Close() //nolint:errcheck

	// Each node's chain is verified on its own. This node's chain starts at
	// GENESIS ('' rows continue into its clustered rows). Another node's
	// chain arrives from the point that node was clustered, so its first row
	// here anchors it; from there every link and hash is checked.
	prevByChain := map[string]string{}
	for rows.Next() {
		ev, err := scanChainRow(rows, tenantID)
		if err != nil {
			return false, nil, err
		}

		chain := chainOf(ev.ChainNode)
		prevHash, seen := prevByChain[chain]
		if !seen {
			prevHash = "GENESIS"
			if chain != self && ev.Sequence > 1 {
				prevHash = ev.PreviousHash // anchor of a replicated chain
			}
		}
		if ev.PreviousHash != prevHash {
			brk(ev.Sequence, ev.ID, ev.ChainNode, "previous_hash_mismatch")
		}
		expected := chainHash(prevHash, eventHashInput(ev))
		if ev.ChainHash != expected {
			brk(ev.Sequence, ev.ID, ev.ChainNode, "chain_hash_mismatch")
		}
		if ev.HMACSig != "" && s.keys.configured() {
			switch ok, known := s.keys.verify(ev.ChainHash, ev.HMACSig, ev.HMACKeyID); {
			case !known:
				brk(ev.Sequence, ev.ID, ev.ChainNode, "hmac_key_unknown")
			case !ok:
				brk(ev.Sequence, ev.ID, ev.ChainNode, "hmac_mismatch")
			}
		}
		key := fmt.Sprintf("%s|%d", chain, ev.Sequence)
		if cp, ok := heads[key]; ok {
			if ev.ChainHash != cp.Head.ChainHash {
				brk(ev.Sequence, ev.ID, ev.ChainNode, "checkpoint_head_mismatch")
			}
			delete(heads, key)
		}
		prevByChain[chain] = ev.ChainHash
	}
	if err := rows.Err(); err != nil {
		return false, nil, err
	}
	// A signed head with no row: the row was removed.
	for _, cp := range heads {
		brk(cp.Head.Sequence, cp.EventID, cp.Head.ChainNode, "checkpoint_head_mismatch")
	}
	return len(breaks) == 0, breaks, nil
}

func (s *SQLStore) CountDistinctIPsForTarget(ctx context.Context, tenantID string, targetID string, since time.Time) (int, error) {
	if targetID == "" {
		return 0, nil
	}
	var n int
	err := s.db.SQL().QueryRowContext(ctx, `
SELECT COUNT(DISTINCT source_ip)
FROM audit_events
WHERE tenant_id=$1 AND target_id=$2 AND timestamp >= $3
`, tenantID, targetID, since).Scan(&n)
	return n, err
}

func scanEvent(scanner interface {
	Scan(dest ...interface{}) error
}) (AuditEvent, error) {
	var ev AuditEvent
	var tagsRaw []byte
	var detailsRaw []byte
	var timestampRaw interface{}
	var createdRaw interface{}
	err := scanner.Scan(
		&ev.ID, &ev.TenantID, &ev.Sequence, &ev.ChainHash, &ev.PreviousHash,
		&ev.HMACSig, &ev.CategoryGroup,
		&timestampRaw, &ev.Service, &ev.Action,
		&ev.ActorID, &ev.ActorType, &ev.TargetType, &ev.TargetID, &ev.Method, &ev.Endpoint, &ev.SourceIP, &ev.UserAgent,
		&ev.RequestHash, &ev.CorrelationID, &ev.ParentEventID, &ev.SessionID, &ev.Result, &ev.StatusCode, &ev.ErrorMessage,
		&ev.DurationMS, &ev.FIPSCompliant, &ev.ApprovalID, &ev.RiskScore, &tagsRaw, &ev.NodeID, &detailsRaw, &createdRaw,
	)
	if err != nil {
		return AuditEvent{}, err
	}
	ev.Timestamp = parseTimeValue(timestampRaw)
	ev.CreatedAt = parseTimeValue(createdRaw)
	_ = json.Unmarshal(tagsRaw, &ev.Tags)
	_ = json.Unmarshal(detailsRaw, &ev.Details)
	if ev.Details == nil {
		ev.Details = map[string]interface{}{}
	}
	// Restore CountryCode from the stored details JSON when it was enriched on ingest.
	if cc, ok := ev.Details["country_code"].(string); ok && cc != "" {
		ev.CountryCode = cc
	}
	return ev, nil
}

func nullable(v string) interface{} {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	return v
}

func nullableTime(t time.Time) interface{} {
	if t.IsZero() {
		return nil
	}
	return t
}

func parseTimeValue(v interface{}) time.Time {
	switch x := v.(type) {
	case nil:
		return time.Time{}
	case time.Time:
		return x
	case *time.Time:
		if x == nil {
			return time.Time{}
		}
		return *x
	case []byte:
		return parseTimeString(string(x))
	case string:
		return parseTimeString(x)
	default:
		return time.Time{}
	}
}

// ── Store helpers ─────────────────────────────────────────────

func detectPostgresDriver(db *pkgdb.DB) bool {
	if db == nil || db.SQL() == nil {
		return false
	}
	driverType := strings.ToLower(fmt.Sprintf("%T", db.SQL().Driver()))
	return strings.Contains(driverType, "pgx") || strings.Contains(driverType, "postgres") || strings.Contains(driverType, "stdlib")
}

func normalizeSourceIP(raw string) string {
	value := strings.TrimSpace(raw)
	if value == "" {
		return ""
	}
	if i := strings.Index(value, ","); i >= 0 {
		value = strings.TrimSpace(value[:i])
	}
	if host, _, err := net.SplitHostPort(value); err == nil {
		value = host
	}
	value = strings.Trim(value, "[]")
	ip := net.ParseIP(value)
	if ip == nil {
		return ""
	}
	return ip.String()
}

func (s *SQLStore) ensureAuditPartition(ctx context.Context, tx *sql.Tx, ts time.Time) error {
	if !s.isPostgres {
		return nil
	}
	t := ts.UTC()
	if t.IsZero() {
		t = time.Now().UTC()
	}
	monthStart := time.Date(t.Year(), t.Month(), 1, 0, 0, 0, 0, time.UTC)
	nextMonthStart := monthStart.AddDate(0, 1, 0)
	partitionName := fmt.Sprintf("audit_events_%04d_%02d", monthStart.Year(), int(monthStart.Month()))
	stmt := fmt.Sprintf(
		`CREATE TABLE IF NOT EXISTS %s PARTITION OF audit_events FOR VALUES FROM ('%s') TO ('%s')`,
		partitionName,
		monthStart.Format("2006-01-02"),
		nextMonthStart.Format("2006-01-02"),
	)
	_, err := tx.ExecContext(ctx, stmt)
	return err
}

func parseTimeString(v string) time.Time {
	v = strings.TrimSpace(v)
	if v == "" {
		return time.Time{}
	}
	layouts := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02 15:04:05.999999999 -0700 MST",
		"2006-01-02 15:04:05 -0700 MST",
		"2006-01-02 15:04:05.999999999-07:00",
		"2006-01-02 15:04:05-07:00",
		"2006-01-02 15:04:05.999999999",
		"2006-01-02 15:04:05",
		"2006-01-02T15:04:05.999999999-07:00",
		"2006-01-02T15:04:05-07:00",
		"2006-01-02T15:04:05",
	}
	for _, layout := range layouts {
		if ts, err := time.Parse(layout, v); err == nil {
			return ts.UTC()
		}
	}
	return time.Time{}
}

// likePrefix escapes a prefix for LIKE ... ESCAPE '\' ("_" and "%" are
// wildcards: audit.key.hsm_ must not match audit.key.hsmX).
func likePrefix(p string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return r.Replace(p) + "%"
}
