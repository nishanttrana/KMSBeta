package main

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"vecta-kms/pkg/route"
	"vecta-kms/pkg/timebucket"
)

// Audit activity statistics for the Audit Log's Activity charts. Counts are
// computed in SQL over the whole window, never over a sample, so a year of
// events charts as accurately as a day. Generic HTTP request records are
// excluded, as in the event list (exclude_http_requests). Each bucket has a
// matching GET /audit/events filter so a chart segment lists exactly the
// events it counts.

type KeyCount struct {
	Key   string `json:"key"`
	Count int64  `json:"count"`
}

type SeriesPoint struct {
	Start time.Time `json:"start"`
	Count int64     `json:"count"`
}

type AuditStats struct {
	From          time.Time     `json:"from"`
	To            time.Time     `json:"to"`
	BucketSeconds int64         `json:"bucket_seconds"`
	Total         int64         `json:"total"`
	ByResult      []KeyCount    `json:"by_result"`
	TopServices   []KeyCount    `json:"top_services"`
	TopActors     []KeyCount    `json:"top_actors"`
	Actors        int64         `json:"actors"`
	Services      int64         `json:"services"`
	RiskBuckets   []KeyCount    `json:"risk_buckets"`
	Series        []SeriesPoint `json:"series"`
}

// RiskRanges are the risk-score buckets; GET /audit/events takes the same
// bounds as risk_min / risk_max.
var RiskRanges = [][2]int{{0, 20}, {21, 40}, {41, 60}, {61, 80}, {81, 100}}

const notHTTPRequest = `action NOT LIKE '%.http\_request' ESCAPE '\'`

// AuditStats counts events in [from, to]. A zero from means since the first
// recorded event ("since uptime").
func (s *SQLStore) AuditStats(ctx context.Context, tenantID string, from, to time.Time) (AuditStats, error) {
	if to.IsZero() {
		to = time.Now().UTC()
	}
	if from.IsZero() {
		var first interface{}
		if err := s.db.SQL().QueryRowContext(ctx, `SELECT MIN(timestamp) FROM audit_events WHERE tenant_id=$1 AND `+notHTTPRequest, tenantID).Scan(&first); err != nil {
			return AuditStats{}, err
		}
		from = parseTimeValue(first)
		if from.IsZero() {
			from = to
		}
	}
	from, to = from.UTC(), to.UTC()
	out := AuditStats{From: from, To: to, ByResult: []KeyCount{}, TopServices: []KeyCount{}, TopActors: []KeyCount{}, Series: []SeriesPoint{}}
	where := `WHERE tenant_id=$1 AND timestamp >= $2 AND timestamp <= $3 AND ` + notHTTPRequest
	args := []interface{}{tenantID, from, to}

	group := func(col, extra string) ([]KeyCount, error) {
		rows, err := s.db.SQL().QueryContext(ctx, `SELECT COALESCE(`+col+`,''), COUNT(*) FROM audit_events `+where+` GROUP BY COALESCE(`+col+`,'') ORDER BY COUNT(*) DESC, 1 `+extra, args...)
		if err != nil {
			return nil, err
		}
		defer rows.Close() //nolint:errcheck
		res := []KeyCount{}
		for rows.Next() {
			var kc KeyCount
			if err := rows.Scan(&kc.Key, &kc.Count); err != nil {
				return nil, err
			}
			res = append(res, kc)
		}
		return res, rows.Err()
	}
	var err error
	if out.ByResult, err = group("result", ""); err != nil {
		return AuditStats{}, err
	}
	for _, r := range out.ByResult {
		out.Total += r.Count
	}
	if out.TopServices, err = group("service", "LIMIT 10"); err != nil {
		return AuditStats{}, err
	}
	if out.TopActors, err = group("actor_id", "LIMIT 10"); err != nil {
		return AuditStats{}, err
	}
	if err := s.db.SQL().QueryRowContext(ctx, `SELECT COUNT(DISTINCT actor_id), COUNT(DISTINCT service) FROM audit_events `+where, args...).Scan(&out.Actors, &out.Services); err != nil {
		return AuditStats{}, err
	}

	// Risk buckets and the time series in one pass: SUM(CASE ...) is portable
	// across Postgres and SQLite. The series sums "at or after each bucket
	// start"; consecutive differences give each bucket's count.
	starts, w := timebucket.Buckets(from, to)
	out.BucketSeconds = int64(w / time.Second)
	cols := make([]string, 0, len(RiskRanges)+len(starts))
	sargs := append([]interface{}{}, args...)
	for _, rr := range RiskRanges {
		lo := fmt.Sprintf("COALESCE(risk_score,0) >= %d", rr[0])
		if rr[0] == 0 {
			lo = "1=1"
		}
		cols = append(cols, fmt.Sprintf("COALESCE(SUM(CASE WHEN %s AND COALESCE(risk_score,0) <= %d THEN 1 ELSE 0 END),0)", lo, rr[1]))
	}
	for _, st := range starts {
		sargs = append(sargs, st)
		cols = append(cols, fmt.Sprintf("COALESCE(SUM(CASE WHEN timestamp >= $%d THEN 1 ELSE 0 END),0)", len(sargs)))
	}
	vals := make([]int64, len(cols))
	ptrs := make([]interface{}, len(cols))
	for i := range vals {
		ptrs[i] = &vals[i]
	}
	if err := s.db.SQL().QueryRowContext(ctx, `SELECT `+strings.Join(cols, ", ")+` FROM audit_events `+where, sargs...).Scan(ptrs...); err != nil {
		return AuditStats{}, err
	}
	for i, rr := range RiskRanges {
		out.RiskBuckets = append(out.RiskBuckets, KeyCount{Key: fmt.Sprintf("%d-%d", rr[0], rr[1]), Count: vals[i]})
	}
	cum := vals[len(RiskRanges):]
	for i, st := range starts {
		n := cum[i]
		if i+1 < len(cum) {
			n -= cum[i+1]
		}
		out.Series = append(out.Series, SeriesPoint{Start: st, Count: n})
	}
	return out, nil
}

func (h *Handler) statsRouter(audit route.Emitter) *route.Router {
	r := route.New("audit", audit, nil)
	r.Handle("GET /audit/activity/stats", route.Spec{
		Action: "activity_stats_read", Permission: "audit.events.read", Resource: "audit_trail",
	}, h.activityStats)
	return r
}

func (h *Handler) activityStats(c *route.Call) {
	q := c.R.URL.Query()
	from, to := parseTS(q.Get("from")), parseTS(q.Get("to"))
	if (q.Get("from") != "" && from.IsZero()) || (q.Get("to") != "" && to.IsZero()) {
		c.Refuse(http.StatusBadRequest, "bad_window", "from and to must be RFC 3339 times")
		return
	}
	st, err := h.store.AuditStats(c.R.Context(), c.Tenant, from, to)
	if err != nil {
		c.Error(http.StatusInternalServerError, "stats_failed", "audit statistics failed")
		return
	}
	c.Detail("from", st.From)
	c.Detail("to", st.To)
	c.Detail("total", st.Total)
	c.JSON(http.StatusOK, map[string]interface{}{"stats": st})
}
