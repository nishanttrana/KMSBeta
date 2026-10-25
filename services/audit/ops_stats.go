package main

import (
	"context"
	"net/http"
	"time"

	"vecta-kms/pkg/route"
	"vecta-kms/pkg/timebucket"
)

// Operations statistics for Overview → Operations → Operation metrics: the
// same hourly rows as the other ops-metrics reads, counted over a chart
// window (a day to a year, or since uptime) and bucketed by pkg/timebucket.
// The rows are hourly, so the window starts on the hour; every count has a
// GET /audit/events filter (metered_op, outcome, service, node) over the
// same window that lists exactly the operations it counts.

// OpsGroup is one service, operation or node's share of the window.
type OpsGroup struct {
	Key          string   `json:"key"`
	Ops          int64    `json:"ops"`
	Errors       int64    `json:"errors"`
	AvgLatencyMs float64  `json:"avg_latency_ms"`
	P50Ms        *float64 `json:"p50_ms"`
	P90Ms        *float64 `json:"p90_ms"`
	P99Ms        *float64 `json:"p99_ms"`
}

// OpsPoint is one chart bucket.
type OpsPoint struct {
	Start        time.Time `json:"start"`
	Ops          int64     `json:"ops"`
	Errors       int64     `json:"errors"`
	AvgLatencyMs float64   `json:"avg_latency_ms"`
}

type OpsStats struct {
	From          time.Time  `json:"from"`
	To            time.Time  `json:"to"`
	BucketSeconds int64      `json:"bucket_seconds"`
	Scope         string     `json:"scope"`
	RecordedSince *time.Time `json:"recorded_since"`
	Total         OpsGroup   `json:"total"`
	TotalValues   int64      `json:"total_values"`
	Series        []OpsPoint `json:"series"`
	ByOp          []OpsGroup `json:"by_op"`
	ByService     []OpsGroup `json:"by_service"`
	ByNode        []OpsGroup `json:"by_node"`
}

const opsHistogramCols = `COALESCE(SUM(lat_b00),0), COALESCE(SUM(lat_b01),0), COALESCE(SUM(lat_b02),0), COALESCE(SUM(lat_b03),0),
    COALESCE(SUM(lat_b04),0), COALESCE(SUM(lat_b05),0), COALESCE(SUM(lat_b06),0), COALESCE(SUM(lat_b07),0),
    COALESCE(SUM(lat_b08),0), COALESCE(SUM(lat_b09),0), COALESCE(SUM(lat_b10),0), COALESCE(SUM(lat_b11),0),
    COALESCE(SUM(lat_b12),0)`

// OpsStats counts operations in [from, to]. A zero from means since the
// first recorded hour.
func (s *SQLStore) OpsStats(ctx context.Context, tenantID string, from, to time.Time) (OpsStats, error) {
	if to.IsZero() {
		to = time.Now().UTC()
	}
	var first interface{}
	if err := s.db.SQL().QueryRowContext(ctx, `SELECT MIN(hour) FROM ops_metrics_hourly WHERE tenant_id=$1`, tenantID).Scan(&first); err != nil {
		return OpsStats{}, err
	}
	out := OpsStats{Scope: s.opsScope(ctx), Series: []OpsPoint{}, ByOp: []OpsGroup{}, ByService: []OpsGroup{}, ByNode: []OpsGroup{}}
	if t := parseTimeValue(first); first != nil && !t.IsZero() {
		out.RecordedSince = &t
		if from.IsZero() {
			from = t
		}
	}
	if from.IsZero() {
		from = to
	}
	out.From, out.To = from.UTC().Truncate(time.Hour), to.UTC()
	where := `FROM ops_metrics_hourly WHERE tenant_id=$1 AND hour >= $2 AND hour <= $3`
	args := []interface{}{tenantID, out.From, out.To}

	group := func(col string) ([]OpsGroup, error) {
		rows, err := s.db.SQL().QueryContext(ctx, `SELECT `+col+`, COALESCE(SUM(count),0), COALESCE(SUM(error_count),0), COALESCE(SUM(total_latency_us),0), `+opsHistogramCols+` `+where+` GROUP BY `+col+` ORDER BY 2 DESC, 1`, args...)
		if err != nil {
			return nil, err
		}
		defer rows.Close() //nolint:errcheck
		res := []OpsGroup{}
		for rows.Next() {
			g, err := scanOpsGroupValues(rows, nil)
			if err != nil {
				return nil, err
			}
			res = append(res, g)
		}
		return res, rows.Err()
	}
	var err error
	if out.ByOp, err = group("op_type"); err != nil {
		return OpsStats{}, err
	}
	if out.ByService, err = group("service"); err != nil {
		return OpsStats{}, err
	}
	if out.ByNode, err = group("node"); err != nil {
		return OpsStats{}, err
	}

	row := s.db.SQL().QueryRowContext(ctx, `SELECT '', COALESCE(SUM(count),0), COALESCE(SUM(error_count),0), COALESCE(SUM(total_latency_us),0), `+opsHistogramCols+`, COALESCE(SUM(value_count),0) `+where, args...)
	if out.Total, err = scanOpsGroupValues(row, &out.TotalValues); err != nil {
		return OpsStats{}, err
	}

	starts, w := timebucket.Buckets(out.From, out.To)
	out.BucketSeconds = int64(w / time.Second)
	latency := make([]int64, len(starts))
	for _, st := range starts {
		out.Series = append(out.Series, OpsPoint{Start: st})
	}
	rows, err := s.db.SQL().QueryContext(ctx, `SELECT hour, COALESCE(SUM(count),0), COALESCE(SUM(error_count),0), COALESCE(SUM(total_latency_us),0) `+where+` GROUP BY hour`, args...)
	if err != nil {
		return OpsStats{}, err
	}
	defer rows.Close() //nolint:errcheck
	for rows.Next() {
		var hourRaw interface{}
		var ops, errs, us int64
		if err := rows.Scan(&hourRaw, &ops, &errs, &us); err != nil {
			return OpsStats{}, err
		}
		i := timebucket.Index(starts, w, parseTimeValue(hourRaw))
		if i < 0 {
			continue
		}
		out.Series[i].Ops += ops
		out.Series[i].Errors += errs
		latency[i] += us
	}
	if err := rows.Err(); err != nil {
		return OpsStats{}, err
	}
	for i := range out.Series {
		if out.Series[i].Ops > 0 {
			out.Series[i].AvgLatencyMs = float64(latency[i]) / 1000 / float64(out.Series[i].Ops)
		}
	}
	return out, nil
}

type rowScanner interface {
	Scan(dest ...interface{}) error
}

// scanOpsGroupValues reads key, count, errors, latency and the histogram
// (and, when values is set, a trailing value count).
func scanOpsGroupValues(row rowScanner, values *int64) (OpsGroup, error) {
	var g OpsGroup
	var us int64
	hist := make([]int64, len(latencyBucketsMs)+1)
	dest := []interface{}{&g.Key, &g.Ops, &g.Errors, &us}
	for i := range hist {
		dest = append(dest, &hist[i])
	}
	if values != nil {
		dest = append(dest, values)
	}
	if err := row.Scan(dest...); err != nil {
		return OpsGroup{}, err
	}
	if g.Ops > 0 {
		g.AvgLatencyMs = float64(us) / 1000 / float64(g.Ops)
	}
	var sampled int64
	for _, c := range hist {
		sampled += c
	}
	g.P50Ms = bucketPercentile(hist, sampled, 0.50)
	g.P90Ms = bucketPercentile(hist, sampled, 0.90)
	g.P99Ms = bucketPercentile(hist, sampled, 0.99)
	return g, nil
}

func (h *Handler) opsStatsRouter(audit route.Emitter) *route.Router {
	r := route.New("audit", audit, nil)
	r.Handle("GET /ops-metrics/stats", route.Spec{
		Action: "ops_stats_read", Permission: "audit.events.read", Resource: "ops_metrics",
	}, h.opsStats)
	return r
}

func (h *Handler) opsStats(c *route.Call) {
	q := c.R.URL.Query()
	from, to := parseTS(q.Get("from")), parseTS(q.Get("to"))
	if (q.Get("from") != "" && from.IsZero()) || (q.Get("to") != "" && to.IsZero()) {
		c.Refuse(http.StatusBadRequest, "bad_window", "from and to must be RFC 3339 times")
		return
	}
	st, err := h.store.OpsStats(c.R.Context(), c.Tenant, from, to)
	if err != nil {
		c.Error(http.StatusInternalServerError, "stats_failed", "operations statistics failed")
		return
	}
	c.Detail("from", st.From)
	c.Detail("to", st.To)
	c.Detail("total", st.Total.Ops)
	c.JSON(http.StatusOK, map[string]interface{}{"stats": st})
}
