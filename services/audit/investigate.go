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

// Investigation is the Audit Log's Investigate view: for the events matching
// a set of pivots (who, what, on what, from where, how, outcome, session,
// request), the top values of every one of those, counted in SQL over the
// whole window with the event list's own filter (eventFilter). A value's
// count is the number of events GET /audit/events lists with that value
// added to the same filters.
type Investigation struct {
	From          time.Time          `json:"from"`
	To            time.Time          `json:"to"`
	BucketSeconds int64              `json:"bucket_seconds"`
	Total         int64              `json:"total"`
	FirstSeen     *time.Time         `json:"first_seen"`
	LastSeen      *time.Time         `json:"last_seen"`
	Distinct      map[string]int64   `json:"distinct"`
	Facets        map[string][]Facet `json:"facets"`
	Series        []SeriesPoint      `json:"series"`
}

// Facet is one value of a dimension and how many events have it. Kind is
// the actor's or target's type, where the dimension has one.
type Facet struct {
	Key   string `json:"key"`
	Kind  string `json:"kind,omitempty"`
	Count int64  `json:"count"`
}

// facetTop is how many values each dimension returns.
const facetTop = 10

// dimension is a facet: the GET /audit/events parameter that filters by it
// (its name in the response) and the column it groups.
type dimension struct {
	param, kind string
	col         func(*SQLStore) string
}

func column(c string) func(*SQLStore) string { return func(*SQLStore) string { return c } }

var dimensions = []dimension{
	{param: "actor_id", kind: "actor_type", col: column("actor_id")},
	{param: "action", col: column("action")},
	{param: "target_id", kind: "target_type", col: column("target_id")},
	{param: "source_ip", col: (*SQLStore).sourceIPText},
	{param: "user_agent", col: column("user_agent")},
	{param: "service", col: column("service")},
	{param: "result", col: column("result")},
	{param: "session_id", col: column("session_id")},
	{param: "correlation_id", col: column("correlation_id")},
}

// Investigate counts the events q selects. Generic HTTP request records are
// left out, as in the Activity statistics. A zero From is since the first
// matching event; a zero To is now.
func (s *SQLStore) Investigate(ctx context.Context, tenantID string, q EventQuery) (Investigation, error) {
	q.ExcludeHTTPRequests = true
	q.Limit, q.Offset = 0, 0
	where, args := s.eventFilter(tenantID, q)
	out := Investigation{Distinct: map[string]int64{}, Facets: map[string][]Facet{}, Series: []SeriesPoint{}}

	var first, last interface{}
	if err := s.db.SQL().QueryRowContext(ctx, `SELECT COUNT(*), MIN(timestamp), MAX(timestamp) FROM audit_events `+where, args...).Scan(&out.Total, &first, &last); err != nil {
		return Investigation{}, err
	}
	if t := parseTimeValue(first); !t.IsZero() {
		out.FirstSeen = &t
	}
	if t := parseTimeValue(last); !t.IsZero() {
		out.LastSeen = &t
	}

	distinct := make([]string, 0, len(dimensions))
	for _, d := range dimensions {
		distinct = append(distinct, fmt.Sprintf("COUNT(DISTINCT NULLIF(%s,''))", d.col(s)))
	}
	vals := make([]int64, len(dimensions))
	ptrs := make([]interface{}, len(vals))
	for i := range vals {
		ptrs[i] = &vals[i]
	}
	if err := s.db.SQL().QueryRowContext(ctx, `SELECT `+strings.Join(distinct, ", ")+` FROM audit_events `+where, args...).Scan(ptrs...); err != nil {
		return Investigation{}, err
	}
	for i, d := range dimensions {
		out.Distinct[d.param] = vals[i]
	}

	// An empty value has no list filter, so it is not a facet value.
	for _, d := range dimensions {
		col := d.col(s)
		kind := "''"
		if d.kind != "" {
			kind = "MAX(COALESCE(" + d.kind + ",''))"
		}
		rows, err := s.db.SQL().QueryContext(ctx, fmt.Sprintf(`SELECT %[1]s, %[2]s, COUNT(*) FROM audit_events %[3]s AND COALESCE(%[1]s,'') <> ''
GROUP BY %[1]s ORDER BY COUNT(*) DESC, 1 LIMIT %[4]d`, col, kind, where, facetTop), args...)
		if err != nil {
			return Investigation{}, err
		}
		values := []Facet{}
		for rows.Next() {
			var f Facet
			if err := rows.Scan(&f.Key, &f.Kind, &f.Count); err != nil {
				_ = rows.Close()
				return Investigation{}, err
			}
			values = append(values, f)
		}
		_ = rows.Close()
		if err := rows.Err(); err != nil {
			return Investigation{}, err
		}
		out.Facets[d.param] = values
	}

	out.From, out.To = q.From.UTC(), q.To.UTC()
	if q.To.IsZero() {
		out.To = time.Now().UTC()
	}
	if q.From.IsZero() {
		out.From = out.To
		if out.FirstSeen != nil {
			out.From = out.FirstSeen.UTC()
		}
	}
	// One pass for the series, as in AuditStats: each column counts the
	// events at or after a bucket start; differences give each bucket.
	starts, w := timebucket.Buckets(out.From, out.To)
	out.BucketSeconds = int64(w / time.Second)
	if len(starts) == 0 || out.Total == 0 {
		for _, st := range starts {
			out.Series = append(out.Series, SeriesPoint{Start: st})
		}
		return out, nil
	}
	cols := make([]string, 0, len(starts))
	sargs := append([]interface{}{}, args...)
	for _, st := range starts {
		sargs = append(sargs, st)
		cols = append(cols, fmt.Sprintf("COALESCE(SUM(CASE WHEN timestamp >= $%d THEN 1 ELSE 0 END),0)", len(sargs)))
	}
	cum := make([]int64, len(cols))
	cptrs := make([]interface{}, len(cols))
	for i := range cum {
		cptrs[i] = &cum[i]
	}
	if err := s.db.SQL().QueryRowContext(ctx, `SELECT `+strings.Join(cols, ", ")+` FROM audit_events `+where, sargs...).Scan(cptrs...); err != nil {
		return Investigation{}, err
	}
	for i, st := range starts {
		n := cum[i]
		if i+1 < len(cum) {
			n -= cum[i+1]
		}
		out.Series = append(out.Series, SeriesPoint{Start: st, Count: n})
	}
	return out, nil
}

// eventQueryFrom reads GET /audit/events' filters, which GET
// /audit/investigate shares. A malformed filter returns its refusal reason
// and message.
func eventQueryFrom(r *http.Request) (EventQuery, string, string) {
	v := r.URL.Query()
	get := func(k string) string { return strings.TrimSpace(v.Get(k)) }
	q := EventQuery{
		Action: get("action"), ActionPrefixes: v["action_prefix"], ActorID: get("actor_id"), Result: get("result"),
		TargetID: get("target_id"), SessionID: get("session_id"), CorrelationID: get("correlation_id"),
		SourceIP: get("source_ip"), UserAgent: get("user_agent"), Service: get("service"),
		RiskMin: atoi(get("risk_min")), RiskMax: atoi(get("risk_max")),
		ExcludeHTTPRequests: get("exclude_http_requests") == "true", Ascending: get("order") == "asc",
		Limit: atoi(get("limit")), Offset: atoi(get("offset")),
		From: parseTS(get("from")), To: parseTS(get("to")),
		MeteredOp: get("metered_op"), Outcome: get("outcome"), Node: get("node"), HasNode: v.Has("node"),
	}
	if (get("from") != "" && q.From.IsZero()) || (get("to") != "" && q.To.IsZero()) {
		return q, "bad_window", "from and to must be RFC 3339 times"
	}
	if q.Outcome != "" && (q.MeteredOp == "" || (q.Outcome != "error" && q.Outcome != "success")) {
		return q, "bad_outcome", "outcome is error or success, with metered_op"
	}
	return q, "", ""
}

func (h *Handler) investigateRouter(audit route.Emitter) *route.Router {
	r := route.New("audit", audit, nil)
	r.Handle("GET /audit/investigate", route.Spec{
		Action: "investigation_read", Permission: "audit.events.read", Resource: "audit_trail",
	}, h.investigate)
	return r
}

func (h *Handler) investigate(c *route.Call) {
	q, reason, msg := eventQueryFrom(c.R)
	if reason != "" {
		c.Refuse(http.StatusBadRequest, reason, msg)
		return
	}
	// Who investigated whom is part of the record.
	for _, d := range dimensions {
		if v := strings.TrimSpace(c.R.URL.Query().Get(d.param)); v != "" {
			c.Detail(d.param, v)
		}
	}
	inv, err := h.store.Investigate(c.R.Context(), c.Tenant, q)
	if err != nil {
		c.Error(http.StatusInternalServerError, "investigation_failed", "audit investigation failed")
		return
	}
	c.Detail("total", inv.Total)
	c.JSON(http.StatusOK, map[string]interface{}{"investigation": inv})
}
