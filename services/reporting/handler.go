package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"runtime/debug"
	"strings"
	"time"

	pkgauth "vecta-kms/pkg/auth"
	"vecta-kms/pkg/route"
)

// Handler serves the alerting and reporting APIs. Every route is registered
// through the pkg/route kernel, which authenticates the caller, binds the
// tenant to the verified token, checks the route's permission and emits one
// audit.reporting.<action> event per request, refusals included. Identity
// (who acknowledged, who requested, who deleted) is the verified caller,
// never a body field, query parameter or header.
type Handler struct {
	svc          *Service
	router       *route.Router
	releaseTag   string
	buildVersion string
}

// Permissions for the reporting domain.
const (
	permRead   = "reporting.read"
	permWrite  = "reporting.write"
	permDelete = "reporting.delete"
)

func NewHandler(svc *Service, audit route.Emitter, logger *log.Logger) *Handler {
	h := &Handler{
		svc:          svc,
		router:       route.New("reporting", audit, logger),
		releaseTag:   firstNonEmpty(strings.TrimSpace(os.Getenv("RELEASE_TAG")), "reporting"),
		buildVersion: firstNonEmpty(strings.TrimSpace(os.Getenv("BUILD_VERSION")), "dev"),
	}
	h.routes()
	return h
}

// ServeHTTP records a panic as error telemetry under the verified caller's
// tenant (never a tenant the request names) and answers 500.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	defer func() {
		rec := recover()
		if rec == nil {
			return
		}
		tenantID := "root"
		if claims, ok := pkgauth.ClaimsFromContext(r.Context()); ok && strings.TrimSpace(claims.TenantID) != "" {
			tenantID = strings.TrimSpace(claims.TenantID)
		}
		reqID := firstNonEmpty(strings.TrimSpace(r.Header.Get("X-Request-ID")), newID("req"))
		_, _ = h.svc.CaptureErrorTelemetry(context.Background(), tenantID, ErrorTelemetryEvent{
			Source:     "backend",
			Service:    "reporting",
			Component:  firstNonEmpty(r.Method+" "+r.URL.Path, "http"),
			Level:      "critical",
			Message:    fmt.Sprintf("panic recovered in reporting handler: %v", rec),
			StackTrace: string(debug.Stack()),
			Context:    map[string]interface{}{"method": r.Method, "path": r.URL.Path},
			RequestID:  reqID,
			ReleaseTag: h.releaseTag,
			BuildVer:   h.buildVersion,
		})
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"error": map[string]interface{}{
			"code": "internal_error", "message": "internal server error", "request_id": reqID,
		}})
	}()
	h.router.ServeHTTP(w, r)
}

func (h *Handler) routes() {
	r := h.router
	spec := func(action, perm, resource, target string) route.Spec {
		return route.Spec{Action: action, Permission: perm, Resource: resource, TargetParam: target}
	}

	r.Handle("GET /alerts", spec("alerts_listed", permRead, "alert", ""), h.alerts)
	r.Handle("GET /alerts/feed", spec("alerts_feed_streamed", permRead, "alert", ""), h.alertsFeed)
	r.Handle("GET /alerts/unread", spec("alerts_unread_counted", permRead, "alert", ""), h.alertsUnread)
	r.Handle("GET /alerts/{id}", spec("alert_read", permRead, "alert", "id"), h.alert)
	// One pattern for the per-alert operations: separate literal patterns
	// (/alerts/{id}/resolve) would conflict with PUT /alerts/rules/{id}.
	r.Handle("PUT /alerts/{id}/{op}", spec("alert_updated", permWrite, "alert", "id"), h.alertOperation)
	r.Handle("POST /alerts/bulk/acknowledge", spec("alerts_bulk_acknowledged", permWrite, "alert", ""), h.bulkStatus("acknowledged"))
	r.Handle("POST /alerts/bulk/resolve", spec("alerts_bulk_resolved", permWrite, "alert", ""), h.bulkStatus("resolved"))

	r.Handle("GET /incidents", spec("incidents_listed", permRead, "incident", ""), h.incidents)
	r.Handle("GET /incidents/{id}", spec("incident_read", permRead, "incident", "id"), h.incident)
	r.Handle("PUT /incidents/{id}/status", spec("incident_status_updated", permWrite, "incident", "id"), h.incidentStatus)
	r.Handle("PUT /incidents/{id}/assign", spec("incident_assigned", permWrite, "incident", "id"), h.incidentAssign)

	r.Handle("GET /alerts/rules", spec("rules_listed", permRead, "alert_rule", ""), h.listRules)
	r.Handle("POST /alerts/rules", spec("rule_created", permWrite, "alert_rule", ""), h.createRule)
	r.Handle("PUT /alerts/rules/{id}", spec("rule_updated", permWrite, "alert_rule", "id"), h.updateRule)
	r.Handle("POST /alerts/rules/test", spec("rule_tested", permRead, "alert_rule", ""), h.testRule)
	delRule := spec("rule_deleted", permDelete, "alert_rule", "id")
	delRule.Severity = "warning"
	r.Handle("DELETE /alerts/rules/{id}", delRule, h.deleteRule)
	r.Handle("GET /alerts/severity-config", spec("severity_config_read", permRead, "severity_config", ""), h.getSeverityConfig)
	r.Handle("PUT /alerts/severity-config", spec("severity_config_updated", permWrite, "severity_config", ""), h.updateSeverityConfig)
	r.Handle("GET /alerts/channels", spec("channels_listed", permRead, "alert_channel", ""), h.listChannels)
	r.Handle("PUT /alerts/channels", spec("channels_updated", permWrite, "alert_channel", ""), h.updateChannels)

	// The template catalogue is the same for every tenant.
	r.Handle("GET /reports/templates", route.Spec{Action: "report_templates_listed", Permission: permRead, Resource: "report_template", Tenancy: route.PlatformScoped}, h.reportTemplates)
	r.Handle("POST /reports/generate", spec("report_requested", permWrite, "report_job", ""), h.generateReport)
	r.Handle("GET /reports/jobs", spec("report_jobs_listed", permRead, "report_job", ""), h.listReportJobs)
	r.Handle("GET /reports/jobs/{id}", spec("report_job_read", permRead, "report_job", "id"), h.reportJob)
	r.Handle("GET /reports/jobs/{id}/download", spec("report_downloaded", permRead, "report_job", "id"), h.reportDownload)
	delJob := spec("report_deleted", permDelete, "report_job", "id")
	delJob.Severity = "warning"
	r.Handle("DELETE /reports/jobs/{id}", delJob, h.deleteReportJob)
	r.Handle("GET /reports/scheduled", spec("scheduled_reports_listed", permRead, "scheduled_report", ""), h.listScheduledReports)
	r.Handle("POST /reports/scheduled", spec("report_scheduled", permWrite, "scheduled_report", ""), h.createScheduledReport)
	// Any signed-in dashboard reports its own errors, under its own tenant.
	r.Handle("POST /telemetry/errors", spec("error_telemetry_captured", route.Authenticated, "error_telemetry", ""), h.captureErrorTelemetry)
	r.Handle("GET /telemetry/errors", spec("error_telemetry_listed", permRead, "error_telemetry", ""), h.listErrorTelemetry)

	r.Handle("GET /alerts/stats", spec("alert_stats_read", permRead, "alert", ""), h.alertStats)
	r.Handle("GET /alerts/stats/mttd", spec("mttd_stats_viewed", permRead, "alert", ""), h.mttdStats)
	r.Handle("GET /alerts/stats/mttr", spec("mttr_stats_read", permRead, "alert", ""), h.mttrStats)
	r.Handle("GET /alerts/stats/top-sources", spec("top_sources_read", permRead, "alert", ""), h.topSources)
}

func (h *Handler) alerts(c *route.Call) {
	qs := c.R.URL.Query()
	q := AlertQuery{
		Severity:   strings.ToLower(strings.TrimSpace(qs.Get("severity"))),
		Status:     strings.ToLower(strings.TrimSpace(qs.Get("status"))),
		Action:     strings.TrimSpace(qs.Get("action")),
		TargetType: strings.TrimSpace(qs.Get("target_type")),
		TargetID:   strings.TrimSpace(qs.Get("target_id")),
		ActorID:    strings.TrimSpace(qs.Get("actor_id")),
		SourceIP:   strings.TrimSpace(qs.Get("source_ip")),
		Service:    strings.TrimSpace(qs.Get("service")),
		Resolved:   qs.Get("resolved") == "true",
		Linked:     qs.Get("linked") == "true",
		Limit:      min(atoi(qs.Get("limit")), alertPageLimit),
		Offset:     atoi(qs.Get("offset")),
		From:       parseTimeString(qs.Get("from")),
		To:         parseTimeString(qs.Get("to")),
	}
	items, err := h.svc.ListAlerts(c.R.Context(), c.Tenant, q)
	if err != nil {
		h.serviceError(c, err)
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"items": items})
}

// alertsFeed streams the tenant's new alerts as server-sent events until the
// client disconnects. The audit event is emitted when the stream ends.
func (h *Handler) alertsFeed(c *route.Call) {
	rc := http.NewResponseController(c.W)
	c.W.Header().Set("Content-Type", "text/event-stream")
	c.W.Header().Set("Cache-Control", "no-cache")
	c.W.Header().Set("Connection", "keep-alive")
	// Subscribe before "ready" so nothing published after it is missed.
	ch, cancel := h.svc.hub.Subscribe(c.Tenant)
	defer cancel()
	writeSSE(c.W, "ready", map[string]interface{}{"request_id": c.RequestID, "tenant_id": c.Tenant})
	if err := rc.Flush(); err != nil {
		c.Detail("stream_error", "streaming not supported")
		return
	}
	tick := time.NewTicker(20 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-c.R.Context().Done():
			return
		case item := <-ch:
			writeSSE(c.W, "alert", item)
		case <-tick.C:
			writeSSE(c.W, "keepalive", map[string]interface{}{"timestamp": time.Now().UTC().Format(time.RFC3339)})
		}
		_ = rc.Flush()
	}
}

func (h *Handler) alertsUnread(c *route.Call) {
	out, err := h.svc.CountUnread(c.R.Context(), c.Tenant)
	if err != nil {
		h.serviceError(c, err)
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"counts": out})
}

func (h *Handler) alert(c *route.Call) {
	item, event, err := h.svc.GetAlert(c.R.Context(), c.Tenant, c.R.PathValue("id"))
	if err != nil {
		h.serviceError(c, err)
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"alert": item, "audit_event": event})
}

// alertOperation acknowledges, resolves, marks false-positive or escalates
// one alert. The acting user is the verified caller.
func (h *Handler) alertOperation(c *route.Call) {
	op := c.R.PathValue("op")
	id := c.R.PathValue("id")
	ctx := c.R.Context()
	c.Detail("operation", strings.ReplaceAll(op, "-", "_"))
	var err error
	switch op {
	case "acknowledge", "resolve", "false-positive":
		var body struct {
			Note string `json:"note"`
		}
		if !decodeOptional(c, &body) {
			return
		}
		switch op {
		case "acknowledge":
			err = h.svc.AcknowledgeAlert(ctx, c.Tenant, id, c.Actor())
		case "resolve":
			err = h.svc.ResolveAlert(ctx, c.Tenant, id, c.Actor(), body.Note)
		default:
			err = h.svc.MarkFalsePositive(ctx, c.Tenant, id, c.Actor(), body.Note)
		}
	case "escalate":
		var body struct {
			Severity string `json:"severity"`
		}
		if !c.Decode(&body) {
			return
		}
		c.Detail("severity", normalizeSeverity(body.Severity))
		err = h.svc.EscalateAlert(ctx, c.Tenant, id, body.Severity)
	default:
		c.Error(http.StatusNotFound, "not_found", "unsupported alert action")
		return
	}
	if err != nil {
		h.serviceError(c, err)
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"status": "ok"})
}

func (h *Handler) bulkStatus(status string) func(*route.Call) {
	return func(c *route.Call) {
		var body struct {
			IDs  []string `json:"ids"`
			Note string   `json:"note"`
		}
		if !decodeOptional(c, &body) {
			return
		}
		qs := c.R.URL.Query()
		q := AlertQuery{
			Severity: strings.TrimSpace(qs.Get("severity")),
			Status:   strings.TrimSpace(qs.Get("status")),
			Action:   strings.TrimSpace(qs.Get("action")),
			Limit:    1000,
		}
		n, err := h.svc.BulkAlertStatus(c.R.Context(), c.Tenant, body.IDs, q, status, c.Actor(), body.Note)
		if err != nil {
			h.serviceError(c, err)
			return
		}
		c.Detail("updated", n)
		c.JSON(http.StatusOK, map[string]interface{}{"updated": n})
	}
}

func (h *Handler) incidents(c *route.Call) {
	items, err := h.svc.ListIncidents(c.R.Context(), c.Tenant, atoi(c.R.URL.Query().Get("limit")), atoi(c.R.URL.Query().Get("offset")))
	if err != nil {
		h.serviceError(c, err)
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"items": items})
}

func (h *Handler) incident(c *route.Call) {
	item, alerts, err := h.svc.GetIncident(c.R.Context(), c.Tenant, c.R.PathValue("id"))
	if err != nil {
		h.serviceError(c, err)
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"incident": item, "alerts": alerts})
}

func (h *Handler) incidentStatus(c *route.Call) {
	var body struct {
		Status string `json:"status"`
		Notes  string `json:"notes"`
	}
	if !c.Decode(&body) {
		return
	}
	c.Detail("status", body.Status)
	if err := h.svc.UpdateIncidentStatus(c.R.Context(), c.Tenant, c.R.PathValue("id"), body.Status, body.Notes); err != nil {
		h.serviceError(c, err)
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"status": "ok"})
}

func (h *Handler) incidentAssign(c *route.Call) {
	var body struct {
		AssignedTo string `json:"assigned_to"`
	}
	if !c.Decode(&body) {
		return
	}
	c.Detail("assigned_to", body.AssignedTo)
	if err := h.svc.AssignIncident(c.R.Context(), c.Tenant, c.R.PathValue("id"), body.AssignedTo); err != nil {
		h.serviceError(c, err)
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"status": "ok"})
}

func (h *Handler) listRules(c *route.Call) {
	items, err := h.svc.ListRules(c.R.Context(), c.Tenant)
	if err != nil {
		h.serviceError(c, err)
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"items": items})
}

// createRule and updateRule accept the rule's tenant_id only as the kernel
// verified it; the service stores the rule under c.Tenant.
func (h *Handler) createRule(c *route.Call) {
	var body AlertRule
	if !c.Decode(&body) {
		return
	}
	item, err := h.svc.CreateRule(c.R.Context(), c.Tenant, body)
	if err != nil {
		h.serviceError(c, err)
		return
	}
	c.Target(item.ID)
	c.Detail("name", item.Name)
	c.JSON(http.StatusCreated, map[string]interface{}{"item": item})
}

// testRule checks a rule without saving it: validity, one supplied event,
// and a replay of the tenant's recent audit events (rule_check.go).
func (h *Handler) testRule(c *route.Call) {
	var body RuleCheckInput
	if !c.Decode(&body) {
		return
	}
	res := h.svc.CheckRule(c.R.Context(), c.Tenant, body)
	c.Detail("condition", body.Rule.Condition)
	c.Detail("valid", res.Valid)
	if res.Replay != nil {
		c.Detail("replay_hours", res.Replay.Hours)
		c.Detail("replay_matched", res.Replay.Matched)
		c.Detail("replay_fired", res.Replay.Fired)
	}
	c.JSON(http.StatusOK, map[string]interface{}{"result": res})
}

func (h *Handler) updateRule(c *route.Call) {
	var body AlertRule
	if !c.Decode(&body) {
		return
	}
	if err := h.svc.UpdateRule(c.R.Context(), c.Tenant, c.R.PathValue("id"), body); err != nil {
		h.serviceError(c, err)
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"status": "ok"})
}

func (h *Handler) deleteRule(c *route.Call) {
	if err := h.svc.DeleteRule(c.R.Context(), c.Tenant, c.R.PathValue("id")); err != nil {
		h.serviceError(c, err)
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"status": "ok"})
}

func (h *Handler) getSeverityConfig(c *route.Call) {
	cfg, err := h.svc.GetSeverityConfig(c.R.Context(), c.Tenant)
	if err != nil {
		h.serviceError(c, err)
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"items": cfg})
}

func (h *Handler) updateSeverityConfig(c *route.Call) {
	var body map[string]string
	if !c.Decode(&body) {
		return
	}
	c.Detail("count", len(body))
	if err := h.svc.UpdateSeverityConfig(c.R.Context(), c.Tenant, body); err != nil {
		h.serviceError(c, err)
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"status": "ok"})
}

func (h *Handler) listChannels(c *route.Call) {
	items, err := h.svc.ListChannels(c.R.Context(), c.Tenant)
	if err != nil {
		h.serviceError(c, err)
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"items": items})
}

func (h *Handler) updateChannels(c *route.Call) {
	var body []NotificationChannel
	if !c.Decode(&body) {
		return
	}
	accepted, err := h.svc.UpdateChannels(c.R.Context(), c.Tenant, body)
	if err != nil {
		h.serviceError(c, err)
		return
	}
	c.Detail("count", accepted)
	c.JSON(http.StatusOK, map[string]interface{}{"status": "ok"})
}

func (h *Handler) reportTemplates(c *route.Call) {
	c.JSON(http.StatusOK, map[string]interface{}{"items": h.svc.Templates()})
}

// generateReport queues a report for the caller's tenant. The requester is
// the verified caller; requested_by is no longer read from the body.
func (h *Handler) generateReport(c *route.Call) {
	var body struct {
		TenantID   string                 `json:"tenant_id"` // verified by the kernel; c.Tenant is used
		TemplateID string                 `json:"template_id"`
		Format     string                 `json:"format"`
		Filters    map[string]interface{} `json:"filters"`
	}
	if !c.Decode(&body) {
		return
	}
	job, err := h.svc.GenerateReport(c.R.Context(), c.Tenant, body.TemplateID, body.Format, c.Actor(), body.Filters)
	if err != nil {
		h.serviceError(c, err)
		return
	}
	c.Target(job.ID)
	c.Detail("template_id", job.TemplateID)
	c.Detail("format", job.Format)
	c.JSON(http.StatusAccepted, map[string]interface{}{"job": job})
}

func (h *Handler) reportJob(c *route.Call) {
	job, err := h.svc.GetReportJob(c.R.Context(), c.Tenant, c.R.PathValue("id"))
	if err != nil {
		h.serviceError(c, err)
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"job": job})
}

func (h *Handler) listReportJobs(c *route.Call) {
	items, err := h.svc.ListReportJobs(c.R.Context(), c.Tenant, atoi(c.R.URL.Query().Get("limit")), atoi(c.R.URL.Query().Get("offset")))
	if err != nil {
		h.serviceError(c, err)
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"items": items})
}

func (h *Handler) reportDownload(c *route.Call) {
	job, err := h.svc.GetReportJob(c.R.Context(), c.Tenant, c.R.PathValue("id"))
	if err != nil {
		h.serviceError(c, err)
		return
	}
	if job.Status != "completed" {
		c.Error(http.StatusConflict, "not_ready", "report job not completed")
		return
	}
	c.Detail("template_id", job.TemplateID)
	c.JSON(http.StatusOK, map[string]interface{}{
		"content":       job.ResultContent,
		"content_type":  job.ResultContentType,
		"template_id":   job.TemplateID,
		"generated_at":  job.CompletedAt,
		"report_job_id": job.ID,
	})
}

// deleteReportJob deletes a report job; the deleting actor is the verified
// caller (the actor query parameter and X-Actor-ID header are not read).
func (h *Handler) deleteReportJob(c *route.Call) {
	job, err := h.svc.DeleteReportJob(c.R.Context(), c.Tenant, c.R.PathValue("id"))
	if err != nil {
		h.serviceError(c, err)
		return
	}
	c.Detail("template_id", job.TemplateID)
	c.Detail("format", job.Format)
	c.Detail("requested_by", job.RequestedBy)
	c.JSON(http.StatusOK, map[string]interface{}{"deleted": true})
}

func (h *Handler) listScheduledReports(c *route.Call) {
	items, err := h.svc.ListScheduledReports(c.R.Context(), c.Tenant)
	if err != nil {
		h.serviceError(c, err)
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"items": items})
}

func (h *Handler) createScheduledReport(c *route.Call) {
	var body struct {
		TenantID   string                 `json:"tenant_id"` // verified by the kernel; c.Tenant is used
		Name       string                 `json:"name"`
		TemplateID string                 `json:"template_id"`
		Format     string                 `json:"format"`
		Schedule   string                 `json:"schedule"`
		Filters    map[string]interface{} `json:"filters"`
	}
	if !c.Decode(&body) {
		return
	}
	item, err := h.svc.ScheduleReport(c.R.Context(), c.Tenant, body.Name, body.TemplateID, body.Format, body.Schedule, body.Filters)
	if err != nil {
		h.serviceError(c, err)
		return
	}
	c.Target(item.ID)
	c.Detail("template_id", item.TemplateID)
	c.Detail("schedule", item.Schedule)
	c.JSON(http.StatusCreated, map[string]interface{}{"item": item})
}

func (h *Handler) captureErrorTelemetry(c *route.Call) {
	var body struct {
		TenantID    string                 `json:"tenant_id"` // verified by the kernel; c.Tenant is used
		Source      string                 `json:"source"`
		Service     string                 `json:"service"`
		Component   string                 `json:"component"`
		Level       string                 `json:"level"`
		Message     string                 `json:"message"`
		StackTrace  string                 `json:"stack_trace"`
		Context     map[string]interface{} `json:"context"`
		Fingerprint string                 `json:"fingerprint"`
		RequestID   string                 `json:"request_id"`
		ReleaseTag  string                 `json:"release_tag"`
		BuildVer    string                 `json:"build_version"`
	}
	if !c.Decode(&body) {
		return
	}
	if strings.TrimSpace(body.Message) == "" {
		c.Error(http.StatusBadRequest, "bad_request", "message is required")
		return
	}
	item, err := h.svc.CaptureErrorTelemetry(c.R.Context(), c.Tenant, ErrorTelemetryEvent{
		Source:      body.Source,
		Service:     body.Service,
		Component:   body.Component,
		Level:       body.Level,
		Message:     body.Message,
		StackTrace:  body.StackTrace,
		Context:     body.Context,
		Fingerprint: body.Fingerprint,
		RequestID:   firstNonEmpty(body.RequestID, c.RequestID),
		ReleaseTag:  body.ReleaseTag,
		BuildVer:    body.BuildVer,
	})
	if err != nil {
		h.serviceError(c, err)
		return
	}
	c.Target(item.ID)
	c.Detail("source", item.Source)
	c.Detail("level", item.Level)
	c.JSON(http.StatusAccepted, map[string]interface{}{"item": item})
}

func (h *Handler) listErrorTelemetry(c *route.Call) {
	qs := c.R.URL.Query()
	q := ErrorTelemetryQuery{
		Source:      strings.ToLower(strings.TrimSpace(qs.Get("source"))),
		Service:     strings.ToLower(strings.TrimSpace(qs.Get("service"))),
		Component:   strings.ToLower(strings.TrimSpace(qs.Get("component"))),
		Level:       strings.ToLower(strings.TrimSpace(qs.Get("level"))),
		Fingerprint: strings.TrimSpace(qs.Get("fingerprint")),
		RequestID:   strings.TrimSpace(qs.Get("request_id")),
		Limit:       atoi(qs.Get("limit")),
		Offset:      atoi(qs.Get("offset")),
		From:        parseTimeString(qs.Get("from")),
		To:          parseTimeString(qs.Get("to")),
	}
	items, err := h.svc.ListErrorTelemetry(c.R.Context(), c.Tenant, q)
	if err != nil {
		h.serviceError(c, err)
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"items": items})
}

// statsWindow reads the optional from/to (RFC 3339) of the chart window.
// Both absent means since the first alert.
func statsWindow(c *route.Call) (AlertWindow, bool) {
	qs := c.R.URL.Query()
	w := AlertWindow{From: parseTimeString(qs.Get("from")), To: parseTimeString(qs.Get("to"))}
	if (qs.Get("from") != "" && w.From.IsZero()) || (qs.Get("to") != "" && w.To.IsZero()) {
		c.Refuse(http.StatusBadRequest, "bad_window", "from and to must be RFC 3339 times")
		return w, false
	}
	return w, true
}

func (h *Handler) alertStats(c *route.Call) {
	w, ok := statsWindow(c)
	if !ok {
		return
	}
	out, err := h.svc.AlertStats(c.R.Context(), c.Tenant, w)
	if err != nil {
		h.serviceError(c, err)
		return
	}
	c.Detail("total", out["total"])
	c.JSON(http.StatusOK, map[string]interface{}{"stats": out})
}

func (h *Handler) mttrStats(c *route.Call) {
	w, ok := statsWindow(c)
	if !ok {
		return
	}
	out, err := h.svc.MTTRStats(c.R.Context(), c.Tenant, w)
	if err != nil {
		h.serviceError(c, err)
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"mttr_minutes": out})
}

func (h *Handler) mttdStats(c *route.Call) {
	w, ok := statsWindow(c)
	if !ok {
		return
	}
	out, alertCount, truncated, err := h.svc.MTTDStats(c.R.Context(), c.Tenant, w)
	if err != nil {
		h.serviceError(c, err)
		return
	}
	c.Detail("alert_count", alertCount)
	c.Detail("bucket_count", len(out))
	c.JSON(http.StatusOK, map[string]interface{}{"mttd_minutes": out, "measured": alertCount, "truncated": truncated})
}

func (h *Handler) topSources(c *route.Call) {
	w, ok := statsWindow(c)
	if !ok {
		return
	}
	out, err := h.svc.TopSources(c.R.Context(), c.Tenant, w)
	if err != nil {
		h.serviceError(c, err)
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{
		"top_actors":   out["actors"],
		"top_ips":      out["ips"],
		"top_services": out["services"],
		"sources":      out,
	})
}

// serviceError writes a service error. Server-side failures are also kept as
// error telemetry, and their details stay out of the response.
func (h *Handler) serviceError(c *route.Call, err error) {
	var svcErr serviceError
	if errors.As(err, &svcErr) {
		if svcErr.HTTPStatus >= http.StatusInternalServerError {
			h.telemetry(c, "service_error", defaultString(svcErr.Message, "reporting service error"), svcErr.Code)
		}
		c.Error(svcErr.HTTPStatus, svcErr.Code, svcErr.Message)
		return
	}
	h.telemetry(c, "unhandled_error", err.Error(), "internal_error")
	status := httpStatusForErr(err)
	msg := err.Error()
	if status >= 500 {
		msg = "internal server error"
	}
	c.Error(status, "internal_error", msg)
}

func (h *Handler) telemetry(c *route.Call, component, message, fingerprint string) {
	_, _ = h.svc.CaptureErrorTelemetry(context.Background(), firstNonEmpty(c.Tenant, "root"), ErrorTelemetryEvent{
		Source:      "backend",
		Service:     "reporting",
		Component:   component,
		Level:       "error",
		Message:     message,
		Fingerprint: fingerprint,
		RequestID:   c.RequestID,
		ReleaseTag:  h.releaseTag,
		BuildVer:    h.buildVersion,
	})
}

// decodeOptional decodes a JSON body that may be absent, rejecting unknown
// fields. On a malformed body it writes a 400 and returns false.
func decodeOptional(c *route.Call, out interface{}) bool {
	raw, err := io.ReadAll(io.LimitReader(c.R.Body, route.MaxBody))
	if err != nil {
		c.Error(http.StatusBadRequest, "bad_request", "unreadable request body")
		return false
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return true
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		c.Error(http.StatusBadRequest, "bad_request", err.Error())
		return false
	}
	return true
}

func writeSSE(w http.ResponseWriter, event string, payload interface{}) {
	raw, _ := json.Marshal(payload)
	_, _ = w.Write([]byte("event: " + event + "\n"))
	_, _ = w.Write([]byte("data: " + string(raw) + "\n\n"))
}

// Public reports whether r reaches a Public route (pkg/jwtauth.MustWrapRouter).
func (h *Handler) Public(r *http.Request) bool { return h.router.Public(r) }

// Routed reports whether r matches a route (pkg/jwtauth.MustWrapRouter).
func (h *Handler) Routed(r *http.Request) bool { return h.router.Routed(r) }
