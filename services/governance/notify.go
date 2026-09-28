package main

import (
	"context"
	"net/http"
	"strings"

	pkgaudit "vecta-kms/pkg/audit"
	pkgauth "vecta-kms/pkg/auth"
	"vecta-kms/pkg/route"
	"vecta-kms/pkg/tenantcheck"
)

// Email notifications for compliance playbooks (send_email). Governance owns
// the tenant's SMTP settings, so it sends; only the kms-compliance service
// identity may ask, and only to active users of the tenant (by email, or
// every active holder of a role as role:<name>), so a playbook can't be used
// to mail arbitrary addresses.

const notifyingService = "kms-compliance"

const (
	maxNotifySubject = 200
	maxNotifyBody    = 16 << 10
)

// kernelEmitter sends kernel events through governance's unified audit
// client, resolved per call so it can be wired after the routes are built.
type kernelEmitter struct{ h *Handler }

func (e kernelEmitter) Emit(ctx context.Context, action string, evt pkgaudit.Event) error {
	if e.h.kernelAudit == nil {
		return nil
	}
	return e.h.kernelAudit.Emit(ctx, action, evt)
}

// SetAuditClient wires the unified audit client used by kernel routes.
func (h *Handler) SetAuditClient(c *pkgaudit.Client) {
	if c != nil {
		h.kernelAudit = c
	}
}

func (h *Handler) notifyRouter() *route.Router {
	r := route.New("governance", kernelEmitter{h}, nil)
	r.Handle("POST /governance/notify/email", route.Spec{Action: "notification_email_sent", Permission: route.Authenticated, Resource: "notification"}, h.notifyEmail)
	return r
}

// mountKernel serves r's routes on mux with the bearer token verified into
// the request context (governance's legacy routes parse it themselves).
func (h *Handler) mountKernel(mux *http.ServeMux, r *route.Router) {
	verified := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if raw := strings.TrimSpace(strings.TrimPrefix(req.Header.Get("Authorization"), "Bearer")); raw != "" && h.parseToken != nil {
			if claims, err := h.parseToken(raw); err == nil {
				req = req.WithContext(pkgauth.ContextWithClaims(req.Context(), claims))
			}
		}
		r.ServeHTTP(w, req)
	})
	for _, rt := range r.Routes() {
		mux.Handle(rt.Pattern, verified)
	}
}

func (h *Handler) notifyEmail(c *route.Call) {
	if !tenantcheck.IsServicePrincipal(c.Claims) || c.Claims.ClientID != notifyingService {
		c.Refuse(http.StatusForbidden, "service_identity_required", "only the compliance service sends playbook email")
		return
	}
	var in struct {
		TenantID      string   `json:"tenant_id"`
		To            []string `json:"to"`
		Subject       string   `json:"subject"`
		Body          string   `json:"body"`
		PlaybookRunID string   `json:"playbook_run_id"`
	}
	if !c.Decode(&in) {
		return
	}
	c.Detail("playbook_run_id", in.PlaybookRunID)
	subject := strings.TrimSpace(strings.ReplaceAll(strings.ReplaceAll(in.Subject, "\r", " "), "\n", " "))
	if subject == "" || len(subject) > maxNotifySubject || len(in.Body) > maxNotifyBody || len(in.To) == 0 || len(in.To) > 20 {
		c.Error(http.StatusBadRequest, "bad_request", "1 to 20 recipients, a subject of at most 200 characters and a body of at most 16 KiB are required")
		return
	}
	ctx := c.R.Context()
	seen := map[string]bool{}
	var recipients []string
	for _, r := range in.To {
		r = strings.ToLower(strings.TrimSpace(r))
		var emails []string
		if role, ok := strings.CutPrefix(r, "role:"); ok {
			holders, err := h.svc.store.RoleHolderEmails(ctx, c.Tenant, []string{role})
			if err != nil {
				c.Error(http.StatusInternalServerError, "internal_error", "resolve role failed")
				return
			}
			emails = holders
		} else if ok, err := h.svc.store.IsActiveUserEmail(ctx, c.Tenant, r); err != nil {
			c.Error(http.StatusInternalServerError, "internal_error", "resolve recipient failed")
			return
		} else if ok {
			emails = []string{r}
		}
		if len(emails) == 0 {
			c.Detail("recipient", r)
			c.Refuse(http.StatusBadRequest, "recipient_not_tenant_user", r+" is not an active user (or role with active users) of this tenant")
			return
		}
		for _, e := range emails {
			if !seen[e] {
				seen[e] = true
				recipients = append(recipients, e)
			}
		}
	}
	c.Detail("recipients", len(recipients))
	settings, err := h.svc.GetSettings(ctx, c.Tenant)
	if err != nil {
		c.Error(http.StatusInternalServerError, "internal_error", "read settings failed")
		return
	}
	if strings.TrimSpace(settings.SMTPHost) == "" || strings.TrimSpace(settings.SMTPPort) == "" {
		c.Error(http.StatusConflict, "smtp_not_configured", "configure SMTP in Governance settings to send email")
		return
	}
	sender := h.svc.email
	if sender == nil {
		sender = NewSMTPMailer(SMTPConfig{Host: settings.SMTPHost, Port: settings.SMTPPort, Username: settings.SMTPUsername,
			Password: settings.SMTPPassword, From: settings.SMTPFrom, StartTLS: settings.SMTPStartTLS})
	}
	var failed []string
	for _, to := range recipients {
		if err := sender.Send(ctx, EmailMessage{To: to, Subject: "[Vecta KMS] " + subject, Body: in.Body}); err != nil {
			failed = append(failed, to)
		}
	}
	if len(failed) > 0 {
		c.Detail("failed", failed)
		c.Error(http.StatusBadGateway, "send_failed", "email to "+strings.Join(failed, ", ")+" could not be sent")
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"sent": len(recipients)})
}
