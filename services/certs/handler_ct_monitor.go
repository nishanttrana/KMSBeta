package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// handleListWatchedDomains returns all CT-monitored domains for a tenant.
func (h *Handler) handleListWatchedDomains(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	items, err := h.svc.store.ListWatchedDomains(r.Context(), tenantID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "list_watched_domains_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items, "request_id": reqID})
}

// handleAddWatchedDomain adds a domain to CT monitoring and starts a background scan.
func (h *Handler) handleAddWatchedDomain(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req AddWatchedDomainRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}
	if strings.TrimSpace(req.TenantID) == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "tenant_id is required", reqID, "")
		return
	}
	if strings.TrimSpace(req.Domain) == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "domain is required", reqID, req.TenantID)
		return
	}
	if req.AlertOnExpiringDay <= 0 {
		req.AlertOnExpiringDay = 30
	}

	d := WatchedDomain{
		ID:                 ctNewID("wd"),
		TenantID:           strings.TrimSpace(req.TenantID),
		Domain:             strings.TrimSpace(req.Domain),
		IncludeSubdomains:  req.IncludeSubdomains,
		AlertOnUnknownCA:   req.AlertOnUnknownCA,
		AlertOnExpiringDay: req.AlertOnExpiringDay,
		Enabled:            true,
		AddedAt:            time.Now().UTC(),
	}

	saved, err := h.svc.store.AddWatchedDomain(r.Context(), d)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "add_watched_domain_failed", err.Error(), reqID, req.TenantID)
		return
	}

	// Background goroutine: simulate CT log fetch and create synthetic entries.
	go h.simulateCTFetch(saved)

	writeJSON(w, http.StatusCreated, map[string]interface{}{"domain": saved, "request_id": reqID})
}

// handleToggleWatchedDomain enables or disables a watched domain (PATCH).
func (h *Handler) handleToggleWatchedDomain(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "id is required", reqID, tenantID)
		return
	}
	var req ToggleWatchedDomainRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, tenantID)
		return
	}
	updated, err := h.svc.store.UpdateWatchedDomain(r.Context(), tenantID, id, req.Enabled)
	if err != nil {
		status := http.StatusInternalServerError
		if err == errStoreNotFound {
			status = http.StatusNotFound
		}
		writeErr(w, status, "toggle_watched_domain_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"domain": updated, "request_id": reqID})
}

// handleDeleteWatchedDomain removes a domain from CT monitoring.
func (h *Handler) handleDeleteWatchedDomain(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "id is required", reqID, tenantID)
		return
	}
	if err := h.svc.store.DeleteWatchedDomain(r.Context(), tenantID, id); err != nil {
		status := http.StatusInternalServerError
		if err == errStoreNotFound {
			status = http.StatusNotFound
		}
		writeErr(w, status, "delete_watched_domain_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"status": "deleted", "request_id": reqID})
}

// handleListCTLogEntries returns CT log entries for a tenant (optionally filtered by domain).
func (h *Handler) handleListCTLogEntries(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	domain := strings.TrimSpace(r.URL.Query().Get("domain"))
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 {
		limit = 100
	}
	items, err := h.svc.store.ListCTLogEntries(r.Context(), tenantID, domain, limit)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "list_ct_log_entries_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items, "request_id": reqID})
}

// handleListCTAlerts returns all CT alerts for a tenant.
func (h *Handler) handleListCTAlerts(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	items, err := h.svc.store.ListCTAlerts(r.Context(), tenantID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "list_ct_alerts_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items, "request_id": reqID})
}

// handleAcknowledgeCTAlert acknowledges an open CT alert.
func (h *Handler) handleAcknowledgeCTAlert(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "id is required", reqID, tenantID)
		return
	}
	alert, err := h.svc.store.AcknowledgeCTAlert(r.Context(), tenantID, id)
	if err != nil {
		status := http.StatusInternalServerError
		if err == errStoreNotFound {
			status = http.StatusNotFound
		}
		writeErr(w, status, "acknowledge_ct_alert_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"alert": alert, "request_id": reqID})
}

// simulateCTFetch runs in a goroutine after a domain is added, simulating CT log polling.
// It creates 2-3 synthetic log entries and creates alerts for any unknown CA entries.
func (h *Handler) simulateCTFetch(d WatchedDomain) {
	time.Sleep(1 * time.Second)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	knownIssuers := []struct {
		name        string
		fingerprint string
		isKnown     bool
	}{
		{"Let's Encrypt Authority X3", ctFingerprint("letsencrypt-x3"), true},
		{"DigiCert SHA2 Secure Server CA", ctFingerprint("digicert-sha2"), true},
		{"UnknownCA-ShadowNet", ctFingerprint("shadownet-ca"), false},
	}

	numEntries := 2 + (ctRandByte() % 2) // 2 or 3

	for i := 0; i < int(numEntries); i++ {
		issuerIdx := i % len(knownIssuers)
		issuer := knownIssuers[issuerIdx]

		notBefore := time.Now().UTC().Add(-30 * 24 * time.Hour)
		notAfter := time.Now().UTC().Add(time.Duration(60+i*30) * 24 * time.Hour)

		sanList := []string{d.Domain}
		if d.IncludeSubdomains {
			sanList = append(sanList, "*."+d.Domain)
		}

		entry := CTLogEntry{
			ID:                ctNewID("ctle"),
			TenantID:          d.TenantID,
			Domain:            d.Domain,
			SubjectCN:         d.Domain,
			SANs:              sanList,
			Issuer:            issuer.name,
			IssuerFingerprint: issuer.fingerprint,
			NotBefore:         notBefore,
			NotAfter:          notAfter,
			Serial:            ctRandSerial(),
			CTLog:             "argon2024",
			LoggedAt:          time.Now().UTC(),
			IsKnownCA:         issuer.isKnown,
			IsRevoked:         false,
		}

		// Determine if an alert should fire.
		var alertReason string
		if d.AlertOnUnknownCA && !issuer.isKnown {
			alertReason = fmt.Sprintf("certificate issued by unknown CA: %s", issuer.name)
			entry.AlertTriggered = true
			entry.AlertReason = alertReason
		}

		expiringInDays := int(time.Until(notAfter).Hours() / 24)
		if d.AlertOnExpiringDay > 0 && expiringInDays <= d.AlertOnExpiringDay {
			expReason := fmt.Sprintf("certificate expires in %d days", expiringInDays)
			if alertReason == "" {
				alertReason = expReason
			} else {
				alertReason += "; " + expReason
			}
			entry.AlertTriggered = true
			entry.AlertReason = alertReason
		}

		saved, err := h.svc.store.AddCTLogEntry(ctx, entry)
		if err != nil {
			logger.Printf("ct_monitor: failed to store log entry for domain %s: %v", d.Domain, err)
			continue
		}
		h.svc.store.BumpCTDomainCertCount(ctx, d.TenantID, d.Domain)

		// Create alert if triggered.
		if saved.AlertTriggered {
			alert := CTAlert{
				ID:          ctNewID("cta"),
				TenantID:    d.TenantID,
				Domain:      d.Domain,
				EntryID:     saved.ID,
				Reason:      alertReason,
				Severity:    "high",
				Status:      "open",
				TriggeredAt: time.Now().UTC(),
				CertSummary: fmt.Sprintf("CN=%s, Issuer=%s, NotAfter=%s", saved.SubjectCN, saved.Issuer, saved.NotAfter.Format("2006-01-02")),
			}
			if _, err := h.svc.store.CreateCTAlert(ctx, alert); err != nil {
				logger.Printf("ct_monitor: failed to create alert for domain %s: %v", d.Domain, err)
			} else {
				h.svc.store.BumpCTDomainAlertCount(ctx, d.TenantID, d.Domain)
			}
		}
	}

	logger.Printf("ct_monitor: completed synthetic CT fetch for domain %s (tenant %s)", d.Domain, d.TenantID)
}

// --- CT monitor utility helpers ---

func ctNewID(prefix string) string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return prefix + "_" + hex.EncodeToString(b)
}

func ctFingerprint(seed string) string {
	sum := sha256.Sum256([]byte(seed))
	return hex.EncodeToString(sum[:])
}

func ctRandByte() byte {
	b := make([]byte, 1)
	_, _ = rand.Read(b)
	return b[0]
}

func ctRandSerial() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
