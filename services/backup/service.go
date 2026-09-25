package main

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

// BackupService serves backup policies, runs and restore points.
//
// Preview (pkg/features "backup.scheduler", docs/PREVIEW_FEATURES.md): this
// service stores backup policies but does not execute backups or restores.
// It previously simulated both (random key counts and sizes, a fake file path,
// a checksum over its own made-up metadata, a restore that did nothing); that
// was removed. Real encrypted backup and restore is the governance service
// (System Administration > Backups).
type BackupService struct {
	store  Store
	events EventPublisher
}

// NewBackupService creates a new BackupService. events may be nil (no NATS).
func NewBackupService(store Store, events EventPublisher) *BackupService {
	return &BackupService{store: store, events: events}
}

// audit emits a specific audit event for an activity (the generic HTTP
// request log alone does not say what changed or why something was refused).
func (svc *BackupService) audit(r *http.Request, subject, tenantID string, data map[string]interface{}) {
	if svc.events == nil {
		return
	}
	data["actor"] = firstNonEmptyHeader(r, "X-Actor", "X-Username")
	data["source_ip"] = r.RemoteAddr
	raw, err := json.Marshal(map[string]interface{}{
		"tenant_id": tenantID,
		"service":   "backup",
		"action":    subject,
		"timestamp": time.Now().UTC().Format(time.RFC3339Nano),
		"data":      data,
	})
	if err != nil {
		return
	}
	_ = svc.events.Publish(context.WithoutCancel(r.Context()), subject, raw)
}

func firstNonEmptyHeader(r *http.Request, names ...string) string {
	for _, n := range names {
		if v := strings.TrimSpace(r.Header.Get(n)); v != "" {
			return v
		}
	}
	return ""
}
