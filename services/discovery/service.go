package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"sort"
	"strings"
	"time"
)

type Service struct {
	store   Store
	keycore KeyCoreClient
	certs   CertsClient
	events  EventPublisher
	now     func() time.Time
	cloud   CloudClient
	root    string
}

func NewService(store Store, keycore KeyCoreClient, certs CertsClient, events EventPublisher) *Service {
	root := strings.TrimSpace(os.Getenv("WORKSPACE_ROOT")) // code scan refuses when unset
	return &Service{
		store:   store,
		keycore: keycore,
		certs:   certs,
		events:  events,
		now:     func() time.Time { return time.Now().UTC() },
		root:    root,
	}
}

func (s *Service) StartScan(ctx context.Context, req ScanRequest) (DiscoveryScan, error) {
	req.TenantID = strings.TrimSpace(req.TenantID)
	if req.TenantID == "" {
		return DiscoveryScan{}, newServiceError(400, "bad_request", "tenant_id is required")
	}
	types := normalizeScanTypes(req.ScanTypes)
	scan := DiscoveryScan{
		ID:        newID("scan"),
		TenantID:  req.TenantID,
		ScanType:  strings.Join(types, ","),
		Status:    "running",
		Trigger:   defaultString(req.Trigger, "manual"),
		Stats:     map[string]interface{}{},
		StartedAt: s.now(),
	}
	if err := s.store.CreateScan(ctx, scan); err != nil {
		return DiscoveryScan{}, err
	}
	_ = s.publishAudit(ctx, "audit.discovery.scan_initiated", req.TenantID, map[string]interface{}{
		"scan_id":    scan.ID,
		"scan_types": types,
	})

	assets := make([]CryptoAsset, 0)
	stats := map[string]interface{}{
		"network_assets": 0,
		"cloud_assets":   0,
		"certs_assets":   0,
		"code_assets":    0,
	}
	// Each type reports its own outcome: a failed or unconfigured source is
	// recorded as such, never replaced by invented assets.
	errs := map[string]string{}
	for _, scanType := range types {
		var items []CryptoAsset
		var err error
		switch scanType {
		case "network":
			items, err = s.scanNetwork(ctx, req.TenantID, scan.ID)
		case "cloud":
			items, err = s.scanCloud(ctx, req.TenantID, scan.ID)
		case "certs":
			items, err = s.scanCertificates(ctx, req.TenantID, scan.ID)
		case "code":
			items, err = s.scanCode(ctx, req.TenantID, scan.ID)
		}
		if err != nil {
			errs[scanType] = err.Error()
		}
		assets = append(assets, items...)
		stats[scanType+"_assets"] = len(items)
	}
	status := "completed"
	switch {
	case len(errs) == len(types):
		status = "failed"
	case len(errs) > 0:
		status = "completed_with_errors"
	}
	if len(errs) > 0 {
		stats["errors"] = errs
	}
	seen := map[string]struct{}{}
	inserted := 0
	for _, a := range assets {
		if _, ok := seen[a.ID]; ok {
			continue
		}
		seen[a.ID] = struct{}{}
		if err := s.store.UpsertAsset(ctx, a); err == nil {
			inserted++
			_ = s.publishAudit(ctx, "audit.discovery.asset_found", req.TenantID, map[string]interface{}{
				"asset_id":       a.ID,
				"asset_type":     a.AssetType,
				"classification": a.Classification,
				"source":         a.Source,
			})
		}
	}
	stats["assets_discovered"] = inserted
	scan.Status = status
	scan.Stats = stats
	scan.CompletedAt = s.now()
	if err := s.store.UpdateScan(ctx, scan); err != nil {
		return DiscoveryScan{}, err
	}
	completed := map[string]interface{}{
		"scan_id":           scan.ID,
		"assets_discovered": inserted,
		"status":            status,
	}
	if len(errs) > 0 {
		completed["errors"] = errs
	}
	_ = s.publishAudit(ctx, "audit.discovery.scan_completed", req.TenantID, completed)
	return s.store.GetScan(ctx, req.TenantID, scan.ID)
}

func (s *Service) ListScans(ctx context.Context, tenantID string, limit int, offset int) ([]DiscoveryScan, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return nil, newServiceError(400, "bad_request", "tenant_id is required")
	}
	return s.store.ListScans(ctx, tenantID, limit, offset)
}

func (s *Service) GetScan(ctx context.Context, tenantID string, id string) (DiscoveryScan, error) {
	tenantID = strings.TrimSpace(tenantID)
	id = strings.TrimSpace(id)
	if tenantID == "" || id == "" {
		return DiscoveryScan{}, newServiceError(400, "bad_request", "tenant_id and id are required")
	}
	return s.store.GetScan(ctx, tenantID, id)
}

func (s *Service) ListAssets(ctx context.Context, tenantID string, limit int, offset int, source string, assetType string, classification string) ([]CryptoAsset, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return nil, newServiceError(400, "bad_request", "tenant_id is required")
	}
	return s.store.ListAssets(ctx, tenantID, limit, offset, source, assetType, classification)
}

func (s *Service) GetAsset(ctx context.Context, tenantID string, id string) (CryptoAsset, error) {
	tenantID = strings.TrimSpace(tenantID)
	id = strings.TrimSpace(id)
	if tenantID == "" || id == "" {
		return CryptoAsset{}, newServiceError(400, "bad_request", "tenant_id and id are required")
	}
	return s.store.GetAsset(ctx, tenantID, id)
}

// errClassificationIsCatalogue: an asset's classification is what
// pkg/cryptocatalog says about its algorithm; a review records status and
// notes only, never a different label.
var errClassificationIsCatalogue = errors.New("classification comes from the algorithm catalogue and can't be overridden; record a status or notes instead")

func (s *Service) ClassifyAsset(ctx context.Context, tenantID string, id string, req ClassifyRequest) (CryptoAsset, error) {
	tenantID = strings.TrimSpace(tenantID)
	id = strings.TrimSpace(id)
	if tenantID == "" || id == "" {
		return CryptoAsset{}, newServiceError(400, "bad_request", "tenant_id and id are required")
	}
	item, err := s.store.GetAsset(ctx, tenantID, id)
	if err != nil {
		return CryptoAsset{}, err
	}
	if c := strings.ToLower(strings.TrimSpace(req.Classification)); c != "" && c != item.Classification {
		return CryptoAsset{}, errClassificationIsCatalogue
	}
	if strings.TrimSpace(req.Status) != "" {
		item.Status = strings.ToLower(strings.TrimSpace(req.Status))
	}
	if item.Metadata == nil {
		item.Metadata = map[string]interface{}{}
	}
	if strings.TrimSpace(req.Notes) != "" {
		item.Metadata["classification_notes"] = strings.TrimSpace(req.Notes)
	}
	item.UpdatedAt = s.now()
	item.LastSeen = s.now()
	if err := s.store.UpsertAsset(ctx, item); err != nil {
		return CryptoAsset{}, err
	}
	_ = s.publishAudit(ctx, "audit.discovery.asset_classified", tenantID, map[string]interface{}{
		"asset_id":       item.ID,
		"classification": item.Classification,
		"status":         item.Status,
	})
	return s.store.GetAsset(ctx, tenantID, id)
}

func (s *Service) Summary(ctx context.Context, tenantID string) (DiscoverySummary, error) {
	items, err := s.ListAssets(ctx, tenantID, 10000, 0, "", "", "")
	if err != nil {
		return DiscoverySummary{}, err
	}
	sum := DiscoverySummary{
		TenantID:              tenantID,
		TotalAssets:           len(items),
		SourceDistribution:    map[string]int{},
		AlgorithmDistribution: map[string]int{},
		ClassificationCounts:  map[string]int{"strong": 0, "vulnerable": 0, "unknown": 0},
	}
	for _, it := range items {
		sum.SourceDistribution[it.Source]++
		sum.AlgorithmDistribution[it.Algorithm]++
		sum.ClassificationCounts[it.Classification]++
		if it.PQCReady {
			sum.PQCReadyCount++
		}
	}
	if sum.TotalAssets > 0 {
		sum.PQCReadinessPercent = round2(pct(sum.PQCReadyCount, sum.TotalAssets))
	}
	return sum, nil
}

func normalizeScanTypes(in []string) []string {
	if len(in) == 0 {
		return []string{"network", "cloud", "certs", "code"}
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, t := range in {
		t = strings.ToLower(strings.TrimSpace(t))
		switch t {
		case "network", "cloud", "certs", "code", "all":
		default:
			continue
		}
		if t == "all" {
			return []string{"network", "cloud", "certs", "code"}
		}
		if _, ok := seen[t]; ok {
			continue
		}
		seen[t] = struct{}{}
		out = append(out, t)
	}
	if len(out) == 0 {
		return []string{"network", "cloud", "certs", "code"}
	}
	return out
}

func max(a int, b int) int {
	if a > b {
		return a
	}
	return b
}

func (s *Service) publishAudit(ctx context.Context, subject string, tenantID string, data map[string]interface{}) error {
	if s.events == nil {
		return nil
	}
	raw, err := json.Marshal(map[string]interface{}{
		"tenant_id": tenantID,
		"service":   "discovery",
		"action":    subject,
		"timestamp": s.now().Format(time.RFC3339Nano),
		"data":      data,
	})
	if err != nil {
		return err
	}
	return s.events.Publish(ctx, subject, raw)
}

func sortAssets(items []CryptoAsset) {
	sort.Slice(items, func(i, j int) bool {
		return items[i].Source+"|"+items[i].AssetType+"|"+items[i].ID < items[j].Source+"|"+items[j].AssetType+"|"+items[j].ID
	})
}
