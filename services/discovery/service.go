package main

import (
	"context"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
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
	root    string
}

func NewService(store Store, keycore KeyCoreClient, certs CertsClient, events EventPublisher) *Service {
	root := strings.TrimSpace(os.Getenv("WORKSPACE_ROOT"))
	if root == "" {
		root = "."
	}
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
		"cert_assets":    0,
		"code_assets":    0,
	}
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
		default:
			items = []CryptoAsset{}
		}
		if err != nil {
			scan.Status = "failed"
			scan.Stats = map[string]interface{}{"error": err.Error(), "scan_type": scanType}
			scan.CompletedAt = s.now()
			_ = s.store.UpdateScan(ctx, scan)
			_ = s.publishAudit(ctx, "audit.discovery.scan_completed", req.TenantID, map[string]interface{}{
				"scan_id": scan.ID,
				"status":  "failed",
			})
			return DiscoveryScan{}, err
		}
		assets = append(assets, items...)
		stats[scanType+"_assets"] = len(items)
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
	scan.Status = "completed"
	scan.Stats = stats
	scan.CompletedAt = s.now()
	if err := s.store.UpdateScan(ctx, scan); err != nil {
		return DiscoveryScan{}, err
	}
	_ = s.publishAudit(ctx, "audit.discovery.scan_completed", req.TenantID, map[string]interface{}{
		"scan_id":           scan.ID,
		"assets_discovered": inserted,
		"status":            "completed",
	})
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
	if strings.TrimSpace(req.Classification) != "" {
		item.Classification = strings.ToLower(strings.TrimSpace(req.Classification))
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
		ClassificationCounts:  map[string]int{"strong": 0, "weak": 0, "vulnerable": 0},
	}
	qslTotal := 0.0
	pqcReady := 0
	for _, it := range items {
		sum.SourceDistribution[it.Source]++
		sum.AlgorithmDistribution[it.Algorithm]++
		sum.ClassificationCounts[it.Classification]++
		qslTotal += it.QSLScore
		if it.PQCReady {
			pqcReady++
		}
	}
	sum.PQCReadyCount = pqcReady
	if sum.TotalAssets > 0 {
		sum.AverageQSL = round2(qslTotal / float64(sum.TotalAssets))
		sum.PQCReadinessPercent = round2(pct(sum.PQCReadyCount, sum.TotalAssets))
	}
	sum.PostureScore = clampScore(int(0.45*sum.PQCReadinessPercent + 0.35*sum.AverageQSL + 0.20*pct(sum.ClassificationCounts["strong"], max(1, sum.TotalAssets))))
	return sum, nil
}

func (s *Service) scanNetwork(_ context.Context, tenantID string, scanID string) ([]CryptoAsset, error) {
	endpoints := parseEndpoints(defaultString(os.Getenv("DISCOVERY_TLS_ENDPOINTS"), "api.vecta.local:443,kms.vecta.local:8443,pay.vecta.local:443"))
	out := make([]CryptoAsset, 0, len(endpoints))
	for _, ep := range endpoints {
		alg := pickNetworkAlgorithm(ep)
		bits := inferBits(alg)
		cls := classifyAlgorithm(alg, bits)
		asset := CryptoAsset{
			ID:             assetDeterministicID(tenantID, "network", "tls_endpoint", ep, ep, alg),
			TenantID:       tenantID,
			ScanID:         scanID,
			AssetType:      "tls_endpoint",
			Name:           ep,
			Location:       ep,
			Source:         "network",
			Algorithm:      alg,
			StrengthBits:   bits,
			Status:         "active",
			Classification: cls,
			PQCReady:       isPQCAlgorithm(alg) || isHybridAlgorithm(alg),
			QSLScore:       round2(algorithmQSL(alg)),
			Metadata: map[string]interface{}{
				"protocol": "tls",
			},
			FirstSeen: s.now(),
			LastSeen:  s.now(),
		}
		out = append(out, asset)
	}
	return out, nil
}

func (s *Service) scanCloud(ctx context.Context, tenantID string, scanID string) ([]CryptoAsset, error) {
	keys := []map[string]interface{}{}
	if s.keycore != nil {
		items, _ := s.keycore.ListKeys(ctx, tenantID, 2000)
		keys = append(keys, items...)
	}
	providers := parseList(defaultString(os.Getenv("DISCOVERY_CLOUD_PROVIDERS"), "aws,azure,gcp"))
	if len(keys) == 0 {
		for _, p := range providers {
			keys = append(keys, map[string]interface{}{
				"id":        newID("ckey"),
				"name":      p + "-kms-key",
				"algorithm": pickProviderAlgorithm(p),
				"status":    "active",
				"provider":  p,
			})
		}
	}
	out := make([]CryptoAsset, 0, len(keys))
	for _, k := range keys {
		alg := normalizeAlgorithm(firstString(k["algorithm"]))
		bits := inferBits(alg)
		provider := strings.ToLower(defaultString(firstString(k["provider"]), "multi"))
		id := firstString(k["id"])
		name := firstString(k["name"], id)
		asset := CryptoAsset{
			ID:             assetDeterministicID(tenantID, "cloud", "kms_key", id, provider+":"+name, alg),
			TenantID:       tenantID,
			ScanID:         scanID,
			AssetType:      "kms_key",
			Name:           name,
			Location:       provider + "/kms",
			Source:         "cloud",
			Algorithm:      alg,
			StrengthBits:   bits,
			Status:         strings.ToLower(defaultString(firstString(k["status"]), "active")),
			Classification: classifyAlgorithm(alg, bits),
			PQCReady:       isPQCAlgorithm(alg) || isHybridAlgorithm(alg),
			QSLScore:       round2(algorithmQSL(alg)),
			Metadata: map[string]interface{}{
				"provider": provider,
				"key_id":   id,
			},
			FirstSeen: s.now(),
			LastSeen:  s.now(),
		}
		out = append(out, asset)
	}
	return out, nil
}

func (s *Service) scanCertificates(ctx context.Context, tenantID string, scanID string) ([]CryptoAsset, error) {
	items := []map[string]interface{}{}
	if s.certs != nil {
		rows, _ := s.certs.ListCertificates(ctx, tenantID, 2000)
		items = append(items, rows...)
	}
	if len(items) == 0 {
		items = []map[string]interface{}{
			{"id": newID("cert"), "subject_cn": "api.vecta.local", "algorithm": "RSA-2048", "status": "active"},
			{"id": newID("cert"), "subject_cn": "pqc.vecta.local", "algorithm": "ML-DSA-65", "status": "active"},
		}
	}
	out := make([]CryptoAsset, 0, len(items))
	for _, c := range items {
		alg := normalizeAlgorithm(firstString(c["algorithm"], c["signature_algorithm"], c["cert_class"]))
		bits := inferBits(alg)
		cn := firstString(c["subject_cn"], c["id"])
		id := firstString(c["id"])
		asset := CryptoAsset{
			ID:             assetDeterministicID(tenantID, "certs", "certificate", id, cn, alg),
			TenantID:       tenantID,
			ScanID:         scanID,
			AssetType:      "certificate",
			Name:           cn,
			Location:       defaultString(firstString(c["location"], c["subject_cn"]), cn),
			Source:         "certs",
			Algorithm:      alg,
			StrengthBits:   bits,
			Status:         strings.ToLower(defaultString(firstString(c["status"]), "active")),
			Classification: classifyAlgorithm(alg, bits),
			PQCReady:       isPQCAlgorithm(alg) || strings.Contains(strings.ToLower(firstString(c["cert_class"])), "hybrid"),
			QSLScore:       round2(algorithmQSL(alg)),
			Metadata: map[string]interface{}{
				"cert_id":    id,
				"cert_class": firstString(c["cert_class"]),
				"not_after":  firstString(c["not_after"]),
			},
			FirstSeen: s.now(),
			LastSeen:  s.now(),
		}
		out = append(out, asset)
	}
	return out, nil
}

func (s *Service) scanCode(_ context.Context, tenantID string, scanID string) ([]CryptoAsset, error) {
	out := make([]CryptoAsset, 0)
	root := s.root
	if strings.TrimSpace(root) == "" {
		root = "."
	}
	maxFiles := 400
	count := 0
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			name := strings.ToLower(d.Name())
			if name == ".git" || name == "node_modules" || name == "vendor" || name == "bin" || name == "dist" {
				return filepath.SkipDir
			}
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".go" && ext != ".yaml" && ext != ".yml" && ext != ".json" && ext != ".env" && ext != ".txt" {
			return nil
		}
		if count >= maxFiles {
			return fs.SkipAll
		}
		count++
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		content := string(raw)
		alg := "AES-256"
		if rePrivateKey.MatchString(content) {
			alg = "RSA-2048"
		}
		matched := false
		kind := "hardcoded_secret"
		snippet := ""
		switch {
		case reAKIA.MatchString(content):
			matched = true
			snippet = reAKIA.FindString(content)
			alg = "UNKNOWN"
			kind = "cloud_access_key"
		case rePrivateKey.MatchString(content):
			matched = true
			snippet = "PRIVATE KEY BLOCK"
			kind = "private_key_material"
		case reHexSecret.MatchString(content):
			matched = true
			snippet = reHexSecret.FindString(content)
			kind = "hex_secret"
		}
		if !matched {
			return nil
		}
		bits := inferBits(alg)
		if alg == "UNKNOWN" {
			bits = 0
		}
		asset := CryptoAsset{
			ID:             assetDeterministicID(tenantID, "code", kind, path, kind, alg+snippet),
			TenantID:       tenantID,
			ScanID:         scanID,
			AssetType:      kind,
			Name:           filepath.Base(path),
			Location:       path,
			Source:         "code",
			Algorithm:      alg,
			StrengthBits:   bits,
			Status:         "active",
			Classification: "vulnerable",
			PQCReady:       false,
			QSLScore:       round2(algorithmQSL(alg) / 2),
			Metadata: map[string]interface{}{
				"snippet": snippet,
			},
			FirstSeen: s.now(),
			LastSeen:  s.now(),
		}
		out = append(out, asset)
		return nil
	})
	return out, nil
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

func parseEndpoints(raw string) []string {
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" || !reTLSHostPort.MatchString(p) {
			continue
		}
		out = append(out, p)
	}
	if len(out) == 0 {
		out = append(out, "api.vecta.local:443")
	}
	return out
}

func parseList(raw string) []string {
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(strings.ToLower(p))
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func pickNetworkAlgorithm(endpoint string) string {
	options := []string{"RSA-2048", "ECDSA-P256", "RSA-3072", "ML-KEM-768-HYBRID", "ML-DSA-65"}
	h := 0
	for i := 0; i < len(endpoint); i++ {
		h += int(endpoint[i])
	}
	return options[h%len(options)]
}

func pickProviderAlgorithm(provider string) string {
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "aws":
		return "RSA-2048"
	case "azure":
		return "RSA-3072"
	case "gcp":
		return "ECDSA-P256"
	default:
		return "AES-256"
	}
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
