package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"vecta-kms/pkg/pdfutil"
)

type Service struct {
	store         Store
	keycore       KeyCoreClient
	certs         CertsClient
	discovery     DiscoveryClient
	events        EventPublisher
	vulnProvider  VulnerabilityProvider
	workspaceRoot string
}

func NewService(store Store, keycore KeyCoreClient, certs CertsClient, discovery DiscoveryClient, events EventPublisher) *Service {
	root := strings.TrimSpace(os.Getenv("WORKSPACE_ROOT"))
	if root == "" {
		root = "."
	}
	return &Service{
		store:         store,
		keycore:       keycore,
		certs:         certs,
		discovery:     discovery,
		events:        events,
		vulnProvider:  newDefaultVulnerabilityProvider(store),
		workspaceRoot: root,
	}
}

func (s *Service) StartScheduler(ctx context.Context, cfg SchedulerConfig) {
	if every := scheduleInterval(cfg.SBOMMode); every > 0 {
		go func() {
			t := time.NewTicker(every)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					_, _ = s.GenerateSBOM(context.Background(), "scheduled")
				}
			}
		}()
	}
	if every := scheduleInterval(cfg.CBOMMode); every > 0 {
		go func() {
			t := time.NewTicker(every)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					for _, tenantID := range s.scheduledTenants(context.Background(), cfg.Tenants) {
						_, _ = s.GenerateCBOM(context.Background(), tenantID, "scheduled")
					}
				}
			}
		}()
	}
}

func scheduleInterval(mode string) time.Duration {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "daily":
		return 24 * time.Hour
	case "weekly":
		return 7 * 24 * time.Hour
	default:
		return 0
	}
}

func (s *Service) scheduledTenants(ctx context.Context, configured []string) []string {
	out := append([]string{}, configured...)
	if known, err := s.store.ListKnownCBOMTenants(ctx); err == nil {
		out = append(out, known...)
	}
	return uniqueStrings(out)
}

func (s *Service) GenerateSBOM(ctx context.Context, trigger string) (SBOMSnapshot, error) {
	doc, err := s.buildSBOMDocument()
	if err != nil {
		return SBOMSnapshot{}, err
	}
	item := SBOMSnapshot{
		ID:         newID("sbom"),
		SourceHash: hashSBOMComponents(doc.Components),
		Document:   doc,
		Summary:    summarizeSBOM(doc),
	}
	if err := s.store.SaveSBOMSnapshot(ctx, item); err != nil {
		return SBOMSnapshot{}, err
	}
	item, err = s.store.GetSBOMSnapshotByID(ctx, item.ID)
	if err != nil {
		return SBOMSnapshot{}, err
	}
	vulnerabilityCount := 0
	if matches, err := s.correlateVulnerabilities(ctx, item.Document.Components); err == nil {
		vulnerabilityCount = len(matches)
	}
	_ = s.publishAudit(ctx, "audit.sbom.generated", "", map[string]interface{}{
		"snapshot_id":       item.ID,
		"component_count":   len(item.Document.Components),
		"trigger":           defaultString(trigger, "manual"),
		"vulnerability_cnt": vulnerabilityCount,
	})
	return item, nil
}

func (s *Service) GetLatestSBOM(ctx context.Context) (SBOMSnapshot, error) {
	item, err := s.store.GetLatestSBOMSnapshot(ctx)
	if err == nil {
		return item, nil
	}
	if errors.Is(err, errNotFound) {
		return s.GenerateSBOM(ctx, "bootstrap")
	}
	return SBOMSnapshot{}, err
}

func (s *Service) ListSBOMHistory(ctx context.Context, limit int) ([]SBOMSnapshot, error) {
	items, err := s.store.ListSBOMSnapshots(ctx, limit)
	if err != nil {
		return nil, err
	}
	if len(items) == 0 {
		item, err := s.GenerateSBOM(ctx, "bootstrap")
		if err != nil {
			return nil, err
		}
		return []SBOMSnapshot{item}, nil
	}
	return items, nil
}

func (s *Service) GetSBOMByID(ctx context.Context, id string) (SBOMSnapshot, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return SBOMSnapshot{}, newServiceError(400, "bad_request", "id is required")
	}
	return s.store.GetSBOMSnapshotByID(ctx, id)
}

func (s *Service) SBOMVulnerabilities(ctx context.Context) ([]VulnerabilityMatch, error) {
	item, err := s.GetLatestSBOM(ctx)
	if err != nil {
		return nil, err
	}
	return s.correlateVulnerabilities(ctx, item.Document.Components)
}

func (s *Service) ListManualAdvisories(ctx context.Context) ([]ManualAdvisory, error) {
	return s.store.ListManualAdvisories(ctx)
}

func (s *Service) SaveManualAdvisory(ctx context.Context, item ManualAdvisory) (ManualAdvisory, error) {
	item.Component = strings.TrimSpace(item.Component)
	item.Ecosystem = normalizeManualEcosystem(item.Ecosystem)
	item.IntroducedVersion = strings.TrimSpace(item.IntroducedVersion)
	item.FixedVersion = strings.TrimSpace(item.FixedVersion)
	item.Severity = normalizeSeverity(item.Severity)
	item.Summary = strings.TrimSpace(item.Summary)
	item.Reference = strings.TrimSpace(item.Reference)
	item.ID = strings.TrimSpace(item.ID)

	if item.Component == "" {
		return ManualAdvisory{}, newServiceError(400, "bad_request", "component is required")
	}
	if item.Severity == "unknown" {
		return ManualAdvisory{}, newServiceError(400, "bad_request", "severity must be low, medium, high, or critical")
	}
	if item.Summary == "" {
		return ManualAdvisory{}, newServiceError(400, "bad_request", "summary is required")
	}
	if item.ID == "" {
		item.ID = newID("osv")
	}
	if item.IntroducedVersion != "" && item.FixedVersion != "" && compareSemver(item.IntroducedVersion, item.FixedVersion) >= 0 {
		return ManualAdvisory{}, newServiceError(400, "bad_request", "introduced_version must be lower than fixed_version")
	}
	if err := s.store.UpsertManualAdvisory(ctx, item); err != nil {
		return ManualAdvisory{}, err
	}
	items, err := s.store.ListManualAdvisories(ctx)
	if err != nil {
		return ManualAdvisory{}, err
	}
	for _, existing := range items {
		if existing.ID == item.ID {
			return existing, nil
		}
	}
	return item, nil
}

func (s *Service) DeleteManualAdvisory(ctx context.Context, id string) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return newServiceError(400, "bad_request", "id is required")
	}
	return s.store.DeleteManualAdvisory(ctx, id)
}

func (s *Service) DiffSBOM(ctx context.Context, fromID string, toID string) (BOMDiff, error) {
	if strings.TrimSpace(fromID) == "" || strings.TrimSpace(toID) == "" {
		return BOMDiff{}, newServiceError(400, "bad_request", "from and to snapshot ids are required")
	}
	from, err := s.store.GetSBOMSnapshotByID(ctx, fromID)
	if err != nil {
		return BOMDiff{}, err
	}
	to, err := s.store.GetSBOMSnapshotByID(ctx, toID)
	if err != nil {
		return BOMDiff{}, err
	}
	diff := diffComponents(from.Document.Components, to.Document.Components)
	diff.FromID = fromID
	diff.ToID = toID
	fromMatches, fromErr := s.correlateVulnerabilities(ctx, from.Document.Components)
	toMatches, toErr := s.correlateVulnerabilities(ctx, to.Document.Components)
	if fromErr == nil && toErr == nil {
		diff.Metrics["vulnerability_delta"] = len(toMatches) - len(fromMatches)
	} else {
		diff.Metrics["vulnerability_delta"] = 0
	}
	return diff, nil
}

func (s *Service) correlateVulnerabilities(ctx context.Context, components []BOMComponent) ([]VulnerabilityMatch, error) {
	if s.vulnProvider == nil {
		return correlateCatalogVulnerabilities(components), nil
	}
	items, err := s.vulnProvider.Match(ctx, components)
	if err == nil {
		return dedupeVulnerabilityMatches(items), nil
	}
	logger.Printf("external vulnerability providers failed, using local catalog fallback: %v", err)
	return correlateCatalogVulnerabilities(components), nil
}

func (s *Service) ExportSBOM(ctx context.Context, id string, format string, encoding string) (ExportArtifact, error) {
	item, err := s.GetSBOMByID(ctx, id)
	if err != nil {
		return ExportArtifact{}, err
	}
	return exportSBOM(item, format, encoding)
}

func (s *Service) GenerateCBOM(ctx context.Context, tenantID string, trigger string) (CBOMSnapshot, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return CBOMSnapshot{}, newServiceError(400, "bad_request", "tenant_id is required")
	}
	keys, keyErr := s.fetchKeyAssets(ctx, tenantID)
	certs, certErr := s.fetchCertAssets(ctx, tenantID)
	discovered, discErr := s.fetchDiscoveryAssets(ctx, tenantID)

	doc := buildCBOMDocument(tenantID, keys, certs, discovered)
	if keyErr != nil || certErr != nil || discErr != nil {
		doc.Metadata["partial_data"] = "true"
	}
	item := CBOMSnapshot{
		ID:         newID("cbom"),
		TenantID:   tenantID,
		SourceHash: hashCBOMAssets(doc.Assets),
		Document:   doc,
		Summary:    summarizeCBOM(doc),
	}
	if err := s.store.SaveCBOMSnapshot(ctx, item); err != nil {
		return CBOMSnapshot{}, err
	}
	item, err := s.store.GetCBOMSnapshotByID(ctx, tenantID, item.ID)
	if err != nil {
		return CBOMSnapshot{}, err
	}
	_ = s.publishAudit(ctx, "audit.cbom.generated", tenantID, map[string]interface{}{
		"snapshot_id":       item.ID,
		"asset_count":       item.Document.TotalAssetCount,
		"pqc_readiness_pct": round2(item.Document.PQCReadinessPercent),
		"trigger":           defaultString(trigger, "manual"),
	})
	return item, nil
}

func (s *Service) GetLatestCBOM(ctx context.Context, tenantID string) (CBOMSnapshot, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return CBOMSnapshot{}, newServiceError(400, "bad_request", "tenant_id is required")
	}
	item, err := s.store.GetLatestCBOMSnapshot(ctx, tenantID)
	if err == nil {
		return item, nil
	}
	if errors.Is(err, errNotFound) {
		return s.GenerateCBOM(ctx, tenantID, "bootstrap")
	}
	return CBOMSnapshot{}, err
}

func (s *Service) ListCBOMHistory(ctx context.Context, tenantID string, limit int) ([]CBOMSnapshot, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return nil, newServiceError(400, "bad_request", "tenant_id is required")
	}
	items, err := s.store.ListCBOMSnapshots(ctx, tenantID, limit)
	if err != nil {
		return nil, err
	}
	if len(items) == 0 {
		item, err := s.GenerateCBOM(ctx, tenantID, "bootstrap")
		if err != nil {
			return nil, err
		}
		return []CBOMSnapshot{item}, nil
	}
	return items, nil
}

func (s *Service) GetCBOMByID(ctx context.Context, tenantID string, id string) (CBOMSnapshot, error) {
	tenantID = strings.TrimSpace(tenantID)
	id = strings.TrimSpace(id)
	if tenantID == "" || id == "" {
		return CBOMSnapshot{}, newServiceError(400, "bad_request", "tenant_id and id are required")
	}
	return s.store.GetCBOMSnapshotByID(ctx, tenantID, id)
}

func (s *Service) ExportCBOM(ctx context.Context, tenantID string, id string, format string) (ExportArtifact, error) {
	item, err := s.GetCBOMByID(ctx, tenantID, id)
	if err != nil {
		return ExportArtifact{}, err
	}
	return exportCBOM(item, format)
}

func (s *Service) CBOMSummary(ctx context.Context, tenantID string) (map[string]interface{}, error) {
	item, err := s.GetLatestCBOM(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	return summarizeCBOM(item.Document), nil
}

func (s *Service) CBOMPQCReadiness(ctx context.Context, tenantID string) (map[string]interface{}, error) {
	item, err := s.GetLatestCBOM(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"tenant_id":             tenantID,
		"pqc_ready_count":       item.Document.PQCReadyCount,
		"total_assets":          item.Document.TotalAssetCount,
		"pqc_readiness_percent": round2(item.Document.PQCReadinessPercent),
		"status":                readinessStatus(item.Document.PQCReadinessPercent),
	}, nil
}

func (s *Service) DiffCBOM(ctx context.Context, tenantID string, fromID string, toID string) (BOMDiff, error) {
	if strings.TrimSpace(tenantID) == "" || strings.TrimSpace(fromID) == "" || strings.TrimSpace(toID) == "" {
		return BOMDiff{}, newServiceError(400, "bad_request", "tenant_id, from and to snapshot ids are required")
	}
	from, err := s.store.GetCBOMSnapshotByID(ctx, tenantID, fromID)
	if err != nil {
		return BOMDiff{}, err
	}
	to, err := s.store.GetCBOMSnapshotByID(ctx, tenantID, toID)
	if err != nil {
		return BOMDiff{}, err
	}
	diff := diffAssets(from.Document, to.Document)
	diff.FromID = fromID
	diff.ToID = toID
	return diff, nil
}

func (s *Service) buildSBOMDocument() (SBOMDocument, error) {
	root := s.workspaceRoot
	if strings.TrimSpace(root) == "" {
		root = "."
	}
	all := dedupeComponents(append(
		append(
			append(
				append(
					append(collectServiceComponents(root), collectGoModuleComponents(root)...),
					collectNodePackageComponents(root)...,
				),
				collectContainerComponents(root)...,
			),
			collectSystemPackageComponents(root)...,
		),
		collectPlatformComponents()...,
	))
	sort.Slice(all, func(i, j int) bool {
		return all[i].Name+"@"+all[i].Version < all[j].Name+"@"+all[j].Version
	})
	return SBOMDocument{
		Format:      "cyclonedx",
		SpecVersion: "1.6",
		GeneratedAt: time.Now().UTC(),
		Appliance:   "vecta-kms",
		Components:  all,
	}, nil
}

func collectServiceComponents(root string) []BOMComponent {
	servicesDir := filepath.Join(root, "services")
	entries, err := os.ReadDir(servicesDir)
	if err != nil {
		return []BOMComponent{}
	}
	out := []BOMComponent{}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if _, err := os.Stat(filepath.Join(servicesDir, e.Name(), "main.go")); err != nil {
			continue
		}
		out = append(out, BOMComponent{
			Name:      "vecta-kms/" + e.Name(),
			Version:   "dev",
			Type:      "application",
			PURL:      "pkg:generic/vecta-kms/" + e.Name() + "@dev",
			Supplier:  "Vecta",
			Licenses:  []string{"Apache-2.0"},
			Hashes:    map[string]string{},
			Metadata:  map[string]string{"source": "services"},
			Ecosystem: "go",
		})
	}
	return out
}

func collectGoModuleComponents(root string) []BOMComponent {
	// Deduplicate by module name so each module appears exactly once with its
	// resolved version. go.mod versions take precedence over go.sum; within
	// go.sum entries for the same module, keep the highest version.
	type modEntry struct {
		name    string // original-cased module name
		version string
		source  string // "go.mod" or "go.sum"
	}
	best := map[string]*modEntry{} // key = lowercase module name

	// 1) Parse go.mod first — these are the actual resolved versions.
	raw, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err == nil {
		lines := strings.Split(string(raw), "\n")
		inRequire := false
		for _, line := range lines {
			l := strings.TrimSpace(line)
			if l == "" || strings.HasPrefix(l, "//") {
				continue
			}
			if l == "require (" {
				inRequire = true
				continue
			}
			if inRequire && l == ")" {
				inRequire = false
				continue
			}
			if strings.HasPrefix(l, "require ") {
				l = strings.TrimSpace(strings.TrimPrefix(l, "require"))
			} else if !inRequire {
				continue
			}
			fields := strings.Fields(l)
			if len(fields) < 2 {
				continue
			}
			moduleName := fields[0]
			version := fields[1]
			if moduleName == "" || version == "" {
				continue
			}
			best[strings.ToLower(moduleName)] = &modEntry{name: moduleName, version: version, source: "go.mod"}
		}
	}

	// 2) Parse go.sum for transitive deps not in go.mod.
	//    Keep only the highest version per module.
	if sumRaw, err := os.ReadFile(filepath.Join(root, "go.sum")); err == nil {
		for _, line := range strings.Split(string(sumRaw), "\n") {
			fields := strings.Fields(strings.TrimSpace(line))
			if len(fields) < 2 {
				continue
			}
			moduleName := strings.TrimSpace(fields[0])
			version := strings.TrimSpace(fields[1])
			if moduleName == "" || version == "" {
				continue
			}
			version = strings.TrimSuffix(version, "/go.mod")
			key := strings.ToLower(moduleName)
			if existing, ok := best[key]; ok {
				if existing.source == "go.mod" {
					continue // go.mod entries always win
				}
				if compareSemver(version, existing.version) <= 0 {
					continue // keep highest version among go.sum entries
				}
			}
			best[key] = &modEntry{name: moduleName, version: version, source: "go.sum"}
		}
	}

	// 3) Build final component list.
	out := make([]BOMComponent, 0, len(best))
	for _, entry := range best {
		out = append(out, BOMComponent{
			Name:      entry.name,
			Version:   entry.version,
			Type:      "library",
			PURL:      "pkg:golang/" + entry.name + "@" + strings.TrimPrefix(entry.version, "v"),
			Supplier:  "unknown",
			Licenses:  []string{},
			Hashes:    map[string]string{},
			Metadata:  map[string]string{"source": entry.source},
			Ecosystem: "go",
		})
	}
	return out
}

func collectContainerComponents(root string) []BOMComponent {
	out := []BOMComponent{}
	out = append(out, parseComposeContainerComponents(filepath.Join(root, "docker-compose.yml"), "docker-compose.yml")...)
	out = append(out, parseComposeContainerComponents(filepath.Join(root, "docker-compose.dev.yml"), "docker-compose.dev.yml")...)
	return out
}

func parseComposeContainerComponents(path string, source string) []BOMComponent {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	lines := strings.Split(string(raw), "\n")
	inServices := false
	currentService := ""
	out := []BOMComponent{}
	for _, line := range lines {
		trim := strings.TrimSpace(line)
		if trim == "" || strings.HasPrefix(trim, "#") {
			continue
		}
		if trim == "services:" {
			inServices = true
			continue
		}
		if !inServices {
			continue
		}
		if !strings.HasPrefix(line, " ") {
			inServices = false
			currentService = ""
			continue
		}
		if strings.HasPrefix(line, "  ") && strings.HasSuffix(trim, ":") && !strings.HasPrefix(trim, "image:") {
			currentService = strings.TrimSuffix(trim, ":")
			continue
		}
		if currentService == "" || !strings.HasPrefix(trim, "image:") {
			continue
		}
		image := strings.TrimSpace(strings.TrimPrefix(trim, "image:"))
		name := image
		version := "latest"
		if idx := strings.LastIndex(image, ":"); idx >= 0 {
			name = image[:idx]
			version = image[idx+1:]
		}
		out = append(out, BOMComponent{
			Name:      name,
			Version:   version,
			Type:      "container",
			PURL:      "pkg:docker/" + name + "@" + version,
			Supplier:  "container-registry",
			Licenses:  []string{},
			Hashes:    map[string]string{},
			Metadata:  map[string]string{"service": currentService, "source": source},
			Ecosystem: "container",
		})
	}
	return out
}

func collectNodePackageComponents(root string) []BOMComponent {
	type lockPackage struct {
		Version string `json:"version"`
	}
	type lockFile struct {
		Packages map[string]lockPackage `json:"packages"`
	}

	raw, err := os.ReadFile(filepath.Join(root, "web", "dashboard", "package-lock.json"))
	if err != nil {
		return nil
	}
	var lock lockFile
	if err := json.Unmarshal(raw, &lock); err != nil {
		return nil
	}
	out := []BOMComponent{}
	for pkgPath, meta := range lock.Packages {
		p := strings.TrimSpace(pkgPath)
		if p == "" {
			continue
		}
		name := ""
		if strings.Contains(p, "node_modules/") {
			name = p[strings.LastIndex(p, "node_modules/")+len("node_modules/"):]
		}
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		version := strings.TrimSpace(meta.Version)
		if version == "" {
			version = "unknown"
		}
		out = append(out, BOMComponent{
			Name:      name,
			Version:   version,
			Type:      "library",
			PURL:      "pkg:npm/" + strings.ReplaceAll(name, "@", "%40") + "@" + strings.TrimPrefix(version, "v"),
			Supplier:  "unknown",
			Licenses:  []string{},
			Hashes:    map[string]string{},
			Metadata:  map[string]string{"source": "web/dashboard/package-lock.json"},
			Ecosystem: "npm",
		})
	}
	return out
}

func collectSystemPackageComponents(root string) []BOMComponent {
	out := []BOMComponent{}
	pkgs := map[string]map[string]string{}
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d == nil || d.IsDir() || d.Name() != "Dockerfile" {
			return nil
		}
		raw, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}
		content := strings.ReplaceAll(string(raw), "\\\n", " ")
		for _, line := range strings.Split(content, "\n") {
			l := strings.TrimSpace(line)
			if !strings.HasPrefix(strings.ToLower(l), "run ") {
				continue
			}
			for _, marker := range []string{"apk add", "apt-get install", "apt install"} {
				for _, name := range extractInstallPackages(l, marker) {
					if _, ok := pkgs[name]; ok {
						continue
					}
					source := filepath.ToSlash(path)
					rootPath := filepath.ToSlash(root)
					source = strings.TrimPrefix(source, rootPath)
					source = strings.TrimPrefix(source, "/")
					pkgs[name] = map[string]string{
						"source": source,
					}
				}
			}
		}
		return nil
	})
	for name, meta := range pkgs {
		out = append(out, BOMComponent{
			Name:      name,
			Version:   "unknown",
			Type:      "os-pkg",
			PURL:      "pkg:generic/" + name + "@unknown",
			Supplier:  "linux-distribution",
			Licenses:  []string{},
			Hashes:    map[string]string{},
			Metadata:  meta,
			Ecosystem: "system",
		})
	}
	return out
}

func extractInstallPackages(line string, marker string) []string {
	lower := strings.ToLower(line)
	idx := strings.Index(lower, marker)
	if idx < 0 {
		return nil
	}
	segment := strings.TrimSpace(line[idx+len(marker):])
	for _, stop := range []string{"&&", ";"} {
		if sidx := strings.Index(segment, stop); sidx >= 0 {
			segment = strings.TrimSpace(segment[:sidx])
		}
	}
	fields := strings.Fields(segment)
	out := []string{}
	for _, field := range fields {
		f := strings.Trim(strings.TrimSpace(field), "'\"")
		if f == "" || strings.HasPrefix(f, "-") || strings.Contains(f, "$") {
			continue
		}
		out = append(out, f)
	}
	return out
}

func collectPlatformComponents() []BOMComponent {
	return []BOMComponent{
		{
			Name:      "go-runtime",
			Version:   runtime.Version(),
			Type:      "runtime",
			PURL:      "pkg:golang/go@" + strings.TrimPrefix(runtime.Version(), "go"),
			Supplier:  "golang",
			Licenses:  []string{"BSD-3-Clause"},
			Hashes:    map[string]string{},
			Metadata:  map[string]string{"os": runtime.GOOS, "arch": runtime.GOARCH},
			Ecosystem: "go",
		},
		{
			Name:      "postgresql",
			Version:   "16",
			Type:      "infrastructure",
			PURL:      "pkg:generic/postgresql@16",
			Supplier:  "postgresql",
			Licenses:  []string{"PostgreSQL"},
			Hashes:    map[string]string{},
			Metadata:  map[string]string{"source": "platform"},
			Ecosystem: "database",
		},
		{
			Name:      "nats",
			Version:   "2.x",
			Type:      "infrastructure",
			PURL:      "pkg:generic/nats@2",
			Supplier:  "nats.io",
			Licenses:  []string{"Apache-2.0"},
			Hashes:    map[string]string{},
			Metadata:  map[string]string{"source": "platform"},
			Ecosystem: "messaging",
		},
		{
			Name:      "valkey",
			Version:   "7",
			Type:      "infrastructure",
			PURL:      "pkg:generic/valkey@7",
			Supplier:  "valkey",
			Licenses:  []string{"BSD-3-Clause"},
			Hashes:    map[string]string{},
			Metadata:  map[string]string{"source": "platform"},
			Ecosystem: "cache",
		},
	}
}

func dedupeComponents(in []BOMComponent) []BOMComponent {
	seen := map[string]BOMComponent{}
	for _, c := range in {
		key := strings.ToLower(c.Type + "|" + c.Name + "|" + c.Version)
		if _, ok := seen[key]; ok {
			continue
		}
		if c.Metadata == nil {
			c.Metadata = map[string]string{}
		}
		if c.Hashes == nil {
			c.Hashes = map[string]string{}
		}
		seen[key] = c
	}
	out := make([]BOMComponent, 0, len(seen))
	for _, c := range seen {
		out = append(out, c)
	}
	return out
}

func summarizeSBOM(doc SBOMDocument) map[string]interface{} {
	typeCount := map[string]int{}
	for _, c := range doc.Components {
		typeCount[c.Type]++
	}
	return map[string]interface{}{
		"appliance":       doc.Appliance,
		"format":          doc.Format,
		"spec_version":    doc.SpecVersion,
		"component_count": len(doc.Components),
		"type_count":      typeCount,
		"generated_at":    doc.GeneratedAt,
	}
}

func hashSBOMComponents(items []BOMComponent) string {
	keys := make([]string, 0, len(items))
	for _, c := range items {
		keys = append(keys, c.Type+"|"+c.Name+"|"+c.Version)
	}
	sort.Strings(keys)
	sum := sha256.Sum256([]byte(strings.Join(keys, "\n")))
	return fmt.Sprintf("%x", sum[:])
}

func diffComponents(from []BOMComponent, to []BOMComponent) BOMDiff {
	fromMap := map[string]BOMComponent{}
	toMap := map[string]BOMComponent{}
	for _, c := range from {
		fromMap[strings.ToLower(c.Type+"|"+c.Name)] = c
	}
	for _, c := range to {
		toMap[strings.ToLower(c.Type+"|"+c.Name)] = c
	}
	added := []map[string]interface{}{}
	removed := []map[string]interface{}{}
	changed := []map[string]interface{}{}
	for key, next := range toMap {
		prev, ok := fromMap[key]
		if !ok {
			added = append(added, map[string]interface{}{"name": next.Name, "type": next.Type, "version": next.Version})
			continue
		}
		if prev.Version != next.Version {
			changed = append(changed, map[string]interface{}{
				"name":         next.Name,
				"type":         next.Type,
				"from_version": prev.Version,
				"to_version":   next.Version,
			})
		}
	}
	for key, prev := range fromMap {
		if _, ok := toMap[key]; ok {
			continue
		}
		removed = append(removed, map[string]interface{}{"name": prev.Name, "type": prev.Type, "version": prev.Version})
	}
	sortDiffItems(added)
	sortDiffItems(removed)
	sortDiffItems(changed)
	return BOMDiff{
		Added:    added,
		Removed:  removed,
		Changed:  changed,
		Metrics:  map[string]interface{}{"added": len(added), "removed": len(removed), "changed": len(changed)},
		Compared: time.Now().UTC(),
	}
}

func sortDiffItems(items []map[string]interface{}) {
	sort.Slice(items, func(i, j int) bool {
		return firstString(items[i]["name"]) < firstString(items[j]["name"])
	})
}

func exportSBOM(item SBOMSnapshot, format string, encoding string) (ExportArtifact, error) {
	format = strings.ToLower(strings.TrimSpace(format))
	if format == "" {
		format = "cyclonedx"
	}
	encoding = strings.ToLower(strings.TrimSpace(encoding))
	if encoding == "" {
		encoding = "json"
	}
	switch format {
	case "cyclonedx":
		if encoding == "xml" {
			content, err := renderCycloneDXXML(item.Document)
			if err != nil {
				return ExportArtifact{}, err
			}
			return ExportArtifact{Format: format, ContentType: "application/xml", Encoding: "utf-8", Content: content}, nil
		}
		raw, _ := json.MarshalIndent(renderCycloneDXJSON(item.Document.Components), "", "  ")
		return ExportArtifact{Format: format, ContentType: "application/json", Encoding: "utf-8", Content: string(raw)}, nil
	case "spdx":
		raw, _ := json.MarshalIndent(renderSPDXJSON(item.Document), "", "  ")
		return ExportArtifact{Format: format, ContentType: "application/json", Encoding: "utf-8", Content: string(raw)}, nil
	case "pdf":
		lines := []string{
			"Snapshot: " + item.ID,
			"Generated: " + item.CreatedAt.Format(time.RFC3339),
			"Format: " + defaultString(item.Document.Format, "cyclonedx"),
			"Spec Version: " + defaultString(item.Document.SpecVersion, "1.6"),
			"Appliance: " + defaultString(item.Document.Appliance, "vecta-kms"),
			fmt.Sprintf("Total Components: %d", len(item.Document.Components)),
			"",
			"Component Inventory",
		}
		for idx, c := range item.Document.Components {
			lines = append(lines, fmt.Sprintf(
				"%04d. [%s/%s] %s @ %s",
				idx+1,
				defaultString(c.Type, "library"),
				defaultString(c.Ecosystem, "unknown"),
				defaultString(c.Name, "unknown"),
				defaultString(c.Version, "unknown"),
			))
		}
		pdf := renderTextPDF("Vecta KMS SBOM Report", lines)
		return ExportArtifact{Format: format, ContentType: "application/pdf", Encoding: "base64", Content: base64.StdEncoding.EncodeToString(pdf)}, nil
	default:
		return ExportArtifact{}, newServiceError(400, "bad_request", "unsupported export format")
	}
}

func exportCBOM(item CBOMSnapshot, format string) (ExportArtifact, error) {
	format = strings.ToLower(strings.TrimSpace(format))
	if format == "" {
		format = "cyclonedx"
	}
	switch format {
	case "cyclonedx":
		raw, _ := json.MarshalIndent(renderCycloneDXJSON(item.Document), "", "  ")
		return ExportArtifact{Format: format, ContentType: "application/json", Encoding: "utf-8", Content: string(raw)}, nil
	case "pdf":
		lines := []string{
			"Snapshot: " + item.ID,
			"Tenant: " + item.TenantID,
			"Generated: " + item.CreatedAt.Format(time.RFC3339),
			"Format: " + defaultString(item.Document.Format, "cyclonedx-crypto"),
			"Spec Version: " + defaultString(item.Document.SpecVersion, "1.6"),
			fmt.Sprintf("Total Assets: %d", item.Document.TotalAssetCount),
			fmt.Sprintf("PQC Ready: %d", item.Document.PQCReadyCount),
			fmt.Sprintf("Deprecated: %d", item.Document.DeprecatedCount),
			fmt.Sprintf("PQC Readiness: %.2f%%", item.Document.PQCReadinessPercent),
			"",
			"Asset Inventory",
		}
		for idx, a := range item.Document.Assets {
			lines = append(lines, fmt.Sprintf(
				"%04d. [%s/%s] %s | alg=%s | bits=%d | status=%s | pqc=%t | deprecated=%t",
				idx+1,
				defaultString(a.Source, "unknown"),
				defaultString(a.AssetType, "asset"),
				defaultString(a.Name, defaultString(a.ID, "unknown")),
				defaultString(a.Algorithm, "unknown"),
				a.StrengthBits,
				defaultString(a.Status, "unknown"),
				a.PQCReady,
				a.Deprecated,
			))
		}
		pdf := renderTextPDF("Vecta KMS CBOM Report", lines)
		return ExportArtifact{Format: format, ContentType: "application/pdf", Encoding: "base64", Content: base64.StdEncoding.EncodeToString(pdf)}, nil
	default:
		return ExportArtifact{}, newServiceError(400, "bad_request", "unsupported export format")
	}
}

func renderCycloneDXJSON(components interface{}) map[string]interface{} {
	return map[string]interface{}{
		"bomFormat":    "CycloneDX",
		"specVersion":  "1.6",
		"serialNumber": "urn:uuid:" + newID("bom"),
		"version":      1,
		"metadata": map[string]interface{}{
			"timestamp": time.Now().UTC().Format(time.RFC3339),
			"tools":     []map[string]interface{}{{"name": "kms-sbom", "version": "v1"}},
		},
		"components": components,
	}
}

func renderSPDXJSON(doc SBOMDocument) map[string]interface{} {
	pkgs := make([]map[string]interface{}, 0, len(doc.Components))
	for _, c := range doc.Components {
		pkgs = append(pkgs, map[string]interface{}{
			"SPDXID":           "SPDXRef-" + sanitizeSPDXID(c.Name),
			"name":             c.Name,
			"versionInfo":      c.Version,
			"supplier":         c.Supplier,
			"downloadLocation": "NOASSERTION",
			"licenseConcluded": "NOASSERTION",
		})
	}
	return map[string]interface{}{
		"spdxVersion":       "SPDX-2.3",
		"dataLicense":       "CC0-1.0",
		"SPDXID":            "SPDXRef-DOCUMENT",
		"name":              "vecta-kms-sbom",
		"documentNamespace": "https://vecta.example/sbom/" + newID("doc"),
		"creationInfo":      map[string]interface{}{"created": doc.GeneratedAt.Format(time.RFC3339), "creators": []string{"Tool:kms-sbom"}},
		"packages":          pkgs,
	}
}

func renderCycloneDXXML(doc SBOMDocument) (string, error) {
	type cdxComponent struct {
		Type    string `xml:"type,attr"`
		Name    string `xml:"name"`
		Version string `xml:"version"`
		PURL    string `xml:"purl,omitempty"`
	}
	type cdxMetadata struct {
		Timestamp string `xml:"timestamp"`
		ToolName  string `xml:"tools>tool>name"`
		ToolVer   string `xml:"tools>tool>version"`
	}
	type cdx struct {
		XMLName      xml.Name       `xml:"bom"`
		XMLNS        string         `xml:"xmlns,attr"`
		SpecVersion  string         `xml:"specVersion,attr"`
		Version      int            `xml:"version,attr"`
		SerialNumber string         `xml:"serialNumber,attr"`
		Metadata     cdxMetadata    `xml:"metadata"`
		Components   []cdxComponent `xml:"components>component"`
	}
	comps := make([]cdxComponent, 0, len(doc.Components))
	for _, c := range doc.Components {
		comps = append(comps, cdxComponent{Type: defaultString(c.Type, "library"), Name: c.Name, Version: c.Version, PURL: c.PURL})
	}
	payload := cdx{
		XMLNS:        "http://cyclonedx.org/schema/bom/1.6",
		SpecVersion:  "1.6",
		Version:      1,
		SerialNumber: "urn:uuid:" + newID("bom"),
		Metadata:     cdxMetadata{Timestamp: doc.GeneratedAt.Format(time.RFC3339), ToolName: "kms-sbom", ToolVer: "v1"},
		Components:   comps,
	}
	raw, err := xml.MarshalIndent(payload, "", "  ")
	if err != nil {
		return "", err
	}
	return xml.Header + string(raw), nil
}

func renderTextPDF(title string, lines []string) []byte {
	raw, err := pdfutil.RenderTextPDF(title, lines)
	if err != nil {
		fallback := []byte("%PDF-1.4\n% Report generation failed\n1 0 obj\n<< /Type /Catalog >>\nendobj\nxref\n0 2\n0000000000 65535 f \n0000000015 00000 n \ntrailer\n<< /Size 2 /Root 1 0 R >>\nstartxref\n52\n%%EOF\n")
		return fallback
	}
	return raw
}

func sanitizeSPDXID(v string) string {
	replacer := strings.NewReplacer("/", "-", "\\", "-", ":", "-", ".", "-", "@", "-")
	return replacer.Replace(v)
}

func (s *Service) fetchKeyAssets(ctx context.Context, tenantID string) ([]map[string]interface{}, error) {
	if s.keycore == nil {
		return []map[string]interface{}{}, nil
	}
	return s.keycore.ListKeys(ctx, tenantID, 5000)
}

func (s *Service) fetchCertAssets(ctx context.Context, tenantID string) ([]map[string]interface{}, error) {
	if s.certs == nil {
		return []map[string]interface{}{}, nil
	}
	return s.certs.ListCertificates(ctx, tenantID, 5000)
}

func (s *Service) fetchDiscoveryAssets(ctx context.Context, tenantID string) ([]map[string]interface{}, error) {
	if s.discovery == nil {
		return []map[string]interface{}{}, nil
	}
	return s.discovery.ListCryptoAssets(ctx, tenantID, 5000)
}

func buildCBOMDocument(tenantID string, keys []map[string]interface{}, certs []map[string]interface{}, discovered []map[string]interface{}) CBOMDocument {
	assets := make([]CryptoAsset, 0, len(keys)+len(certs)+len(discovered))
	algorithmDist := map[string]int{}
	strengthHist := map[string]int{"<128": 0, "128-255": 0, "256-3071": 0, ">=3072": 0}
	sourceCount := map[string]int{"keycore": 0, "certs": 0, "discovery": 0}
	pqcReady := 0
	deprecated := 0

	add := func(a CryptoAsset) {
		if strings.TrimSpace(a.ID) == "" {
			a.ID = newID("asset")
		}
		a.TenantID = tenantID
		if a.Metadata == nil {
			a.Metadata = map[string]interface{}{}
		}
		alg := normalizeAlgorithm(a.Algorithm)
		a.Algorithm = alg
		if a.StrengthBits <= 0 {
			a.StrengthBits = inferBits(alg)
		}
		a.PQCReady = a.PQCReady || isPQCAlgorithm(alg)
		a.Deprecated = a.Deprecated || isDeprecatedAlgorithm(alg)
		algorithmDist[alg]++
		switch {
		case a.StrengthBits < 128:
			strengthHist["<128"]++
		case a.StrengthBits < 256:
			strengthHist["128-255"]++
		case a.StrengthBits < 3072:
			strengthHist["256-3071"]++
		default:
			strengthHist[">=3072"]++
		}
		if a.PQCReady {
			pqcReady++
		}
		if a.Deprecated {
			deprecated++
		}
		sourceCount[a.Source]++
		assets = append(assets, a)
	}

	for _, k := range keys {
		alg := normalizeAlgorithm(firstString(k["algorithm"]))
		add(CryptoAsset{
			ID:           firstString(k["id"], k["key_id"]),
			Source:       "keycore",
			AssetType:    "key",
			Name:         firstString(k["name"], k["id"]),
			Algorithm:    alg,
			StrengthBits: inferBits(alg),
			Status:       strings.ToLower(defaultString(firstString(k["status"]), "active")),
			PQCReady:     isPQCAlgorithm(alg),
			Deprecated:   isDeprecatedAlgorithm(alg),
			Metadata: map[string]interface{}{
				"purpose":    firstString(k["purpose"]),
				"kcv":        firstString(k["kcv"]),
				"expires_at": firstString(k["expires_at"], k["expiry"], k["expire_at"]),
			},
		})
	}
	for _, c := range certs {
		alg := normalizeAlgorithm(firstString(c["algorithm"], c["cert_class"]))
		class := strings.ToLower(firstString(c["cert_class"]))
		add(CryptoAsset{
			ID:           firstString(c["id"], c["cert_id"]),
			Source:       "certs",
			AssetType:    "certificate",
			Name:         firstString(c["subject_cn"], c["id"]),
			Algorithm:    alg,
			StrengthBits: inferBits(alg),
			Status:       strings.ToLower(defaultString(firstString(c["status"]), "active")),
			PQCReady:     strings.Contains(class, "pqc") || strings.Contains(class, "hybrid") || isPQCAlgorithm(alg),
			Deprecated:   isDeprecatedAlgorithm(alg),
			Metadata: map[string]interface{}{
				"cert_class": class,
				"not_after":  firstString(c["not_after"]),
				"profile_id": firstString(c["profile_id"]),
			},
		})
	}
	for _, d := range discovered {
		alg := normalizeAlgorithm(firstString(d["algorithm"], d["cipher"], d["signature_algorithm"]))
		add(CryptoAsset{
			ID:           firstString(d["id"], d["asset_id"]),
			Source:       "discovery",
			AssetType:    defaultString(firstString(d["asset_type"], d["type"]), "discovered"),
			Name:         firstString(d["name"], d["resource"], d["id"]),
			Algorithm:    alg,
			StrengthBits: inferBits(alg),
			Status:       strings.ToLower(defaultString(firstString(d["status"]), "unknown")),
			PQCReady:     isPQCAlgorithm(alg) || extractBool(d["pqc_ready"]),
			Deprecated:   isDeprecatedAlgorithm(alg),
			Metadata:     map[string]interface{}{"location": firstString(d["location"], d["path"])},
		})
	}
	sort.Slice(assets, func(i, j int) bool {
		return assets[i].Source+"|"+assets[i].ID < assets[j].Source+"|"+assets[j].ID
	})
	total := len(assets)
	readiness := 0.0
	if total > 0 {
		readiness = pct(pqcReady, total)
	}
	return CBOMDocument{
		Format:                "cyclonedx-crypto",
		SpecVersion:           "1.6",
		TenantID:              tenantID,
		GeneratedAt:           time.Now().UTC(),
		Assets:                assets,
		AlgorithmDistribution: algorithmDist,
		StrengthHistogram:     strengthHist,
		DeprecatedCount:       deprecated,
		PQCReadyCount:         pqcReady,
		TotalAssetCount:       total,
		PQCReadinessPercent:   round2(readiness),
		SourceCount:           sourceCount,
		Metadata:              map[string]string{},
	}
}

func summarizeCBOM(doc CBOMDocument) map[string]interface{} {
	return map[string]interface{}{
		"tenant_id":              doc.TenantID,
		"algorithm_distribution": doc.AlgorithmDistribution,
		"strength_histogram":     doc.StrengthHistogram,
		"deprecated_count":       doc.DeprecatedCount,
		"pqc_ready_count":        doc.PQCReadyCount,
		"total_assets":           doc.TotalAssetCount,
		"pqc_readiness_percent":  round2(doc.PQCReadinessPercent),
		"source_count":           doc.SourceCount,
	}
}

func hashCBOMAssets(items []CryptoAsset) string {
	keys := make([]string, 0, len(items))
	for _, a := range items {
		keys = append(keys, a.Source+"|"+a.AssetType+"|"+a.ID+"|"+a.Algorithm+"|"+fmt.Sprintf("%d", a.StrengthBits))
	}
	sort.Strings(keys)
	sum := sha256.Sum256([]byte(strings.Join(keys, "\n")))
	return fmt.Sprintf("%x", sum[:])
}

func diffAssets(from CBOMDocument, to CBOMDocument) BOMDiff {
	key := func(a CryptoAsset) string {
		id := a.ID
		if id == "" {
			id = a.Name + "|" + a.Algorithm
		}
		return strings.ToLower(a.Source + "|" + a.AssetType + "|" + id)
	}
	fromMap := map[string]CryptoAsset{}
	toMap := map[string]CryptoAsset{}
	for _, a := range from.Assets {
		fromMap[key(a)] = a
	}
	for _, a := range to.Assets {
		toMap[key(a)] = a
	}
	added := []map[string]interface{}{}
	removed := []map[string]interface{}{}
	changed := []map[string]interface{}{}
	for k, b := range toMap {
		a, ok := fromMap[k]
		if !ok {
			added = append(added, map[string]interface{}{"id": b.ID, "source": b.Source, "asset_type": b.AssetType, "algorithm": b.Algorithm})
			continue
		}
		if a.Algorithm != b.Algorithm || a.StrengthBits != b.StrengthBits || a.Status != b.Status || a.PQCReady != b.PQCReady {
			changed = append(changed, map[string]interface{}{
				"id":             b.ID,
				"source":         b.Source,
				"asset_type":     b.AssetType,
				"from_algorithm": a.Algorithm,
				"to_algorithm":   b.Algorithm,
				"from_bits":      a.StrengthBits,
				"to_bits":        b.StrengthBits,
			})
		}
	}
	for k, a := range fromMap {
		if _, ok := toMap[k]; ok {
			continue
		}
		removed = append(removed, map[string]interface{}{"id": a.ID, "source": a.Source, "asset_type": a.AssetType, "algorithm": a.Algorithm})
	}
	sortDiffItems(added)
	sortDiffItems(removed)
	sortDiffItems(changed)

	algoDelta := map[string]int{}
	seen := map[string]struct{}{}
	for alg := range from.AlgorithmDistribution {
		seen[alg] = struct{}{}
	}
	for alg := range to.AlgorithmDistribution {
		seen[alg] = struct{}{}
	}
	for alg := range seen {
		algoDelta[alg] = to.AlgorithmDistribution[alg] - from.AlgorithmDistribution[alg]
	}
	return BOMDiff{
		Added:   added,
		Removed: removed,
		Changed: changed,
		Metrics: map[string]interface{}{
			"added":               len(added),
			"removed":             len(removed),
			"changed":             len(changed),
			"algorithm_delta":     algoDelta,
			"deprecated_delta":    to.DeprecatedCount - from.DeprecatedCount,
			"pqc_readiness_delta": round2(to.PQCReadinessPercent - from.PQCReadinessPercent),
		},
		Compared: time.Now().UTC(),
	}
}

func (s *Service) publishAudit(ctx context.Context, subject string, tenantID string, data map[string]interface{}) error {
	if s.events == nil {
		return nil
	}
	raw, err := json.Marshal(map[string]interface{}{
		"tenant_id": tenantID,
		"service":   "sbom",
		"action":    subject,
		"timestamp": time.Now().UTC().Format(time.RFC3339Nano),
		"data":      data,
	})
	if err != nil {
		return err
	}
	return s.events.Publish(ctx, subject, raw)
}
