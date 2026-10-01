package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	pkgaudit "vecta-kms/pkg/audit"
	"vecta-kms/pkg/route"
	"vecta-kms/pkg/svctls"
)

type Service struct {
	store   Store
	keycore KeyCoreClient
	certs   CertsClient
	events  EventPublisher
	now     func() time.Time
	cloud   CloudClient
	root    string
	// targetGuard builds, per scan, the dial guard for every network target
	// (newTargetGuard; tests swap it to reach their loopback server).
	targetGuard func(ctx context.Context) dialControl

	mu     sync.Mutex
	active map[string]string // tenant ID -> the scan running for it
	scans  sync.WaitGroup

	// audit emits events playbooks can trigger on (secret_exposed); nil
	// when NATS is unavailable.
	audit route.Emitter

	// conns opens a private repository's git connection (compliance) and
	// authority re-checks who authorized a schedule (auth).
	conns     ConnectionResolver
	authority AuthorityChecker
	// repoRoots trusts a test hosting server's certificate; nil in
	// production (the system roots).
	repoRoots *x509.CertPool
	// primary reports whether this node runs scheduled scans
	// (clusterstate.RunsPrimaryJobs).
	primary func(context.Context) bool
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

		targetGuard: newTargetGuard,
		active:      map[string]string{},
	}
}

// scanDeadline bounds one scan. A scan still "running" after it (the
// service restarted mid-scan) reads as "interrupted".
const scanDeadline = 10 * time.Minute

var errScanRunning = errors.New("a scan is already running for this tenant")

// StartScan records a running scan and reads its sources in the background
// (7.18.0-beta; before, the request waited for every source, so a slow
// cloud account or a large range outlived the HTTP timeout). Poll
// GET /discovery/scans/{id} for progress. One scan runs per tenant at a time.
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
		Stats:     map[string]interface{}{"sources_done": []string{}},
		StartedAt: s.now(),
	}
	s.mu.Lock()
	if id, busy := s.active[req.TenantID]; busy {
		s.mu.Unlock()
		return DiscoveryScan{ID: id, TenantID: req.TenantID, Status: "running"}, errScanRunning
	}
	s.active[req.TenantID] = scan.ID
	s.mu.Unlock()
	if err := s.store.CreateScan(ctx, scan); err != nil {
		s.release(req.TenantID)
		return DiscoveryScan{}, err
	}
	_ = s.publishAudit(ctx, "audit.discovery.scan_initiated", req.TenantID, map[string]interface{}{
		"scan_id":    scan.ID,
		"scan_types": types,
	})
	s.scans.Add(1)
	go func() {
		defer s.scans.Done()
		defer s.release(scan.TenantID)
		bg, cancel := context.WithTimeout(context.WithoutCancel(ctx), scanDeadline)
		defer cancel()
		s.runScan(bg, scan, types)
	}()
	return scan, nil
}

func (s *Service) release(tenantID string) {
	s.mu.Lock()
	delete(s.active, tenantID)
	s.mu.Unlock()
}

// runScan reads every source concurrently. Each source's assets are stored
// and its outcome recorded on the scan as it finishes. A failed or
// unconfigured source is recorded as such, never replaced by invented
// assets.
func (s *Service) runScan(ctx context.Context, scan DiscoveryScan, types []string) {
	var (
		mu       sync.Mutex
		wg       sync.WaitGroup
		errs     = map[string]string{}
		done     = []string{}
		seen     = map[string]bool{}
		inserted int
	)
	stats := map[string]interface{}{"sources_done": done}
	for _, t := range types {
		stats[t+"_assets"] = 0
	}
	for _, t := range types {
		wg.Add(1)
		go func(t string) {
			defer wg.Done()
			items, extra, err := s.scanSource(ctx, scan.TenantID, scan.ID, t)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs[t] = err.Error()
				stats["errors"] = copyErrs(errs)
			}
			inserted += s.storeAssets(ctx, scan.TenantID, items, seen)
			stats[t+"_assets"] = len(items)
			for k, v := range extra {
				stats[k] = v
			}
			done = append(done, t)
			stats["sources_done"] = append([]string(nil), done...)
			stats["assets_discovered"] = inserted
			scan.Stats = stats
			_ = s.store.UpdateScan(ctx, scan)
		}(t)
	}
	wg.Wait()
	status := "completed"
	switch {
	case len(errs) == len(types):
		status = "failed"
	case len(errs) > 0:
		status = "completed_with_errors"
	}
	stats["assets_discovered"] = inserted
	scan.Status, scan.Stats, scan.CompletedAt = status, stats, s.now()
	// The scan's own context may have hit its deadline.
	fin, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	if err := s.store.UpdateScan(fin, scan); err != nil {
		logger.Printf("scan %s: record completion: %v", scan.ID, err)
	}
	completed := map[string]interface{}{
		"scan_id":           scan.ID,
		"assets_discovered": inserted,
		"status":            status,
	}
	if len(errs) > 0 {
		completed["errors"] = copyErrs(errs)
	}
	_ = s.publishAudit(fin, "audit.discovery.scan_completed", scan.TenantID, completed)
}

func copyErrs(m map[string]string) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// scanSource reads one source. What it parses comes from other people's
// servers and files, so a panic there is reported as that source's error
// and never takes the service down.
func (s *Service) scanSource(ctx context.Context, tenantID, scanID, source string) (items []CryptoAsset, extra map[string]interface{}, err error) {
	defer func() {
		if r := recover(); r != nil {
			logger.Printf("scan %s: %s source panicked: %v", scanID, source, r)
			items, extra, err = nil, nil, fmt.Errorf("%s scan failed unexpectedly", source)
		}
	}()
	switch source {
	case "network":
		res, err := s.sweepNetwork(ctx, tenantID, scanID)
		return res.assets, map[string]interface{}{"network_endpoints": res.probed, "network_no_service": res.noService, "network_skipped": res.skipped}, err
	case "cloud":
		items, err := s.scanCloud(ctx, tenantID, scanID)
		return items, nil, err
	case "certs":
		items, err := s.scanCertificates(ctx, tenantID, scanID)
		return items, nil, err
	case "code":
		items, err := s.scanCode(ctx, tenantID, scanID)
		return items, nil, err
	case "git":
		return s.scanGit(ctx, tenantID, scanID)
	}
	return nil, nil, fmt.Errorf("unknown source %q", source)
}

// storeAssets upserts each asset once and audits it; it returns how many
// were stored.
func (s *Service) storeAssets(ctx context.Context, tenantID string, items []CryptoAsset, seen map[string]bool) int {
	n := 0
	for _, a := range items {
		if seen[a.ID] {
			continue
		}
		seen[a.ID] = true
		// A rescan rewrites what it observed and keeps the review.
		old, err := s.store.GetAsset(ctx, tenantID, a.ID)
		if err == nil {
			old = withReview(old)
			if a.Metadata == nil {
				a.Metadata = map[string]interface{}{}
			}
			for _, k := range reviewKeys {
				if v, ok := old.Metadata[k]; ok {
					a.Metadata[k] = v
				}
			}
		}
		if err := s.store.UpsertAsset(ctx, a); err != nil {
			continue
		}
		n++
		// A long hex string is listed as exposed but is often a hash, so
		// it doesn't raise the incident event.
		if errors.Is(err, errNotFound) && a.Classification == "exposed" && a.AssetType != "hex_secret" {
			s.secretExposed(ctx, a)
		}
		_ = s.publishAudit(ctx, "audit.discovery.asset_found", tenantID, map[string]interface{}{
			"asset_id":       a.ID,
			"asset_type":     a.AssetType,
			"classification": a.Classification,
			"source":         a.Source,
		})
	}
	return n
}

// secretExposed emits audit.discovery.secret_exposed the first time a
// private key, keystore or access key is found in code or an upload, so a
// playbook can respond (trigger "secret_exposed"). A rescan that finds the
// same secret again does not repeat it. The event names where the secret is
// and its fingerprint prefix, never the secret.
func (s *Service) secretExposed(ctx context.Context, a CryptoAsset) {
	if s.audit == nil {
		return
	}
	_ = s.audit.Emit(ctx, "secret_exposed", pkgaudit.Event{
		TenantID: a.TenantID, ActorID: "kms-discovery", ActorType: "service", Result: "success",
		TargetType: "crypto_asset", TargetID: a.ID, RiskScore: 80,
		Details: map[string]interface{}{
			"asset_type": a.AssetType, "source": a.Source, "location": a.Location, "algorithm": a.Algorithm,
			"fingerprint_sha256_prefix": a.Metadata["fingerprint_sha256_prefix"], "scan_id": a.ScanID,
		},
	})
}

// settle reads a scan left "running" past its deadline as "interrupted".
func (s *Service) settle(sc DiscoveryScan) DiscoveryScan {
	if sc.Status == "running" && !sc.StartedAt.IsZero() && s.now().Sub(sc.StartedAt) > scanDeadline+time.Minute {
		sc.Status = "interrupted"
	}
	return sc
}

const maxUploadBytes = 2 << 20

// ScanUpload inventories one uploaded file (7.18.0-beta): certificates,
// public and SSH keys by the key they hold, and private keys, keystores and
// other secrets by fingerprint. The file itself is never stored. It is
// recorded as a scan of source "upload".
func (s *Service) ScanUpload(ctx context.Context, tenantID, name string, content []byte) (DiscoveryScan, []CryptoAsset, error) {
	name = uploadName(name)
	scan := DiscoveryScan{
		ID: newID("scan"), TenantID: tenantID, ScanType: "upload", Status: "running", Trigger: "upload",
		Stats: map[string]interface{}{"file": name}, StartedAt: s.now(),
	}
	if err := s.store.CreateScan(ctx, scan); err != nil {
		return DiscoveryScan{}, nil, err
	}
	_ = s.publishAudit(ctx, "audit.discovery.scan_initiated", tenantID, map[string]interface{}{
		"scan_id": scan.ID, "scan_types": []string{"upload"}, "file": name,
	})
	assets := s.materialAssets(tenantID, scan.ID, "upload", name, findMaterial(name, content))
	n := s.storeAssets(ctx, tenantID, assets, map[string]bool{})
	scan.Status, scan.CompletedAt = "completed", s.now()
	scan.Stats = map[string]interface{}{"file": name, "bytes": len(content), "upload_assets": len(assets), "assets_discovered": n, "sources_done": []string{"upload"}}
	if err := s.store.UpdateScan(ctx, scan); err != nil {
		return DiscoveryScan{}, nil, err
	}
	_ = s.publishAudit(ctx, "audit.discovery.scan_completed", tenantID, map[string]interface{}{
		"scan_id": scan.ID, "assets_discovered": n, "status": scan.Status,
	})
	return scan, assets, nil
}

// uploadName keeps a file's base name, printable and at most 128 bytes.
func uploadName(name string) string {
	name = filepath.Base(strings.ReplaceAll(strings.TrimSpace(name), "\\", "/"))
	name = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, name)
	if len(name) > 128 {
		name = name[:128]
	}
	if name == "" || name == "." || name == "/" {
		return "upload"
	}
	return name
}

func (s *Service) ListScans(ctx context.Context, tenantID string, limit int, offset int) ([]DiscoveryScan, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return nil, newServiceError(400, "bad_request", "tenant_id is required")
	}
	items, err := s.store.ListScans(ctx, tenantID, limit, offset)
	for i := range items {
		items[i] = s.settle(items[i])
	}
	return items, err
}

func (s *Service) GetScan(ctx context.Context, tenantID string, id string) (DiscoveryScan, error) {
	tenantID = strings.TrimSpace(tenantID)
	id = strings.TrimSpace(id)
	if tenantID == "" || id == "" {
		return DiscoveryScan{}, newServiceError(400, "bad_request", "tenant_id and id are required")
	}
	item, err := s.store.GetScan(ctx, tenantID, id)
	return s.settle(item), err
}

// ListAssets is FindAssets for callers that filter by source, type and one
// class and don't need the total.
func (s *Service) ListAssets(ctx context.Context, tenantID string, limit int, offset int, source string, assetType string, classification string) ([]CryptoAsset, error) {
	f := AssetFilter{Source: source, AssetType: assetType}
	if classification != "" {
		f.Classes = []string{classification}
	}
	items, _, err := s.FindAssets(ctx, tenantID, limit, offset, f)
	return items, err
}

// FindAssets returns one page of the assets matching f and how many match
// in all. It reads the whole inventory (7.18.0-beta; before, the newest
// 10000 rows), so the total is exact however large the estate is.
func (s *Service) FindAssets(ctx context.Context, tenantID string, limit int, offset int, f AssetFilter) ([]CryptoAsset, int, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return nil, 0, newServiceError(400, "bad_request", "tenant_id is required")
	}
	if limit <= 0 || limit > 10000 {
		limit = 1000
	}
	offset = max(offset, 0)
	out := make([]CryptoAsset, 0)
	total := 0
	err := s.walkAssets(ctx, tenantID, f, func(a CryptoAsset) {
		if total >= offset && len(out) < limit {
			out = append(out, a)
		}
		total++
	})
	return out, total, err
}

// walkAssets calls fn for every asset matching f. The class is derived on
// read (the stored column can predate a catalogue change) and rows from
// before 7.13.0-beta that name platform services are skipped.
func (s *Service) walkAssets(ctx context.Context, tenantID string, f AssetFilter, fn func(CryptoAsset)) error {
	var lastScan map[string]time.Time
	if f.NotSeen {
		scans, err := s.store.ListScans(ctx, tenantID, 100, 0)
		if err != nil {
			return err
		}
		lastScan = map[string]time.Time{}
		last := lastScans(scans)
		for _, src := range scannedSources {
			if sc, ok := last[src]; ok {
				lastScan[src] = sc.StartedAt
			}
		}
	}
	now := s.now()
	return s.store.EachAsset(ctx, tenantID, func(a CryptoAsset) error {
		if isPlatformAsset(a) {
			return nil
		}
		a.Classification = assetClass(a)
		if a = withReview(a); f.match(a, now, lastScan) {
			fn(a)
		}
		return nil
	})
}

func (f AssetFilter) match(a CryptoAsset, now time.Time, lastScan map[string]time.Time) bool {
	switch {
	case f.Source != "" && a.Source != f.Source,
		f.AssetType != "" && a.AssetType != f.AssetType,
		len(f.Classes) > 0 && !containsString(f.Classes, a.Classification),
		f.Algorithm != nil && a.Algorithm != *f.Algorithm,
		f.PQCReady && !a.PQCReady,
		f.ExpiringDays > 0 && !expiresWithin(a, now, f.ExpiringDays),
		f.NotSeen && !notSeen(a, lastScan):
		return false
	}
	q := strings.ToLower(strings.TrimSpace(f.Query))
	return q == "" || strings.Contains(strings.ToLower(a.Name+" "+a.Location+" "+a.Algorithm+" "+a.AssetType+" "+a.Source), q)
}

// expiresWithin: the asset carries a not_after that has passed or falls
// within days.
func expiresWithin(a CryptoAsset, now time.Time, days int) bool {
	na, _ := a.Metadata["not_after"].(string)
	t := parseTimeString(na)
	return !t.IsZero() && t.Before(now.Add(time.Duration(days)*24*time.Hour))
}

// scannedSources: sources a scan re-reads in full, so an asset the last
// scan didn't observe is gone or failed to answer. Uploads are one-off.
var scannedSources = allScanTypes

func notSeen(a CryptoAsset, lastScan map[string]time.Time) bool {
	started, ok := lastScan[a.Source]
	return ok && a.LastSeen.Before(started.Add(-5*time.Second))
}

// lastScans maps each source to the newest finished scan that read it.
// scans are newest first.
func lastScans(scans []DiscoveryScan) map[string]DiscoveryScan {
	out := map[string]DiscoveryScan{}
	for _, sc := range scans {
		if sc.Status == "running" {
			continue
		}
		for _, src := range strings.Split(sc.ScanType, ",") {
			if _, ok := out[src]; !ok {
				out[src] = sc
			}
		}
	}
	return out
}

// isPlatformAsset: a KMS service's own certificate or TLS endpoint, stored
// by a scan before 7.13.0-beta. The inventory is the customer's estate; the
// platform's certificates are in the PKI tab.
func isPlatformAsset(a CryptoAsset) bool {
	switch a.Source {
	case "certs":
		_, ok := svctls.HostFor(a.Name)
		return ok
	case "network":
		host, _, err := net.SplitHostPort(a.Location)
		return err == nil && isPlatformHost(host)
	}
	return false
}

// assetClass is an asset's classification, derived on every read: a secret
// found in code or an upload is "exposed" whatever its algorithm; anything
// else (a certificate or public key found there too, since 7.18.0-beta) is
// the catalogue's class for its algorithm (weak, quantum_vulnerable, strong
// or unknown). Rows stored before 7.11.0-beta say "vulnerable" for both of
// the first two; deriving means none of them shows that stale label.
func assetClass(a CryptoAsset) string {
	if (a.Source == "code" || a.Source == "upload" || a.Source == "git") && secretKinds[a.AssetType] {
		return "exposed"
	}
	return classifyAlgorithm(a.Algorithm)
}

// RemoveAsset deletes an asset from the inventory, for an endpoint or file
// that no longer exists. A later scan that observes it again adds it back.
func (s *Service) RemoveAsset(ctx context.Context, tenantID string, id string) (CryptoAsset, error) {
	item, err := s.GetAsset(ctx, tenantID, id)
	if err != nil {
		return CryptoAsset{}, err
	}
	return item, s.store.DeleteAsset(ctx, tenantID, id)
}

func (s *Service) GetAsset(ctx context.Context, tenantID string, id string) (CryptoAsset, error) {
	tenantID = strings.TrimSpace(tenantID)
	id = strings.TrimSpace(id)
	if tenantID == "" || id == "" {
		return CryptoAsset{}, newServiceError(400, "bad_request", "tenant_id and id are required")
	}
	item, err := s.store.GetAsset(ctx, tenantID, id)
	if err == nil && isPlatformAsset(item) {
		return CryptoAsset{}, errNotFound
	}
	item.Classification = assetClass(item)
	return withReview(item), err
}

// An operator's review lives in metadata (7.18.0-beta). Before, it replaced
// status, which every rescan rewrote with what it observed, so a review was
// lost on the next scan and "reviewed" reached the CBOM as a key status.
var (
	reviewStatuses = map[string]bool{"active": true, "reviewed": true, "accepted_risk": true, "remediated": true}
	reviewKeys     = []string{"review_status", "review_notes", "reviewed_by", "reviewed_at"}
)

// withReview reads a review that a row stored before 7.18.0-beta kept in
// status or classification_notes. The status itself is left as stored: what
// the scan observed then is unknown, and the next scan rewrites it.
func withReview(a CryptoAsset) CryptoAsset {
	if a.Metadata == nil {
		a.Metadata = map[string]interface{}{}
	}
	if _, ok := a.Metadata["review_status"]; !ok && a.Status != "active" && reviewStatuses[a.Status] {
		a.Metadata["review_status"] = a.Status
	}
	if n, ok := a.Metadata["classification_notes"]; ok {
		if _, has := a.Metadata["review_notes"]; !has {
			a.Metadata["review_notes"] = n
		}
		delete(a.Metadata, "classification_notes")
	}
	return a
}

// errClassificationIsCatalogue: an asset's classification is what
// pkg/cryptocatalog says about its algorithm; a review records status and
// notes only, never a different label.
var errClassificationIsCatalogue = errors.New("classification comes from the algorithm catalogue and can't be overridden; record a status or notes instead")

func (s *Service) ClassifyAsset(ctx context.Context, tenantID string, id string, req ClassifyRequest, actor string) (CryptoAsset, error) {
	tenantID = strings.TrimSpace(tenantID)
	id = strings.TrimSpace(id)
	if tenantID == "" || id == "" {
		return CryptoAsset{}, newServiceError(400, "bad_request", "tenant_id and id are required")
	}
	item, err := s.GetAsset(ctx, tenantID, id)
	if err != nil {
		return CryptoAsset{}, err
	}
	if c := strings.ToLower(strings.TrimSpace(req.Classification)); c != "" && c != item.Classification {
		return CryptoAsset{}, errClassificationIsCatalogue
	}
	review := strings.ToLower(strings.TrimSpace(req.Status))
	if review != "" && !reviewStatuses[review] {
		return CryptoAsset{}, newServiceError(400, "bad_request", "status must be active, reviewed, accepted_risk or remediated")
	}
	if review != "" {
		item.Metadata["review_status"] = review
	}
	if notes := strings.TrimSpace(req.Notes); notes != "" {
		item.Metadata["review_notes"] = notes
	}
	item.Metadata["reviewed_by"] = actor
	item.Metadata["reviewed_at"] = s.now().Format(time.RFC3339)
	item.UpdatedAt = s.now()
	if err := s.store.UpsertAsset(ctx, item); err != nil {
		return CryptoAsset{}, err
	}
	_ = s.publishAudit(ctx, "audit.discovery.asset_classified", tenantID, map[string]interface{}{
		"asset_id":       item.ID,
		"classification": item.Classification,
		"review_status":  item.Metadata["review_status"],
	})
	return s.GetAsset(ctx, tenantID, id)
}

// Summary counts the whole inventory in one pass.
func (s *Service) Summary(ctx context.Context, tenantID string) (DiscoverySummary, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return DiscoverySummary{}, newServiceError(400, "bad_request", "tenant_id is required")
	}
	sum := DiscoverySummary{
		TenantID:              tenantID,
		SourceDistribution:    map[string]int{},
		AlgorithmDistribution: map[string]int{},
		ClassificationCounts:  map[string]int{"strong": 0, "quantum_vulnerable": 0, "weak": 0, "exposed": 0, "unknown": 0},
		AlgorithmClasses:      map[string]map[string]int{},
		SourceClassification:  map[string]map[string]int{},
	}
	bump := func(m map[string]map[string]int, k, class string) {
		if m[k] == nil {
			m[k] = map[string]int{}
		}
		m[k][class]++
	}
	now := s.now()
	err := s.walkAssets(ctx, tenantID, AssetFilter{}, func(it CryptoAsset) {
		sum.TotalAssets++
		sum.SourceDistribution[it.Source]++
		sum.AlgorithmDistribution[it.Algorithm]++
		sum.ClassificationCounts[it.Classification]++
		bump(sum.AlgorithmClasses, it.Algorithm, it.Classification)
		bump(sum.SourceClassification, it.Source, it.Classification)
		if it.PQCReady {
			sum.PQCReadyCount++
		}
		if expiresWithin(it, now, 30) {
			sum.Expiring30++
		}
	})
	if err != nil {
		return DiscoverySummary{}, err
	}
	if sum.TotalAssets > 0 {
		sum.PQCReadinessPercent = round2(pct(sum.PQCReadyCount, sum.TotalAssets))
	}
	return sum, nil
}

// Sources reports, for each scan source, whether it has anything to read and
// how its last scan went, so the dashboard can say what to set up.
func (s *Service) Sources(ctx context.Context, tenantID string) ([]SourceStatus, error) {
	targets, err := s.store.ListTargets(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	env := len(parseEndpoints(os.Getenv("DISCOVERY_TLS_ENDPOINTS")))
	hosts, ranges, ssh, addrs := 0, 0, 0, env
	for _, t := range targets {
		if _, err := netip.ParsePrefix(t.Host); err == nil {
			ranges++
		} else {
			hosts++
		}
		if t.proto() == "ssh" {
			ssh++
		}
		addrs += t.addresses()
	}
	network := SourceStatus{ID: "network", Configured: addrs > 0, Detail: map[string]interface{}{
		"targets": len(targets), "hosts": hosts, "ranges": ranges, "ssh": ssh, "addresses": addrs, "operator_endpoints": env,
	}}
	cloud := SourceStatus{ID: "cloud", Detail: map[string]interface{}{}}
	certs := SourceStatus{ID: "certs", Detail: map[string]interface{}{}}
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		if s.cloud == nil {
			cloud.Error = "no cloud service client"
			return
		}
		accts, err := s.cloud.ListAccounts(cctx, tenantID)
		if err != nil {
			cloud.Error = "cloud service: " + err.Error()
			return
		}
		providers := []string{}
		for _, a := range accts {
			if p := strings.ToLower(firstString(a["provider"])); p != "" && !containsString(providers, p) {
				providers = append(providers, p)
			}
		}
		sort.Strings(providers)
		cloud.Configured, cloud.Detail = len(accts) > 0, map[string]interface{}{"accounts": len(accts), "providers": providers}
	}()
	go func() {
		defer wg.Done()
		if s.certs == nil {
			certs.Error = "no certs service client"
			return
		}
		items, err := s.certs.ListCertificates(cctx, tenantID, 2000)
		if err != nil {
			certs.Error = "certs service: " + err.Error()
			return
		}
		n := 0
		for _, c := range items {
			if !strings.EqualFold(firstString(c["cert_class"]), "internal-mtls") {
				n++
			}
		}
		certs.Configured, certs.Detail = n > 0, map[string]interface{}{"certificates": n}
	}()
	wg.Wait()
	// The mount path is operator configuration; only whether it is usable
	// is reported.
	code := SourceStatus{ID: "code", Detail: map[string]interface{}{}}
	if st, err := os.Stat(s.root); strings.TrimSpace(s.root) != "" && err == nil && st.IsDir() {
		code.Configured = true
	}
	repos, err := s.store.ListRepositories(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	private := 0
	for _, r := range repos {
		if r.ConnectionID != "" {
			private++
		}
	}
	git := SourceStatus{ID: "git", Configured: len(repos) > 0, Detail: map[string]interface{}{"repositories": len(repos), "private": private}}
	upload := SourceStatus{ID: "upload", Configured: true, Detail: map[string]interface{}{"max_bytes": maxUploadBytes}}
	out := []SourceStatus{network, cloud, certs, git, code, upload}

	scans, err := s.store.ListScans(ctx, tenantID, 100, 0)
	if err != nil {
		return nil, err
	}
	last := lastScans(scans)
	for i := range out {
		sc, ok := last[out[i].ID]
		if !ok {
			continue
		}
		l := &SourceLastScan{ScanID: sc.ID, StartedAt: sc.StartedAt, At: sc.CompletedAt, Assets: extractInt(sc.Stats[out[i].ID+"_assets"])}
		if l.At.IsZero() {
			l.At = sc.StartedAt
		}
		if errs, ok := sc.Stats["errors"].(map[string]interface{}); ok {
			l.Error = firstString(errs[out[i].ID])
		}
		out[i].LastScan = l
	}
	return out, nil
}

// allScanTypes are the sources a scan can read; uploads are scanned as they
// arrive.
var allScanTypes = []string{"network", "cloud", "certs", "code", "git"}

// normalizeScanTypes returns the requested sources, or every source when
// none, or "all", is named.
func normalizeScanTypes(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, t := range in {
		t = strings.ToLower(strings.TrimSpace(t))
		if t == "all" {
			return append([]string(nil), allScanTypes...)
		}
		if containsString(allScanTypes, t) && !seen[t] {
			seen[t] = true
			out = append(out, t)
		}
	}
	if len(out) == 0 {
		return append([]string(nil), allScanTypes...)
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
