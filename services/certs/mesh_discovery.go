package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

// Mesh discovery reconciles the live service mesh (the consul catalog) into the
// mTLS mesh registry, so the dashboard shows every internal service on the mesh
// and stays current as services register/deregister — no manual entry. consul
// is the source of truth: every KMS service registers itself there, and the
// mesh secures all service-to-service traffic with mTLS.

type consulCatalogEntry struct {
	ServiceName    string `json:"ServiceName"`
	ServiceAddress string `json:"ServiceAddress"`
	Address        string `json:"Address"`
	ServicePort    int    `json:"ServicePort"`
}

func consulAddr() string {
	addr := strings.TrimSpace(os.Getenv("CONSUL_HTTP_ADDR"))
	if addr == "" {
		return ""
	}
	if !strings.HasPrefix(addr, "http://") && !strings.HasPrefix(addr, "https://") {
		addr = "http://" + addr
	}
	return strings.TrimRight(addr, "/")
}

// meshDiscoveryTenant is the tenant the platform mesh is recorded under (the
// internal services are global infrastructure, owned by the root tenant).
func meshDiscoveryTenant() string {
	if t := strings.TrimSpace(os.Getenv("MESH_DISCOVERY_TENANT")); t != "" {
		return t
	}
	return "root"
}

// ReconcileMeshFromConsul lists registered services from the consul catalog and
// upserts each as a mesh service. Best-effort: a discovery failure never breaks
// the certs service.
func (s *Service) ReconcileMeshFromConsul(ctx context.Context) (int, error) {
	base := consulAddr()
	if base == "" {
		return 0, nil
	}
	client := &http.Client{Timeout: 8 * time.Second}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/v1/catalog/services", nil)
	if err != nil {
		return 0, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("consul catalog: status %d", resp.StatusCode)
	}
	var catalog map[string][]string
	if err := json.NewDecoder(resp.Body).Decode(&catalog); err != nil {
		return 0, err
	}

	tenant := meshDiscoveryTenant()
	count := 0
	for name := range catalog {
		// Only the KMS service mesh; skip consul itself and anything else.
		if !strings.HasPrefix(name, "kms-") {
			continue
		}
		endpoint := consulServiceEndpoint(ctx, client, base, name)
		display := strings.TrimPrefix(name, "kms-")
		svc := MeshService{
			ID:          newID("mesh"),
			TenantID:    tenant,
			Name:        display,
			Namespace:   "platform",
			Endpoint:    endpoint,
			CertStatus:  "discovered",
			MTLSEnabled: true,
			CreatedAt:   time.Now().UTC(),
		}
		if err := s.store.UpsertDiscoveredMeshService(ctx, svc); err != nil {
			continue
		}
		count++
	}
	return count, nil
}

// consulServiceEndpoint resolves a service's address:port from the catalog;
// returns "" if unavailable (the service is still recorded as a mesh member).
func consulServiceEndpoint(ctx context.Context, client *http.Client, base, name string) string {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/v1/catalog/service/"+name, nil)
	if err != nil {
		return ""
	}
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		return ""
	}
	var entries []consulCatalogEntry
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil || len(entries) == 0 {
		return ""
	}
	e := entries[0]
	addr := e.ServiceAddress
	if addr == "" {
		addr = e.Address
	}
	if addr == "" {
		return ""
	}
	if e.ServicePort > 0 {
		return fmt.Sprintf("%s:%d", addr, e.ServicePort)
	}
	return addr
}

// StartMeshDiscovery runs ReconcileMeshFromConsul on startup and on an interval.
func (s *Service) StartMeshDiscovery(ctx context.Context, logger interface{ Printf(string, ...any) }) {
	if consulAddr() == "" || strings.EqualFold(strings.TrimSpace(os.Getenv("MESH_DISCOVERY_ENABLED")), "false") {
		return
	}
	interval := 60 * time.Second
	go func() {
		run := func() {
			rctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			if n, err := s.ReconcileMeshFromConsul(rctx); err != nil {
				logger.Printf("mesh discovery warning: %v", err)
			} else if n > 0 {
				logger.Printf("mesh discovery: reconciled %d services from consul", n)
			}
		}
		run()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				run()
			}
		}
	}()
}
