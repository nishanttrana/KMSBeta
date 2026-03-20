package main

import (
	"context"
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"time"
)

type EventPublisher interface {
	Publish(ctx context.Context, subject string, payload []byte) error
}

type Service struct {
	store  Store
	auth   AuthClient
	audit  AuditClient
	events EventPublisher
	now    func() time.Time
}

func NewService(store Store, auth AuthClient, audit AuditClient, events EventPublisher) *Service {
	return &Service{
		store:  store,
		auth:   auth,
		audit:  audit,
		events: events,
		now:    func() time.Time { return time.Now().UTC() },
	}
}

func defaultSettings(tenantID string) WorkloadIdentitySettings {
	trustDomain := strings.TrimSpace(tenantID)
	if trustDomain == "" {
		trustDomain = "root"
	}
	return WorkloadIdentitySettings{
		TenantID:              strings.TrimSpace(tenantID),
		Enabled:               false,
		TrustDomain:           trustDomain,
		FederationEnabled:     false,
		TokenExchangeEnabled:  true,
		DisableStaticAPIKeys:  false,
		DefaultX509TTLSeconds: int((12 * time.Hour).Seconds()),
		DefaultJWTTTLSeconds:  int((30 * time.Minute).Seconds()),
		RotationWindowSeconds: int((30 * time.Minute).Seconds()),
		AllowedAudiences:      []string{"kms", "kms-workload", "kms-rest"},
	}
}

func normalizeSettings(in WorkloadIdentitySettings) WorkloadIdentitySettings {
	out := in
	out.TenantID = strings.TrimSpace(out.TenantID)
	out.TrustDomain = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(out.TrustDomain), "spiffe://"))
	if out.TrustDomain == "" {
		out.TrustDomain = firstNonEmpty(out.TenantID, "root")
	}
	if out.DefaultX509TTLSeconds < 300 {
		out.DefaultX509TTLSeconds = int((12 * time.Hour).Seconds())
	}
	if out.DefaultJWTTTLSeconds < 120 {
		out.DefaultJWTTTLSeconds = int((30 * time.Minute).Seconds())
	}
	if out.RotationWindowSeconds < 60 {
		out.RotationWindowSeconds = int((30 * time.Minute).Seconds())
	}
	if out.RotationWindowSeconds >= out.DefaultX509TTLSeconds {
		out.RotationWindowSeconds = out.DefaultX509TTLSeconds / 4
	}
	if out.RotationWindowSeconds >= out.DefaultJWTTTLSeconds {
		out.RotationWindowSeconds = minInt(out.RotationWindowSeconds, out.DefaultJWTTTLSeconds/2)
	}
	out.AllowedAudiences = uniqueStrings(out.AllowedAudiences)
	out.UpdatedBy = strings.TrimSpace(out.UpdatedBy)
	return out
}

func sanitizeSettings(item WorkloadIdentitySettings) WorkloadIdentitySettings {
	item.LocalCAKeyPEM = ""
	item.JWTSignerPrivatePEM = ""
	return item
}

func (s *Service) ensureSettings(ctx context.Context, tenantID string) (WorkloadIdentitySettings, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return WorkloadIdentitySettings{}, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id is required")
	}
	item, err := s.store.GetSettings(ctx, tenantID)
	if err == nil {
		return normalizeSettings(item), nil
	}
	if err != errNotFound {
		return WorkloadIdentitySettings{}, err
	}
	item = defaultSettings(tenantID)
	caCertPEM, caKeyPEM, jwtPrivPEM, jwtPubPEM, kid, jwksJSON, genErr := generateSigningMaterial(item.TrustDomain)
	if genErr != nil {
		return WorkloadIdentitySettings{}, genErr
	}
	item.LocalCACertificatePEM = caCertPEM
	item.LocalCAKeyPEM = caKeyPEM
	item.JWTSignerPrivatePEM = jwtPrivPEM
	item.JWTSignerPublicPEM = jwtPubPEM
	item.JWTSignerKeyID = kid
	item.LocalBundleJWKS = jwksJSON
	item, err = s.store.UpsertSettings(ctx, item)
	if err != nil {
		return WorkloadIdentitySettings{}, err
	}
	return normalizeSettings(item), nil
}

func (s *Service) GetSettings(ctx context.Context, tenantID string) (WorkloadIdentitySettings, error) {
	item, err := s.ensureSettings(ctx, tenantID)
	if err != nil {
		return WorkloadIdentitySettings{}, err
	}
	return sanitizeSettings(item), nil
}

func (s *Service) UpdateSettings(ctx context.Context, in WorkloadIdentitySettings) (WorkloadIdentitySettings, error) {
	current, err := s.ensureSettings(ctx, in.TenantID)
	if err != nil {
		return WorkloadIdentitySettings{}, err
	}
	next := normalizeSettings(in)
	if next.TrustDomain == "" {
		next.TrustDomain = current.TrustDomain
	}
	next.LocalCACertificatePEM = current.LocalCACertificatePEM
	next.LocalCAKeyPEM = current.LocalCAKeyPEM
	next.JWTSignerPrivatePEM = current.JWTSignerPrivatePEM
	next.JWTSignerPublicPEM = current.JWTSignerPublicPEM
	next.JWTSignerKeyID = current.JWTSignerKeyID
	next.LocalBundleJWKS = current.LocalBundleJWKS
	if !strings.EqualFold(next.TrustDomain, current.TrustDomain) {
		caCertPEM, caKeyPEM, jwtPrivPEM, jwtPubPEM, kid, jwksJSON, genErr := generateSigningMaterial(next.TrustDomain)
		if genErr != nil {
			return WorkloadIdentitySettings{}, genErr
		}
		next.LocalCACertificatePEM = caCertPEM
		next.LocalCAKeyPEM = caKeyPEM
		next.JWTSignerPrivatePEM = jwtPrivPEM
		next.JWTSignerPublicPEM = jwtPubPEM
		next.JWTSignerKeyID = kid
		next.LocalBundleJWKS = jwksJSON
	}
	item, err := s.store.UpsertSettings(ctx, next)
	if err != nil {
		return WorkloadIdentitySettings{}, err
	}
	_ = s.publishAudit(ctx, "audit.workload.settings_updated", item.TenantID, map[string]interface{}{
		"trust_domain":             item.TrustDomain,
		"federation_enabled":       item.FederationEnabled,
		"token_exchange_enabled":   item.TokenExchangeEnabled,
		"disable_static_api_keys":  item.DisableStaticAPIKeys,
		"default_x509_ttl_seconds": item.DefaultX509TTLSeconds,
		"default_jwt_ttl_seconds":  item.DefaultJWTTTLSeconds,
	})
	return sanitizeSettings(item), nil
}

func normalizeRegistration(in WorkloadRegistration, settings WorkloadIdentitySettings) (WorkloadRegistration, error) {
	out := in
	out.ID = strings.TrimSpace(out.ID)
	if out.ID == "" {
		out.ID = newID("wid")
	}
	out.TenantID = strings.TrimSpace(out.TenantID)
	out.Name = strings.TrimSpace(out.Name)
	out.SpiffeID = strings.TrimSpace(out.SpiffeID)
	if out.SpiffeID == "" {
		slug := slugify(firstNonEmpty(out.Name, out.ID))
		out.SpiffeID = "spiffe://" + settings.TrustDomain + "/workloads/" + slug
	}
	if !strings.HasPrefix(strings.ToLower(out.SpiffeID), "spiffe://") {
		return WorkloadRegistration{}, newServiceError(http.StatusBadRequest, "bad_request", "spiffe_id must start with spiffe://")
	}
	if spiffeTrustDomain(out.SpiffeID) != settings.TrustDomain {
		return WorkloadRegistration{}, newServiceError(http.StatusBadRequest, "bad_request", "spiffe_id trust domain must match tenant workload trust domain")
	}
	out.Selectors = uniqueStrings(out.Selectors)
	out.AllowedInterfaces = normalizeInterfaces(out.AllowedInterfaces)
	if len(out.AllowedInterfaces) == 0 {
		out.AllowedInterfaces = []string{"rest"}
	}
	out.AllowedKeyIDs = uniqueStrings(out.AllowedKeyIDs)
	out.Permissions = normalizePermissions(out.Permissions)
	if len(out.Permissions) == 0 {
		out.Permissions = []string{"key.encrypt", "key.decrypt"}
	}
	if out.DefaultTTLSeconds <= 0 {
		out.DefaultTTLSeconds = settings.DefaultJWTTTLSeconds
	}
	if !out.IssueX509SVID && !out.IssueJWTSVID {
		out.IssueJWTSVID = true
	}
	return out, nil
}

func normalizeFederationBundle(in WorkloadFederationBundle) WorkloadFederationBundle {
	out := in
	out.ID = strings.TrimSpace(out.ID)
	if out.ID == "" {
		out.ID = newID("fed")
	}
	out.TenantID = strings.TrimSpace(out.TenantID)
	out.TrustDomain = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(out.TrustDomain), "spiffe://"))
	out.BundleEndpoint = strings.TrimSpace(out.BundleEndpoint)
	out.JWKSJSON = strings.TrimSpace(out.JWKSJSON)
	out.CABundlePEM = strings.TrimSpace(out.CABundlePEM)
	return out
}

func (s *Service) ListRegistrations(ctx context.Context, tenantID string) ([]WorkloadRegistration, error) {
	if _, err := s.ensureSettings(ctx, tenantID); err != nil {
		return nil, err
	}
	items, err := s.store.ListRegistrations(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	_ = s.publishAudit(ctx, "audit.workload.registrations_viewed", tenantID, map[string]interface{}{"count": len(items)})
	return items, nil
}

func (s *Service) UpsertRegistration(ctx context.Context, in WorkloadRegistration) (WorkloadRegistration, error) {
	settings, err := s.ensureSettings(ctx, in.TenantID)
	if err != nil {
		return WorkloadRegistration{}, err
	}
	item, err := normalizeRegistration(in, settings)
	if err != nil {
		return WorkloadRegistration{}, err
	}
	item, err = s.store.UpsertRegistration(ctx, item)
	if err != nil {
		return WorkloadRegistration{}, err
	}
	_ = s.publishAudit(ctx, "audit.workload.registration_upserted", item.TenantID, map[string]interface{}{
		"registration_id":         item.ID,
		"spiffe_id":               item.SpiffeID,
		"issue_x509_svid":         item.IssueX509SVID,
		"issue_jwt_svid":          item.IssueJWTSVID,
		"allowed_interface_count": len(item.AllowedInterfaces),
		"allowed_key_count":       len(item.AllowedKeyIDs),
		"permission_count":        len(item.Permissions),
		"enabled":                 item.Enabled,
	})
	return item, nil
}

func (s *Service) DeleteRegistration(ctx context.Context, tenantID string, id string) error {
	if err := s.store.DeleteRegistration(ctx, tenantID, id); err != nil {
		return err
	}
	_ = s.publishAudit(ctx, "audit.workload.registration_deleted", tenantID, map[string]interface{}{"registration_id": id})
	return nil
}

func (s *Service) ListFederationBundles(ctx context.Context, tenantID string) ([]WorkloadFederationBundle, error) {
	if _, err := s.ensureSettings(ctx, tenantID); err != nil {
		return nil, err
	}
	items, err := s.store.ListFederationBundles(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	_ = s.publishAudit(ctx, "audit.workload.federation_viewed", tenantID, map[string]interface{}{"count": len(items)})
	return items, nil
}

func (s *Service) UpsertFederationBundle(ctx context.Context, in WorkloadFederationBundle) (WorkloadFederationBundle, error) {
	if _, err := s.ensureSettings(ctx, in.TenantID); err != nil {
		return WorkloadFederationBundle{}, err
	}
	item := normalizeFederationBundle(in)
	if item.TrustDomain == "" {
		return WorkloadFederationBundle{}, newServiceError(http.StatusBadRequest, "bad_request", "trust_domain is required")
	}
	if item.JWKSJSON == "" && item.CABundlePEM == "" {
		return WorkloadFederationBundle{}, newServiceError(http.StatusBadRequest, "bad_request", "jwks_json or ca_bundle_pem is required")
	}
	item, err := s.store.UpsertFederationBundle(ctx, item)
	if err != nil {
		return WorkloadFederationBundle{}, err
	}
	_ = s.publishAudit(ctx, "audit.workload.federation_bundle_upserted", item.TenantID, map[string]interface{}{
		"bundle_id":       item.ID,
		"trust_domain":    item.TrustDomain,
		"bundle_endpoint": item.BundleEndpoint,
		"enabled":         item.Enabled,
	})
	return item, nil
}

func (s *Service) DeleteFederationBundle(ctx context.Context, tenantID string, id string) error {
	if err := s.store.DeleteFederationBundle(ctx, tenantID, id); err != nil {
		return err
	}
	_ = s.publishAudit(ctx, "audit.workload.federation_bundle_deleted", tenantID, map[string]interface{}{"bundle_id": id})
	return nil
}

func (s *Service) ListIssuances(ctx context.Context, tenantID string, limit int) ([]WorkloadIssuanceRecord, error) {
	if _, err := s.ensureSettings(ctx, tenantID); err != nil {
		return nil, err
	}
	items, err := s.store.ListIssuanceRecords(ctx, tenantID, limit)
	if err != nil {
		return nil, err
	}
	_ = s.publishAudit(ctx, "audit.workload.issuance_history_viewed", tenantID, map[string]interface{}{"count": len(items)})
	return items, nil
}

func (s *Service) IssueSVID(ctx context.Context, in IssueSVIDRequest) (IssuedSVID, error) {
	settings, err := s.ensureSettings(ctx, in.TenantID)
	if err != nil {
		return IssuedSVID{}, err
	}
	reg, err := s.resolveRegistration(ctx, in.TenantID, in.RegistrationID, in.SpiffeID)
	if err != nil {
		return IssuedSVID{}, err
	}
	if !reg.Enabled {
		return IssuedSVID{}, newServiceError(http.StatusConflict, "disabled", "registration is disabled")
	}
	svidType := normalizeSVIDType(in.SVIDType)
	if svidType == "" {
		return IssuedSVID{}, newServiceError(http.StatusBadRequest, "bad_request", "svid_type must be x509 or jwt")
	}
	ttl := time.Duration(in.TTLSeconds) * time.Second
	var out IssuedSVID
	switch svidType {
	case "x509":
		if !reg.IssueX509SVID {
			return IssuedSVID{}, newServiceError(http.StatusBadRequest, "bad_request", "registration does not permit x509-svid issuance")
		}
		out, err = issueX509SVID(settings, reg, ttl)
	case "jwt":
		if !reg.IssueJWTSVID {
			return IssuedSVID{}, newServiceError(http.StatusBadRequest, "bad_request", "registration does not permit jwt-svid issuance")
		}
		out, err = issueJWTSVID(settings, reg, uniqueStrings(in.Audiences), ttl)
	}
	if err != nil {
		return IssuedSVID{}, err
	}
	out.IssuanceID = newID("iss")
	record := WorkloadIssuanceRecord{
		ID:             out.IssuanceID,
		TenantID:       reg.TenantID,
		RegistrationID: reg.ID,
		SpiffeID:       reg.SpiffeID,
		SVIDType:       out.SVIDType,
		Audiences:      uniqueStrings(in.Audiences),
		SerialOrKeyID:  out.SerialOrKeyID,
		DocumentHash:   sha256Hex(out.CertificatePEM, out.JWTSVID),
		ExpiresAt:      out.ExpiresAt,
		RotationDueAt:  out.RotationDueAt,
		Status:         issuanceStatus(out.ExpiresAt, s.now()),
		IssuedAt:       s.now(),
	}
	if err := s.store.InsertIssuanceRecord(ctx, record); err != nil {
		return IssuedSVID{}, err
	}
	_ = s.store.TouchRegistrationIssued(ctx, reg.TenantID, reg.ID, record.IssuedAt)
	_ = s.publishAudit(ctx, "audit.workload.svid_issued", reg.TenantID, map[string]interface{}{
		"registration_id":  reg.ID,
		"spiffe_id":        reg.SpiffeID,
		"svid_type":        out.SVIDType,
		"serial_or_key_id": out.SerialOrKeyID,
		"expires_at":       out.ExpiresAt.Format(time.RFC3339Nano),
	})
	return out, nil
}

func (s *Service) ExchangeToken(ctx context.Context, in TokenExchangeRequest) (TokenExchangeResult, error) {
	settings, err := s.ensureSettings(ctx, in.TenantID)
	if err != nil {
		return TokenExchangeResult{}, err
	}
	if !settings.Enabled {
		return TokenExchangeResult{}, newServiceError(http.StatusConflict, "disabled", "workload identity is disabled for this tenant")
	}
	if !settings.TokenExchangeEnabled {
		return TokenExchangeResult{}, newServiceError(http.StatusConflict, "disabled", "token exchange is disabled for this tenant")
	}
	bundles, _ := s.store.ListFederationBundles(ctx, in.TenantID)
	var verified verificationResult
	switch {
	case strings.TrimSpace(in.JWTSVID) != "":
		verified, err = verifyJWTSVID(in.JWTSVID, settings, bundles, strings.TrimSpace(in.Audience))
	case strings.TrimSpace(in.X509SVIDChainPEM) != "":
		verified, err = verifyX509SVID(in.X509SVIDChainPEM, settings, bundles)
	default:
		err = newServiceError(http.StatusBadRequest, "bad_request", "jwt_svid or x509_svid_chain_pem is required")
	}
	if err != nil {
		return TokenExchangeResult{}, err
	}
	reg, err := s.resolveRegistration(ctx, in.TenantID, in.RegistrationID, verified.SpiffeID)
	if err != nil {
		return TokenExchangeResult{}, err
	}
	if !reg.Enabled {
		return TokenExchangeResult{}, newServiceError(http.StatusConflict, "disabled", "registration is disabled")
	}
	interfaceName := normalizeInterfaces([]string{in.InterfaceName})
	if len(interfaceName) == 0 {
		return TokenExchangeResult{}, newServiceError(http.StatusBadRequest, "bad_request", "interface_name is required")
	}
	if !containsFold(reg.AllowedInterfaces, interfaceName[0]) && !containsFold(reg.AllowedInterfaces, "*") {
		return TokenExchangeResult{}, newServiceError(http.StatusForbidden, "forbidden", "registration is not allowed on this interface")
	}
	allowedPerms := intersectPermissions(reg.Permissions, in.RequestedPermissions)
	if len(allowedPerms) == 0 {
		return TokenExchangeResult{}, newServiceError(http.StatusForbidden, "forbidden", "no permitted workload operations remain after request scoping")
	}
	allowedKeys := intersectValues(reg.AllowedKeyIDs, in.RequestedKeyIDs)
	if len(allowedKeys) == 0 && len(reg.AllowedKeyIDs) > 0 {
		return TokenExchangeResult{}, newServiceError(http.StatusForbidden, "forbidden", "requested keys are not allowed for this workload")
	}
	authResp, err := s.auth.IssueWorkloadToken(ctx, AuthWorkloadTokenRequest{
		TenantID:            reg.TenantID,
		ClientID:            firstNonEmpty(strings.TrimSpace(in.ClientID), reg.ID),
		SubjectID:           reg.SpiffeID,
		InterfaceName:       interfaceName[0],
		Permissions:         allowedPerms,
		AllowedKeyIDs:       allowedKeys,
		WorkloadTrustDomain: verified.TrustDomain,
		TTLSeconds:          minInt(int(time.Until(verified.ExpiresAt).Seconds()), settings.DefaultJWTTTLSeconds),
	})
	if err != nil {
		return TokenExchangeResult{}, err
	}
	now := s.now()
	_ = s.store.TouchRegistrationUsed(ctx, reg.TenantID, reg.ID, now)
	_ = s.publishAudit(ctx, "audit.workload.token_exchanged", reg.TenantID, map[string]interface{}{
		"registration_id":   reg.ID,
		"spiffe_id":         reg.SpiffeID,
		"trust_domain":      verified.TrustDomain,
		"svid_type":         verified.SVIDType,
		"interface_name":    interfaceName[0],
		"allowed_key_count": len(allowedKeys),
		"allowed_key_ids":   allowedKeys,
		"permission_count":  len(allowedPerms),
		"document_hash":     verified.DocumentHash,
		"serial_or_key_id":  verified.SerialOrKeyID,
	})
	return TokenExchangeResult{
		TenantID:             reg.TenantID,
		RegistrationID:       reg.ID,
		SpiffeID:             reg.SpiffeID,
		TrustDomain:          verified.TrustDomain,
		SVIDType:             verified.SVIDType,
		InterfaceName:        interfaceName[0],
		AllowedPermissions:   allowedPerms,
		AllowedKeyIDs:        allowedKeys,
		KMSAccessToken:       authResp.AccessToken,
		KMSAccessTokenExpiry: authResp.ExpiresAt,
		SVIDExpiresAt:        verified.ExpiresAt,
		RotationDueAt:        verified.ExpiresAt.Add(-time.Duration(settings.RotationWindowSeconds) * time.Second),
	}, nil
}

func (s *Service) ListUsage(ctx context.Context, tenantID string, limit int) ([]WorkloadUsageRecord, error) {
	if _, err := s.ensureSettings(ctx, tenantID); err != nil {
		return nil, err
	}
	items, err := s.collectKeyUsage(ctx, tenantID, limit)
	if err != nil {
		return nil, err
	}
	_ = s.publishAudit(ctx, "audit.workload.key_usage_viewed", tenantID, map[string]interface{}{"count": len(items)})
	return items, nil
}

func (s *Service) GetGraph(ctx context.Context, tenantID string) (WorkloadAuthorizationGraph, error) {
	if _, err := s.ensureSettings(ctx, tenantID); err != nil {
		return WorkloadAuthorizationGraph{}, err
	}
	regs, err := s.store.ListRegistrations(ctx, tenantID)
	if err != nil {
		return WorkloadAuthorizationGraph{}, err
	}
	usage, _ := s.collectKeyUsage(ctx, tenantID, 250)
	nodes := map[string]WorkloadGraphNode{}
	edges := map[string]WorkloadGraphEdge{}
	for _, reg := range regs {
		status := "enabled"
		if !reg.Enabled {
			status = "disabled"
		} else if isOverPrivileged(reg) {
			status = "over-privileged"
		}
		nodes["workload:"+reg.SpiffeID] = WorkloadGraphNode{
			ID:     "workload:" + reg.SpiffeID,
			Label:  reg.SpiffeID,
			Kind:   "workload",
			Status: status,
			Detail: firstNonEmpty(reg.Name, reg.ID),
		}
		for _, keyID := range reg.AllowedKeyIDs {
			if strings.TrimSpace(keyID) == "" {
				continue
			}
			nodes["key:"+keyID] = WorkloadGraphNode{ID: "key:" + keyID, Label: keyID, Kind: "key", Status: "bound"}
			edgeKey := reg.SpiffeID + "|" + keyID + "|policy"
			edges[edgeKey] = WorkloadGraphEdge{Source: "workload:" + reg.SpiffeID, Target: "key:" + keyID, Label: "authorized", Kind: "policy"}
		}
	}
	for _, item := range usage {
		if item.WorkloadIdentity == "" || item.KeyID == "" {
			continue
		}
		nodes["workload:"+item.WorkloadIdentity] = WorkloadGraphNode{ID: "workload:" + item.WorkloadIdentity, Label: item.WorkloadIdentity, Kind: "workload", Status: "active"}
		nodes["key:"+item.KeyID] = WorkloadGraphNode{ID: "key:" + item.KeyID, Label: item.KeyID, Kind: "key", Status: "active"}
		edgeKey := item.WorkloadIdentity + "|" + item.KeyID + "|" + item.Operation
		edge := edges[edgeKey]
		edge.Source = "workload:" + item.WorkloadIdentity
		edge.Target = "key:" + item.KeyID
		edge.Kind = "usage"
		edge.Label = firstNonEmpty(item.Operation, "used")
		edge.Weight++
		edges[edgeKey] = edge
	}
	graph := WorkloadAuthorizationGraph{TenantID: tenantID, GeneratedAt: s.now(), Nodes: mapValues(nodes), Edges: mapEdgeValues(edges)}
	sort.Slice(graph.Nodes, func(i, j int) bool { return graph.Nodes[i].ID < graph.Nodes[j].ID })
	sort.Slice(graph.Edges, func(i, j int) bool {
		return graph.Edges[i].Source+graph.Edges[i].Target < graph.Edges[j].Source+graph.Edges[j].Target
	})
	_ = s.publishAudit(ctx, "audit.workload.graph_viewed", tenantID, map[string]interface{}{"node_count": len(graph.Nodes), "edge_count": len(graph.Edges)})
	return graph, nil
}

func (s *Service) GetSummary(ctx context.Context, tenantID string) (WorkloadIdentitySummary, error) {
	settings, err := s.ensureSettings(ctx, tenantID)
	if err != nil {
		return WorkloadIdentitySummary{}, err
	}
	regs, err := s.store.ListRegistrations(ctx, tenantID)
	if err != nil {
		return WorkloadIdentitySummary{}, err
	}
	bundles, err := s.store.ListFederationBundles(ctx, tenantID)
	if err != nil {
		return WorkloadIdentitySummary{}, err
	}
	issuances, err := s.store.ListIssuanceRecords(ctx, tenantID, 500)
	if err != nil {
		return WorkloadIdentitySummary{}, err
	}
	usage, _ := s.collectKeyUsage(ctx, tenantID, 250)
	now := s.now()
	summary := WorkloadIdentitySummary{
		TenantID:                  tenantID,
		Enabled:                   settings.Enabled,
		TrustDomain:               settings.TrustDomain,
		FederationEnabled:         settings.FederationEnabled,
		TokenExchangeEnabled:      settings.TokenExchangeEnabled,
		DisableStaticAPIKeys:      settings.DisableStaticAPIKeys,
		RegistrationCount:         len(regs),
		FederatedTrustDomainCount: len(bundles),
	}
	for _, reg := range regs {
		if reg.Enabled {
			summary.EnabledRegistrationCount++
		}
		if isOverPrivileged(reg) {
			summary.OverPrivilegedCount++
		}
	}
	expiringBy := now.Add(time.Duration(settings.RotationWindowSeconds) * time.Second)
	for _, item := range issuances {
		if item.IssuedAt.After(now.Add(-24 * time.Hour)) {
			summary.IssuanceCount24h++
		}
		if item.ExpiresAt.Before(now) {
			summary.ExpiredSVIDCount++
		} else if item.ExpiresAt.Before(expiringBy) {
			summary.ExpiringSVIDCount++
		}
	}
	workloadSet := map[string]struct{}{}
	keySet := map[string]struct{}{}
	for _, item := range usage {
		if item.CreatedAt.After(now.Add(-24 * time.Hour)) {
			summary.KeyUsageCount24h++
			if item.WorkloadIdentity != "" {
				workloadSet[item.WorkloadIdentity] = struct{}{}
			}
			if item.KeyID != "" {
				keySet[item.KeyID] = struct{}{}
			}
			if summary.LastKeyUseAt.IsZero() || item.CreatedAt.After(summary.LastKeyUseAt) {
				summary.LastKeyUseAt = item.CreatedAt
			}
		}
	}
	for _, reg := range regs {
		if !reg.LastUsedAt.IsZero() && reg.LastUsedAt.After(now.Add(-24*time.Hour)) {
			summary.TokenExchangeCount24h++
			if summary.LastExchangeAt.IsZero() || reg.LastUsedAt.After(summary.LastExchangeAt) {
				summary.LastExchangeAt = reg.LastUsedAt
			}
		}
	}
	summary.UniqueWorkloadsUsingKeys24h = len(workloadSet)
	summary.UniqueKeysUsed24h = len(keySet)
	summary.RotationHealthy = summary.ExpiredSVIDCount == 0 && summary.ExpiringSVIDCount <= maxInt(1, summary.EnabledRegistrationCount)
	_ = s.publishAudit(ctx, "audit.workload.summary_viewed", tenantID, map[string]interface{}{
		"registration_count": summary.RegistrationCount,
		"federated_domains":  summary.FederatedTrustDomainCount,
		"expired_svid_count": summary.ExpiredSVIDCount,
		"over_privileged":    summary.OverPrivilegedCount,
	})
	return summary, nil
}

func (s *Service) resolveRegistration(ctx context.Context, tenantID string, registrationID string, spiffeID string) (WorkloadRegistration, error) {
	registrationID = strings.TrimSpace(registrationID)
	spiffeID = strings.TrimSpace(spiffeID)
	if registrationID != "" {
		return s.store.GetRegistration(ctx, tenantID, registrationID)
	}
	if spiffeID == "" {
		return WorkloadRegistration{}, newServiceError(http.StatusBadRequest, "bad_request", "registration_id or spiffe_id is required")
	}
	return s.store.GetRegistrationBySPIFFEID(ctx, tenantID, spiffeID)
}

func (s *Service) collectKeyUsage(ctx context.Context, tenantID string, limit int) ([]WorkloadUsageRecord, error) {
	if s.audit == nil {
		return []WorkloadUsageRecord{}, nil
	}
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	events, err := s.audit.ListEvents(ctx, tenantID, maxInt(limit*4, 200))
	if err != nil {
		return nil, err
	}
	out := make([]WorkloadUsageRecord, 0, limit)
	for _, item := range events {
		action := strings.TrimSpace(toString(item["action"]))
		if !strings.HasPrefix(action, "audit.key.") {
			continue
		}
		details, _ := item["details"].(map[string]interface{})
		workloadID := strings.TrimSpace(toString(details["workload_identity"]))
		if workloadID == "" {
			continue
		}
		record := WorkloadUsageRecord{
			EventID:          strings.TrimSpace(toString(item["id"])),
			TenantID:         strings.TrimSpace(toString(item["tenant_id"])),
			WorkloadIdentity: workloadID,
			TrustDomain:      strings.TrimSpace(toString(details["workload_trust_domain"])),
			KeyID:            strings.TrimSpace(toString(details["key_id"])),
			Operation:        strings.TrimPrefix(action, "audit.key."),
			InterfaceName:    strings.TrimSpace(toString(details["interface_name"])),
			ClientID:         strings.TrimSpace(toString(details["client_id"])),
			Result:           strings.TrimSpace(toString(item["result"])),
			CreatedAt:        parseTimeValue(item["created_at"]),
		}
		if record.CreatedAt.IsZero() {
			record.CreatedAt = parseTimeValue(item["timestamp"])
		}
		out = append(out, record)
		if len(out) >= limit {
			break
		}
	}
	return out, nil
}

func (s *Service) publishAudit(ctx context.Context, subject string, tenantID string, data map[string]interface{}) error {
	if s.events == nil {
		return nil
	}
	raw, err := json.Marshal(map[string]interface{}{
		"tenant_id": tenantID,
		"timestamp": s.now().Format(time.RFC3339Nano),
		"data":      data,
	})
	if err != nil {
		return err
	}
	return s.events.Publish(ctx, subject, raw)
}

func normalizeSVIDType(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "x509", "x509-svid", "x509_svid":
		return "x509"
	case "jwt", "jwt-svid", "jwt_svid":
		return "jwt"
	default:
		return ""
	}
}

func normalizeInterfaces(values []string) []string {
	out := make([]string, 0, len(values))
	for _, raw := range values {
		value := strings.ToLower(strings.TrimSpace(raw))
		value = strings.ReplaceAll(value, "_", "-")
		switch value {
		case "", "rest-api", "api":
			value = "rest"
		case "kmip-tls":
			value = "kmip"
		case "ekm-data":
			value = "ekm"
		case "hyok-api":
			value = "hyok"
		case "payment", "paymenttcp":
			value = "payment-tcp"
		}
		if value != "" {
			out = append(out, value)
		}
	}
	return uniqueStrings(out)
}

func normalizePermissions(values []string) []string {
	out := make([]string, 0, len(values))
	for _, raw := range values {
		value := strings.ToLower(strings.TrimSpace(raw))
		if value == "" {
			continue
		}
		switch value {
		case "encrypt", "decrypt", "wrap", "unwrap", "sign", "verify", "mac", "derive", "export", "key.*", "*":
			if value == "*" {
				value = "key.*"
			} else if !strings.HasPrefix(value, "key.") && value != "key.*" {
				value = "key." + value
			}
		}
		out = append(out, value)
	}
	return uniqueStrings(out)
}

func intersectPermissions(allowed []string, requested []string) []string {
	allowed = normalizePermissions(allowed)
	if len(requested) == 0 {
		return allowed
	}
	requested = normalizePermissions(requested)
	out := []string{}
	for _, value := range requested {
		if containsFold(allowed, value) || containsFold(allowed, "key.*") {
			out = append(out, value)
		}
	}
	return uniqueStrings(out)
}

func intersectValues(allowed []string, requested []string) []string {
	allowed = uniqueStrings(allowed)
	if len(allowed) == 0 {
		return []string{}
	}
	if len(requested) == 0 {
		return allowed
	}
	out := []string{}
	for _, value := range uniqueStrings(requested) {
		if containsFold(allowed, value) || containsFold(allowed, "*") {
			out = append(out, value)
		}
	}
	return uniqueStrings(out)
}

func containsFold(values []string, target string) bool {
	for _, value := range values {
		if strings.EqualFold(strings.TrimSpace(value), strings.TrimSpace(target)) {
			return true
		}
	}
	return false
}

func isOverPrivileged(reg WorkloadRegistration) bool {
	if containsFold(reg.Permissions, "key.*") {
		return true
	}
	if len(reg.AllowedKeyIDs) == 0 || containsFold(reg.AllowedKeyIDs, "*") {
		return true
	}
	if containsFold(reg.AllowedInterfaces, "*") {
		return true
	}
	return len(reg.AllowedKeyIDs) > 25 || len(reg.Permissions) > 8
}

func issuanceStatus(expiresAt time.Time, now time.Time) string {
	if expiresAt.IsZero() {
		return "unknown"
	}
	if expiresAt.Before(now) {
		return "expired"
	}
	return "active"
}

func slugify(raw string) string {
	raw = strings.ToLower(strings.TrimSpace(raw))
	if raw == "" {
		return "workload"
	}
	replacer := strings.NewReplacer(" ", "-", "_", "-", "/", "-", ".", "-")
	raw = replacer.Replace(raw)
	for strings.Contains(raw, "--") {
		raw = strings.ReplaceAll(raw, "--", "-")
	}
	raw = strings.Trim(raw, "-")
	if raw == "" {
		return "workload"
	}
	return raw
}

func minInt(a int, b int) int {
	if a <= 0 {
		return b
	}
	if b <= 0 {
		return a
	}
	if a < b {
		return a
	}
	return b
}

func maxInt(a int, b int) int {
	if a > b {
		return a
	}
	return b
}

func mapValues(m map[string]WorkloadGraphNode) []WorkloadGraphNode {
	out := make([]WorkloadGraphNode, 0, len(m))
	for _, value := range m {
		out = append(out, value)
	}
	return out
}

func mapEdgeValues(m map[string]WorkloadGraphEdge) []WorkloadGraphEdge {
	out := make([]WorkloadGraphEdge, 0, len(m))
	for _, value := range m {
		out = append(out, value)
	}
	return out
}
