package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	neturl "net/url"
	"strings"
	"time"

	"vecta-kms/pkg/route"
	"vecta-kms/pkg/ssrfguard"
	"vecta-kms/pkg/svctls"
	"vecta-kms/pkg/tenantcheck"
)

// Approved private endpoints (7.40.0-beta). The outbound guard refuses
// private addresses for every connection, so a credential could never be
// used against a git server or object store on the customer's own network.
// A root administrator can approve a private address range for one tenant.
// A source connection (git, s3, azure_blob, gcs) of that tenant may then
// name a host inside it, and discovery sends that connection's credential
// to a private address only if it is inside an approved range, checked on
// the address actually dialled (after DNS resolution).
//
// The same approval covers mail relays (8.0.0-beta) and notification,
// ticketing and SIEM destinations (8.1.0-beta): an on-premises Splunk,
// QRadar, Jira or chat server. Compliance, audit and governance dial those
// with a client built for the one tenant from its ranges
// (ssrfguard.Allow), never the shared public-only client.
//
// What an approval can never cover: loopback, link-local and metadata
// addresses, multicast, and the KMS platform's own services, which every
// dial guard refuses whatever is approved.

const (
	permPrivateEndpoint          = "compliance.private_endpoint.approve"
	reasonPlatformTenant         = "platform_tenant_required"
	reasonInvalidPrivateEndpoint = "invalid_private_endpoint"
	maxPrivateEndpointsPerTenant = 64
)

// PrivateEndpoint is a private address range a root administrator approved
// for a tenant's source connections.
type PrivateEndpoint struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"tenant_id"` // the tenant it is approved for
	CIDR      string    `json:"cidr"`
	Note      string    `json:"note"`
	CreatedBy string    `json:"created_by"`
	CreatedAt time.Time `json:"created_at"`
}

var errPrivateEndpointExists = errors.New("this range is already approved for the tenant")

// approvable are the private address spaces an approval may fall in.
var approvable = func() []netip.Prefix {
	var out []netip.Prefix
	for _, p := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7"} {
		out = append(out, netip.MustParsePrefix(p))
	}
	return out
}()

// normalizePrivateRange accepts an address or a CIDR range and returns it
// masked. It must lie wholly inside private address space and be no wider
// than a /16 (IPv4) or /48 (IPv6): an approval names a network, not "every
// private address".
func normalizePrivateRange(raw string) (netip.Prefix, error) {
	raw = strings.TrimSpace(raw)
	p, err := netip.ParsePrefix(raw)
	if err != nil {
		a, aerr := netip.ParseAddr(raw)
		if aerr != nil {
			return netip.Prefix{}, errors.New("enter an address or a range in CIDR notation, such as 10.4.0.20 or 10.4.0.0/24")
		}
		p = netip.PrefixFrom(a, a.BitLen())
	}
	if p.Addr().Is4In6() || p.Addr().Zone() != "" {
		return netip.Prefix{}, errors.New("enter a plain IPv4 or IPv6 range")
	}
	p = p.Masked()
	inside := false
	for _, space := range approvable {
		if space.Bits() <= p.Bits() && space.Contains(p.Addr()) {
			inside = true
		}
	}
	if !inside {
		return netip.Prefix{}, errors.New("only private address space can be approved (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10, fc00::/7); public addresses need no approval, and loopback, link-local and metadata addresses can't have one")
	}
	if least := map[bool]int{true: 16, false: 48}[p.Addr().Is4()]; p.Bits() < least {
		return netip.Prefix{}, fmt.Errorf("a range is at most a /%d", least)
	}
	return p, nil
}

// rootApprover admits a person in the platform (root) tenant. A tenant's own
// administrator can't widen where that tenant's credentials may go, and a
// service can't approve on anyone's behalf.
func rootApprover(c *route.Call) bool {
	tenant := strings.TrimSpace(c.Claims.TenantID)
	if (tenant == "" || tenant == tenantcheck.InternalServiceTenant()) && !tenantcheck.IsServicePrincipal(c.Claims) {
		return true
	}
	c.Refuse(http.StatusForbidden, reasonPlatformTenant, "private endpoints are approved by a root administrator")
	return false
}

func (h *Handler) privateEndpointRoutes(rt *route.Router) {
	rt.Handle("GET /compliance/private-endpoints", route.Spec{Action: "private_endpoints_listed", Permission: permPlaybookRead, Resource: "private_endpoint"}, h.listPrivateEndpoints)
	rt.Handle("POST /compliance/private-endpoints", route.Spec{Action: "private_endpoint_added", Permission: permPrivateEndpoint, Resource: "private_endpoint", Severity: "warning"}, h.addPrivateEndpoint)
	rt.Handle("DELETE /compliance/private-endpoints/{id}", route.Spec{Action: "private_endpoint_removed", Permission: permPrivateEndpoint, Resource: "private_endpoint", TargetParam: "id", Severity: "warning"}, h.removePrivateEndpoint)
}

// listPrivateEndpoints shows a tenant the ranges approved for it; the root
// tenant sees every tenant's.
func (h *Handler) listPrivateEndpoints(c *route.Call) {
	of := c.Tenant
	if c.Tenant == tenantcheck.InternalServiceTenant() {
		of = ""
	}
	items, err := h.svc.store.ListPrivateEndpoints(c.R.Context(), of)
	if err != nil {
		c.Error(http.StatusInternalServerError, "internal_error", "list private endpoints failed")
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"data": items, "can_approve": (c.Tenant == tenantcheck.InternalServiceTenant()) && route.Allowed(c.Claims, permPrivateEndpoint) && !tenantcheck.IsServicePrincipal(c.Claims)})
}

func (h *Handler) addPrivateEndpoint(c *route.Call) {
	var in struct {
		TenantID  string `json:"tenant_id"` // verified by the kernel: the root tenant
		ForTenant string `json:"for_tenant"`
		CIDR      string `json:"cidr"`
		Note      string `json:"note"`
	}
	if !c.Decode(&in) {
		return
	}
	in.ForTenant, in.Note = strings.TrimSpace(in.ForTenant), strings.TrimSpace(in.Note)
	c.Detail("for_tenant", in.ForTenant)
	c.Detail("cidr", in.CIDR)
	if !rootApprover(c) {
		return
	}
	if in.ForTenant == "" || len(in.ForTenant) > 128 || len(in.Note) > 256 {
		c.Refuse(http.StatusBadRequest, reasonInvalidPrivateEndpoint, "name the tenant the range is approved for (for_tenant); a note is at most 256 characters")
		return
	}
	p, err := normalizePrivateRange(in.CIDR)
	if err != nil {
		c.Refuse(http.StatusBadRequest, reasonInvalidPrivateEndpoint, err.Error())
		return
	}
	existing, err := h.svc.store.ListPrivateEndpoints(c.R.Context(), in.ForTenant)
	if err != nil {
		c.Error(http.StatusInternalServerError, "internal_error", "read private endpoints failed")
		return
	}
	if len(existing) >= maxPrivateEndpointsPerTenant {
		c.Refuse(http.StatusConflict, "private_endpoint_limit", fmt.Sprintf("at most %d ranges per tenant", maxPrivateEndpointsPerTenant))
		return
	}
	item := PrivateEndpoint{ID: newID("pvt"), TenantID: in.ForTenant, CIDR: p.String(), Note: in.Note, CreatedBy: c.Actor()}
	switch err := h.svc.store.CreatePrivateEndpoint(c.R.Context(), item); {
	case errors.Is(err, errPrivateEndpointExists):
		c.Refuse(http.StatusConflict, "private_endpoint_exists", err.Error())
	case err != nil:
		c.Error(http.StatusInternalServerError, "internal_error", "save private endpoint failed")
	default:
		c.Target(item.ID)
		c.Detail("cidr", item.CIDR)
		item.CreatedAt = time.Now().UTC()
		c.JSON(http.StatusCreated, map[string]interface{}{"data": item})
	}
}

// removePrivateEndpoint withdraws an approval. Connections that named a
// host inside it stay, but discovery no longer sends their credential
// there: the next scan of what they read fails and says why.
func (h *Handler) removePrivateEndpoint(c *route.Call) {
	if !rootApprover(c) {
		return
	}
	item, err := h.svc.store.DeletePrivateEndpoint(c.R.Context(), c.R.PathValue("id"))
	if errors.Is(err, errNotFound) {
		c.Error(http.StatusNotFound, "not_found", "private endpoint not found")
		return
	} else if err != nil {
		c.Error(http.StatusInternalServerError, "internal_error", "remove private endpoint failed")
		return
	}
	c.Detail("for_tenant", item.TenantID)
	c.Detail("cidr", item.CIDR)
	c.JSON(http.StatusOK, map[string]interface{}{"data": map[string]string{"status": "removed"}})
}

// approvedRanges are the ranges approved for a tenant, parsed.
func (h *Handler) approvedRanges(ctx context.Context, tenantID string) ([]netip.Prefix, []string, error) {
	items, err := h.svc.store.ListPrivateEndpoints(ctx, tenantID)
	if err != nil {
		return nil, nil, err
	}
	var (
		out   []netip.Prefix
		names []string
	)
	for _, it := range items {
		if p, err := netip.ParsePrefix(it.CIDR); err == nil {
			out = append(out, p)
			names = append(names, p.String())
		}
	}
	return out, names, nil
}

// lookupHost resolves a connection's host (a variable so a test can answer).
var lookupHost = func(ctx context.Context, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

// privateSourceAllowed reports whether a source connection may name rawURL
// although the outbound guard refuses it: an https address, not a platform
// service, every address of which is public or inside a range approved for
// the tenant.
func (h *Handler) privateSourceAllowed(ctx context.Context, tenantID, rawURL string) (bool, error) {
	u, err := neturl.Parse(strings.TrimSpace(rawURL))
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || svctls.IsInternalHost(u.Hostname()) {
		return false, nil
	}
	var addrs []netip.Addr
	if a, err := netip.ParseAddr(u.Hostname()); err == nil {
		addrs = []netip.Addr{a}
	} else if addrs, err = lookupHost(ctx, u.Hostname()); err != nil || len(addrs) == 0 {
		return false, nil
	}
	ranges, _, err := h.approvedRanges(ctx, tenantID)
	if err != nil {
		return false, err
	}
	for _, a := range addrs {
		a = a.Unmap()
		if !ssrfguard.BlockedIP(net.IP(a.AsSlice())) {
			continue // public
		}
		ok := false
		for _, p := range ranges {
			ok = ok || p.Contains(a)
		}
		if !ok {
			return false, nil
		}
	}
	return true, nil
}
