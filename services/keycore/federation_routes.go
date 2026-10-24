package main

import (
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"vecta-kms/pkg/crypto"
	"vecta-kms/pkg/route"
)

// Federation routes (federation.go, docs/FEDERATION.md).

func (h *Handler) federationRouter(audit route.Emitter) *route.Router {
	r := route.New("key", audit, nil)
	r.Handle("GET /federation/identity", route.Spec{Action: "federation_identity_read", Permission: permFederationRead, Resource: "federation"}, h.getFederationIdentity)
	r.Handle("GET /federation/peers", route.Spec{Action: "federation_peers_listed", Permission: permFederationRead, Resource: "federation"}, h.listFederationPeers)
	r.Handle("POST /federation/peers", route.Spec{Action: "federation_peer_added", Permission: permFederationWrite, Resource: "federation", Severity: "warning"}, h.addFederationPeer)
	r.Handle("DELETE /federation/peers/{id}", route.Spec{Action: "federation_peer_removed", Permission: permFederationWrite, Resource: "federation", TargetParam: "id", Severity: "warning"}, h.removeFederationPeer)
	r.Handle("GET /federation/links", route.Spec{Action: "federation_links_listed", Permission: permFederationRead, Resource: "federation"}, h.listFederationLinks)
	r.Handle("POST /federation/links", route.Spec{Action: "federation_link_created", Permission: permFederationWrite, Resource: "key", Severity: "warning"}, h.createFederationLink)
	r.Handle("POST /federation/links/{id}/sync", route.Spec{Action: "federation_link_synced", Permission: permFederationWrite, Resource: "federation", TargetParam: "id"}, h.syncFederationLink)
	r.Handle("DELETE /federation/links/{id}", route.Spec{Action: "federation_link_removed", Permission: permFederationWrite, Resource: "federation", TargetParam: "id", Severity: "warning"}, h.removeFederationLink)
	r.Handle("GET /federation/keys/{id}", route.Spec{Action: "federation_key_state_read", Permission: permFederationRead, Resource: "key", TargetParam: "id"}, h.getFederationKeyState)
	r.Handle("POST /federation/keys/{id}/promote", route.Spec{Action: "federation_key_promoted", Permission: permFederationWrite, Resource: "key", TargetParam: "id", Severity: "warning"}, h.promoteFederatedKey)
	r.Handle("POST /federation/receive", route.Spec{Action: "federation_key_received", Permission: permFederationReceive, Resource: "key", Severity: "warning"}, h.receiveFederatedKey)
	return r
}

func fedFail(c *route.Call, err error) {
	var fr *federationRefusal
	switch {
	case errors.As(err, &fr):
		c.Refuse(fr.Status, fr.Reason, fr.Msg)
	case errors.Is(err, errStoreNotFound):
		c.Error(http.StatusNotFound, "not_found", "not found")
	case errors.Is(err, errFederationPeerExists):
		c.Refuse(http.StatusConflict, "peer_exists", err.Error())
	case errors.Is(err, errFederationLinkExists):
		c.Refuse(http.StatusConflict, "link_exists", err.Error())
	default:
		c.Error(http.StatusInternalServerError, "federation_failed", err.Error())
	}
}

func (h *Handler) getFederationIdentity(c *route.Call) {
	id, err := h.svc.federationIdentity(c.R.Context(), c.Tenant)
	if err != nil {
		fedFail(c, err)
		return
	}
	c.Detail("fingerprint", id.fingerprint)
	// Exactly what the other installation's administrator pastes.
	c.JSON(http.StatusOK, map[string]any{"identity": map[string]any{
		"tenant_id": c.Tenant, "fingerprint": id.fingerprint,
		"kem_public": base64.StdEncoding.EncodeToString(id.kemPublic), "sign_public_pem": id.signPub,
	}})
}

func (h *Handler) listFederationPeers(c *route.Call) {
	peers, err := h.svc.store.ListFederationPeers(c.R.Context(), c.Tenant)
	if err != nil {
		fedFail(c, err)
		return
	}
	c.JSON(http.StatusOK, map[string]any{"items": peers})
}

type fedPeerInput struct {
	Name         string `json:"name"`
	URL          string `json:"url"`
	PeerTenantID string `json:"peer_tenant_id"`
	Identity     struct {
		TenantID      string `json:"tenant_id"`
		Fingerprint   string `json:"fingerprint"`
		KEMPublic     string `json:"kem_public"`
		SignPublicPEM string `json:"sign_public_pem"`
	} `json:"identity"`
	CAPEM    string `json:"ca_pem"`
	ClientID string `json:"client_id"`
	APIKey   string `json:"api_key"`
}

func (h *Handler) addFederationPeer(c *route.Call) {
	var in fedPeerInput
	if !c.Decode(&in) {
		return
	}
	bad := func(msg string) { c.Refuse(http.StatusBadRequest, "invalid_peer", msg) }
	in.Name, in.URL, in.PeerTenantID = strings.TrimSpace(in.Name), strings.TrimRight(strings.TrimSpace(in.URL), "/"), strings.TrimSpace(in.PeerTenantID)
	if in.PeerTenantID == "" {
		in.PeerTenantID = strings.TrimSpace(in.Identity.TenantID) // the pasted identity names it
	}
	u, err := url.Parse(in.URL)
	switch {
	case in.Name == "" || len(in.Name) > 128:
		bad("name is required (at most 128 characters)")
		return
	case err != nil || u.Scheme != "https" || u.Host == "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.User != nil:
		bad("url must be https://host[:port], the other installation's edge")
		return
	case in.PeerTenantID == "":
		bad("peer_tenant_id is required: the tenant on the other installation")
		return
	case strings.TrimSpace(in.ClientID) == "" || strings.TrimSpace(in.APIKey) == "":
		bad("client_id and api_key are required: a REST client on the other installation with key.federation.receive")
		return
	}
	kemPub, err := base64.StdEncoding.DecodeString(strings.TrimSpace(in.Identity.KEMPublic))
	if err != nil || len(kemPub) != 1184 {
		bad("identity.kem_public must be the other installation's ML-KEM-768 key (GET /federation/identity there)")
		return
	}
	pub, err := crypto.ParsePublicKeyPEM(in.Identity.SignPublicPEM)
	if family, bits := crypto.DescribePublicKey(pub); err != nil || family != "ECDSA" || bits != 256 {
		bad("identity.sign_public_pem must be the other installation's ECDSA P-256 key")
		return
	}
	fp := fedFingerprint(kemPub, in.Identity.SignPublicPEM)
	if want := strings.TrimSpace(in.Identity.Fingerprint); want != "" && want != fp {
		bad("identity.fingerprint doesn't match its keys: copy the identity again")
		return
	}
	own, err := h.svc.federationIdentity(c.R.Context(), c.Tenant)
	if err != nil {
		fedFail(c, err)
		return
	}
	if fp == own.fingerprint {
		bad("that is this installation's own identity")
		return
	}
	if strings.TrimSpace(in.CAPEM) != "" {
		if _, err := (&fedPeerClient{}).httpClient(FederationPeer{CAPEM: in.CAPEM}); err != nil {
			bad("ca_pem holds no certificate")
			return
		}
	}
	sealed, err := h.svc.sealSecret([]byte(strings.TrimSpace(in.APIKey)))
	if err != nil {
		fedFail(c, err)
		return
	}
	p := FederationPeer{TenantID: c.Tenant, ID: newID("fedp"), Name: in.Name, URL: in.URL, PeerTenantID: in.PeerTenantID,
		KEMPublic: base64.StdEncoding.EncodeToString(kemPub), SignPublicPEM: strings.TrimSpace(in.Identity.SignPublicPEM),
		Fingerprint: fp, CAPEM: strings.TrimSpace(in.CAPEM), ClientID: strings.TrimSpace(in.ClientID), APIKeySealed: sealed, CreatedBy: c.Actor()}
	if err := h.svc.store.CreateFederationPeer(c.R.Context(), p); err != nil {
		fedFail(c, err)
		return
	}
	c.Target(p.ID)
	c.Detail("name", p.Name)
	c.Detail("url", p.URL)
	c.Detail("fingerprint", p.Fingerprint)
	c.JSON(http.StatusCreated, map[string]any{"peer": p})
}

func (h *Handler) removeFederationPeer(c *route.Call) {
	id := c.R.PathValue("id")
	n, err := h.svc.store.CountFederationLinksForPeer(c.R.Context(), c.Tenant, id)
	if err != nil {
		fedFail(c, err)
		return
	}
	if n > 0 {
		c.Refuse(http.StatusConflict, "peer_in_use", "remove the peer's links first")
		return
	}
	if err := h.svc.store.DeleteFederationPeer(c.R.Context(), c.Tenant, id); err != nil {
		fedFail(c, err)
		return
	}
	c.JSON(http.StatusOK, map[string]any{"deleted": id})
}

func (h *Handler) listFederationLinks(c *route.Call) {
	links, err := h.svc.store.ListFederationLinks(c.R.Context(), c.Tenant)
	if err != nil {
		fedFail(c, err)
		return
	}
	c.JSON(http.StatusOK, map[string]any{"items": links})
}

func (h *Handler) createFederationLink(c *route.Call) {
	var in struct {
		KeyID  string `json:"key_id"`
		PeerID string `json:"peer_id"`
	}
	if !c.Decode(&in) {
		return
	}
	ctx := c.R.Context()
	c.Target(in.KeyID)
	c.Detail("peer_id", in.PeerID)
	key, err := h.svc.store.GetKey(ctx, c.Tenant, strings.TrimSpace(in.KeyID))
	if err == nil {
		err = h.svc.ensureKeyVisible(ctx, key)
	}
	if err != nil {
		c.Error(http.StatusNotFound, "not_found", "key not found")
		return
	}
	if _, err := h.svc.store.GetFederationPeer(ctx, c.Tenant, in.PeerID); err != nil {
		c.Error(http.StatusNotFound, "not_found", "peer not found")
		return
	}
	// Replicating sends the material to another installation: an export.
	if !key.ExportAllowed {
		c.Refuse(http.StatusConflict, "key_not_exportable", "the key doesn't allow export; replicating it would move its material out of this installation")
		return
	}
	if isDeletedLike(key.Status) {
		c.Refuse(http.StatusConflict, "key_deleted", "the key is deleted")
		return
	}
	vers, err := h.svc.store.ListVersions(ctx, c.Tenant, key.ID)
	if err != nil {
		fedFail(c, err)
		return
	}
	for _, v := range vers {
		if v.Protection == protectionHSMResident {
			c.Refuse(http.StatusConflict, "hsm_key_not_replicable", "the key lives in the HSM, which doesn't release its material; replicate it HSM to HSM with the vendor's tools")
			return
		}
	}
	st, err := h.svc.primaryState(ctx, key)
	if err != nil {
		fedFail(c, err)
		return
	}
	if st.Role != fedRolePrimary {
		c.Refuse(http.StatusConflict, "not_primary", replicaRefusal(st).Error())
		return
	}
	link := FederationLink{TenantID: c.Tenant, ID: newID("fedl"), KeyID: key.ID, PeerID: in.PeerID, Status: linkPending, CreatedBy: c.Actor()}
	if err := h.svc.store.CreateFederationLink(ctx, link); err != nil {
		fedFail(c, err)
		return
	}
	synced, err := h.svc.SyncFederationLink(ctx, link)
	if err != nil {
		fedFail(c, err)
		return
	}
	c.Detail("link_id", link.ID)
	c.Detail("status", synced.Status)
	c.JSON(http.StatusCreated, map[string]any{"link": synced})
}

func (h *Handler) syncFederationLink(c *route.Call) {
	link, err := h.svc.store.GetFederationLink(c.R.Context(), c.Tenant, c.R.PathValue("id"))
	if err != nil {
		fedFail(c, err)
		return
	}
	synced, err := h.svc.SyncFederationLink(c.R.Context(), link)
	if err != nil {
		fedFail(c, err)
		return
	}
	c.Detail("key_id", link.KeyID)
	c.Detail("status", synced.Status)
	c.JSON(http.StatusOK, map[string]any{"link": synced})
}

func (h *Handler) removeFederationLink(c *route.Call) {
	if err := h.svc.store.DeleteFederationLink(c.R.Context(), c.Tenant, c.R.PathValue("id")); err != nil {
		fedFail(c, err)
		return
	}
	c.JSON(http.StatusOK, map[string]any{"deleted": c.R.PathValue("id")})
}

func (h *Handler) getFederationKeyState(c *route.Call) {
	ctx := c.R.Context()
	key, err := h.svc.store.GetKey(ctx, c.Tenant, c.R.PathValue("id"))
	if err == nil {
		err = h.svc.ensureKeyVisible(ctx, key)
	}
	if err != nil {
		c.Error(http.StatusNotFound, "not_found", "key not found")
		return
	}
	st, err := h.svc.store.GetFederationKeyState(ctx, c.Tenant, key.ID)
	if errors.Is(err, errStoreNotFound) {
		st = FederationKeyState{TenantID: c.Tenant, KeyID: key.ID, Role: "none"}
	} else if err != nil {
		fedFail(c, err)
		return
	}
	vers, err := h.svc.store.ListVersions(ctx, c.Tenant, key.ID)
	if err != nil {
		fedFail(c, err)
		return
	}
	c.JSON(http.StatusOK, map[string]any{"state": st, "versions": versionStates(vers)})
}

func (h *Handler) promoteFederatedKey(c *route.Call) {
	var in struct {
		Reason string `json:"reason"`
	}
	if !c.Decode(&in) {
		return
	}
	if len(strings.TrimSpace(in.Reason)) < 10 {
		c.Refuse(http.StatusBadRequest, "reason_required", "say why this installation takes over the key (at least 10 characters)")
		return
	}
	c.Detail("reason", strings.TrimSpace(in.Reason))
	st, err := h.svc.PromoteFederatedKey(c.R.Context(), c.Tenant, c.R.PathValue("id"))
	if err != nil {
		fedFail(c, err)
		return
	}
	c.Detail("epoch", st.Epoch)
	c.JSON(http.StatusOK, map[string]any{"state": st})
}

func (h *Handler) receiveFederatedKey(c *route.Call) {
	var in fedSigned
	if !c.Decode(&in) {
		return
	}
	res, err := h.svc.ReceiveFederatedKey(c.R.Context(), c.Tenant, in)
	if res.Report != nil {
		c.Target(res.Report.KeyID)
	}
	var fr *federationRefusal
	if errors.As(err, &fr) && res.Statement != nil {
		// The fence: the refusal carries the signed statement.
		c.Protocol(fr.Status, map[string]any{"error": map[string]any{"code": fr.Reason, "message": fr.Msg, "request_id": c.RequestID},
			"statement": res.Statement}, route.ResultRefused, fr.Reason)
		return
	}
	if err != nil {
		fedFail(c, err)
		return
	}
	c.Detail("epoch", res.Report.Epoch)
	c.Detail("versions", len(res.Report.Versions))
	c.JSON(http.StatusOK, map[string]any{"applied": res.Applied, "report": res.Report})
}

// writeReplicaRefusal answers a lifecycle change to a replica or demoted
// key for the legacy handlers.
func writeReplicaRefusal(w http.ResponseWriter, err error, reqID, tenantID string) bool {
	if !errors.Is(err, errFederatedReplica) {
		return false
	}
	writeErr(w, http.StatusConflict, "federated_replica", err.Error(), reqID, tenantID)
	return true
}
