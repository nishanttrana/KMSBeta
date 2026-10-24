package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"vecta-kms/pkg/crypto"
)

// Key federation (13.60.0-beta, docs/FEDERATION.md): a key replicated from
// this installation to another one, for disaster recovery and serving in
// another region, and failover by promoting the replica.
//
//   - Each tenant has an identity: an ML-KEM-768 key, to which other
//     installations seal key material, and an ECDSA P-256 key that signs
//     what it sends. Administrators exchange identities out of band and
//     register each other as peers.
//   - A link replicates one key to one peer: every version's material is
//     sealed to the peer's ML-KEM key (bound to tenant, key, version and
//     recipient) inside a bundle the sender signs, and pushed over TLS 1.3 as
//     the peer's REST client. The replica keeps the key's ID, version numbers
//     and KCVs, so ciphertext and signatures move between installations.
//   - A replica serves every key operation; lifecycle changes (rotation,
//     metadata, status, destruction) are the primary's, and come with the
//     next push.
//   - Failover: promoting a replica makes it the primary at a higher epoch.
//     The old primary learns it from a signed statement (its next push is
//     refused with one) or from the new primary's push, and is demoted:
//     it keeps serving and can't change. A push never replaces or removes a
//     version that differs (version_conflict): material is never lost to a
//     split brain.

const (
	permFederationRead    = "key.federation.read"
	permFederationWrite   = "key.federation.write"
	permFederationReceive = "key.federation.receive"

	fedRolePrimary = "primary"
	fedRoleReplica = "replica"
	fedRoleDemoted = "demoted"

	fedBundleKind    = "vecta.federation.key.v1"
	fedStatementKind = "vecta.federation.primary.v1"
	fedSealLabel     = "vecta/federation/key-version/v1"
	fedSignAlg       = crypto.AlgECDSAP256
	fedMaxSkew       = 10 * time.Minute
	fedSyncInterval  = time.Minute
	fedVerifyEvery   = time.Hour
)

var (
	errFederationPeerExists = errors.New("a peer with this name or identity exists")
	errFederationLinkExists = errors.New("this key already replicates to this peer")
	errFederatedReplica     = errors.New("federated replica")
)

// federationRefusal is a refusal with a reason the routes report.
type federationRefusal struct {
	Status int
	Reason string
	Msg    string
}

func (e *federationRefusal) Error() string { return e.Msg }

func fedRefuse(status int, reason, format string, args ...any) error {
	return &federationRefusal{Status: status, Reason: reason, Msg: fmt.Sprintf(format, args...)}
}

// replicaRefusal is what a lifecycle change on a replica or demoted key
// gets: the primary changes the key; promote this one to change it here.
func replicaRefusal(st FederationKeyState) error {
	if st.Role == fedRoleDemoted {
		return fmt.Errorf("%w: this key was demoted when another installation was promoted (epoch %d); it serves operations but changes are made on the primary", errFederatedReplica, st.Epoch)
	}
	return fmt.Errorf("%w: this key is a replica (epoch %d); change it on the primary, or promote this replica first", errFederatedReplica, st.Epoch)
}

// refuseReplicaChange stops lifecycle changes to a replica or demoted key.
func (s *Service) refuseReplicaChange(ctx context.Context, tenantID, keyID string) error {
	st, err := s.store.GetFederationKeyState(ctx, tenantID, keyID)
	if errors.Is(err, errStoreNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if st.Role == fedRoleReplica || st.Role == fedRoleDemoted {
		return replicaRefusal(st)
	}
	return nil
}

// Identity.

type fedIdentity struct {
	kem         *crypto.KEMRecipient
	signer      *crypto.KeyPair
	kemPublic   []byte
	signPub     string
	fingerprint string
}

func fedFingerprint(kemPublic []byte, signPubPEM string) string {
	h := sha256.New()
	h.Write([]byte("vecta-federation-identity|"))
	h.Write(kemPublic)
	h.Write([]byte("|"))
	h.Write([]byte(strings.TrimSpace(signPubPEM)))
	return hex.EncodeToString(h.Sum(nil))
}

func (s *Service) sealSecret(raw []byte) (string, error) {
	env, err := crypto.EncryptEnvelope(s.mek, raw)
	if err != nil {
		return "", err
	}
	b, err := json.Marshal(env)
	return string(b), err
}

func (s *Service) openSecret(sealed string) ([]byte, error) {
	var env crypto.EnvelopeCiphertext
	if err := json.Unmarshal([]byte(sealed), &env); err != nil {
		return nil, err
	}
	return crypto.DecryptEnvelope(s.mek, &env)
}

// federationIdentity returns the tenant's identity, creating it once.
func (s *Service) federationIdentity(ctx context.Context, tenantID string) (*fedIdentity, error) {
	rec, err := s.store.GetFederationIdentity(ctx, tenantID)
	if errors.Is(err, errStoreNotFound) {
		kem, err := crypto.NewKEMRecipient()
		if err != nil {
			return nil, err
		}
		kp, err := crypto.GenerateKeyPair(fedSignAlg)
		if err != nil {
			return nil, err
		}
		privPEM, err := crypto.MarshalPrivateKeyPEM(kp)
		if err != nil {
			return nil, err
		}
		pubPEM, err := crypto.MarshalPublicKeyPEM(kp.Public)
		if err != nil {
			return nil, err
		}
		seed := kem.Seed()
		sealedSeed, err := s.sealSecret(seed)
		crypto.Zeroize(seed)
		if err != nil {
			return nil, err
		}
		sealedSign, err := s.sealSecret(privPEM)
		crypto.Zeroize(privPEM)
		if err != nil {
			return nil, err
		}
		kemPub := kem.EncapsulationKey()
		rec = FederationIdentity{TenantID: tenantID, KEMSeedSealed: sealedSeed, SignKeySealed: sealedSign,
			KEMPublic: base64.StdEncoding.EncodeToString(kemPub), SignPublicPEM: string(pubPEM), Fingerprint: fedFingerprint(kemPub, string(pubPEM))}
		if err := s.store.CreateFederationIdentity(ctx, rec); err != nil {
			return nil, err
		}
		if rec, err = s.store.GetFederationIdentity(ctx, tenantID); err != nil { // another node may have won
			return nil, err
		}
		_ = s.publishAudit(ctx, "audit.key.federation_identity_created", tenantID, map[string]any{"fingerprint": rec.Fingerprint})
	} else if err != nil {
		return nil, err
	}
	seed, err := s.openSecret(rec.KEMSeedSealed)
	if err != nil {
		return nil, fmt.Errorf("federation identity: %w", err)
	}
	defer crypto.Zeroize(seed)
	kem, err := crypto.KEMRecipientFromSeed(seed)
	if err != nil {
		return nil, err
	}
	privPEM, err := s.openSecret(rec.SignKeySealed)
	if err != nil {
		return nil, fmt.Errorf("federation identity: %w", err)
	}
	defer crypto.Zeroize(privPEM)
	kp, err := crypto.ParsePrivateKeyPEM(privPEM)
	if err != nil {
		return nil, err
	}
	kemPub, _ := base64.StdEncoding.DecodeString(rec.KEMPublic)
	return &fedIdentity{kem: kem, signer: kp, kemPublic: kemPub, signPub: rec.SignPublicPEM, fingerprint: rec.Fingerprint}, nil
}

// The wire format: a bundle's exact bytes, and the sender's signature over
// them (no canonicalisation to get wrong).

type fedSigned struct {
	Payload   []byte `json:"payload"`
	Signature []byte `json:"signature"`
}

type fedVersion struct {
	Version     int    `json:"version"`
	Status      string `json:"status"`
	Algorithm   string `json:"algorithm,omitempty"`
	KCV         []byte `json:"kcv"`
	PublicKey   []byte `json:"public_key,omitempty"`
	RotatedFrom int    `json:"rotated_from,omitempty"`
	Sealed      []byte `json:"sealed,omitempty"` // KEMSeal of the material; none for a destroyed version
}

type fedKey struct {
	ID             string            `json:"id"`
	Name           string            `json:"name"`
	Description    string            `json:"description"`
	Algorithm      string            `json:"algorithm"`
	KeyType        string            `json:"key_type"`
	Purpose        string            `json:"purpose"`
	Status         string            `json:"status"`
	IVMode         string            `json:"iv_mode"`
	Owner          string            `json:"owner"`
	Labels         map[string]string `json:"labels"`
	Tags           []string          `json:"tags"`
	ExportAllowed  bool              `json:"export_allowed"`
	KCVAlgorithm   string            `json:"kcv_algorithm"`
	CurrentVersion int               `json:"current_version"`
	Versions       []fedVersion      `json:"versions"`
}

type fedBundle struct {
	Kind     string    `json:"kind"`
	From     string    `json:"from"`
	To       string    `json:"to"`
	Tenant   string    `json:"tenant"` // the receiver's tenant
	Epoch    int64     `json:"epoch"`
	IssuedAt time.Time `json:"issued_at"`
	Key      fedKey    `json:"key"`
}

// fedStatement is a signed "the primary of this key is here, at this
// epoch": the fence an old primary acts on.
type fedStatement struct {
	Kind     string    `json:"kind"`
	From     string    `json:"from"`
	To       string    `json:"to"`
	KeyID    string    `json:"key_id"`
	Role     string    `json:"role"`
	Epoch    int64     `json:"epoch"`
	IssuedAt time.Time `json:"issued_at"`
}

func fedSealAAD(tenant, keyID string, version int, recipient string) []byte {
	return []byte("vecta-federation|" + tenant + "|" + keyID + "|" + strconv.Itoa(version) + "|" + recipient)
}

func (id *fedIdentity) sign(v any) (fedSigned, error) {
	payload, err := json.Marshal(v)
	if err != nil {
		return fedSigned{}, err
	}
	sig, err := crypto.Sign(id.signer, payload)
	return fedSigned{Payload: payload, Signature: sig}, err
}

func fedVerify(peer FederationPeer, s fedSigned) error {
	pub, err := crypto.ParsePublicKeyPEM(peer.SignPublicPEM)
	if err != nil {
		return err
	}
	return crypto.Verify(fedSignAlg, pub, s.Payload, s.Signature)
}

// fedVersionState is a version as both sides compare it.
type fedVersionState struct {
	Version int    `json:"version"`
	Status  string `json:"status"`
	KCV     string `json:"kcv"`
}

type fedKeyReport struct {
	KeyID    string            `json:"key_id"`
	Role     string            `json:"role"`
	Epoch    int64             `json:"epoch"`
	Versions []fedVersionState `json:"versions"`
}

func versionStates(vers []KeyVersion) []fedVersionState {
	out := make([]fedVersionState, 0, len(vers))
	for _, v := range vers {
		out = append(out, fedVersionState{Version: v.Version, Status: normalizeLifecycleStatus(v.Status), KCV: strings.ToUpper(hex.EncodeToString(v.KCV))})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Version < out[j].Version })
	return out
}

// fedDigest is what a link last delivered: when it changes, push again.
func fedDigest(key Key, vers []KeyVersion, epoch int64) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s|%s|%s|%s|%s|%d|%d|", key.ID, key.Name, key.Description, key.Status, key.Purpose, key.CurrentVersion, epoch)
	labels, _ := json.Marshal(key.Labels)
	tags, _ := json.Marshal(key.Tags)
	h.Write(labels)
	h.Write(tags)
	for _, v := range versionStates(vers) {
		fmt.Fprintf(h, "%d:%s:%s|", v.Version, v.Status, v.KCV)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// primaryState returns the key's federation state, making a key that has
// none the primary at epoch 1 (its first link).
func (s *Service) primaryState(ctx context.Context, key Key) (FederationKeyState, error) {
	st, err := s.store.GetFederationKeyState(ctx, key.TenantID, key.ID)
	if errors.Is(err, errStoreNotFound) {
		st = FederationKeyState{TenantID: key.TenantID, KeyID: key.ID, Role: fedRolePrimary, Epoch: 1}
		return st, s.store.PutFederationKeyState(ctx, st)
	}
	return st, err
}

// buildBundle seals every version of key to peer and signs the bundle.
func (s *Service) buildBundle(ctx context.Context, id *fedIdentity, key Key, vers []KeyVersion, st FederationKeyState, peer FederationPeer) (fedSigned, error) {
	kemPub, err := base64.StdEncoding.DecodeString(peer.KEMPublic)
	if err != nil {
		return fedSigned{}, err
	}
	fk := fedKey{ID: key.ID, Name: key.Name, Description: key.Description, Algorithm: key.Algorithm, KeyType: key.KeyType,
		Purpose: key.Purpose, Status: key.Status, IVMode: key.IVMode, Owner: key.Owner, Labels: key.Labels, Tags: key.Tags,
		ExportAllowed: key.ExportAllowed, KCVAlgorithm: key.KCVAlgorithm, CurrentVersion: key.CurrentVersion}
	for _, v := range vers {
		fv := fedVersion{Version: v.Version, Status: normalizeLifecycleStatus(v.Status), Algorithm: v.Algorithm, KCV: v.KCV,
			PublicKey: v.PublicKey, RotatedFrom: v.RotatedFrom}
		if !isDeletedLike(v.Status) {
			raw, err := s.decryptMaterial(v)
			if err != nil {
				return fedSigned{}, err
			}
			sealed, err := crypto.KEMSeal(kemPub, raw, fedSealAAD(peer.PeerTenantID, key.ID, v.Version, peer.Fingerprint), fedSealLabel)
			crypto.Zeroize(raw)
			if err != nil {
				return fedSigned{}, err
			}
			fv.Sealed = sealed
		}
		fk.Versions = append(fk.Versions, fv)
	}
	return id.sign(fedBundle{Kind: fedBundleKind, From: id.fingerprint, To: peer.Fingerprint, Tenant: peer.PeerTenantID,
		Epoch: st.Epoch, IssuedAt: time.Now().UTC(), Key: fk})
}

// Receiving.

type fedReceiveResult struct {
	Applied   bool          `json:"applied"`
	Report    *fedKeyReport `json:"report,omitempty"`
	Statement *fedSigned    `json:"statement,omitempty"`
}

// ReceiveFederatedKey applies a peer's push to tenantID.
func (s *Service) ReceiveFederatedKey(ctx context.Context, tenantID string, in fedSigned) (fedReceiveResult, error) {
	var b fedBundle
	if err := json.Unmarshal(in.Payload, &b); err != nil || b.Kind != fedBundleKind {
		return fedReceiveResult{}, fedRefuse(http.StatusBadRequest, "bad_bundle", "not a federation key bundle")
	}
	if b.Tenant != tenantID {
		return fedReceiveResult{}, fedRefuse(http.StatusForbidden, "tenant_mismatch", "the bundle is for tenant %q", b.Tenant)
	}
	peer, err := s.store.GetFederationPeerByFingerprint(ctx, tenantID, b.From)
	if errors.Is(err, errStoreNotFound) {
		return fedReceiveResult{}, fedRefuse(http.StatusForbidden, "unknown_peer", "no peer with identity %s is registered here", shortFP(b.From))
	}
	if err != nil {
		return fedReceiveResult{}, err
	}
	if err := fedVerify(peer, in); err != nil {
		return fedReceiveResult{}, fedRefuse(http.StatusForbidden, "bad_signature", "the bundle isn't signed by peer %s", peer.Name)
	}
	id, err := s.federationIdentity(ctx, tenantID)
	if err != nil {
		return fedReceiveResult{}, err
	}
	if b.To != id.fingerprint {
		return fedReceiveResult{}, fedRefuse(http.StatusForbidden, "wrong_recipient", "the bundle is for another identity")
	}
	if skew := time.Since(b.IssuedAt); skew > fedMaxSkew || skew < -fedMaxSkew {
		return fedReceiveResult{}, fedRefuse(http.StatusForbidden, "stale_bundle", "the bundle was issued at %s; clocks differ by more than %s, or it is replayed", b.IssuedAt.Format(time.RFC3339), fedMaxSkew)
	}
	fk := b.Key
	if fk.ID == "" || len(fk.Versions) == 0 {
		return fedReceiveResult{}, fedRefuse(http.StatusBadRequest, "bad_bundle", "the bundle names no key or versions")
	}
	local, kerr := s.store.GetKey(ctx, tenantID, fk.ID)
	if kerr != nil && !errors.Is(kerr, errStoreNotFound) {
		return fedReceiveResult{}, kerr
	}
	exists := kerr == nil
	st, serr := s.store.GetFederationKeyState(ctx, tenantID, fk.ID)
	if serr != nil && !errors.Is(serr, errStoreNotFound) {
		return fedReceiveResult{}, serr
	}
	hasState := serr == nil
	switch {
	case exists && !hasState:
		return fedReceiveResult{}, fedRefuse(http.StatusConflict, "key_exists", "key %s exists here and isn't federated; it is never overwritten", fk.ID)
	case hasState && st.Role == fedRolePrimary && b.Epoch <= st.Epoch:
		// This side is the primary: fence the sender.
		stmt, err := id.sign(fedStatement{Kind: fedStatementKind, From: id.fingerprint, To: peer.Fingerprint, KeyID: fk.ID,
			Role: fedRolePrimary, Epoch: st.Epoch, IssuedAt: time.Now().UTC()})
		if err != nil {
			return fedReceiveResult{}, err
		}
		return fedReceiveResult{Statement: &stmt}, fedRefuse(http.StatusConflict, "primary_here",
			"key %s is the primary here at epoch %d; the push at epoch %d is refused", fk.ID, st.Epoch, b.Epoch)
	case hasState && b.Epoch < st.Epoch:
		return fedReceiveResult{}, fedRefuse(http.StatusConflict, "stale_epoch", "key %s is at epoch %d here; the push is at %d", fk.ID, st.Epoch, b.Epoch)
	case hasState && st.Role == fedRoleReplica && st.SourcePeerID != peer.ID && b.Epoch == st.Epoch:
		return fedReceiveResult{}, fedRefuse(http.StatusConflict, "other_source", "key %s replicates from another peer at this epoch", fk.ID)
	case hasState && st.LastAppliedAt != nil && b.Epoch == st.Epoch && !b.IssuedAt.After(*st.LastAppliedAt):
		return fedReceiveResult{}, fedRefuse(http.StatusConflict, "stale_bundle", "a newer push for key %s was applied already", fk.ID)
	}

	var localVers []KeyVersion
	if exists {
		if localVers, err = s.store.ListVersions(ctx, tenantID, fk.ID); err != nil {
			return fedReceiveResult{}, err
		}
	}
	have := map[int]KeyVersion{}
	for _, v := range localVers {
		have[v.Version] = v
	}
	incoming := map[int]fedVersion{}
	for _, v := range fk.Versions {
		incoming[v.Version] = v
	}
	// Agreement: every version here is in the push with the same KCV.
	for n, v := range have {
		in, ok := incoming[n]
		if !ok || !bytes.Equal(in.KCV, v.KCV) {
			return fedReceiveResult{}, fedRefuse(http.StatusConflict, "version_conflict",
				"version %d of key %s differs between the installations; nothing was changed (resolve it before replicating)", n, fk.ID)
		}
	}
	var newVers []KeyVersion
	statuses := map[int]string{}
	for _, in := range fk.Versions {
		if _, ok := have[in.Version]; ok {
			statuses[in.Version] = in.Status
			continue
		}
		if len(in.Sealed) == 0 {
			continue // destroyed at the source: nothing to hold
		}
		raw, err := id.kem.Open(in.Sealed, fedSealAAD(tenantID, fk.ID, in.Version, id.fingerprint), fedSealLabel)
		if err != nil {
			return fedReceiveResult{}, fedRefuse(http.StatusBadRequest, "bad_material", "version %d's material doesn't open here", in.Version)
		}
		alg := in.Algorithm
		if alg == "" {
			alg = fk.Algorithm
		}
		kcv, _, kerr := computeKCVStrict(alg, raw)
		if kerr == nil && !bytes.Equal(kcv, in.KCV) {
			crypto.Zeroize(raw)
			return fedReceiveResult{}, fedRefuse(http.StatusBadRequest, "kcv_mismatch", "version %d's material doesn't match its KCV", in.Version)
		}
		ver := KeyVersion{ID: newID("kv"), TenantID: tenantID, KeyID: fk.ID, Version: in.Version, KCV: in.KCV, PublicKey: in.PublicKey,
			RotatedFrom: in.RotatedFrom, Status: in.Status, Algorithm: in.Algorithm}
		err = s.protectMaterial(ctx, &ver, raw)
		crypto.Zeroize(raw)
		if err != nil {
			return fedReceiveResult{}, err
		}
		newVers = append(newVers, ver)
	}
	key := Key{ID: fk.ID, TenantID: tenantID, Name: fk.Name, Description: fk.Description, Algorithm: fk.Algorithm, KeyType: fk.KeyType,
		Purpose: fk.Purpose, Status: fk.Status, CurrentVersion: fk.CurrentVersion, KCVAlgorithm: fk.KCVAlgorithm, IVMode: fk.IVMode,
		Owner: fk.Owner, Labels: fk.Labels, Tags: fk.Tags, ExportAllowed: fk.ExportAllowed, CreatedBy: "federation:" + peer.Name}
	if cur, ok := incoming[fk.CurrentVersion]; ok {
		key.KCV = cur.KCV
	}
	if exists {
		key.CreatedBy = local.CreatedBy
		key.Compliance, key.Cloud, key.Region = local.Compliance, local.Cloud, local.Region
	}
	applied := b.IssuedAt
	next := FederationKeyState{TenantID: tenantID, KeyID: fk.ID, Role: fedRoleReplica, Epoch: b.Epoch, SourcePeerID: peer.ID,
		PrimaryFingerprint: peer.Fingerprint, LastAppliedAt: &applied}
	if err := s.store.ApplyFederatedKey(ctx, key, !exists, newVers, statuses, next); err != nil {
		return fedReceiveResult{}, err
	}
	_ = s.cache.Delete(ctx, tenantID, fk.ID)
	if hasState && st.Role != fedRoleReplica {
		_ = s.publishAudit(ctx, "audit.key.federation_demoted", tenantID, map[string]any{
			"key_id": fk.ID, "from_role": st.Role, "epoch": b.Epoch, "primary_peer": peer.Name, "severity": "warning",
		})
	}
	vers, err := s.store.ListVersions(ctx, tenantID, fk.ID)
	if err != nil {
		return fedReceiveResult{}, err
	}
	return fedReceiveResult{Applied: true, Report: &fedKeyReport{KeyID: fk.ID, Role: fedRoleReplica, Epoch: b.Epoch, Versions: versionStates(vers)}}, nil
}

// Pushing.

type fedPeerClient struct {
	mu     sync.Mutex
	tokens map[string]fedToken // by tenant/peer ID
}

type fedToken struct {
	token   string
	expires time.Time
}

func (c *fedPeerClient) httpClient(peer FederationPeer) (*http.Client, error) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS13}
	if strings.TrimSpace(peer.CAPEM) != "" {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(peer.CAPEM)) {
			return nil, errors.New("the peer's CA PEM holds no certificate")
		}
		cfg.RootCAs = pool
	}
	return &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: cfg}}, nil
}

// do sends one JSON request to the peer as its REST client; out receives a
// 2xx body or, for a 409, the refusal (with any statement) in conflict.
func (c *fedPeerClient) do(ctx context.Context, s *Service, peer FederationPeer, method, path string, in, out any) (int, []byte, error) {
	hc, err := c.httpClient(peer)
	if err != nil {
		return 0, nil, err
	}
	base := strings.TrimRight(peer.URL, "/")
	send := func(token string) (int, []byte, error) {
		var body io.Reader
		if in != nil {
			raw, err := json.Marshal(in)
			if err != nil {
				return 0, nil, err
			}
			body = bytes.NewReader(raw)
		}
		req, err := http.NewRequestWithContext(ctx, method, base+path, body)
		if err != nil {
			return 0, nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("X-Tenant-ID", peer.PeerTenantID)
		resp, err := hc.Do(req)
		if err != nil {
			return 0, nil, err
		}
		defer resp.Body.Close() //nolint:errcheck
		raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
		return resp.StatusCode, raw, err
	}
	for attempt := 0; attempt < 2; attempt++ {
		token, err := c.token(ctx, s, peer, hc, attempt > 0)
		if err != nil {
			return 0, nil, err
		}
		status, raw, err := send(token)
		if err != nil {
			return 0, nil, err
		}
		if status == http.StatusUnauthorized && attempt == 0 {
			continue
		}
		if status/100 == 2 && out != nil {
			if err := json.Unmarshal(raw, out); err != nil {
				return status, raw, fmt.Errorf("the peer's answer isn't JSON: %w", err)
			}
		}
		return status, raw, nil
	}
	return http.StatusUnauthorized, nil, errors.New("the peer refused its REST client's token")
}

func (c *fedPeerClient) token(ctx context.Context, s *Service, peer FederationPeer, hc *http.Client, renew bool) (string, error) {
	key := peer.TenantID + "/" + peer.ID
	c.mu.Lock()
	defer c.mu.Unlock()
	if t, ok := c.tokens[key]; ok && !renew && time.Until(t.expires) > 30*time.Second {
		return t.token, nil
	}
	apiKey, err := s.openSecret(peer.APIKeySealed)
	if err != nil {
		return "", err
	}
	defer crypto.Zeroize(apiKey)
	body, _ := json.Marshal(map[string]any{"tenant_id": peer.PeerTenantID, "client_id": peer.ClientID, "ttl_seconds": 300})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(peer.URL, "/")+"/svc/auth/auth/client-token", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", string(apiKey))
	resp, err := hc.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close() //nolint:errcheck
	var out struct {
		AccessToken string `json:"access_token"`
	}
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 || json.Unmarshal(raw, &out) != nil || out.AccessToken == "" {
		return "", fmt.Errorf("the peer refused the REST client %s (%d)", peer.ClientID, resp.StatusCode)
	}
	if c.tokens == nil {
		c.tokens = map[string]fedToken{}
	}
	c.tokens[key] = fedToken{token: out.AccessToken, expires: time.Now().Add(270 * time.Second)}
	return out.AccessToken, nil
}

const (
	linkPending    = "pending"
	linkInSync     = "in_sync"
	linkMismatch   = "mismatch"
	linkConflict   = "conflict"
	linkSuperseded = "superseded"
	linkError      = "error"
)

// SyncFederationLink pushes the key to the link's peer and records what
// happened: in_sync (the peer holds the same versions), superseded (the
// peer is the primary now; this key was demoted), conflict, mismatch or
// error.
func (s *Service) SyncFederationLink(ctx context.Context, link FederationLink) (FederationLink, error) {
	finish := func(status, digest, msg string) (FederationLink, error) {
		now := time.Now().UTC()
		if err := s.store.UpdateFederationLinkSync(ctx, link.TenantID, link.ID, status, digest, msg, now); err != nil {
			return link, err
		}
		link.Status, link.LastDigest, link.LastError, link.LastSyncAt = status, digest, msg, &now
		return link, nil
	}
	peer, err := s.store.GetFederationPeer(ctx, link.TenantID, link.PeerID)
	if err != nil {
		return finish(linkError, "", "the peer is gone: "+err.Error())
	}
	key, err := s.store.GetKey(ctx, link.TenantID, link.KeyID)
	if err != nil {
		return finish(linkError, "", "the key is gone: "+err.Error())
	}
	st, err := s.primaryState(ctx, key)
	if err != nil {
		return link, err
	}
	if st.Role != fedRolePrimary {
		return finish(linkSuperseded, "", fmt.Sprintf("this key is %s here (epoch %d); only the primary replicates", st.Role, st.Epoch))
	}
	vers, err := s.store.ListVersions(ctx, key.TenantID, key.ID)
	if err != nil {
		return link, err
	}
	id, err := s.federationIdentity(ctx, link.TenantID)
	if err != nil {
		return link, err
	}
	signed, err := s.buildBundle(ctx, id, key, vers, st, peer)
	if err != nil {
		return finish(linkError, "", "can't seal the key: "+err.Error())
	}
	digest := fedDigest(key, vers, st.Epoch)
	var res fedReceiveResult
	status, raw, err := s.fedClient.do(ctx, s, peer, http.MethodPost, "/svc/keycore/federation/receive?tenant_id="+url.QueryEscape(peer.PeerTenantID), signed, &res)
	if err != nil {
		return finish(linkError, "", "the peer can't be reached: "+err.Error())
	}
	if status == http.StatusConflict {
		var refusal struct {
			Error struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
			Statement *fedSigned `json:"statement"`
		}
		_ = json.Unmarshal(raw, &refusal)
		if refusal.Error.Code == "primary_here" && refusal.Statement != nil {
			return s.fencedBy(ctx, link, peer, key, st, *refusal.Statement, finish)
		}
		return finish(linkConflict, "", refusal.Error.Code+": "+refusal.Error.Message)
	}
	if status/100 != 2 || !res.Applied || res.Report == nil {
		return finish(linkError, "", fmt.Sprintf("the peer answered %d: %s", status, strings.TrimSpace(string(raw))))
	}
	// Sync verification: the peer reports what it now holds.
	if want, got := versionStates(vers), res.Report.Versions; !sameVersions(want, got) || res.Report.Epoch != st.Epoch {
		return finish(linkMismatch, "", "the peer reports different versions after the push")
	}
	return finish(linkInSync, digest, "")
}

func sameVersions(a, b []fedVersionState) bool {
	held := map[int]fedVersionState{}
	for _, v := range b {
		held[v.Version] = v
	}
	for _, v := range a {
		if v.Status == "deleted" || v.Status == "destroy-pending" {
			continue // material the source no longer holds may be absent there
		}
		if h, ok := held[v.Version]; !ok || h.KCV != v.KCV || h.Status != v.Status {
			return false
		}
	}
	return true
}

// fencedBy acts on a peer's signed statement that it is the primary: at a
// higher epoch, this key is demoted (it keeps serving and can't change).
func (s *Service) fencedBy(ctx context.Context, link FederationLink, peer FederationPeer, key Key, st FederationKeyState, stmt fedSigned,
	finish func(status, digest, msg string) (FederationLink, error)) (FederationLink, error) {
	var sm fedStatement
	if fedVerify(peer, stmt) != nil || json.Unmarshal(stmt.Payload, &sm) != nil || sm.Kind != fedStatementKind || sm.KeyID != key.ID || sm.From != peer.Fingerprint {
		return finish(linkConflict, "", "the peer claims to be the primary without a valid signed statement")
	}
	if sm.Epoch <= st.Epoch {
		return finish(linkConflict, "", fmt.Sprintf("both installations are the primary of this key at epoch %d; promote one and demote the other", st.Epoch))
	}
	st.Role, st.Epoch, st.SourcePeerID, st.PrimaryFingerprint = fedRoleDemoted, sm.Epoch, peer.ID, peer.Fingerprint
	if err := s.store.PutFederationKeyState(ctx, st); err != nil {
		return link, err
	}
	_ = s.publishAudit(ctx, "audit.key.federation_demoted", key.TenantID, map[string]any{
		"key_id": key.ID, "from_role": fedRolePrimary, "epoch": sm.Epoch, "primary_peer": peer.Name, "severity": "warning",
	})
	return finish(linkSuperseded, "", fmt.Sprintf("peer %s was promoted (epoch %d); this key is demoted here", peer.Name, sm.Epoch))
}

// PromoteFederatedKey makes a replica (or demoted key) the primary here at
// the next epoch. The old primary is fenced by this side's next push, or
// by its own push being refused.
func (s *Service) PromoteFederatedKey(ctx context.Context, tenantID, keyID string) (FederationKeyState, error) {
	st, err := s.store.GetFederationKeyState(ctx, tenantID, keyID)
	if errors.Is(err, errStoreNotFound) {
		return st, fedRefuse(http.StatusConflict, "not_federated", "key %s isn't federated", keyID)
	}
	if err != nil {
		return st, err
	}
	if st.Role == fedRolePrimary {
		return st, fedRefuse(http.StatusConflict, "already_primary", "key %s is already the primary here (epoch %d)", keyID, st.Epoch)
	}
	st.Role, st.Epoch, st.SourcePeerID, st.PrimaryFingerprint, st.LastAppliedAt = fedRolePrimary, st.Epoch+1, "", "", nil
	if err := s.store.PutFederationKeyState(ctx, st); err != nil {
		return st, err
	}
	_ = s.cache.Delete(ctx, tenantID, keyID)
	return st, nil
}

// RunFederationSync pushes every link whose key changed since its last
// push, and every link once an hour (sync verification). Primary only.
func (s *Service) RunFederationSync(ctx context.Context, primary func(context.Context) bool) {
	t := time.NewTicker(fedSyncInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if !primary(ctx) {
			continue
		}
		s.syncDueLinks(ctx)
	}
}

func (s *Service) syncDueLinks(ctx context.Context) {
	links, err := s.store.ListAllFederationLinks(ctx)
	if err != nil {
		return
	}
	for _, l := range links {
		key, err := s.store.GetKey(ctx, l.TenantID, l.KeyID)
		if err != nil {
			continue
		}
		st, err := s.store.GetFederationKeyState(ctx, l.TenantID, l.KeyID)
		if err != nil || st.Role != fedRolePrimary {
			continue
		}
		vers, err := s.store.ListVersions(ctx, l.TenantID, l.KeyID)
		if err != nil {
			continue
		}
		stale := l.LastSyncAt == nil || time.Since(*l.LastSyncAt) > fedVerifyEvery
		if l.Status == linkInSync && l.LastDigest == fedDigest(key, vers, st.Epoch) && !stale {
			continue
		}
		if l.Status == linkConflict && !stale {
			continue // an administrator resolves a conflict; retried hourly
		}
		before := l.Status
		after, err := s.SyncFederationLink(ctx, l)
		if err == nil && after.Status != before {
			_ = s.publishAudit(ctx, "audit.key.federation_synced", l.TenantID, map[string]any{
				"link_id": l.ID, "key_id": l.KeyID, "peer_id": l.PeerID, "status": after.Status, "error": after.LastError,
				"severity": map[bool]string{true: "info", false: "warning"}[after.Status == linkInSync],
			})
		}
	}
}

func shortFP(fp string) string {
	if len(fp) > 16 {
		return fp[:16]
	}
	return fp
}
