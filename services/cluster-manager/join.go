package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"vecta-kms/pkg/clustercatalog"
	"vecta-kms/pkg/clusterrepl"
	"vecta-kms/pkg/clusterstate"
	pkgcrypto "vecta-kms/pkg/crypto"
	"vecta-kms/pkg/servicetoken"
)

// Secure cluster join (docs/CLUSTERING.md, slice 2).
//
// On the primary, a root admin creates a join request (existing
// /cluster/join/request); the response carries a join bundle: the primary's
// URL, its TLS certificate fingerprint, the token id and the one-time secret.
// On the new node, a root admin pastes the bundle (POST /cluster/join/connect):
//
//  1. the member's keycore creates a one-time ML-KEM join key, and the
//     member's cluster-manager creates another for the replication credentials;
//  2. the member calls the primary's POST /cluster/join/exchange over TLS
//     pinned to the bundle's fingerprint, with the token secret;
//  3. the primary consumes the token, registers the node, creates a
//     replication role for exactly the member's components, has its keycore
//     seal the master key to the member's keycore, and seals the replication
//     credentials to the member's cluster-manager;
//  4. the member installs the master key (keycore restarts on it) and
//     subscribes to each component, replacing its own copy of that data.
//
// Plaintext secrets never cross the network; every step is audited.

const (
	labelReplicationCreds = "cluster-replication"
	joinBundlePrefix      = "vecta-join-v1:"
)

type JoinBundle struct {
	PrimaryURL     string `json:"primary_url"`
	TLSFingerprint string `json:"tls_fingerprint"`
	TokenID        string `json:"token_id"`
	JoinSecret     string `json:"join_secret"`
}

// EncodeJoinBundle returns the text an admin pastes on the joining node.
func EncodeJoinBundle(b JoinBundle) string {
	raw, _ := json.Marshal(b)
	return joinBundlePrefix + base64.RawURLEncoding.EncodeToString(raw)
}

func DecodeJoinBundle(s string) (JoinBundle, error) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, joinBundlePrefix) {
		return JoinBundle{}, errors.New("join bundle must start with " + joinBundlePrefix)
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(s, joinBundlePrefix))
	if err != nil {
		return JoinBundle{}, errors.New("join bundle is not valid base64")
	}
	var b JoinBundle
	if err := json.Unmarshal(raw, &b); err != nil || b.PrimaryURL == "" || b.TokenID == "" || b.JoinSecret == "" {
		return JoinBundle{}, errors.New("join bundle is incomplete")
	}
	return b, nil
}

// ---- configuration ----

type joinConfig struct {
	advertiseURL   string // this node's cluster-manager URL as peers reach it
	tlsFingerprint string // SHA-256 of this node's cluster-manager TLS certificate
	pgHost         string // this node's Postgres as members reach it
	pgPort         string
	pgDB           string
	pgSSLMode      string
	keycoreURL     string
	allowHTTP      bool // lab only: plain-HTTP join
}

func loadJoinConfig() joinConfig {
	c := joinConfig{
		advertiseURL: strings.TrimRight(strings.TrimSpace(os.Getenv("CLUSTER_ADVERTISE_URL")), "/"),
		pgHost:       strings.TrimSpace(os.Getenv("CLUSTER_PG_ADVERTISE_HOST")),
		pgPort:       envOr("CLUSTER_PG_ADVERTISE_PORT", "5432"),
		pgDB:         envOr("POSTGRES_DB", "vecta"),
		pgSSLMode:    envOr("CLUSTER_PG_SSLMODE", "verify-full"),
		keycoreURL:   strings.TrimRight(envOr("KEYCORE_URL", "https://keycore:8010"), "/"),
		allowHTTP:    envBool("CLUSTER_JOIN_ALLOW_HTTP", false),
	}
	if certFile := strings.TrimSpace(os.Getenv("CLUSTER_HTTP_TLS_CERT_FILE")); certFile != "" {
		if fp, err := certFileFingerprint(certFile); err == nil {
			c.tlsFingerprint = fp
		}
	}
	return c
}

func certFileFingerprint(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return "", errors.New("no PEM certificate")
	}
	if _, err := x509.ParseCertificate(block.Bytes); err != nil {
		return "", err
	}
	sum := sha256.Sum256(block.Bytes)
	return hex.EncodeToString(sum[:]), nil
}

// ---- primary side ----

type ExchangeJoinInput struct {
	TokenID               string `json:"token_id"`
	JoinSecret            string `json:"join_secret"`
	NodeID                string `json:"node_id"`
	NodeName              string `json:"node_name"`
	Endpoint              string `json:"endpoint"`
	KeycoreJoinKey        string `json:"keycore_join_key"`
	ClusterManagerJoinKey string `json:"cluster_manager_join_key"`
}

type ExchangeJoinResult struct {
	PrimaryNodeID     string   `json:"primary_node_id"`
	Components        []string `json:"components"`
	Context           string   `json:"context"`
	SealedMEK         string   `json:"sealed_mek"`
	MEKFingerprint    string   `json:"mek_fingerprint"`
	SealedReplication string   `json:"sealed_replication"`
}

type replicationCreds struct {
	Host     string `json:"host"`
	Port     string `json:"port"`
	DB       string `json:"db"`
	User     string `json:"user"`
	Password string `json:"password"`
	SSLMode  string `json:"sslmode"`
	// ForwardCredential authenticates this member's forwarded writes to the
	// primary's cluster-manager (forward.go).
	ForwardCredential string `json:"forward_credential"`
}

func (c replicationCreds) conninfo() string {
	q := func(v string) string {
		return "'" + strings.ReplaceAll(strings.ReplaceAll(v, `\`, `\\`), "'", `\'`) + "'"
	}
	return fmt.Sprintf("host=%s port=%s dbname=%s user=%s password=%s sslmode=%s", q(c.Host), q(c.Port), q(c.DB), q(c.User), q(c.Password), q(c.SSLMode))
}

func joinContext(tokenID, nodeID string) string { return "cluster-join|" + tokenID + "|" + nodeID }

// ExchangeJoin runs on the primary for a joining member.
func (s *Service) ExchangeJoin(ctx context.Context, in ExchangeJoinInput) (ExchangeJoinResult, error) {
	cfg := s.joinCfg
	if s.replication == nil || s.keycore == nil {
		return ExchangeJoinResult{}, newServiceError(503, "cluster_not_ready", "replication or keycore client not configured")
	}
	if cfg.pgHost == "" {
		return ExchangeJoinResult{}, newServiceError(503, "cluster_not_configured", "this node is not configured as a primary: set CLUSTER_PG_ADVERTISE_HOST")
	}
	if in.KeycoreJoinKey == "" || in.ClusterManagerJoinKey == "" || strings.TrimSpace(in.NodeID) == "" {
		return ExchangeJoinResult{}, newServiceError(400, "bad_request", "node_id, keycore_join_key and cluster_manager_join_key are required")
	}
	node, err := s.CompleteJoin(ctx, CompleteJoinInput{
		TenantID: "root", TokenID: in.TokenID, JoinSecret: in.JoinSecret,
		NodeID: in.NodeID, NodeName: in.NodeName, Endpoint: in.Endpoint,
	})
	if err != nil {
		return ExchangeJoinResult{}, err
	}
	components := clustercatalog.WithCore(node.EnabledComponents)
	if _, err := s.replication.EnsurePublications(ctx, clustercatalog.Components()); err != nil {
		return ExchangeJoinResult{}, err
	}
	pwRaw, err := pkgcrypto.RandomBytes(32)
	if err != nil {
		return ExchangeJoinResult{}, err
	}
	password := hex.EncodeToString(pwRaw)
	role, err := s.replication.EnsureReplicationRole(ctx, node.ID, password, components)
	if err != nil {
		return ExchangeJoinResult{}, err
	}
	jctx := joinContext(in.TokenID, node.ID)
	sealedMEK, fp, err := s.keycore.ExportMEK(ctx, in.KeycoreJoinKey, jctx, node.ID)
	if err != nil {
		return ExchangeJoinResult{}, fmt.Errorf("keycore master-key export: %w", err)
	}
	fwdRaw, err := pkgcrypto.RandomBytes(32)
	if err != nil {
		return ExchangeJoinResult{}, err
	}
	forwardCredential := hex.EncodeToString(fwdRaw)
	if err := s.store.SetMemberCredential(ctx, node.ID, credentialHash(forwardCredential)); err != nil {
		return ExchangeJoinResult{}, err
	}
	credsJSON, _ := json.Marshal(replicationCreds{Host: cfg.pgHost, Port: cfg.pgPort, DB: cfg.pgDB, User: role, Password: password, SSLMode: cfg.pgSSLMode, ForwardCredential: forwardCredential})
	cmKey, err := base64.StdEncoding.DecodeString(in.ClusterManagerJoinKey)
	if err != nil {
		return ExchangeJoinResult{}, newServiceError(400, "bad_request", "cluster_manager_join_key must be base64")
	}
	sealedCreds, err := pkgcrypto.KEMSeal(cmKey, credsJSON, []byte(jctx), labelReplicationCreds)
	pkgcrypto.Zeroize(credsJSON)
	if err != nil {
		return ExchangeJoinResult{}, err
	}
	_ = s.publishAudit(ctx, "audit.cluster.member_joined", "root", map[string]interface{}{
		"member_node_id": node.ID, "member_name": node.Name, "member_endpoint": node.Endpoint,
		"components": components, "replication_role": role, "mek_fingerprint": fp, "token_id": in.TokenID,
		"severity": "warning", "result": "success",
		"description": "a node joined the cluster and received the master key and replication access for its components",
	})
	return ExchangeJoinResult{
		PrimaryNodeID: s.bootstrapNodeID, Components: components, Context: jctx,
		SealedMEK: sealedMEK, MEKFingerprint: fp,
		SealedReplication: base64.StdEncoding.EncodeToString(sealedCreds),
	}, nil
}

// ---- member side ----

type ConnectInput struct {
	JoinBundle     string `json:"join_bundle"`
	NodeName       string `json:"node_name"`
	Endpoint       string `json:"endpoint"`
	ConfirmReplace bool   `json:"confirm_replace"`
	Actor          string `json:"-"`
}

type ConnectResult struct {
	PrimaryNodeID string   `json:"primary_node_id"`
	Components    []string `json:"components"`
	Subscribed    []string `json:"subscribed"`
	Status        string   `json:"status"`
}

// joinHTTPClient pins the primary's TLS certificate (pkg/clusterstate).
func joinHTTPClient(fingerprint string) *http.Client {
	return clusterstate.PinnedHTTPClient(fingerprint, 60*time.Second)
}

// ConnectToCluster runs on the joining node.
func (s *Service) ConnectToCluster(ctx context.Context, in ConnectInput) (ConnectResult, error) {
	if !in.ConfirmReplace {
		return ConnectResult{}, newServiceError(400, "confirmation_required", "joining replaces this node's data for the assigned components and its master key; set confirm_replace")
	}
	if s.replication == nil || s.keycore == nil {
		return ConnectResult{}, newServiceError(503, "cluster_not_ready", "replication or keycore client not configured")
	}
	b, err := DecodeJoinBundle(in.JoinBundle)
	if err != nil {
		return ConnectResult{}, newServiceError(400, "bad_request", err.Error())
	}
	u, err := url.Parse(b.PrimaryURL)
	if err != nil || (u.Scheme != "https" && !(u.Scheme == "http" && s.joinCfg.allowHTTP)) {
		return ConnectResult{}, newServiceError(400, "bad_request", "primary_url must be https (plain http only with CLUSTER_JOIN_ALLOW_HTTP=true in a lab)")
	}
	if u.Scheme == "https" && strings.TrimSpace(b.TLSFingerprint) == "" {
		return ConnectResult{}, newServiceError(400, "bad_request", "join bundle has no TLS fingerprint to pin")
	}
	recipient, err := pkgcrypto.NewKEMRecipient()
	if err != nil {
		return ConnectResult{}, err
	}
	joinKeyID, keycoreKey, err := s.keycore.CreateJoinKey(ctx)
	if err != nil {
		return ConnectResult{}, fmt.Errorf("keycore join key: %w", err)
	}
	payload, _ := json.Marshal(ExchangeJoinInput{
		TokenID: b.TokenID, JoinSecret: b.JoinSecret, NodeID: s.bootstrapNodeID,
		NodeName: firstNonEmpty(in.NodeName, s.bootstrapNodeName), Endpoint: firstNonEmpty(in.Endpoint, s.joinCfg.advertiseURL),
		KeycoreJoinKey: keycoreKey, ClusterManagerJoinKey: base64.StdEncoding.EncodeToString(recipient.EncapsulationKey()),
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(b.PrimaryURL, "/")+"/cluster/join/exchange", bytes.NewReader(payload))
	if err != nil {
		return ConnectResult{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 60 * time.Second}
	if u.Scheme == "https" {
		client = joinHTTPClient(b.TLSFingerprint)
	}
	resp, err := client.Do(req)
	if err != nil {
		return ConnectResult{}, newServiceError(502, "primary_unreachable", err.Error())
	}
	defer resp.Body.Close() //nolint:errcheck
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return ConnectResult{}, newServiceError(502, "join_refused", fmt.Sprintf("primary refused the join (%d): %s", resp.StatusCode, strings.TrimSpace(string(body))))
	}
	var envelope struct {
		Result ExchangeJoinResult `json:"result"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return ConnectResult{}, err
	}
	res := envelope.Result
	sealed, err := base64.StdEncoding.DecodeString(res.SealedReplication)
	if err != nil {
		return ConnectResult{}, errors.New("primary returned malformed replication credentials")
	}
	credsJSON, err := recipient.Open(sealed, []byte(res.Context), labelReplicationCreds)
	if err != nil {
		return ConnectResult{}, err
	}
	var creds replicationCreds
	err = json.Unmarshal(credsJSON, &creds)
	pkgcrypto.Zeroize(credsJSON)
	if err != nil {
		return ConnectResult{}, err
	}
	// Master key first, so replicated key material is readable on arrival.
	if err := s.keycore.ImportMEK(ctx, joinKeyID, res.SealedMEK, res.Context, res.MEKFingerprint); err != nil {
		return ConnectResult{}, fmt.Errorf("keycore master-key import: %w", err)
	}
	out := ConnectResult{PrimaryNodeID: res.PrimaryNodeID, Components: res.Components, Subscribed: []string{}}
	for _, c := range res.Components {
		if _, ok := clustercatalog.Replicated[c]; !ok {
			continue // component owns no tables
		}
		if err := s.replication.Subscribe(ctx, s.bootstrapNodeID, c, creds.conninfo(), clusterrepl.SubscribeOptions{ResetLocalData: true}); err != nil {
			return out, fmt.Errorf("subscribe %s: %w", c, err)
		}
		out.Subscribed = append(out.Subscribed, c)
	}
	// From here this node's services forward lifecycle writes to the primary.
	if err := s.store.SetLocalState(ctx, clusterstate.State{
		NodeID: s.bootstrapNodeID, Role: clusterstate.RoleFollower, PrimaryNodeID: res.PrimaryNodeID,
		PrimaryURL: b.PrimaryURL, PrimaryFingerprint: b.TLSFingerprint, ForwardCredential: creds.ForwardCredential,
	}); err != nil {
		return out, fmt.Errorf("record cluster role: %w", err)
	}
	out.Status = "joined; initial copy in progress (see /cluster/replication/status); lifecycle writes now go to the primary"
	_ = s.publishAudit(ctx, "audit.cluster.joined_cluster", "root", map[string]interface{}{
		"primary_node_id": res.PrimaryNodeID, "primary_url": b.PrimaryURL, "components": res.Components,
		"subscribed": out.Subscribed, "mek_fingerprint": res.MEKFingerprint, "actor": in.Actor,
		"severity": "warning", "result": "success",
		"description": "this node joined a cluster: master key replaced and component data now replicates from the primary",
	})
	return out, nil
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// ---- keycore client ----

// KeycoreMEKClient is the keycore side of the master-key transfer.
type KeycoreMEKClient interface {
	CreateJoinKey(ctx context.Context) (joinKeyID, encapsulationKey string, err error)
	ExportMEK(ctx context.Context, encapsulationKey, context_, memberNodeID string) (sealed, fingerprint string, err error)
	ImportMEK(ctx context.Context, joinKeyID, sealed, context_, fingerprint string) error
}

type httpKeycoreMEKClient struct {
	baseURL string
	client  *http.Client
}

func newHTTPKeycoreMEKClient(baseURL string) *httpKeycoreMEKClient {
	return &httpKeycoreMEKClient{baseURL: baseURL, client: &http.Client{Timeout: 30 * time.Second}}
}

func (c *httpKeycoreMEKClient) post(ctx context.Context, path string, in, out any) error {
	raw, _ := json.Marshal(in)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	servicetoken.Authorize(ctx, req)
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close() //nolint:errcheck
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 300 {
		return fmt.Errorf("keycore %s: %d %s", path, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(body, out)
}

func (c *httpKeycoreMEKClient) CreateJoinKey(ctx context.Context) (string, string, error) {
	var out struct {
		ID string `json:"join_key_id"`
		EK string `json:"encapsulation_key"`
	}
	err := c.post(ctx, "/cluster/mek/join-key", map[string]any{}, &out)
	return out.ID, out.EK, err
}

func (c *httpKeycoreMEKClient) ExportMEK(ctx context.Context, ek, context_, member string) (string, string, error) {
	var out struct {
		Sealed string `json:"sealed_mek"`
		FP     string `json:"mek_fingerprint"`
	}
	err := c.post(ctx, "/cluster/mek/export", map[string]any{"encapsulation_key": ek, "context": context_, "member_node_id": member}, &out)
	return out.Sealed, out.FP, err
}

func (c *httpKeycoreMEKClient) ImportMEK(ctx context.Context, joinKeyID, sealed, context_, fp string) error {
	return c.post(ctx, "/cluster/mek/import", map[string]any{
		"join_key_id": joinKeyID, "sealed_mek": sealed, "context": context_, "mek_fingerprint": fp, "confirm_replace": true,
	}, nil)
}
