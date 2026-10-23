package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	pkgcrypto "vecta-kms/pkg/crypto"
)

// The edge agent (docs/SECURITY/EDGE_DEVICES.md) keeps, in its state
// directory (mode 0700, every file 0600):
//
//	state.json     server, tenant, device ID and device credential
//	signing.pem    its ECDSA P-256 key: signs the enrolment proof and receipts
//	kem.seed       its ML-KEM-768 seed: opens the leases sealed to it
//	leases/<id>    each lease's data key, until it expires or is revoked
//	receipts.jsonl what it did offline, not yet sent; receipts.seq the last number
//
// A lease's data key is on disk in the clear for as long as the lease lasts:
// protect the directory (disk encryption, a TPM-sealed volume). The data
// itself stays decryptable centrally through keycore with the wrapped copy
// each file carries.

const (
	deviceKeyHeader = "X-Edge-Device-Key"
	enrollProof     = "vecta-edge-enroll|"
	leaseLabel      = "edge-lease"
	fileAADPrefix   = "vecta-edge-file|v1|"
	agentVersion    = "13.52.0-beta"
	maxBatch        = 1000
)

type state struct {
	Server    string `json:"server"`
	CA        string `json:"ca,omitempty"`
	TenantID  string `json:"tenant_id"`
	DeviceID  string `json:"device_id"`
	DeviceKey string `json:"device_key"`
	Revoked   bool   `json:"revoked,omitempty"`
}

type lease struct {
	ID           string    `json:"id"`
	KeyID        string    `json:"key_id"`
	KeyVersion   int64     `json:"key_version"`
	WrappedDEK   string    `json:"wrapped_dek"`
	WrappedDEKIV string    `json:"wrapped_dek_iv"`
	AAD          string    `json:"aad"`
	ExpiresAt    time.Time `json:"expires_at"`
	DEK          string    `json:"dek"`
}

type receipt struct {
	Seq       int64     `json:"seq"`
	LeaseID   string    `json:"lease_id"`
	Operation string    `json:"operation"`
	Bytes     int64     `json:"bytes"`
	At        time.Time `json:"at"`
}

// envelope is an encrypted file: what keycore needs to unwrap its data key
// centrally, and the ciphertext.
type envelope struct {
	V            int    `json:"v"`
	LeaseID      string `json:"lease_id"`
	KeyID        string `json:"key_id"`
	KeyVersion   int64  `json:"key_version"`
	WrappedDEK   string `json:"wrapped_dek"`
	WrappedDEKIV string `json:"wrapped_dek_iv"`
	AAD          string `json:"aad"`
	Ciphertext   string `json:"ciphertext"`
}

type agent struct {
	dir  string
	st   state
	http *http.Client
	now  func() time.Time
}

func writeSecret(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// validateConfig checks a state the agent is about to use.
func validateConfig(st state) error {
	switch {
	case !strings.HasPrefix(st.Server, "https://"):
		return errors.New("the server is https://<host>/svc/ekm")
	case st.TenantID == "" || st.DeviceID == "" || st.DeviceKey == "":
		return errors.New("this directory holds no enrolled device: run enroll first")
	}
	return nil
}

func httpClient(caPath string) (*http.Client, error) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS13}
	if strings.TrimSpace(caPath) != "" {
		raw, err := os.ReadFile(caPath)
		if err != nil {
			return nil, fmt.Errorf("read CA bundle: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(raw) {
			return nil, errors.New("no certificate in the CA bundle")
		}
		cfg.RootCAs = pool
	}
	return &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: cfg}}, nil
}

func loadAgent(dir string) (*agent, error) {
	raw, err := os.ReadFile(filepath.Join(dir, "state.json"))
	if err != nil {
		return nil, fmt.Errorf("read state: %w (run enroll first)", err)
	}
	var st state
	if err := json.Unmarshal(raw, &st); err != nil {
		return nil, err
	}
	if err := validateConfig(st); err != nil {
		return nil, err
	}
	client, err := httpClient(st.CA)
	if err != nil {
		return nil, err
	}
	return &agent{dir: dir, st: st, http: client, now: time.Now}, nil
}

// apiError is the KMS's answer to a refused call.
type apiError struct {
	Status int
	Code   string
	Msg    string
}

func (e *apiError) Error() string { return fmt.Sprintf("%s (%d %s)", e.Msg, e.Status, e.Code) }

func call(ctx context.Context, client *http.Client, server, tenant, path, deviceKey string, body, out any) error {
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, server+path+"?tenant_id="+url.QueryEscape(tenant), bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if deviceKey != "" {
		req.Header.Set(deviceKeyHeader, deviceKey)
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close() //nolint:errcheck
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode >= 300 {
		var e struct {
			Error struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		_ = json.Unmarshal(data, &e)
		return &apiError{Status: resp.StatusCode, Code: e.Error.Code, Msg: e.Error.Message}
	}
	return json.Unmarshal(data, out)
}

func tokenTenant(token string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 4 || parts[0] != "vedge-reg" {
		return "", errors.New("the token file holds no edge registration token")
	}
	t, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || len(t) == 0 {
		return "", errors.New("the token file holds no edge registration token")
	}
	return string(t), nil
}

// enroll makes the device's keys, enrols with the one-use token and keeps
// the credential. The token file is removed: the token is spent.
func enroll(ctx context.Context, dir, server, tokenFile, caPath string) (*agent, error) {
	server = strings.TrimRight(strings.TrimSpace(server), "/")
	if !strings.HasPrefix(server, "https://") {
		return nil, errors.New("-server is https://<host>/svc/ekm")
	}
	raw, err := os.ReadFile(tokenFile)
	if err != nil {
		return nil, fmt.Errorf("read token file: %w", err)
	}
	token := strings.TrimSpace(string(raw))
	tenant, err := tokenTenant(token)
	if err != nil {
		return nil, err
	}
	client, err := httpClient(caPath)
	if err != nil {
		return nil, err
	}
	signer, err := pkgcrypto.GenerateKeyPair(pkgcrypto.AlgECDSAP256)
	if err != nil {
		return nil, err
	}
	kem, err := pkgcrypto.NewKEMRecipient()
	if err != nil {
		return nil, err
	}
	pub, err := pkgcrypto.MarshalPublicKeyPEM(signer.Public)
	if err != nil {
		return nil, err
	}
	proof, err := pkgcrypto.Sign(signer, []byte(enrollProof+token))
	if err != nil {
		return nil, err
	}
	var out struct {
		DeviceID  string `json:"device_id"`
		DeviceKey string `json:"device_key"`
	}
	if err := call(ctx, client, server, tenant, "/ekm/edge/enroll", "", map[string]any{
		"tenant_id": tenant, "token": token, "signing_public_key": string(pub), "proof": base64.StdEncoding.EncodeToString(proof),
		"kem_public_key": base64.StdEncoding.EncodeToString(kem.EncapsulationKey()), "version": agentVersion,
	}, &out); err != nil {
		return nil, fmt.Errorf("enrol: %w", err)
	}
	signerPEM, err := pkgcrypto.MarshalPrivateKeyPEM(signer)
	if err != nil {
		return nil, err
	}
	st := state{Server: server, CA: caPath, TenantID: tenant, DeviceID: out.DeviceID, DeviceKey: out.DeviceKey}
	stJSON, _ := json.MarshalIndent(st, "", "  ")
	for name, data := range map[string][]byte{"signing.pem": signerPEM, "kem.seed": kem.Seed(), "state.json": stJSON} {
		if err := writeSecret(filepath.Join(dir, name), data); err != nil {
			return nil, err
		}
	}
	_ = os.Remove(tokenFile)
	return &agent{dir: dir, st: st, http: client, now: time.Now}, nil
}

func (a *agent) kem() (*pkgcrypto.KEMRecipient, error) {
	seed, err := os.ReadFile(filepath.Join(a.dir, "kem.seed"))
	if err != nil {
		return nil, err
	}
	defer pkgcrypto.Zeroize(seed)
	return pkgcrypto.KEMRecipientFromSeed(seed)
}

func (a *agent) signer() (*pkgcrypto.KeyPair, error) {
	raw, err := os.ReadFile(filepath.Join(a.dir, "signing.pem"))
	if err != nil {
		return nil, err
	}
	return pkgcrypto.ParsePrivateKeyPEM(raw)
}

// takeLease leases a data key under keyID and keeps it until it expires.
func (a *agent) takeLease(ctx context.Context, keyID string, ttl int64) (lease, error) {
	if a.st.Revoked {
		return lease{}, errors.New("this device was revoked")
	}
	var out struct {
		Lease struct {
			ID           string    `json:"id"`
			KeyID        string    `json:"key_id"`
			KeyVersion   int64     `json:"key_version"`
			WrappedDEK   string    `json:"wrapped_dek"`
			WrappedDEKIV string    `json:"wrapped_dek_iv"`
			ExpiresAt    time.Time `json:"expires_at"`
		} `json:"lease"`
		SealedDEK string `json:"sealed_dek"`
		AAD       string `json:"aad"`
	}
	if err := call(ctx, a.http, a.st.Server, a.st.TenantID, "/ekm/edge/devices/"+url.PathEscape(a.st.DeviceID)+"/leases", a.st.DeviceKey,
		map[string]any{"tenant_id": a.st.TenantID, "key_id": keyID, "ttl_seconds": ttl}, &out); err != nil {
		return lease{}, a.noteRevoked(err)
	}
	kem, err := a.kem()
	if err != nil {
		return lease{}, err
	}
	sealed, err := base64.StdEncoding.DecodeString(out.SealedDEK)
	aad, aerr := base64.StdEncoding.DecodeString(out.AAD)
	if err != nil || aerr != nil {
		return lease{}, errors.New("the lease answer is not base64")
	}
	if want := "vecta-edge-lease|" + a.st.TenantID + "|" + a.st.DeviceID + "|" + out.Lease.ID; string(aad) != want {
		return lease{}, errors.New("the lease is bound to another device or lease")
	}
	dek, err := kem.Open(sealed, aad, leaseLabel)
	if err != nil {
		return lease{}, fmt.Errorf("open the lease: %w", err)
	}
	defer pkgcrypto.Zeroize(dek)
	l := lease{ID: out.Lease.ID, KeyID: out.Lease.KeyID, KeyVersion: out.Lease.KeyVersion, WrappedDEK: out.Lease.WrappedDEK,
		WrappedDEKIV: out.Lease.WrappedDEKIV, AAD: out.AAD, ExpiresAt: out.Lease.ExpiresAt, DEK: base64.StdEncoding.EncodeToString(dek)}
	raw, _ := json.Marshal(l)
	return l, writeSecret(filepath.Join(a.dir, "leases", l.ID+".json"), raw)
}

func (a *agent) loadLease(id string) (lease, error) {
	if strings.ContainsAny(id, `/\`) || id == "" {
		return lease{}, errors.New("not a lease ID")
	}
	raw, err := os.ReadFile(filepath.Join(a.dir, "leases", id+".json"))
	if err != nil {
		return lease{}, fmt.Errorf("lease %s is not on this device", id)
	}
	var l lease
	if err := json.Unmarshal(raw, &l); err != nil {
		return lease{}, err
	}
	if !a.now().Before(l.ExpiresAt) {
		return lease{}, fmt.Errorf("lease %s expired at %s: take a new one, or decrypt centrally", id, l.ExpiresAt.Format(time.RFC3339))
	}
	return l, nil
}

func fileAAD(e envelope) []byte {
	return []byte(fmt.Sprintf("%s%s|%s|%d", fileAADPrefix, e.LeaseID, e.KeyID, e.KeyVersion))
}

// encrypt seals plaintext under a lease, offline, and records a receipt.
func (a *agent) encrypt(leaseID string, plaintext []byte) ([]byte, error) {
	l, err := a.loadLease(leaseID)
	if err != nil {
		return nil, err
	}
	dek, err := base64.StdEncoding.DecodeString(l.DEK)
	if err != nil {
		return nil, err
	}
	defer pkgcrypto.Zeroize(dek)
	e := envelope{V: 1, LeaseID: l.ID, KeyID: l.KeyID, KeyVersion: l.KeyVersion, WrappedDEK: l.WrappedDEK, WrappedDEKIV: l.WrappedDEKIV, AAD: l.AAD}
	ct, err := pkgcrypto.Seal(dek, plaintext, fileAAD(e))
	if err != nil {
		return nil, err
	}
	e.Ciphertext = base64.StdEncoding.EncodeToString(ct)
	if err := a.record(l.ID, "encrypt", int64(len(plaintext))); err != nil {
		return nil, err
	}
	return json.Marshal(e)
}

// decrypt opens a file sealed under a lease this device still holds.
func (a *agent) decrypt(data []byte) ([]byte, error) {
	var e envelope
	if err := json.Unmarshal(data, &e); err != nil || e.V != 1 {
		return nil, errors.New("not an edge-encrypted file")
	}
	l, err := a.loadLease(e.LeaseID)
	if err != nil {
		return nil, err
	}
	dek, err := base64.StdEncoding.DecodeString(l.DEK)
	if err != nil {
		return nil, err
	}
	defer pkgcrypto.Zeroize(dek)
	ct, err := base64.StdEncoding.DecodeString(e.Ciphertext)
	if err != nil {
		return nil, err
	}
	out, err := pkgcrypto.Open(dek, ct, fileAAD(e))
	if err != nil {
		return nil, errors.New("the file was altered or is not sealed under this lease")
	}
	return out, a.record(l.ID, "decrypt", int64(len(out)))
}

// record appends a receipt with the next number.
func (a *agent) record(leaseID, op string, n int64) error {
	seqPath := filepath.Join(a.dir, "receipts.seq")
	var seq int64
	if raw, err := os.ReadFile(seqPath); err == nil {
		_, _ = fmt.Sscan(strings.TrimSpace(string(raw)), &seq)
	}
	seq++
	line, _ := json.Marshal(receipt{Seq: seq, LeaseID: leaseID, Operation: op, Bytes: n, At: a.now().UTC().Truncate(time.Second)})
	f, err := os.OpenFile(filepath.Join(a.dir, "receipts.jsonl"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return writeSecret(seqPath, []byte(fmt.Sprint(seq)))
}

func (a *agent) pending() ([]receipt, error) {
	f, err := os.Open(filepath.Join(a.dir, "receipts.jsonl"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close() //nolint:errcheck
	var out []receipt
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var r receipt
		if json.Unmarshal(sc.Bytes(), &r) == nil && r.Seq > 0 {
			out = append(out, r)
		}
	}
	return out, sc.Err()
}

// noteRevoked wipes every lease when the KMS says the device was revoked.
func (a *agent) noteRevoked(err error) error {
	var ae *apiError
	if errors.As(err, &ae) && ae.Code == "device_revoked" {
		_ = os.RemoveAll(filepath.Join(a.dir, "leases"))
		a.st.Revoked = true
		raw, _ := json.MarshalIndent(a.st, "", "  ")
		_ = writeSecret(filepath.Join(a.dir, "state.json"), raw)
	}
	return err
}

type syncResult struct {
	Sent    int
	Dropped []string
	Revoked bool
}

// sync checks in, drops revoked and expired leases, and sends the receipts.
func (a *agent) sync(ctx context.Context) (syncResult, error) {
	var res syncResult
	var in struct {
		RevokedLeaseIDs []string `json:"revoked_lease_ids"`
	}
	if err := call(ctx, a.http, a.st.Server, a.st.TenantID, "/ekm/edge/devices/"+url.PathEscape(a.st.DeviceID)+"/check-in", a.st.DeviceKey,
		map[string]any{"tenant_id": a.st.TenantID, "version": agentVersion}, &in); err != nil {
		err = a.noteRevoked(err)
		res.Revoked = a.st.Revoked
		return res, err
	}
	revoked := map[string]bool{}
	for _, id := range in.RevokedLeaseIDs {
		revoked[id] = true
	}
	entries, _ := os.ReadDir(filepath.Join(a.dir, "leases"))
	for _, e := range entries {
		id := strings.TrimSuffix(e.Name(), ".json")
		if _, err := a.loadLease(id); revoked[id] || err != nil {
			_ = os.Remove(filepath.Join(a.dir, "leases", e.Name()))
			res.Dropped = append(res.Dropped, id)
		}
	}
	sort.Strings(res.Dropped)
	receipts, err := a.pending()
	if err != nil || len(receipts) == 0 {
		return res, err
	}
	signer, err := a.signer()
	if err != nil {
		return res, err
	}
	for start := 0; start < len(receipts); start += maxBatch {
		end := min(start+maxBatch, len(receipts))
		raw, _ := json.Marshal(receipts[start:end])
		sig, err := pkgcrypto.Sign(signer, raw)
		if err != nil {
			return res, err
		}
		var out struct {
			Received int `json:"received"`
		}
		err = call(ctx, a.http, a.st.Server, a.st.TenantID, "/ekm/edge/devices/"+url.PathEscape(a.st.DeviceID)+"/receipts", a.st.DeviceKey,
			map[string]any{"tenant_id": a.st.TenantID, "receipts": string(raw), "signature": base64.StdEncoding.EncodeToString(sig)}, &out)
		var ae *apiError
		if err != nil && !(errors.As(err, &ae) && ae.Code == "receipts_replayed") {
			return res, a.keepFrom(receipts[start:])
		}
		res.Sent += end - start
	}
	return res, a.keepFrom(nil)
}

// keepFrom rewrites the pending receipts to those not yet sent.
func (a *agent) keepFrom(rest []receipt) error {
	var buf bytes.Buffer
	for _, r := range rest {
		line, _ := json.Marshal(r)
		buf.Write(append(line, '\n'))
	}
	return writeSecret(filepath.Join(a.dir, "receipts.jsonl"), buf.Bytes())
}
