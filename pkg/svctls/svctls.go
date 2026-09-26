// Package svctls gives every KMS service its internal mTLS identity
// (CLAUDE.md rule 10, docs/SECURITY/INTERNAL_TLS.md).
//
// At startup a service generates its own key, sends a CSR to the certs
// service's enrolment endpoint with an HMAC proof of its platform identity,
// and receives a short-lived certificate from the internal-services Sub CA.
// The key never leaves the process. The certificate is renewed with a fresh
// key at two thirds of its lifetime and swapped in without a restart.
//
// Servers require a client certificate from the Sub CA. Init replaces
// http.DefaultTransport with a router: calls to an internal service go over
// mTLS (plain http:// to one is refused), everything else keeps public-CA
// trust.
package svctls

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	pkgcrypto "vecta-kms/pkg/crypto"
	"vecta-kms/pkg/servicetoken"
	"vecta-kms/pkg/tlsprofile"
)

// Services maps each platform identity to its hostname on the service
// network. Enrolment assigns SANs from here, never from the CSR, and the
// client router treats these hosts as internal.
var Services = map[string]string{
	"kms-ai-gateway":        "ai-gateway",
	"kms-audit":             "audit",
	"kms-auth":              "auth",
	"kms-autokey":           "autokey",
	"kms-backup":            "backup",
	"kms-certs":             "certs",
	"kms-cloud":             "cloud",
	"kms-cluster-manager":   "cluster-manager",
	"kms-compliance":        "compliance",
	"kms-confidential":      "confidential",
	"kms-dataprotect":       "dataprotect",
	"kms-discovery":         "discovery",
	"kms-ekm":               "ekm",
	"kms-featureforge":      "featureforge",
	"kms-governance":        "governance",
	"kms-hsm":               "hsm-connector",
	"kms-hyok-proxy":        "hyok",
	"kms-key-access":        "keyaccess",
	"kms-keycore":           "keycore",
	"kms-kmip":              "kmip",
	"kms-payment":           "payment",
	"kms-policy":            "policy",
	"kms-posture":           "posture",
	"kms-pqc":               "pqc",
	"kms-reconciler":        "reconciler",
	"kms-reporting":         "reporting",
	"kms-sbom":              "sbom",
	"kms-secrets":           "secrets",
	"kms-signing":           "signing",
	"kms-watchdog":          "watchdog",
	"kms-workload-identity": "workload",
}

// Materialized identities get their certificate written by the certs service
// (they can't enrol themselves): Envoy's client certificate and the
// dashboard's server certificate.
var Materialized = map[string]string{
	"vecta-envoy":     "envoy",
	"vecta-dashboard": "dashboard",
}

// Infrastructure servers get a Sub CA server certificate written by the
// certs service; clients reach them over mTLS.
var Infrastructure = map[string]string{
	"vecta-postgres": "postgres",
	"vecta-nats":     "nats",
	"vecta-valkey":   "valkey",
	"vecta-consul":   "consul",
}

const (
	// EnrollPath is served by the certs enrolment listener.
	EnrollPath       = "/v1/enroll"
	proofHeader      = "X-Vecta-Enroll-Proof"
	proofLabel       = "vecta-enroll-v1"
	defaultTrustFile = "/run/vecta/trust/internal-ca.crt"
	defaultEnrollURL = "https://certs:8035" + EnrollPath
	// MaxClockSkew bounds how old an enrolment proof may be.
	MaxClockSkew = 5 * time.Minute
)

var (
	ErrPlainHTTP    = errors.New("svctls: plain http to an internal service is refused; use https")
	ErrNotEnrolled  = errors.New("svctls: no internal certificate yet")
	internalHostSet = func() map[string]bool {
		m := map[string]bool{}
		for _, h := range Services {
			m[h] = true
		}
		for _, h := range Materialized {
			m[h] = true
		}
		for _, h := range Infrastructure {
			m[h] = true
		}
		return m
	}()
)

// IsInternalHost reports whether host (no port) is a platform service.
func IsInternalHost(host string) bool {
	return internalHostSet[strings.ToLower(strings.TrimSpace(host))]
}

// HostFor returns the service hostname of a platform identity.
func HostFor(identity string) (string, bool) {
	if h, ok := Services[identity]; ok {
		return h, true
	}
	if h, ok := Materialized[identity]; ok {
		return h, true
	}
	h, ok := Infrastructure[identity]
	return h, ok
}

// EnrollRequest is the enrolment body.
type EnrollRequest struct {
	Identity  string `json:"identity"`
	CSRPEM    string `json:"csr_pem"`
	Timestamp int64  `json:"timestamp"`
}

// EnrollResponse carries the issued leaf and its chain up to the Sub CA.
type EnrollResponse struct {
	CertificatePEM string    `json:"certificate_pem"`
	ChainPEM       string    `json:"chain_pem"`
	Serial         string    `json:"serial"`
	NotAfter       time.Time `json:"not_after"`
}

// Proof computes the enrolment proof: HMAC-SHA256 under the identity's
// platform API key (servicetoken.DeriveAPIKey) over the identity, the
// timestamp and the CSR digest. It binds this CSR to this identity without
// sending the key.
func Proof(bootstrapSecret, identity string, timestamp int64, csrDER []byte) (string, error) {
	key := servicetoken.DeriveAPIKey(bootstrapSecret, identity)
	if key == "" {
		return "", errors.New("svctls: INTERNAL_SERVICE_BOOTSTRAP_SECRET is unset or weak")
	}
	msg := proofLabel + "\n" + identity + "\n" + strconv.FormatInt(timestamp, 10) + "\n" + hex.EncodeToString(pkgcrypto.SHA256(csrDER))
	return hex.EncodeToString(pkgcrypto.HMACSHA256([]byte(key), []byte(msg))), nil
}

// VerifyProof checks a proof in constant time and the timestamp window.
func VerifyProof(bootstrapSecret string, req EnrollRequest, csrDER []byte, proof string, now time.Time) error {
	if _, ok := Services[req.Identity]; !ok {
		return fmt.Errorf("unknown identity %q", req.Identity)
	}
	skew := now.Sub(time.Unix(req.Timestamp, 0))
	if skew > MaxClockSkew || skew < -MaxClockSkew {
		return errors.New("enrolment proof expired or from the future")
	}
	want, err := Proof(bootstrapSecret, req.Identity, req.Timestamp, csrDER)
	if err != nil {
		return err
	}
	got, err := hex.DecodeString(strings.TrimSpace(proof))
	wantRaw, _ := hex.DecodeString(want)
	if err != nil || !pkgcrypto.ConstantTimeEqual(got, wantRaw) {
		return errors.New("enrolment proof does not match the identity")
	}
	return nil
}

// Enroller turns a CSR into a certificate. The network enroller calls the
// certs service; the certs service itself passes a local one.
type Enroller interface {
	Enroll(ctx context.Context, identity string, csrDER []byte) (EnrollResponse, error)
}

// Identity is a service's live internal certificate.
type Identity struct {
	Name      string
	Algorithm string
	cert      atomic.Pointer[tls.Certificate]
	roots     *x509.CertPool
	enroller  Enroller
	logger    *log.Logger
}

var current atomic.Pointer[Identity]

// Current returns the process identity, or nil before Init.
func Current() *Identity { return current.Load() }

// Options tune Init. Zero values use the defaults.
type Options struct {
	Enroller  Enroller // default: the certs enrolment endpoint
	TrustFile string   // default: VECTA_INTERNAL_CA_FILE or /run/vecta/trust/internal-ca.crt
	Algorithm string   // default: VECTA_MTLS_KEY_ALGORITHM or ECDSA-P256
	Logger    *log.Logger
	// KeepDefaultTransport leaves http.DefaultTransport alone (tests).
	KeepDefaultTransport bool
}

// Init enrols the service, retrying until the certs service answers or ctx
// ends, installs the client router and starts renewal. A service must not
// serve before Init returns.
func Init(ctx context.Context, identity string, opts Options) (*Identity, error) {
	if _, ok := Services[identity]; !ok {
		return nil, fmt.Errorf("svctls: %q is not a registered platform identity", identity)
	}
	logger := opts.Logger
	if logger == nil {
		logger = log.New(os.Stderr, "[svctls] ", log.LstdFlags)
	}
	trustFile := firstNonEmpty(opts.TrustFile, os.Getenv("VECTA_INTERNAL_CA_FILE"), defaultTrustFile)
	roots, err := waitForTrust(ctx, trustFile, logger)
	if err != nil {
		return nil, err
	}
	enroller := opts.Enroller
	if enroller == nil {
		enroller = &networkEnroller{
			url:    firstNonEmpty(os.Getenv("CERTS_ENROLL_URL"), defaultEnrollURL),
			secret: os.Getenv("INTERNAL_SERVICE_BOOTSTRAP_SECRET"),
			client: &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{
				TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: "certs"},
			}},
		}
	}
	id := &Identity{
		Name:      identity,
		Algorithm: firstNonEmpty(opts.Algorithm, os.Getenv("VECTA_MTLS_KEY_ALGORITHM"), pkgcrypto.AlgECDSAP256),
		roots:     roots,
		enroller:  enroller,
		logger:    logger,
	}
	for attempt := 0; ; attempt++ {
		if err = id.renew(ctx); err == nil {
			break
		}
		logger.Printf("internal mTLS enrolment for %s failed (attempt %d): %v", identity, attempt+1, err)
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("svctls: enrolment not completed: %w", err)
		case <-time.After(backoff(attempt)):
		}
	}
	current.Store(id)
	if !opts.KeepDefaultTransport {
		http.DefaultTransport = id.Router(http.DefaultTransport)
	}
	go id.renewLoop(ctx)
	return id, nil
}

// Certificate returns the live certificate.
func (id *Identity) Certificate() (*tls.Certificate, error) {
	c := id.cert.Load()
	if c == nil {
		return nil, ErrNotEnrolled
	}
	return c, nil
}

// Leaf returns the parsed live leaf certificate.
func (id *Identity) Leaf() *x509.Certificate {
	if c := id.cert.Load(); c != nil {
		return c.Leaf
	}
	return nil
}

// ServerConfig requires a client certificate from the internal Sub CA.
func (id *Identity) ServerConfig() *tls.Config {
	return tlsprofile.ApplyServerDefaults(&tls.Config{
		MinVersion:     tls.VersionTLS13,
		ClientAuth:     tls.RequireAndVerifyClientCert,
		ClientCAs:      id.roots,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return id.Certificate() },
	})
}

// ClientConfig presents this identity and trusts only the internal Sub CA.
func (id *Identity) ClientConfig() *tls.Config {
	return tlsprofile.ApplyClientDefaults(&tls.Config{
		MinVersion:           tls.VersionTLS13,
		RootCAs:              id.roots,
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return id.Certificate() },
	})
}

// ClientTLSConfigFor presents this identity to serverName, trusting only
// the internal Sub CA (Postgres, NATS, Valkey and other non-HTTP clients).
func (id *Identity) ClientTLSConfigFor(serverName string) *tls.Config {
	cfg := id.ClientConfig()
	cfg.ServerName = serverName
	return cfg
}

// HTTPClient is an HTTP client over the process router (internal hosts
// over mTLS), for libraries that build their own transport.
func (id *Identity) HTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout, Transport: id.Router(http.DefaultTransport)}
}

// Router sends internal hosts over mTLS and everything else to external.
func (id *Identity) Router(external http.RoundTripper) http.RoundTripper {
	internal := &http.Transport{
		Proxy:                 nil,
		DialContext:           (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSClientConfig:       id.ClientConfig(),
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          200,
		MaxIdleConnsPerHost:   32,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
	return roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if IsInternalHost(req.URL.Hostname()) {
			if req.URL.Scheme != "https" {
				return nil, ErrPlainHTTP
			}
			return internal.RoundTrip(req)
		}
		return external.RoundTrip(req)
	})
}

// PeerIdentity names the verified internal caller of r, or "".
func PeerIdentity(r *http.Request) string {
	if r == nil || r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return ""
	}
	return r.TLS.PeerCertificates[0].Subject.CommonName
}

func (id *Identity) renew(ctx context.Context) error {
	kp, err := pkgcrypto.GenerateKeyPair(id.Algorithm)
	if err != nil {
		return err
	}
	host, _ := HostFor(id.Name)
	csrDER, err := x509.CreateCertificateRequest(pkgcrypto.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: id.Name, Organization: []string{"Vecta KMS internal"}},
		DNSNames: []string{host, id.Name},
	}, kp.Private)
	if err != nil {
		return err
	}
	resp, err := id.enroller.Enroll(ctx, id.Name, csrDER)
	if err != nil {
		return err
	}
	cert, err := assemble(resp, kp.Private)
	if err != nil {
		return err
	}
	if _, err := cert.Leaf.Verify(x509.VerifyOptions{Roots: id.roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return fmt.Errorf("issued certificate doesn't chain to the internal CA: %w", err)
	}
	id.cert.Store(cert)
	id.logger.Printf("internal mTLS certificate for %s: serial %s, %s, valid until %s", id.Name, resp.Serial, id.Algorithm, cert.Leaf.NotAfter.UTC().Format(time.RFC3339))
	return nil
}

func (id *Identity) renewLoop(ctx context.Context) {
	for {
		wait := time.Minute
		if leaf := id.Leaf(); leaf != nil {
			life := leaf.NotAfter.Sub(leaf.NotBefore)
			wait = time.Until(leaf.NotBefore.Add(life * 2 / 3))
			if wait < 30*time.Second {
				wait = 30 * time.Second
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		if err := id.renew(ctx); err != nil {
			id.logger.Printf("internal mTLS renewal for %s failed, retrying: %v", id.Name, err)
		}
	}
}

func assemble(resp EnrollResponse, key any) (*tls.Certificate, error) {
	var chain [][]byte
	for _, raw := range []string{resp.CertificatePEM, resp.ChainPEM} {
		rest := []byte(raw)
		for {
			var b *pem.Block
			b, rest = pem.Decode(rest)
			if b == nil {
				break
			}
			if b.Type == "CERTIFICATE" {
				chain = append(chain, b.Bytes)
			}
		}
	}
	if len(chain) == 0 {
		return nil, errors.New("enrolment returned no certificate")
	}
	leaf, err := x509.ParseCertificate(chain[0])
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{Certificate: chain, PrivateKey: key, Leaf: leaf}, nil
}

type networkEnroller struct {
	url, secret string
	client      *http.Client
}

func (n *networkEnroller) Enroll(ctx context.Context, identity string, csrDER []byte) (EnrollResponse, error) {
	ts := time.Now().Unix()
	proof, err := Proof(n.secret, identity, ts, csrDER)
	if err != nil {
		return EnrollResponse{}, err
	}
	body, _ := json.Marshal(EnrollRequest{
		Identity:  identity,
		CSRPEM:    string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})),
		Timestamp: ts,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.url, bytes.NewReader(body))
	if err != nil {
		return EnrollResponse{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(proofHeader, proof)
	res, err := n.client.Do(req)
	if err != nil {
		return EnrollResponse{}, err
	}
	defer res.Body.Close() //nolint:errcheck
	raw, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if res.StatusCode != http.StatusOK {
		return EnrollResponse{}, fmt.Errorf("enrolment refused: %s: %s", res.Status, strings.TrimSpace(string(raw)))
	}
	var out EnrollResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return EnrollResponse{}, err
	}
	return out, nil
}

// KeyAlgorithm names an approved internal certificate key, or refuses it.
func KeyAlgorithm(pub any) (string, error) {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		switch k.Curve.Params().BitSize {
		case 256:
			return pkgcrypto.AlgECDSAP256, nil
		case 384:
			return pkgcrypto.AlgECDSAP384, nil
		}
	case *rsa.PublicKey:
		if k.N.BitLen() >= 3072 {
			return pkgcrypto.AlgRSA3072, nil
		}
	}
	return "", errors.New("key must be ECDSA P-256/P-384 or RSA >= 3072")
}

// ProofHeader is the header carrying the enrolment proof.
func ProofHeader() string { return proofHeader }

// LoadTrust reads the internal CA bundle.
func LoadTrust(path string) (*x509.CertPool, error) {
	raw, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(raw) {
		return nil, fmt.Errorf("no certificate in %s", path)
	}
	return pool, nil
}

func waitForTrust(ctx context.Context, path string, logger *log.Logger) (*x509.CertPool, error) {
	for attempt := 0; ; attempt++ {
		pool, err := LoadTrust(path)
		if err == nil {
			return pool, nil
		}
		if attempt%10 == 0 {
			logger.Printf("waiting for the internal CA bundle at %s: %v", path, err)
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("svctls: internal CA bundle unavailable: %w", err)
		case <-time.After(2 * time.Second):
		}
	}
}

func backoff(attempt int) time.Duration {
	d := time.Duration(1<<min(attempt, 5)) * time.Second
	return d
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if strings.TrimSpace(s) != "" {
			return strings.TrimSpace(s)
		}
	}
	return ""
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
