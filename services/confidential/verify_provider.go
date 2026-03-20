package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	cbor "github.com/fxamacker/cbor/v2"
	"github.com/golang-jwt/jwt/v5"
)

const awsNitroRootPEM = `-----BEGIN CERTIFICATE-----
MIICETCCAZagAwIBAgIRAPkxdWgbkK/hHUbMtOTn+FYwCgYIKoZIzj0EAwMwSTEL
MAkGA1UEBhMCVVMxDzANBgNVBAoMBkFtYXpvbjEMMAoGA1UECwwDQVdTMRswGQYD
VQQDDBJhd3Mubml0cm8tZW5jbGF2ZXMwHhcNMTkxMDI4MTMyODA1WhcNNDkxMDI4
MTQyODA1WjBJMQswCQYDVQQGEwJVUzEPMA0GA1UECgwGQW1hem9uMQwwCgYDVQQL
DANBV1MxGzAZBgNVBAMMEmF3cy5uaXRyby1lbmNsYXZlczB2MBAGByqGSM49AgEG
BSuBBAAiA2IABPwCVOumCMHzaHDimtqQvkY4MpJzbolL//Zy2YlES1BR5TSksfbb
48C8WBoyt7F2Bw7eEtaaP+ohG2bnUs990d0JX28TcPQXCEPZ3BABIeTPYwEoCWZE
h8l5YoQwTcU/9KNCMEAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUkCW1DdkF
R+eWw5b6cp3PmanfS5YwDgYDVR0PAQH/BAQDAgGGMAoGCCqGSM49BAMDA2kAMGYC
MQCjfy+Rocm9Xue4YnwWmNJVA44fA0P5W2OpYow9OYCVRaEevL8uO1XYru5xtMPW
rfMCMQCi85sWBbJwKKXdS6BptQFuZbT73o/gBh1qUxl/nNr12UO8Yfwr6wPLb+6N
IwLz3/Y=
-----END CERTIFICATE-----`

type attestationVerification struct {
	CryptographicallyVerified bool
	VerificationMode          string
	VerificationIssuer        string
	VerificationKeyID         string
	AttestationDocumentHash   string
	AttestationDocumentFormat string
	Issues                    []string
	MissingAttributes         []string

	Claims           map[string]string
	Measurements     map[string]string
	WorkloadIdentity string
	Attester         string
	ImageRef         string
	ImageDigest      string
	Audience         string
	Nonce            string
	EvidenceIssuedAt time.Time
	HasEvidenceTime  bool
	SecureBoot       bool
	HasSecureBoot    bool
	DebugDisabled    bool
	HasDebugDisabled bool
	ClusterNodeID    string
}

func (v attestationVerification) applyTo(in AttestedReleaseRequest) AttestedReleaseRequest {
	if normalizeProvider(in.Provider) == "generic" {
		return in
	}
	out := in
	out.WorkloadIdentity = strings.TrimSpace(v.WorkloadIdentity)
	out.Attester = strings.TrimSpace(v.Attester)
	out.ImageRef = strings.TrimSpace(v.ImageRef)
	out.ImageDigest = strings.TrimSpace(v.ImageDigest)
	out.Claims = copyStringMap(v.Claims)
	out.Measurements = copyStringMap(v.Measurements)
	if strings.TrimSpace(v.Audience) != "" {
		out.Audience = strings.TrimSpace(v.Audience)
	}
	if strings.TrimSpace(v.Nonce) != "" {
		out.Nonce = strings.TrimSpace(v.Nonce)
	}
	if v.HasEvidenceTime {
		out.EvidenceIssuedAt = v.EvidenceIssuedAt.UTC().Format(time.RFC3339Nano)
	} else {
		out.EvidenceIssuedAt = ""
	}
	if v.HasSecureBoot {
		out.SecureBoot = v.SecureBoot
	} else {
		out.SecureBoot = false
	}
	if v.HasDebugDisabled {
		out.DebugDisabled = v.DebugDisabled
	} else {
		out.DebugDisabled = false
	}
	if strings.TrimSpace(v.ClusterNodeID) != "" {
		out.ClusterNodeID = strings.TrimSpace(v.ClusterNodeID)
	}
	return out
}

func (v *attestationVerification) addIssue(message string, missing ...string) {
	message = strings.TrimSpace(message)
	if message != "" {
		v.Issues = append(v.Issues, message)
	}
	for _, item := range missing {
		item = strings.TrimSpace(item)
		if item != "" {
			v.MissingAttributes = append(v.MissingAttributes, item)
		}
	}
}

type oidcDiscoveryDocument struct {
	Issuer  string `json:"issuer"`
	JWKSURI string `json:"jwks_uri"`
}

type cachedOIDCDiscovery struct {
	Value     oidcDiscoveryDocument
	ExpiresAt time.Time
}

type jwkSet struct {
	Keys []jwkKey `json:"keys"`
}

type jwkKey struct {
	Kty string   `json:"kty"`
	Kid string   `json:"kid"`
	Alg string   `json:"alg"`
	Use string   `json:"use"`
	N   string   `json:"n"`
	E   string   `json:"e"`
	X5c []string `json:"x5c"`
}

type cachedJWKS struct {
	Value     jwkSet
	ExpiresAt time.Time
}

type ProviderVerifier struct {
	client            *http.Client
	mu                sync.Mutex
	oidcCache         map[string]cachedOIDCDiscovery
	jwksCache         map[string]cachedJWKS
	awsRootCerts      *x509.CertPool
	azureAllowedHosts []string
	gcpAllowedIssuers []string
}

func NewProviderVerifier() *ProviderVerifier {
	return &ProviderVerifier{
		client:            &http.Client{Timeout: 10 * time.Second},
		oidcCache:         map[string]cachedOIDCDiscovery{},
		jwksCache:         map[string]cachedJWKS{},
		awsRootCerts:      loadAWSRootPool(),
		azureAllowedHosts: []string{"attest.azure.net"},
		gcpAllowedIssuers: []string{"https://confidentialcomputing.googleapis.com"},
	}
}

func loadAWSRootPool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM([]byte(awsNitroRootPEM))
	if path := strings.TrimSpace(os.Getenv("CONFIDENTIAL_AWS_ROOT_PEM_PATH")); path != "" {
		if body, err := os.ReadFile(path); err == nil {
			pool.AppendCertsFromPEM(body)
		}
	}
	return pool
}

func (v *ProviderVerifier) Verify(ctx context.Context, in AttestedReleaseRequest) attestationVerification {
	verification := attestationVerification{
		Claims:       map[string]string{},
		Measurements: map[string]string{},
	}
	switch normalizeProvider(in.Provider) {
	case "aws_nitro_enclaves", "aws_nitro_tpm":
		return v.verifyAWSAttestation(ctx, in)
	case "azure_secure_key_release":
		return v.verifyOIDCAttestation(ctx, in, "azure")
	case "gcp_confidential_space":
		return v.verifyOIDCAttestation(ctx, in, "gcp")
	default:
		verification.VerificationMode = "generic_manual"
		return verification
	}
}

func (v *ProviderVerifier) verifyAWSAttestation(ctx context.Context, in AttestedReleaseRequest) attestationVerification {
	verification := attestationVerification{
		VerificationMode: "aws_cose_sign1_x509",
		Claims:           map[string]string{},
		Measurements:     map[string]string{},
	}
	_ = ctx
	raw, format, err := extractAWSAttestationBytes(in.AttestationDocument)
	if err != nil {
		verification.addIssue("provider attestation document is required and must be a base64 COSE_Sign1 blob", "attestation_document", "cryptographic_verification")
		return verification
	}
	verification.AttestationDocumentHash = hashBytes(raw)
	verification.AttestationDocumentFormat = firstNonEmpty(normalizeAttestationFormat(in.AttestationFormat), format, "cose_sign1")

	sign1, err := parseCOSESign1(raw)
	if err != nil {
		verification.addIssue("failed to parse AWS attestation document", "cryptographic_verification")
		return verification
	}
	doc, leaf, chainID, err := v.verifyAWSNitroSign1(sign1)
	if err != nil {
		verification.addIssue(err.Error(), "cryptographic_verification")
		return verification
	}

	verification.CryptographicallyVerified = true
	verification.VerificationIssuer = firstNonEmpty(leaf.Issuer.CommonName, leaf.Subject.CommonName, "aws.nitro-enclaves")
	verification.VerificationKeyID = chainID
	verification.Attester = verification.VerificationIssuer
	verification.HasEvidenceTime = !doc.Timestamp.IsZero()
	verification.EvidenceIssuedAt = doc.Timestamp.UTC()
	verification.HasSecureBoot = true
	verification.SecureBoot = true
	verification.HasDebugDisabled = true
	verification.DebugDisabled = true

	if doc.ModuleID != "" {
		verification.Claims["module_id"] = doc.ModuleID
	}
	if doc.Digest != "" {
		verification.Claims["nitro_digest"] = doc.Digest
	}
	verification.Claims["provider"] = normalizeProvider(in.Provider)
	verification.Claims["attestation_type"] = "aws_nitro"

	for key, value := range doc.PCRs {
		verification.Measurements[strings.ToLower(strings.TrimSpace(key))] = value
	}

	if doc.Nonce != "" {
		verification.Nonce = doc.Nonce
		verification.Claims["nonce"] = doc.Nonce
		if expected := strings.TrimSpace(in.Nonce); expected != "" && !strings.EqualFold(expected, doc.Nonce) {
			verification.addIssue("attestation nonce does not match the expected request nonce", "nonce")
		}
	} else if strings.TrimSpace(in.Nonce) != "" {
		verification.addIssue("attestation nonce is missing from the AWS provider evidence", "nonce")
	}

	userData := parseBoundEvidenceJSON(doc.UserData)
	if len(userData.Claims) > 0 {
		for key, value := range userData.Claims {
			verification.Claims[key] = value
		}
	}
	if len(userData.Measurements) > 0 {
		for key, value := range userData.Measurements {
			verification.Measurements[key] = value
		}
	}
	verification.WorkloadIdentity = firstNonEmpty(userData.WorkloadIdentity, doc.ModuleID)
	verification.ImageRef = userData.ImageRef
	verification.ImageDigest = userData.ImageDigest
	verification.ClusterNodeID = userData.ClusterNodeID
	if userData.Audience != "" {
		verification.Audience = userData.Audience
	}
	if userData.Attester != "" {
		verification.Attester = userData.Attester
	}
	return verification
}

func (v *ProviderVerifier) verifyOIDCAttestation(ctx context.Context, in AttestedReleaseRequest, family string) attestationVerification {
	verification := attestationVerification{
		VerificationMode: "oidc_jwks_rs256",
		Claims:           map[string]string{},
		Measurements:     map[string]string{},
	}
	tokenString, format, err := extractJWTAttestationToken(in.AttestationDocument)
	if err != nil {
		verification.addIssue("provider attestation document is required and must be a signed JWT", "attestation_document", "cryptographic_verification")
		return verification
	}
	verification.AttestationDocumentHash = hashString(tokenString)
	verification.AttestationDocumentFormat = firstNonEmpty(normalizeAttestationFormat(in.AttestationFormat), format, "jwt")

	unverifiedClaims, err := parseUnverifiedJWTClaims(tokenString)
	if err != nil {
		verification.addIssue("failed to parse attestation token claims", "cryptographic_verification")
		return verification
	}
	issuer := strings.TrimSpace(anyToString(unverifiedClaims["iss"]))
	if !v.isAllowedOIDCIssuer(family, issuer) {
		verification.addIssue("attestation issuer is not allowed for the selected provider", "attester", "cryptographic_verification")
		return verification
	}
	discovery, err := v.fetchOIDCDiscovery(ctx, issuer)
	if err != nil {
		verification.addIssue("failed to discover attestation issuer signing metadata", "cryptographic_verification")
		return verification
	}
	jwks, err := v.fetchJWKS(ctx, discovery.JWKSURI)
	if err != nil {
		verification.addIssue("failed to fetch attestation issuer signing keys", "cryptographic_verification")
		return verification
	}

	claims := jwt.MapClaims{}
	parserOptions := []jwt.ParserOption{
		jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithIssuer(issuer),
		jwt.WithLeeway(time.Minute),
	}
	if audience := strings.TrimSpace(in.Audience); audience != "" {
		parserOptions = append(parserOptions, jwt.WithAudience(audience))
	}
	parser := jwt.NewParser(parserOptions...)
	var selectedKID string
	token, err := parser.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		selectedKID = strings.TrimSpace(anyToString(token.Header["kid"]))
		key, keyErr := jwks.lookupRSAPublicKey(selectedKID)
		if keyErr != nil {
			return nil, keyErr
		}
		return key, nil
	})
	if err != nil || token == nil || !token.Valid {
		verification.addIssue("attestation token signature or registered claims validation failed", "cryptographic_verification")
		if strings.TrimSpace(in.Audience) != "" {
			verification.MissingAttributes = append(verification.MissingAttributes, "audience")
		}
		return verification
	}

	verification.CryptographicallyVerified = true
	verification.VerificationIssuer = issuer
	verification.VerificationKeyID = selectedKID
	verification.Attester = issuer

	flatClaims := flattenClaimsMap(map[string]any(claims))
	for key, value := range flatClaims {
		verification.Claims[key] = value
	}
	verification.WorkloadIdentity = deriveWorkloadIdentity(flatClaims)
	verification.ImageRef = deriveImageRef(flatClaims)
	verification.ImageDigest = deriveImageDigest(flatClaims)
	verification.Audience = deriveAudience(flatClaims)
	verification.Nonce = firstNonEmpty(flatClaims["nonce"], flatClaims["eat_nonce"])
	if verification.Nonce == "" && strings.TrimSpace(in.Nonce) != "" {
		verification.addIssue("attestation token is missing the expected nonce binding", "nonce")
	}
	if verification.Nonce != "" && strings.TrimSpace(in.Nonce) != "" && !strings.EqualFold(verification.Nonce, strings.TrimSpace(in.Nonce)) {
		verification.addIssue("attestation token nonce does not match the expected request nonce", "nonce")
	}

	if ts := deriveEvidenceTime(flatClaims); !ts.IsZero() {
		verification.HasEvidenceTime = true
		verification.EvidenceIssuedAt = ts
	}
	if secure, ok := deriveSecureBoot(flatClaims); ok {
		verification.HasSecureBoot = true
		verification.SecureBoot = secure
	}
	if debugDisabled, ok := deriveDebugDisabled(flatClaims); ok {
		verification.HasDebugDisabled = true
		verification.DebugDisabled = debugDisabled
	}
	if clusterNode := deriveClusterNodeID(flatClaims); clusterNode != "" {
		verification.ClusterNodeID = clusterNode
		if expected := strings.TrimSpace(in.ClusterNodeID); expected != "" && !strings.EqualFold(clusterNode, expected) {
			verification.addIssue("provider attestation cluster node does not match the requested cluster node", "cluster_node")
		}
	}
	verification.Measurements = deriveMeasurements(flatClaims)
	return verification
}

type coseSign1Envelope struct {
	Protected   []byte
	Unprotected map[any]any
	Payload     []byte
	Signature   []byte
}

type awsNitroDocument struct {
	ModuleID    string
	Digest      string
	Timestamp   time.Time
	PCRs        map[string]string
	Certificate []byte
	CABundle    [][]byte
	UserData    []byte
	Nonce       string
}

func extractAWSAttestationBytes(raw string) ([]byte, string, error) {
	value := extractDocumentString(raw, "attestation_document", "document", "token", "evidence")
	if value == "" {
		return nil, "", errors.New("empty document")
	}
	decoded, err := decodeBase64Any(value)
	if err != nil {
		return nil, "", err
	}
	return decoded, "cose_sign1", nil
}

func extractJWTAttestationToken(raw string) (string, string, error) {
	value := extractDocumentString(raw, "token", "jwt", "attestation_token", "attestation_document", "document")
	if value == "" {
		return "", "", errors.New("empty document")
	}
	if strings.Count(value, ".") != 2 {
		return "", "", errors.New("expected compact JWT")
	}
	return value, "jwt", nil
}

func extractDocumentString(raw string, keys ...string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	var payload map[string]any
	if json.Unmarshal([]byte(raw), &payload) == nil {
		for _, key := range keys {
			if value := strings.TrimSpace(anyToString(payload[key])); value != "" {
				return value
			}
		}
	}
	return raw
}

func parseCOSESign1(raw []byte) (coseSign1Envelope, error) {
	var items []any
	if err := cbor.Unmarshal(raw, &items); err != nil {
		return coseSign1Envelope{}, err
	}
	if len(items) != 4 {
		return coseSign1Envelope{}, errors.New("cose sign1 envelope must have 4 items")
	}
	protected, ok := items[0].([]byte)
	if !ok {
		return coseSign1Envelope{}, errors.New("cose protected header is invalid")
	}
	unprotected, _ := items[1].(map[any]any)
	payload, ok := items[2].([]byte)
	if !ok {
		return coseSign1Envelope{}, errors.New("cose payload is invalid")
	}
	signature, ok := items[3].([]byte)
	if !ok {
		return coseSign1Envelope{}, errors.New("cose signature is invalid")
	}
	return coseSign1Envelope{
		Protected:   protected,
		Unprotected: unprotected,
		Payload:     payload,
		Signature:   signature,
	}, nil
}

func (v *ProviderVerifier) verifyAWSNitroSign1(sign1 coseSign1Envelope) (awsNitroDocument, *x509.Certificate, string, error) {
	doc, err := parseAWSNitroDocument(sign1.Payload)
	if err != nil {
		return awsNitroDocument{}, nil, "", err
	}
	leaf, err := x509.ParseCertificate(doc.Certificate)
	if err != nil {
		return awsNitroDocument{}, nil, "", fmt.Errorf("failed to parse AWS attestation signing certificate")
	}
	intermediates := x509.NewCertPool()
	for _, der := range doc.CABundle {
		if cert, certErr := x509.ParseCertificate(der); certErr == nil {
			intermediates.AddCert(cert)
		}
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         v.awsRootCerts,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return awsNitroDocument{}, nil, "", fmt.Errorf("aws attestation certificate chain verification failed")
	}
	if err := verifyCOSESignature(sign1, leaf.PublicKey); err != nil {
		return awsNitroDocument{}, nil, "", fmt.Errorf("aws attestation signature verification failed")
	}
	return doc, leaf, strings.ToLower(strings.TrimSpace(leaf.SerialNumber.Text(16))), nil
}

func parseAWSNitroDocument(payload []byte) (awsNitroDocument, error) {
	var raw map[any]any
	if err := cbor.Unmarshal(payload, &raw); err != nil {
		return awsNitroDocument{}, err
	}
	document := awsNitroDocument{
		ModuleID: strings.TrimSpace(anyToString(raw["module_id"])),
		Digest:   strings.TrimSpace(anyToString(raw["digest"])),
		PCRs:     map[string]string{},
	}
	if ts, ok := anyToUnixMillis(raw["timestamp"]); ok {
		document.Timestamp = time.UnixMilli(ts).UTC()
	}
	document.Certificate, _ = raw["certificate"].([]byte)
	if nonceBytes, ok := raw["nonce"].([]byte); ok {
		document.Nonce = bytesToStableString(nonceBytes)
	}
	if userData, ok := raw["user_data"].([]byte); ok {
		document.UserData = userData
	}
	if pcrs, ok := raw["pcrs"].(map[any]any); ok {
		for key, value := range pcrs {
			label := strings.ToLower(strings.TrimSpace(anyToString(key)))
			if label == "" {
				continue
			}
			if !strings.HasPrefix(label, "pcr") {
				label = "pcr" + label
			}
			if bytesValue, ok := value.([]byte); ok {
				document.PCRs[label] = hex.EncodeToString(bytesValue)
			}
		}
	}
	if bundle, ok := raw["cabundle"].([]any); ok {
		for _, item := range bundle {
			if certDER, derOK := item.([]byte); derOK && len(certDER) > 0 {
				document.CABundle = append(document.CABundle, certDER)
			}
		}
	}
	if len(document.Certificate) == 0 {
		return awsNitroDocument{}, errors.New("aws attestation document does not contain a signing certificate")
	}
	return document, nil
}

func verifyCOSESignature(sign1 coseSign1Envelope, publicKey any) error {
	alg, err := coseAlgorithm(sign1.Protected)
	if err != nil {
		return err
	}
	sigStructure, err := cbor.Marshal([]any{"Signature1", sign1.Protected, []byte{}, sign1.Payload})
	if err != nil {
		return err
	}

	switch alg {
	case -7:
		sum := sha256.Sum256(sigStructure)
		return verifyECDSACOSESignature(sum[:], sign1.Signature, publicKey, 32)
	case -35:
		sum := sha512.Sum384(sigStructure)
		return verifyECDSACOSESignature(sum[:], sign1.Signature, publicKey, 48)
	case -36:
		sum := sha512.Sum512(sigStructure)
		return verifyECDSACOSESignature(sum[:], sign1.Signature, publicKey, 66)
	default:
		return fmt.Errorf("unsupported cose algorithm %d", alg)
	}
}

func coseAlgorithm(protected []byte) (int64, error) {
	headers := map[int64]any{}
	if err := cbor.Unmarshal(protected, &headers); err != nil {
		return 0, err
	}
	switch value := headers[1].(type) {
	case int64:
		return value, nil
	case uint64:
		return int64(value), nil
	case int:
		return int64(value), nil
	default:
		return 0, errors.New("missing cose algorithm header")
	}
}

func verifyECDSACOSESignature(digest []byte, signature []byte, publicKey any, partSize int) error {
	key, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return errors.New("attestation signing key is not ECDSA")
	}
	if len(signature) != partSize*2 {
		return errors.New("cose ecdsa signature has an unexpected length")
	}
	r := new(big.Int).SetBytes(signature[:partSize])
	s := new(big.Int).SetBytes(signature[partSize:])
	if !ecdsa.Verify(key, digest, r, s) {
		return errors.New("ecdsa signature verification failed")
	}
	switch key.Curve {
	case elliptic.P256(), elliptic.P384(), elliptic.P521():
		return nil
	default:
		return errors.New("unsupported ecdsa curve")
	}
}

type boundEvidence struct {
	Claims           map[string]string
	Measurements     map[string]string
	WorkloadIdentity string
	Attester         string
	ImageRef         string
	ImageDigest      string
	Audience         string
	ClusterNodeID    string
}

func parseBoundEvidenceJSON(raw []byte) boundEvidence {
	value := strings.TrimSpace(bytesToStableString(raw))
	if value == "" {
		return boundEvidence{
			Claims:       map[string]string{},
			Measurements: map[string]string{},
		}
	}
	var payload map[string]any
	if json.Unmarshal([]byte(value), &payload) != nil {
		return boundEvidence{
			Claims:       map[string]string{"user_data": value},
			Measurements: map[string]string{},
		}
	}
	out := boundEvidence{
		Claims:       map[string]string{},
		Measurements: map[string]string{},
	}
	if claims, ok := payload["claims"].(map[string]any); ok {
		for key, item := range flattenClaimsMap(claims) {
			out.Claims[key] = item
		}
	}
	if measures, ok := payload["measurements"].(map[string]any); ok {
		for key, item := range flattenClaimsMap(measures) {
			out.Measurements[key] = item
		}
	}
	flat := flattenClaimsMap(payload)
	for key, item := range flat {
		if key == "claims" || strings.HasPrefix(key, "claims.") || key == "measurements" || strings.HasPrefix(key, "measurements.") {
			continue
		}
		out.Claims[key] = item
	}
	out.WorkloadIdentity = firstNonEmpty(flat["workload_identity"], flat["subject"], flat["spiffe_id"], flat["sub"])
	out.Attester = firstNonEmpty(flat["attester"], flat["issuer"])
	out.ImageRef = firstNonEmpty(flat["image_ref"], flat["image_reference"], flat["container_image_reference"])
	out.ImageDigest = firstNonEmpty(flat["image_digest"], flat["container_image_digest"])
	out.Audience = firstNonEmpty(flat["audience"], flat["aud"])
	out.ClusterNodeID = firstNonEmpty(flat["cluster_node_id"], flat["node_id"])
	return out
}

func (v *ProviderVerifier) fetchOIDCDiscovery(ctx context.Context, issuer string) (oidcDiscoveryDocument, error) {
	cacheKey := strings.TrimRight(strings.TrimSpace(issuer), "/")
	v.mu.Lock()
	if cached, ok := v.oidcCache[cacheKey]; ok && cached.ExpiresAt.After(time.Now()) {
		v.mu.Unlock()
		return cached.Value, nil
	}
	v.mu.Unlock()

	issuerURL, err := url.Parse(cacheKey)
	if err != nil || issuerURL.Scheme != "https" || issuerURL.Host == "" {
		return oidcDiscoveryDocument{}, errors.New("invalid attestation issuer")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cacheKey+"/.well-known/openid-configuration", nil)
	if err != nil {
		return oidcDiscoveryDocument{}, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := v.client.Do(req)
	if err != nil {
		return oidcDiscoveryDocument{}, err
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return oidcDiscoveryDocument{}, errors.New("oidc discovery request failed")
	}
	discovery := oidcDiscoveryDocument{}
	if err := json.NewDecoder(resp.Body).Decode(&discovery); err != nil {
		return oidcDiscoveryDocument{}, err
	}
	if strings.TrimRight(strings.TrimSpace(discovery.Issuer), "/") != cacheKey {
		return oidcDiscoveryDocument{}, errors.New("oidc discovery issuer mismatch")
	}
	if strings.TrimSpace(discovery.JWKSURI) == "" {
		return oidcDiscoveryDocument{}, errors.New("oidc discovery missing jwks_uri")
	}
	v.mu.Lock()
	v.oidcCache[cacheKey] = cachedOIDCDiscovery{Value: discovery, ExpiresAt: time.Now().Add(30 * time.Minute)}
	v.mu.Unlock()
	return discovery, nil
}

func (v *ProviderVerifier) fetchJWKS(ctx context.Context, rawURL string) (jwkSet, error) {
	cacheKey := strings.TrimSpace(rawURL)
	v.mu.Lock()
	if cached, ok := v.jwksCache[cacheKey]; ok && cached.ExpiresAt.After(time.Now()) {
		v.mu.Unlock()
		return cached.Value, nil
	}
	v.mu.Unlock()

	parsed, err := url.Parse(cacheKey)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return jwkSet{}, errors.New("invalid jwks_uri")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cacheKey, nil)
	if err != nil {
		return jwkSet{}, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := v.client.Do(req)
	if err != nil {
		return jwkSet{}, err
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return jwkSet{}, errors.New("jwks request failed")
	}
	set := jwkSet{}
	if err := json.NewDecoder(resp.Body).Decode(&set); err != nil {
		return jwkSet{}, err
	}
	v.mu.Lock()
	v.jwksCache[cacheKey] = cachedJWKS{Value: set, ExpiresAt: time.Now().Add(30 * time.Minute)}
	v.mu.Unlock()
	return set, nil
}

func (j jwkSet) lookupRSAPublicKey(kid string) (*rsa.PublicKey, error) {
	if len(j.Keys) == 0 {
		return nil, errors.New("jwks does not contain any signing keys")
	}
	trimmedKID := strings.TrimSpace(kid)
	for _, key := range j.Keys {
		if trimmedKID != "" && strings.TrimSpace(key.Kid) != trimmedKID {
			continue
		}
		pub, err := key.rsaPublicKey()
		if err == nil {
			return pub, nil
		}
	}
	if trimmedKID == "" && len(j.Keys) == 1 {
		return j.Keys[0].rsaPublicKey()
	}
	return nil, errors.New("signing key not found in jwks")
}

func (j jwkKey) rsaPublicKey() (*rsa.PublicKey, error) {
	if strings.TrimSpace(j.Kty) != "RSA" {
		return nil, errors.New("unsupported jwk key type")
	}
	if len(j.X5c) > 0 {
		der, err := base64.StdEncoding.DecodeString(strings.TrimSpace(j.X5c[0]))
		if err == nil {
			cert, certErr := x509.ParseCertificate(der)
			if certErr == nil {
				if key, ok := cert.PublicKey.(*rsa.PublicKey); ok {
					return key, nil
				}
			}
		}
	}
	modulusBytes, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(j.N))
	if err != nil {
		return nil, err
	}
	exponentBytes, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(j.E))
	if err != nil {
		return nil, err
	}
	exponent := 0
	for _, value := range exponentBytes {
		exponent = exponent<<8 + int(value)
	}
	if exponent <= 0 {
		return nil, errors.New("invalid rsa exponent")
	}
	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(modulusBytes),
		E: exponent,
	}, nil
}

func (v *ProviderVerifier) isAllowedOIDCIssuer(family string, issuer string) bool {
	issuer = strings.TrimRight(strings.TrimSpace(issuer), "/")
	if issuer == "" {
		return false
	}
	parsed, err := url.Parse(issuer)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return false
	}
	switch family {
	case "azure":
		host := strings.ToLower(parsed.Hostname())
		for _, allowed := range v.azureAllowedHosts {
			allowed = strings.ToLower(strings.TrimSpace(allowed))
			if allowed == "" {
				continue
			}
			if host == allowed || strings.HasSuffix(host, "."+allowed) {
				return true
			}
		}
		return false
	case "gcp":
		for _, allowed := range v.gcpAllowedIssuers {
			if strings.EqualFold(strings.TrimRight(strings.TrimSpace(allowed), "/"), issuer) {
				return true
			}
		}
		return false
	default:
		return false
	}
}

func parseUnverifiedJWTClaims(tokenString string) (map[string]any, error) {
	parser := jwt.NewParser()
	claims := jwt.MapClaims{}
	_, _, err := parser.ParseUnverified(tokenString, claims)
	if err != nil {
		return nil, err
	}
	return claims, nil
}

func flattenClaimsMap(values map[string]any) map[string]string {
	out := map[string]string{}
	var visit func(prefix string, value any)
	visit = func(prefix string, value any) {
		key := strings.ToLower(strings.TrimSpace(prefix))
		switch item := value.(type) {
		case map[string]any:
			if key != "" {
				out[key] = compactJSON(item)
			}
			keys := make([]string, 0, len(item))
			for child := range item {
				keys = append(keys, child)
			}
			sort.Strings(keys)
			for _, child := range keys {
				next := strings.TrimSpace(child)
				if key != "" {
					next = key + "." + strings.ToLower(next)
				} else {
					next = strings.ToLower(next)
				}
				visit(next, item[child])
			}
		case []any:
			if key != "" {
				out[key] = compactJSON(item)
			}
			allScalar := true
			scalars := make([]string, 0, len(item))
			for _, child := range item {
				switch child.(type) {
				case string, bool, json.Number, float64, float32, int, int64, int32, uint64, uint32, uint, nil:
					scalars = append(scalars, anyToString(child))
				default:
					allScalar = false
				}
			}
			if allScalar && key != "" {
				out[key] = strings.Join(scalars, ",")
			}
			for index, child := range item {
				visit(fmt.Sprintf("%s[%d]", key, index), child)
			}
		default:
			if key != "" {
				out[key] = anyToString(item)
			}
		}
	}
	visit("", values)
	normalized := map[string]string{}
	for key, value := range out {
		k := strings.ToLower(strings.TrimSpace(key))
		v := strings.TrimSpace(value)
		if k == "" || v == "" {
			continue
		}
		normalized[k] = v
	}
	return normalized
}

func deriveMeasurements(claims map[string]string) map[string]string {
	measurements := map[string]string{}
	for key, value := range claims {
		switch measurementLabel(key) {
		case "":
		default:
			measurements[measurementLabel(key)] = value
		}
	}
	return measurements
}

func measurementLabel(key string) string {
	key = strings.ToLower(strings.TrimSpace(key))
	switch {
	case key == "":
		return ""
	case strings.Contains(key, "pcr"):
		if idx := strings.Index(key, "pcr"); idx >= 0 {
			label := key[idx:]
			label = strings.FieldsFunc(label, func(r rune) bool { return !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9') })[0]
			return label
		}
	case strings.Contains(key, "mrenclave"):
		return "mrenclave"
	case strings.Contains(key, "mrsigner"):
		return "mrsigner"
	case strings.Contains(key, "launchmeasurement"):
		return "launchmeasurement"
	case strings.HasSuffix(key, "hostdata") || key == "hostdata":
		return "hostdata"
	}
	return ""
}

func deriveWorkloadIdentity(claims map[string]string) string {
	return firstNonEmpty(
		claims["workload_identity"],
		claims["submods.workload.identity"],
		claims["submods.container.subject"],
		claims["submods.container.service_account"],
		claims["google_service_accounts[0]"],
		claims["google_service_accounts"],
		claims["sub"],
	)
}

func deriveImageRef(claims map[string]string) string {
	return firstNonEmpty(
		claims["image_ref"],
		claims["image_reference"],
		claims["container_image_reference"],
		claims["submods.container.image_reference"],
		claims["swname"],
	)
}

func deriveImageDigest(claims map[string]string) string {
	return firstNonEmpty(
		claims["image_digest"],
		claims["container_image_digest"],
		claims["submods.container.image_digest"],
		claims["hostdata"],
	)
}

func deriveAudience(claims map[string]string) string {
	return firstNonEmpty(claims["aud"], claims["aud[0]"])
}

func deriveClusterNodeID(claims map[string]string) string {
	return firstNonEmpty(claims["cluster_node_id"], claims["node_id"], claims["submods.gce.instance_name"], claims["submods.gce.node_name"])
}

func deriveEvidenceTime(claims map[string]string) time.Time {
	for _, key := range []string{"iat", "nbf"} {
		if ts, ok := numericStringUnixTime(claims[key]); ok {
			return ts
		}
	}
	return time.Time{}
}

func deriveSecureBoot(claims map[string]string) (bool, bool) {
	for _, key := range []string{"secure_boot", "secureboot", "secboot", "x-ms-secureboot"} {
		if raw := strings.TrimSpace(claims[key]); raw != "" {
			if parsed, ok := parseBoolish(raw); ok {
				return parsed, true
			}
		}
	}
	return false, false
}

func deriveDebugDisabled(claims map[string]string) (bool, bool) {
	for _, key := range []string{"debug_disabled", "debugdisabled"} {
		if raw := strings.TrimSpace(claims[key]); raw != "" {
			if parsed, ok := parseBoolish(raw); ok {
				return parsed, true
			}
		}
	}
	for _, key := range []string{"x-ms-sgx-is-debuggable", "is-debuggable"} {
		if raw := strings.TrimSpace(claims[key]); raw != "" {
			if parsed, ok := parseBoolish(raw); ok {
				return !parsed, true
			}
		}
	}
	if raw := strings.ToLower(strings.TrimSpace(firstNonEmpty(claims["dbgstat"], claims["debug_state"]))); raw != "" {
		switch {
		case strings.Contains(raw, "disable"), strings.Contains(raw, "off"), raw == "false", raw == "0":
			return true, true
		case strings.Contains(raw, "enable"), strings.Contains(raw, "debug"), raw == "true", raw == "1":
			return false, true
		}
	}
	return false, false
}

func parseBoolish(raw string) (bool, bool) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "true", "1", "yes", "on", "enabled":
		return true, true
	case "false", "0", "no", "off", "disabled":
		return false, true
	default:
		return false, false
	}
}

func numericStringUnixTime(raw string) (time.Time, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}, false
	}
	if strings.Contains(raw, ".") {
		if value, err := strconv.ParseFloat(raw, 64); err == nil {
			return time.Unix(int64(value), 0).UTC(), true
		}
	}
	if value, err := strconv.ParseInt(raw, 10, 64); err == nil {
		return time.Unix(value, 0).UTC(), true
	}
	return parseTimeString(raw), !parseTimeString(raw).IsZero()
}

func anyToUnixMillis(v any) (int64, bool) {
	switch value := v.(type) {
	case uint64:
		return int64(value), true
	case uint32:
		return int64(value), true
	case int64:
		return value, true
	case int:
		return int64(value), true
	case float64:
		return int64(value), true
	case json.Number:
		if parsed, err := value.Int64(); err == nil {
			return parsed, true
		}
	case string:
		if parsed, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64); err == nil {
			return parsed, true
		}
	}
	return 0, false
}

func anyToString(v any) string {
	switch value := v.(type) {
	case nil:
		return ""
	case string:
		return value
	case []byte:
		return bytesToStableString(value)
	case bool:
		if value {
			return "true"
		}
		return "false"
	case float64:
		if value == float64(int64(value)) {
			return strconv.FormatInt(int64(value), 10)
		}
		return strconv.FormatFloat(value, 'f', -1, 64)
	case float32:
		if value == float32(int64(value)) {
			return strconv.FormatInt(int64(value), 10)
		}
		return strconv.FormatFloat(float64(value), 'f', -1, 32)
	case int:
		return strconv.Itoa(value)
	case int64:
		return strconv.FormatInt(value, 10)
	case uint64:
		return strconv.FormatUint(value, 10)
	case json.Number:
		return value.String()
	default:
		return compactJSON(value)
	}
}

func compactJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(b)
}

func decodeBase64Any(raw string) ([]byte, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errors.New("empty base64 value")
	}
	for _, encoding := range []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	} {
		if decoded, err := encoding.DecodeString(raw); err == nil {
			return decoded, nil
		}
	}
	return nil, errors.New("invalid base64")
}

func bytesToStableString(raw []byte) string {
	raw = bytesTrimSpace(raw)
	if len(raw) == 0 {
		return ""
	}
	if utf8.Valid(raw) {
		return string(raw)
	}
	return hex.EncodeToString(raw)
}

func bytesTrimSpace(raw []byte) []byte {
	start := 0
	for start < len(raw) && (raw[start] == ' ' || raw[start] == '\n' || raw[start] == '\r' || raw[start] == '\t') {
		start++
	}
	end := len(raw)
	for end > start && (raw[end-1] == ' ' || raw[end-1] == '\n' || raw[end-1] == '\r' || raw[end-1] == '\t') {
		end--
	}
	return raw[start:end]
}
