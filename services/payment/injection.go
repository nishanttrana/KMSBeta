package main

import (
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"strings"
	"time"

	pkgcrypto "vecta-kms/pkg/crypto"
)

const (
	injectionStatusPending   = "pending"
	injectionStatusActive    = "active"
	injectionStatusSuspended = "suspended"

	injectionJobQueued    = "queued"
	injectionJobDelivered = "delivered"
	injectionJobApplied   = "applied"
	injectionJobFailed    = "failed"
)

type injectionPayload struct {
	JobID         string `json:"job_id"`
	TerminalID    string `json:"terminal_id"`
	PaymentKeyID  string `json:"payment_key_id"`
	KeyID         string `json:"key_id"`
	TR31Version   string `json:"tr31_version"`
	TR31UsageCode string `json:"tr31_usage_code"`
	TR31KCV       string `json:"tr31_kcv"`
	TR31KeyBlock  string `json:"tr31_key_block"`
	CreatedAt     string `json:"created_at"`
}

func (s *Service) RegisterInjectionTerminal(ctx context.Context, req RegisterInjectionTerminalRequest) (PaymentInjectionTerminal, error) {
	req.TenantID = strings.TrimSpace(req.TenantID)
	req.TerminalID = strings.TrimSpace(req.TerminalID)
	req.Name = strings.TrimSpace(req.Name)
	req.PublicKeyPEM = strings.TrimSpace(req.PublicKeyPEM)
	if req.TenantID == "" || req.TerminalID == "" || req.Name == "" || req.PublicKeyPEM == "" {
		return PaymentInjectionTerminal{}, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id, terminal_id, name and public_key_pem are required")
	}
	if _, err := s.store.GetInjectionTerminalByTerminalID(ctx, req.TenantID, req.TerminalID); err == nil {
		return PaymentInjectionTerminal{}, newServiceError(http.StatusConflict, "terminal_exists", "terminal_id already exists")
	} else if !errors.Is(err, errNotFound) {
		return PaymentInjectionTerminal{}, err
	}
	pub, keyAlg, fingerprint, err := parseAndFingerprintPublicKey(req.PublicKeyPEM)
	if err != nil {
		return PaymentInjectionTerminal{}, err
	}
	switch pub.(type) {
	case *rsa.PublicKey:
	default:
		return PaymentInjectionTerminal{}, newServiceError(http.StatusBadRequest, "bad_request", "public_key_pem must contain an RSA public key for injection wrapping")
	}
	item := PaymentInjectionTerminal{
		ID:                   newID("pit"),
		TenantID:             req.TenantID,
		TerminalID:           req.TerminalID,
		Name:                 req.Name,
		Status:               injectionStatusPending,
		Transport:            normalizeInjectionTransport(req.Transport),
		KeyAlgorithm:         normalizeInjectionKeyAlgorithm(firstString(req.KeyAlgorithm, keyAlg)),
		PublicKeyPEM:         req.PublicKeyPEM,
		PublicKeyFingerprint: fingerprint,
		MetadataJSON:         validJSONOr(req.MetadataJSON, "{}"),
	}
	if err := s.store.CreateInjectionTerminal(ctx, item); err != nil {
		return PaymentInjectionTerminal{}, err
	}
	_ = s.publishAudit(ctx, "audit.payment.injection_terminal_registered", item.TenantID, map[string]interface{}{
		"terminal_id":            item.TerminalID,
		"name":                   item.Name,
		"public_key_fingerprint": item.PublicKeyFingerprint,
		"transport":              item.Transport,
		"status":                 item.Status,
	})
	out, err := s.store.GetInjectionTerminal(ctx, item.TenantID, item.ID)
	if err != nil {
		return PaymentInjectionTerminal{}, err
	}
	out.PublicKeyPEM = ""
	out.AuthTokenHash = ""
	return out, nil
}

func (s *Service) ListInjectionTerminals(ctx context.Context, tenantID string) ([]PaymentInjectionTerminal, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return nil, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id is required")
	}
	items, err := s.store.ListInjectionTerminals(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	for i := range items {
		items[i].PublicKeyPEM = ""
		items[i].AuthTokenHash = ""
		items[i].RegistrationNonce = ""
	}
	return items, nil
}

func (s *Service) IssueInjectionChallenge(ctx context.Context, tenantID string, terminalRowID string) (string, time.Time, error) {
	tenantID = strings.TrimSpace(tenantID)
	terminalRowID = strings.TrimSpace(terminalRowID)
	if tenantID == "" || terminalRowID == "" {
		return "", time.Time{}, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id and terminal_id are required")
	}
	terminal, err := s.store.GetInjectionTerminal(ctx, tenantID, terminalRowID)
	if err != nil {
		return "", time.Time{}, err
	}
	nonceRaw := make([]byte, 32)
	if _, err := rand.Read(nonceRaw); err != nil {
		return "", time.Time{}, newServiceError(http.StatusInternalServerError, "internal_error", "failed to generate registration challenge")
	}
	defer pkgcrypto.Zeroize(nonceRaw)
	nonce := base64.RawURLEncoding.EncodeToString(nonceRaw)
	expiresAt := time.Now().UTC().Add(5 * time.Minute)
	if err := s.store.UpdateInjectionTerminalChallenge(ctx, tenantID, terminalRowID, nonce, expiresAt); err != nil {
		return "", time.Time{}, err
	}
	_ = s.publishAudit(ctx, "audit.payment.injection_terminal_challenge_issued", tenantID, map[string]interface{}{
		"terminal_id":     terminal.TerminalID,
		"terminal_row_id": terminal.ID,
		"expires_at":      expiresAt.Format(time.RFC3339Nano),
	})
	return nonce, expiresAt, nil
}

func (s *Service) VerifyInjectionChallenge(ctx context.Context, terminalRowID string, req VerifyInjectionChallengeRequest) (VerifyInjectionChallengeResponse, error) {
	req.TenantID = strings.TrimSpace(req.TenantID)
	terminalRowID = strings.TrimSpace(terminalRowID)
	if req.TenantID == "" || terminalRowID == "" || strings.TrimSpace(req.SignatureB64) == "" {
		return VerifyInjectionChallengeResponse{}, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id, terminal_id and signature_b64 are required")
	}
	terminal, err := s.store.GetInjectionTerminal(ctx, req.TenantID, terminalRowID)
	if err != nil {
		return VerifyInjectionChallengeResponse{}, err
	}
	if strings.TrimSpace(terminal.RegistrationNonce) == "" || terminal.RegistrationNonceExpiresAt.IsZero() {
		return VerifyInjectionChallengeResponse{}, newServiceError(http.StatusBadRequest, "challenge_missing", "registration challenge was not issued")
	}
	if time.Now().UTC().After(terminal.RegistrationNonceExpiresAt.UTC()) {
		return VerifyInjectionChallengeResponse{}, newServiceError(http.StatusBadRequest, "challenge_expired", "registration challenge has expired")
	}
	signature, err := base64.StdEncoding.DecodeString(strings.TrimSpace(req.SignatureB64))
	if err != nil {
		signature, err = base64.RawURLEncoding.DecodeString(strings.TrimSpace(req.SignatureB64))
		if err != nil {
			return VerifyInjectionChallengeResponse{}, newServiceError(http.StatusBadRequest, "bad_request", "signature_b64 must be base64")
		}
	}
	defer pkgcrypto.Zeroize(signature)
	pub, _, _, err := parseAndFingerprintPublicKey(terminal.PublicKeyPEM)
	if err != nil {
		return VerifyInjectionChallengeResponse{}, err
	}
	if !verifyChallengeSignature(pub, []byte(terminal.RegistrationNonce), signature) {
		return VerifyInjectionChallengeResponse{}, newServiceError(http.StatusUnauthorized, "invalid_signature", "challenge signature verification failed")
	}
	tokenRaw := make([]byte, 32)
	if _, err := rand.Read(tokenRaw); err != nil {
		return VerifyInjectionChallengeResponse{}, newServiceError(http.StatusInternalServerError, "internal_error", "failed to generate terminal token")
	}
	defer pkgcrypto.Zeroize(tokenRaw)
	authToken := base64.RawURLEncoding.EncodeToString(tokenRaw)
	authTokenHash := tokenHash(authToken)
	now := time.Now().UTC()
	if err := s.store.MarkInjectionTerminalVerified(ctx, req.TenantID, terminalRowID, now, authTokenHash, now); err != nil {
		return VerifyInjectionChallengeResponse{}, err
	}
	out, err := s.store.GetInjectionTerminal(ctx, req.TenantID, terminalRowID)
	if err != nil {
		return VerifyInjectionChallengeResponse{}, err
	}
	_ = s.publishAudit(ctx, "audit.payment.injection_terminal_verified", req.TenantID, map[string]interface{}{
		"terminal_id":     out.TerminalID,
		"terminal_row_id": out.ID,
	})
	out.PublicKeyPEM = ""
	out.AuthTokenHash = ""
	out.RegistrationNonce = ""
	return VerifyInjectionChallengeResponse{
		Terminal:  out,
		AuthToken: authToken,
		TokenType: "terminal-bearer",
	}, nil
}

func (s *Service) CreateInjectionJob(ctx context.Context, req CreateInjectionJobRequest) (PaymentInjectionJob, error) {
	req.TenantID = strings.TrimSpace(req.TenantID)
	req.TerminalID = strings.TrimSpace(req.TerminalID)
	req.PaymentKeyID = strings.TrimSpace(req.PaymentKeyID)
	if req.TenantID == "" || req.TerminalID == "" || req.PaymentKeyID == "" {
		return PaymentInjectionJob{}, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id, terminal_id and payment_key_id are required")
	}
	terminal, err := s.store.GetInjectionTerminal(ctx, req.TenantID, req.TerminalID)
	if err != nil {
		return PaymentInjectionJob{}, err
	}
	if !strings.EqualFold(terminal.Status, injectionStatusActive) {
		return PaymentInjectionJob{}, newServiceError(http.StatusConflict, "terminal_not_active", "terminal is not verified/active")
	}
	paymentKey, err := s.store.GetPaymentKey(ctx, req.TenantID, req.PaymentKeyID)
	if err != nil {
		return PaymentInjectionJob{}, err
	}
	algo := "AES"
	if s.keycore != nil {
		if keyMeta, err := s.keycore.GetKey(ctx, req.TenantID, paymentKey.KeyID); err == nil {
			rawAlg := strings.ToUpper(firstString(keyMeta["algorithm"], keyMeta["algorithm_family"]))
			switch {
			case strings.Contains(rawAlg, "AES"):
				algo = "AES"
			case strings.Contains(rawAlg, "TDES"), strings.Contains(rawAlg, "3DES"), strings.Contains(rawAlg, "DES"):
				algo = "TDES"
			}
		}
	}
	tr31Out, err := s.CreateTR31(ctx, CreateTR31Request{
		TenantID:      req.TenantID,
		KeyID:         paymentKey.KeyID,
		TR31Version:   strings.TrimSpace(req.TR31Version),
		Algorithm:     algo,
		UsageCode:     paymentKey.UsageCode,
		ModeOfUse:     paymentKey.ModeOfUse,
		KeyVersionNum: paymentKey.KeyVersionNum,
		Exportability: paymentKey.Exportability,
		KBPKKeyID:     strings.TrimSpace(req.KBPKKeyID),
		KBPKKeyB64:    strings.TrimSpace(req.KBPKKeyB64),
		KEKKeyID:      strings.TrimSpace(req.KEKKeyID),
		KEKKeyB64:     strings.TrimSpace(req.KEKKeyB64),
		SourceFormat:  TR31FormatD,
	})
	if err != nil {
		return PaymentInjectionJob{}, err
	}
	payload := injectionPayload{
		JobID:         newID("pij"),
		TerminalID:    terminal.TerminalID,
		PaymentKeyID:  paymentKey.ID,
		KeyID:         paymentKey.KeyID,
		TR31Version:   tr31Out.Version,
		TR31UsageCode: tr31Out.UsageCode,
		TR31KCV:       tr31Out.KCV,
		TR31KeyBlock:  tr31Out.KeyBlock,
		CreatedAt:     time.Now().UTC().Format(time.RFC3339Nano),
	}
	payloadRaw, _ := json.Marshal(payload)
	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		return PaymentInjectionJob{}, newServiceError(http.StatusInternalServerError, "internal_error", "failed to generate DEK")
	}
	defer pkgcrypto.Zeroize(dek)
	block, err := aes.NewCipher(dek)
	if err != nil {
		return PaymentInjectionJob{}, newServiceError(http.StatusInternalServerError, "internal_error", err.Error())
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return PaymentInjectionJob{}, newServiceError(http.StatusInternalServerError, "internal_error", err.Error())
	}
	iv := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(iv); err != nil {
		return PaymentInjectionJob{}, newServiceError(http.StatusInternalServerError, "internal_error", "failed to generate IV")
	}
	defer pkgcrypto.Zeroize(iv)
	ciphertext := gcm.Seal(nil, iv, payloadRaw, []byte("vecta-payment-injection"))
	pub, _, _, err := parseAndFingerprintPublicKey(terminal.PublicKeyPEM)
	if err != nil {
		return PaymentInjectionJob{}, err
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return PaymentInjectionJob{}, newServiceError(http.StatusBadRequest, "unsupported_key", "terminal public key must be RSA for injection wrapping")
	}
	wrappedDEK, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, rsaPub, dek, []byte("vecta-payment-injection-dek"))
	if err != nil {
		return PaymentInjectionJob{}, newServiceError(http.StatusInternalServerError, "internal_error", "failed to wrap DEK with terminal public key")
	}
	defer pkgcrypto.Zeroize(wrappedDEK)
	now := time.Now().UTC()
	item := PaymentInjectionJob{
		ID:                   payload.JobID,
		TenantID:             req.TenantID,
		TerminalID:           terminal.ID,
		PaymentKeyID:         paymentKey.ID,
		KeyID:                paymentKey.KeyID,
		TR31Version:          tr31Out.Version,
		TR31UsageCode:        tr31Out.UsageCode,
		TR31KCV:              tr31Out.KCV,
		TR31KeyBlock:         tr31Out.KeyBlock,
		PayloadCiphertextB64: base64.StdEncoding.EncodeToString(ciphertext),
		PayloadIVB64:         base64.StdEncoding.EncodeToString(iv),
		WrappedDEKB64:        base64.StdEncoding.EncodeToString(wrappedDEK),
		DEKWrapAlg:           "RSA-OAEP-SHA256",
		Status:               injectionJobQueued,
		CreatedAt:            now,
		UpdatedAt:            now,
	}
	if err := s.store.CreateInjectionJob(ctx, item); err != nil {
		return PaymentInjectionJob{}, err
	}
	_ = s.publishAudit(ctx, "audit.payment.injection_job_created", req.TenantID, map[string]interface{}{
		"job_id":         item.ID,
		"terminal_id":    terminal.TerminalID,
		"payment_key_id": item.PaymentKeyID,
		"key_id":         item.KeyID,
		"tr31_version":   item.TR31Version,
		"tr31_usage":     item.TR31UsageCode,
	})
	return s.store.GetInjectionJob(ctx, req.TenantID, item.ID)
}

func (s *Service) ListInjectionJobs(ctx context.Context, tenantID string, terminalID string) ([]PaymentInjectionJob, error) {
	tenantID = strings.TrimSpace(tenantID)
	terminalID = strings.TrimSpace(terminalID)
	if tenantID == "" {
		return nil, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id is required")
	}
	if terminalID != "" {
		return s.store.ListInjectionJobsByTerminal(ctx, tenantID, terminalID)
	}
	return s.store.ListInjectionJobs(ctx, tenantID)
}

func (s *Service) PullNextInjectionJob(ctx context.Context, tenantID string, terminalRowID string, authToken string) (PaymentInjectionJob, error) {
	terminal, err := s.verifyInjectionTerminalAuth(ctx, tenantID, terminalRowID, authToken)
	if err != nil {
		return PaymentInjectionJob{}, err
	}
	job, err := s.store.GetNextQueuedInjectionJob(ctx, tenantID, terminal.ID)
	if err != nil {
		return PaymentInjectionJob{}, err
	}
	now := time.Now().UTC()
	if err := s.store.MarkInjectionJobDelivered(ctx, tenantID, job.ID, now); err != nil {
		return PaymentInjectionJob{}, err
	}
	_ = s.store.UpdateInjectionTerminalLastSeen(ctx, tenantID, terminal.ID, now)
	out, err := s.store.GetInjectionJob(ctx, tenantID, job.ID)
	if err != nil {
		return PaymentInjectionJob{}, err
	}
	_ = s.publishAudit(ctx, "audit.payment.injection_job_delivered", tenantID, map[string]interface{}{
		"job_id":      out.ID,
		"terminal_id": terminal.TerminalID,
	})
	return out, nil
}

func (s *Service) AckInjectionJob(ctx context.Context, jobID string, req AckInjectionJobRequest, authToken string) (PaymentInjectionJob, error) {
	req.TenantID = strings.TrimSpace(req.TenantID)
	req.TerminalID = strings.TrimSpace(req.TerminalID)
	jobID = strings.TrimSpace(jobID)
	if req.TenantID == "" || req.TerminalID == "" || jobID == "" {
		return PaymentInjectionJob{}, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id, terminal_id and job_id are required")
	}
	terminal, err := s.verifyInjectionTerminalAuth(ctx, req.TenantID, req.TerminalID, authToken)
	if err != nil {
		return PaymentInjectionJob{}, err
	}
	job, err := s.store.GetInjectionJob(ctx, req.TenantID, jobID)
	if err != nil {
		return PaymentInjectionJob{}, err
	}
	if job.TerminalID != terminal.ID {
		return PaymentInjectionJob{}, newServiceError(http.StatusForbidden, "forbidden", "job does not belong to terminal")
	}
	status := normalizeInjectionJobAckStatus(req.Status)
	if status == "" {
		return PaymentInjectionJob{}, newServiceError(http.StatusBadRequest, "bad_request", "status must be applied or failed")
	}
	now := time.Now().UTC()
	if err := s.store.MarkInjectionJobAck(ctx, req.TenantID, jobID, status, req.Detail, now); err != nil {
		return PaymentInjectionJob{}, err
	}
	_ = s.store.UpdateInjectionTerminalLastSeen(ctx, req.TenantID, terminal.ID, now)
	out, err := s.store.GetInjectionJob(ctx, req.TenantID, jobID)
	if err != nil {
		return PaymentInjectionJob{}, err
	}
	_ = s.publishAudit(ctx, "audit.payment.injection_job_acked", req.TenantID, map[string]interface{}{
		"job_id":      out.ID,
		"terminal_id": terminal.TerminalID,
		"status":      status,
		"detail":      strings.TrimSpace(req.Detail),
	})
	return out, nil
}

func (s *Service) verifyInjectionTerminalAuth(ctx context.Context, tenantID string, terminalRowID string, authToken string) (PaymentInjectionTerminal, error) {
	tenantID = strings.TrimSpace(tenantID)
	terminalRowID = strings.TrimSpace(terminalRowID)
	authToken = strings.TrimSpace(authToken)
	if tenantID == "" || terminalRowID == "" {
		return PaymentInjectionTerminal{}, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id and terminal_id are required")
	}
	if authToken == "" {
		return PaymentInjectionTerminal{}, newServiceError(http.StatusUnauthorized, "unauthorized", "terminal token is required")
	}
	terminal, err := s.store.GetInjectionTerminal(ctx, tenantID, terminalRowID)
	if err != nil {
		return PaymentInjectionTerminal{}, err
	}
	if !strings.EqualFold(terminal.Status, injectionStatusActive) {
		return PaymentInjectionTerminal{}, newServiceError(http.StatusForbidden, "forbidden", "terminal is not active")
	}
	if strings.TrimSpace(terminal.AuthTokenHash) == "" {
		return PaymentInjectionTerminal{}, newServiceError(http.StatusForbidden, "forbidden", "terminal is not authenticated")
	}
	given := tokenHash(authToken)
	if subtle.ConstantTimeCompare([]byte(given), []byte(strings.TrimSpace(terminal.AuthTokenHash))) != 1 {
		return PaymentInjectionTerminal{}, newServiceError(http.StatusUnauthorized, "unauthorized", "invalid terminal token")
	}
	return terminal, nil
}

func parseAndFingerprintPublicKey(publicPEM string) (crypto.PublicKey, string, string, error) {
	block, _ := pem.Decode([]byte(strings.TrimSpace(publicPEM)))
	if block == nil {
		return nil, "", "", newServiceError(http.StatusBadRequest, "bad_request", "public_key_pem must be valid PEM")
	}
	var pub interface{}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		if cert, certErr := x509.ParseCertificate(block.Bytes); certErr == nil {
			pub = cert.PublicKey
		} else {
			return nil, "", "", newServiceError(http.StatusBadRequest, "bad_request", "public_key_pem must contain a valid public key")
		}
	}
	pubKey := pub.(crypto.PublicKey)
	der, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return nil, "", "", newServiceError(http.StatusBadRequest, "bad_request", "failed to parse public key")
	}
	fp := sha256.Sum256(der)
	fingerprint := strings.ToUpper(hex.EncodeToString(fp[:]))
	return pubKey, publicKeyAlgorithm(pubKey), fingerprint, nil
}

func publicKeyAlgorithm(pub crypto.PublicKey) string {
	switch key := pub.(type) {
	case *rsa.PublicKey:
		return "rsa-oaep-sha256-" + strconvItoa(key.Size()*8)
	case *ecdsa.PublicKey:
		return "ecdsa"
	case ed25519.PublicKey:
		return "ed25519"
	default:
		return "unknown"
	}
}

func verifyChallengeSignature(pub crypto.PublicKey, challenge []byte, signature []byte) bool {
	digest := sha256.Sum256(challenge)
	switch key := pub.(type) {
	case *rsa.PublicKey:
		if rsa.VerifyPSS(key, crypto.SHA256, digest[:], signature, nil) == nil {
			return true
		}
		return rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], signature) == nil
	case *ecdsa.PublicKey:
		return ecdsa.VerifyASN1(key, digest[:], signature)
	case ed25519.PublicKey:
		return ed25519.Verify(key, challenge, signature)
	default:
		return false
	}
}

func tokenHash(token string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(token)))
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}

func normalizeInjectionTransport(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "jwt":
		return "jwt"
	case "mtls":
		return "mtls"
	default:
		return "jwt"
	}
}

func normalizeInjectionKeyAlgorithm(raw string) string {
	v := strings.TrimSpace(raw)
	if v == "" {
		return "rsa-oaep-sha256"
	}
	return strings.ToLower(v)
}

func normalizeInjectionJobAckStatus(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "applied", "success", "ok":
		return injectionJobApplied
	case "failed", "error":
		return injectionJobFailed
	default:
		return ""
	}
}

func strconvItoa(v int) string {
	if v == 0 {
		return "0"
	}
	sign := ""
	if v < 0 {
		sign = "-"
		v = -v
	}
	buf := [20]byte{}
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + (v % 10))
		v /= 10
	}
	return sign + string(buf[i:])
}
