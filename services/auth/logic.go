package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/argon2"

	pkgauth "vecta-kms/pkg/auth"
	pkgcrypto "vecta-kms/pkg/crypto"
)

type AuthLogic struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	issuer     string
	audience   string
	tokenTTL   time.Duration
	limiter    *FailedLoginLimiter
}

func NewAuthLogic(privateKey *rsa.PrivateKey, issuer string, audience string) *AuthLogic {
	return &AuthLogic{
		privateKey: privateKey,
		publicKey:  &privateKey.PublicKey,
		issuer:     issuer,
		audience:   audience,
		tokenTTL:   15 * time.Minute,
		limiter:    NewFailedLoginLimiter(5, 15*time.Minute),
	}
}

func (a *AuthLogic) ParseJWT(token string) (*pkgauth.Claims, error) {
	return pkgauth.ParseRS256WithOptions(token, a.publicKey, pkgauth.ParseOptions{
		Issuer:   a.issuer,
		Audience: a.audience,
		Leeway:   30 * time.Second,
	})
}

func (a *AuthLogic) IssueJWT(tenantID string, role string, permissions []string, userID string, mustChangePassword bool) (string, time.Time, error) {
	expiresAt := time.Now().UTC().Add(a.tokenTTL)
	claims := &pkgauth.Claims{
		TenantID:           tenantID,
		Role:               role,
		Permissions:        permissions,
		UserID:             userID,
		MustChangePassword: mustChangePassword,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    a.issuer,
			Audience:  jwt.ClaimStrings{a.audience},
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
		},
	}
	signed, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(a.privateKey)
	return signed, expiresAt, err
}

func (a *AuthLogic) IssueClientJWT(
	tenantID string,
	clientID string,
	subjectID string,
	interfaceName string,
	permissions []string,
	ttl time.Duration,
	authMode string,
	confirmation *pkgauth.ConfirmationClaims,
	replayProtection bool,
	httpSignatureKeyID string,
) (string, time.Time, error) {
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	if ttl > time.Hour {
		ttl = time.Hour
	}
	now := time.Now().UTC()
	expiresAt := now.Add(ttl)
	claims := &pkgauth.Claims{
		TenantID:                  strings.TrimSpace(tenantID),
		Role:                      "client-service",
		Permissions:               permissions,
		UserID:                    strings.TrimSpace(subjectID),
		ClientID:                  strings.TrimSpace(clientID),
		AuthMode:                  strings.TrimSpace(authMode),
		ReplayProtection:          replayProtection,
		Confirmation:              confirmation,
		HTTPMessageSignatureKeyID: strings.TrimSpace(httpSignatureKeyID),
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   strings.TrimSpace(subjectID),
			Issuer:    a.issuer,
			Audience:  jwt.ClaimStrings{a.audience},
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now.Add(-5 * time.Second)),
			ID:        fmt.Sprintf("%s:%s:%d", strings.TrimSpace(clientID), strings.TrimSpace(interfaceName), now.UnixNano()),
		},
	}
	signed, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(a.privateKey)
	return signed, expiresAt, err
}

func (a *AuthLogic) IssueWorkloadJWT(
	tenantID string,
	clientID string,
	spiffeID string,
	interfaceName string,
	permissions []string,
	allowedKeyIDs []string,
	trustDomain string,
	ttl time.Duration,
) (string, time.Time, error) {
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	if ttl > 15*time.Minute {
		ttl = 15 * time.Minute
	}
	now := time.Now().UTC()
	expiresAt := now.Add(ttl)
	claims := &pkgauth.Claims{
		TenantID:            strings.TrimSpace(tenantID),
		Role:                "workload-service",
		Permissions:         permissions,
		UserID:              strings.TrimSpace(spiffeID),
		ClientID:            strings.TrimSpace(clientID),
		WorkloadIdentity:    strings.TrimSpace(spiffeID),
		WorkloadTrustDomain: strings.TrimSpace(trustDomain),
		AllowedKeyIDs:       dedupeStrings(allowedKeyIDs),
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   strings.TrimSpace(spiffeID),
			Issuer:    a.issuer,
			Audience:  jwt.ClaimStrings{a.audience},
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now.Add(-5 * time.Second)),
			ID:        fmt.Sprintf("wid:%s:%s:%d", strings.TrimSpace(clientID), strings.TrimSpace(interfaceName), now.UnixNano()),
		},
	}
	signed, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(a.privateKey)
	return signed, expiresAt, err
}

func HashPassword(password string) ([]byte, error) {
	pw := []byte(password)
	defer pkgcrypto.Zeroize(pw)

	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	hash := argon2.IDKey(pw, salt, 3, 64*1024, 4, 32)
	enc := fmt.Sprintf("argon2id$v=19$m=65536,t=3,p=4$%s$%s",
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	)
	pkgcrypto.Zeroize(hash)
	return []byte(enc), nil
}

func VerifyPassword(encodedHash []byte, password string) bool {
	parts := strings.Split(string(encodedHash), "$")
	if len(parts) != 5 {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil {
		return false
	}
	expected, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}
	pw := []byte(password)
	defer pkgcrypto.Zeroize(pw)

	computed := argon2.IDKey(pw, salt, 3, 64*1024, 4, uint32(len(expected)))
	defer pkgcrypto.Zeroize(computed)
	return subtle.ConstantTimeCompare(expected, computed) == 1
}

func GenerateTOTPSecret() (string, error) {
	raw := make([]byte, 20)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	defer pkgcrypto.Zeroize(raw)
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw), nil
}

func ValidateTOTP(secret string, code string, now time.Time) bool {
	secret = strings.TrimSpace(secret)
	if secret == "" {
		return false
	}
	decoded, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(secret))
	if err != nil {
		return false
	}
	defer pkgcrypto.Zeroize(decoded)

	for drift := int64(-1); drift <= 1; drift++ {
		if hotpCode(decoded, now.Unix()/30+drift) == code {
			return true
		}
	}
	return false
}

func hotpCode(secret []byte, counter int64) string {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(counter))

	mac := hmac.New(sha1.New, secret)
	_, _ = mac.Write(buf)
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	binCode := (int(sum[offset])&0x7f)<<24 |
		(int(sum[offset+1])&0xff)<<16 |
		(int(sum[offset+2])&0xff)<<8 |
		(int(sum[offset+3]) & 0xff)
	return fmt.Sprintf("%06d", binCode%1000000)
}

func GenerateAPIKey() (raw string, keyHash []byte, prefix string, err error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return "", nil, "", err
	}
	defer pkgcrypto.Zeroize(key)

	raw = "vk_" + base64.RawURLEncoding.EncodeToString(key)
	sum := sha256.Sum256([]byte(raw))
	hash := make([]byte, len(sum))
	copy(hash, sum[:])
	return raw, hash, raw[:min(len(raw), 10)], nil
}

func dedupeStrings(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, item := range values {
		trimmed := strings.TrimSpace(item)
		if trimmed == "" {
			continue
		}
		key := strings.ToLower(trimmed)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, trimmed)
	}
	return out
}

func NewID(prefix string) string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%s_%s", prefix, hex.EncodeToString(b))
}

func IsIPAllowed(ip string, whitelist []string) bool {
	if len(whitelist) == 0 {
		return true
	}
	addr := net.ParseIP(strings.TrimSpace(ip))
	if addr == nil {
		return false
	}
	for _, entry := range whitelist {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if strings.Contains(entry, "/") {
			_, cidr, err := net.ParseCIDR(entry)
			if err == nil && cidr.Contains(addr) {
				return true
			}
			continue
		}
		if net.ParseIP(entry).Equal(addr) {
			return true
		}
	}
	return false
}

type failedRecord struct {
	Count       int
	LockedUntil time.Time
}

type FailedLoginLimiter struct {
	mu         sync.Mutex
	maxFails   int
	lockWindow time.Duration
	state      map[string]failedRecord
}

func NewFailedLoginLimiter(maxFails int, lockWindow time.Duration) *FailedLoginLimiter {
	return &FailedLoginLimiter{
		maxFails:   maxFails,
		lockWindow: lockWindow,
		state:      make(map[string]failedRecord),
	}
}

func (l *FailedLoginLimiter) IsLocked(key string, now time.Time) (time.Time, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	rec, ok := l.state[key]
	if !ok || rec.LockedUntil.IsZero() || now.After(rec.LockedUntil) {
		return time.Time{}, false
	}
	return rec.LockedUntil, true
}

func (l *FailedLoginLimiter) Fail(key string, now time.Time) (time.Time, bool) {
	return l.FailWithPolicy(key, now, l.maxFails, l.lockWindow)
}

func (l *FailedLoginLimiter) FailWithPolicy(key string, now time.Time, maxFails int, lockWindow time.Duration) (time.Time, bool) {
	if maxFails <= 0 {
		maxFails = l.maxFails
	}
	if lockWindow <= 0 {
		lockWindow = l.lockWindow
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	rec := l.state[key]
	rec.Count++
	if rec.Count >= maxFails {
		rec.Count = 0
		rec.LockedUntil = now.Add(lockWindow)
		l.state[key] = rec
		return rec.LockedUntil, true
	}
	l.state[key] = rec
	return time.Time{}, false
}

func (l *FailedLoginLimiter) Reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.state, key)
}

func tokenHash(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	out := make([]byte, len(sum))
	copy(out, sum[:])
	return out
}

func DefaultPasswordPolicy(tenantID string) PasswordPolicy {
	return PasswordPolicy{
		TenantID:       tenantID,
		MinLength:      12,
		MaxLength:      128,
		RequireUpper:   true,
		RequireLower:   true,
		RequireDigit:   true,
		RequireSpecial: true,
		RequireNoSpace: true,
		DenyUsername:   true,
		DenyEmailLocal: true,
		MinUniqueChars: 6,
		UpdatedBy:      "system",
	}
}

func NormalizePasswordPolicy(policy PasswordPolicy, tenantID string) PasswordPolicy {
	out := policy
	def := DefaultPasswordPolicy(tenantID)
	if strings.TrimSpace(out.TenantID) == "" {
		out.TenantID = def.TenantID
	}
	if out.MinLength <= 0 {
		out.MinLength = def.MinLength
	}
	if out.MaxLength <= 0 {
		out.MaxLength = def.MaxLength
	}
	if out.MaxLength < out.MinLength {
		out.MaxLength = out.MinLength
	}
	if out.MinUniqueChars < 0 {
		out.MinUniqueChars = 0
	}
	if out.MinUniqueChars > out.MinLength {
		out.MinUniqueChars = out.MinLength
	}
	return out
}

func DefaultSecurityPolicy(tenantID string) SecurityPolicy {
	return SecurityPolicy{
		TenantID:           tenantID,
		MaxFailedAttempts:  5,
		LockoutMinutes:     15,
		IdleTimeoutMinutes: 15,
		UpdatedBy:          "system",
	}
}

func NormalizeSecurityPolicy(policy SecurityPolicy, tenantID string) SecurityPolicy {
	out := policy
	def := DefaultSecurityPolicy(tenantID)
	if strings.TrimSpace(out.TenantID) == "" {
		out.TenantID = def.TenantID
	}
	if out.MaxFailedAttempts < 3 {
		out.MaxFailedAttempts = 3
	}
	if out.MaxFailedAttempts > 50 {
		out.MaxFailedAttempts = 50
	}
	if out.LockoutMinutes < 1 {
		out.LockoutMinutes = 1
	}
	if out.LockoutMinutes > 1440 {
		out.LockoutMinutes = 1440
	}
	if out.IdleTimeoutMinutes < 1 {
		out.IdleTimeoutMinutes = 1
	}
	if out.IdleTimeoutMinutes > 1440 {
		out.IdleTimeoutMinutes = 1440
	}
	if strings.TrimSpace(out.UpdatedBy) == "" {
		out.UpdatedBy = def.UpdatedBy
	}
	return out
}

func ValidatePasswordAgainstPolicy(policy PasswordPolicy, password string, username string, email string) error {
	p := NormalizePasswordPolicy(policy, policy.TenantID)
	length := len([]rune(password))
	if length < p.MinLength {
		return fmt.Errorf("password must be at least %d characters", p.MinLength)
	}
	if length > p.MaxLength {
		return fmt.Errorf("password must be at most %d characters", p.MaxLength)
	}

	var hasUpper, hasLower, hasDigit, hasSpecial, hasSpace bool
	unique := map[rune]struct{}{}
	for _, r := range password {
		unique[r] = struct{}{}
		switch {
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsDigit(r):
			hasDigit = true
		case unicode.IsSpace(r):
			hasSpace = true
		case unicode.IsPunct(r) || unicode.IsSymbol(r):
			hasSpecial = true
		}
	}

	if p.RequireUpper && !hasUpper {
		return fmt.Errorf("password must include at least one uppercase letter")
	}
	if p.RequireLower && !hasLower {
		return fmt.Errorf("password must include at least one lowercase letter")
	}
	if p.RequireDigit && !hasDigit {
		return fmt.Errorf("password must include at least one digit")
	}
	if p.RequireSpecial && !hasSpecial {
		return fmt.Errorf("password must include at least one special character")
	}
	if p.RequireNoSpace && hasSpace {
		return fmt.Errorf("password must not contain whitespace")
	}
	if p.MinUniqueChars > 0 && len(unique) < p.MinUniqueChars {
		return fmt.Errorf("password must include at least %d unique characters", p.MinUniqueChars)
	}

	passLower := strings.ToLower(password)
	if p.DenyUsername && strings.TrimSpace(username) != "" {
		userLower := strings.ToLower(strings.TrimSpace(username))
		if userLower != "" && strings.Contains(passLower, userLower) {
			return fmt.Errorf("password must not contain username")
		}
	}
	if p.DenyEmailLocal && strings.TrimSpace(email) != "" {
		local := strings.SplitN(strings.TrimSpace(email), "@", 2)[0]
		local = strings.ToLower(strings.TrimSpace(local))
		if local != "" && strings.Contains(passLower, local) {
			return fmt.Errorf("password must not contain email local-part")
		}
	}
	return nil
}

func assertRequired(v string, field string) error {
	if strings.TrimSpace(v) == "" {
		return fmt.Errorf("%s is required", field)
	}
	return nil
}

func min(a int, b int) int {
	if a < b {
		return a
	}
	return b
}
