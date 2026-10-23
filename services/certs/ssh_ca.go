package main

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	pkgcrypto "vecta-kms/pkg/crypto"
	"vecta-kms/pkg/route"
)

// SSH certificates (13.49.0-beta; docs/CERTIFICATES.md "SSH certificates").
// An SSH CA signs OpenSSH user and host certificates. Its key is sealed
// like an X.509 CA's or kept in the tenant's HSM, and is never returned.
// Its policy says which certificate types and principals it may sign and
// for how long: a holder of cert.ssh.sign can't mint a certificate for a
// principal the CA doesn't list (a "root" certificate is as good as root's
// password on every server that trusts the CA). Each certificate is
// recorded; a revoked one is published in the CA's KRL, which sshd reads
// with RevokedKeys.

const (
	permSSHRead  = "cert.ssh.read"
	permSSHWrite = "cert.ssh.write"
	permSSHSign  = "cert.ssh.sign"

	sshCertUser = "user"
	sshCertHost = "host"

	sshCAActive   = "active"
	sshCADisabled = "disabled"

	sshDefaultValidity = 8 * time.Hour
	sshMaxValidity     = 366 * 24 * time.Hour
	sshMinValidity     = time.Minute
	// sshBackdate covers clock skew between the KMS and the servers.
	sshBackdate      = 5 * time.Minute
	sshMaxPrincipals = 64
	sshListLimit     = 500
)

// sshUserExtensions are the OpenSSH user-certificate extensions a CA may
// grant. Host certificates carry none.
var sshUserExtensions = map[string]bool{
	"permit-pty": true, "permit-port-forwarding": true, "permit-agent-forwarding": true,
	"permit-X11-forwarding": true, "permit-user-rc": true,
}

// sshCAAlgorithms are the CA key algorithms; an HSM key is ECDSA.
var sshCAAlgorithms = map[string]bool{"ECDSA-P256": true, "ECDSA-P384": true, "RSA-3072": true, "RSA-4096": true, "ED25519": true}

// sshSubjectKeyTypes are the public keys a certificate may be issued for.
// DSA and RSA under 2048 bits are refused.
var sshSubjectKeyTypes = map[string]bool{
	ssh.KeyAlgoED25519: true, ssh.KeyAlgoECDSA256: true, ssh.KeyAlgoECDSA384: true, ssh.KeyAlgoECDSA521: true,
	ssh.KeyAlgoSKED25519: true, ssh.KeyAlgoSKECDSA256: true, ssh.KeyAlgoRSA: true,
}

type SSHCA struct {
	ID                 string    `json:"id"`
	TenantID           string    `json:"tenant_id"`
	Name               string    `json:"name"`
	Algorithm          string    `json:"algorithm"`
	KeyBackend         string    `json:"key_backend"`
	KeyRef             string    `json:"key_ref,omitempty"`
	PublicKey          string    `json:"public_key"` // authorized_keys format
	PublicKeyPEM       string    `json:"-"`
	Fingerprint        string    `json:"fingerprint"`
	CertTypes          []string  `json:"cert_types"`
	AllowedPrincipals  []string  `json:"allowed_principals"`
	MaxValiditySeconds int64     `json:"max_validity_seconds"`
	DefaultExtensions  []string  `json:"default_extensions"`
	Status             string    `json:"status"`
	CreatedBy          string    `json:"created_by"`
	CreatedAt          time.Time `json:"created_at"`
	UpdatedAt          time.Time `json:"updated_at"`

	signer EncryptedSigner
}

type SSHCertificate struct {
	ID              string            `json:"id"`
	TenantID        string            `json:"tenant_id"`
	CAID            string            `json:"ca_id"`
	Serial          string            `json:"serial"`
	CertType        string            `json:"cert_type"`
	KeyID           string            `json:"key_id"`
	Principals      []string          `json:"principals"`
	KeyType         string            `json:"key_type"`
	KeyFingerprint  string            `json:"key_fingerprint"`
	Extensions      []string          `json:"extensions"`
	CriticalOptions map[string]string `json:"critical_options"`
	ValidAfter      time.Time         `json:"valid_after"`
	ValidBefore     time.Time         `json:"valid_before"`
	IssuedBy        string            `json:"issued_by"`
	IssuedAt        time.Time         `json:"issued_at"`
	RevokedAt       *time.Time        `json:"revoked_at,omitempty"`
	RevokedBy       string            `json:"revoked_by,omitempty"`
	RevokeReason    string            `json:"revoke_reason,omitempty"`
}

type CreateSSHCARequest struct {
	Name               string   `json:"name"`
	Algorithm          string   `json:"algorithm"`
	KeyBackend         string   `json:"key_backend"`
	HSMConnectionID    string   `json:"hsm_connection_id"`
	CertTypes          []string `json:"cert_types"`
	AllowedPrincipals  []string `json:"allowed_principals"`
	MaxValiditySeconds int64    `json:"max_validity_seconds"`
	DefaultExtensions  []string `json:"default_extensions"`
}

type UpdateSSHCARequest struct {
	Status             string   `json:"status"`
	CertTypes          []string `json:"cert_types"`
	AllowedPrincipals  []string `json:"allowed_principals"`
	MaxValiditySeconds int64    `json:"max_validity_seconds"`
	DefaultExtensions  []string `json:"default_extensions"`
}

type SignSSHRequest struct {
	PublicKey     string   `json:"public_key"`
	CertType      string   `json:"cert_type"`
	Principals    []string `json:"principals"`
	ValidSeconds  int64    `json:"valid_seconds"`
	KeyID         string   `json:"key_id"`
	Extensions    []string `json:"extensions"` // nil: the CA's defaults
	ForceCommand  string   `json:"force_command"`
	SourceAddress []string `json:"source_address"`
}

// sshRefusal is a request the CA's policy or the input doesn't allow; the
// route audits it as refused with its reason.
type sshRefusal struct {
	status         int
	reason, detail string
}

func (e *sshRefusal) Error() string { return e.detail }

func refuseSSH(status int, reason, format string, args ...interface{}) error {
	return &sshRefusal{status: status, reason: reason, detail: fmt.Sprintf(format, args...)}
}

// sshPolicy validates and normalizes a CA's policy fields.
func sshPolicy(types, principals, exts []string, maxSeconds int64) ([]string, []string, []string, int64, error) {
	if len(types) == 0 {
		types = []string{sshCertUser}
	}
	seen := map[string]bool{}
	outTypes := []string{}
	for _, t := range types {
		t = strings.ToLower(strings.TrimSpace(t))
		if t != sshCertUser && t != sshCertHost {
			return nil, nil, nil, 0, refuseSSH(http.StatusBadRequest, "invalid_cert_type", "cert_types are %q and %q, not %q", sshCertUser, sshCertHost, t)
		}
		if !seen[t] {
			seen[t] = true
			outTypes = append(outTypes, t)
		}
	}
	if len(principals) == 0 {
		return nil, nil, nil, 0, refuseSSH(http.StatusBadRequest, "principals_required", "allowed_principals names what the CA may sign (patterns with * and ?; \"*\" for anything)")
	}
	outPrincipals := []string{}
	for _, p := range principals {
		p = strings.TrimSpace(p)
		if err := validPrincipal(p); err != nil {
			return nil, nil, nil, 0, refuseSSH(http.StatusBadRequest, "invalid_principal_pattern", "allowed principal %q: %v", p, err)
		}
		outPrincipals = append(outPrincipals, p)
	}
	outExts, err := sshExtensions(exts)
	if err != nil {
		return nil, nil, nil, 0, err
	}
	if maxSeconds == 0 {
		maxSeconds = int64(sshDefaultValidity / time.Second)
	}
	if maxSeconds < int64(sshMinValidity/time.Second) || maxSeconds > int64(sshMaxValidity/time.Second) {
		return nil, nil, nil, 0, refuseSSH(http.StatusBadRequest, "invalid_validity", "max_validity_seconds is between %d and %d", int64(sshMinValidity/time.Second), int64(sshMaxValidity/time.Second))
	}
	return outTypes, outPrincipals, outExts, maxSeconds, nil
}

func validPrincipal(p string) error {
	switch {
	case p == "":
		return errors.New("empty")
	case len(p) > 255:
		return errors.New("longer than 255 characters")
	case strings.ContainsAny(p, " \t\r\n,\x00"):
		return errors.New("contains whitespace, a comma or NUL")
	}
	return nil
}

func sshExtensions(exts []string) ([]string, error) {
	out := []string{}
	for _, e := range exts {
		e = strings.TrimSpace(e)
		if !sshUserExtensions[e] {
			return nil, refuseSSH(http.StatusBadRequest, "extension_not_allowed", "extension %q is not one of permit-pty, permit-port-forwarding, permit-agent-forwarding, permit-X11-forwarding, permit-user-rc", e)
		}
		out = append(out, e)
	}
	return out, nil
}

// globMatch matches s against a pattern where * is any run of characters
// and ? any one character.
func globMatch(pattern, s string) bool {
	if pattern == "" {
		return s == ""
	}
	switch pattern[0] {
	case '*':
		for i := 0; i <= len(s); i++ {
			if globMatch(pattern[1:], s[i:]) {
				return true
			}
		}
		return false
	case '?':
		return s != "" && globMatch(pattern[1:], s[1:])
	default:
		return s != "" && s[0] == pattern[0] && globMatch(pattern[1:], s[1:])
	}
}

func principalAllowed(ca SSHCA, principal string) bool {
	for _, p := range ca.AllowedPrincipals {
		if globMatch(p, principal) {
			return true
		}
	}
	return false
}

// CreateSSHCA makes an SSH CA with a new key, sealed here or in the HSM.
func (s *Service) CreateSSHCA(ctx context.Context, tenantID, actor string, req CreateSSHCARequest) (SSHCA, error) {
	name := strings.TrimSpace(req.Name)
	if name == "" || len(name) > 128 {
		return SSHCA{}, refuseSSH(http.StatusBadRequest, "invalid_name", "name is 1 to 128 characters")
	}
	alg := strings.ToUpper(strings.TrimSpace(req.Algorithm))
	if alg == "" {
		alg = "ECDSA-P384"
	}
	if !sshCAAlgorithms[alg] {
		return SSHCA{}, refuseSSH(http.StatusBadRequest, "invalid_algorithm", "algorithm is ECDSA-P256, ECDSA-P384, RSA-3072, RSA-4096 or ED25519")
	}
	if err := s.enforceFIPS(alg); err != nil {
		return SSHCA{}, refuseSSH(http.StatusBadRequest, "fips_blocked", "%v", err)
	}
	backend := strings.ToLower(strings.TrimSpace(req.KeyBackend))
	if backend == "" {
		backend = "software"
	}
	if backend != "software" && backend != "hsm" {
		return SSHCA{}, refuseSSH(http.StatusBadRequest, "invalid_key_backend", "key_backend is software or hsm")
	}
	types, principals, exts, maxSeconds, err := sshPolicy(req.CertTypes, req.AllowedPrincipals, req.DefaultExtensions, req.MaxValiditySeconds)
	if err != nil {
		return SSHCA{}, err
	}
	ca := SSHCA{
		ID: newID("sshca"), TenantID: tenantID, Name: name, Algorithm: alg, KeyBackend: backend,
		CertTypes: types, AllowedPrincipals: principals, MaxValiditySeconds: maxSeconds, DefaultExtensions: exts,
		Status: sshCAActive, CreatedBy: actor, CreatedAt: time.Now().UTC().Truncate(time.Microsecond),
	}
	var signer crypto.Signer
	if backend == "hsm" {
		if hsmCAAlgorithm(alg) == "" {
			return SSHCA{}, refuseSSH(http.StatusBadRequest, "invalid_algorithm", "an HSM SSH CA key is ECDSA-P256 or ECDSA-P384")
		}
		key, err := s.newHSMCAKey(ctx, tenantID, alg, name+"-ssh-ca", req.HSMConnectionID)
		if err != nil {
			return SSHCA{}, err
		}
		signer, ca.KeyRef = key, key.keyID
		ca.signer = EncryptedSigner{KeyVersion: signerVersionHSM, WrappedDEK: []byte{}, WrappedDEKIV: []byte{}, Ciphertext: []byte{}, DataIV: []byte{}}
	} else {
		var keyPEM string
		signer, keyPEM, err = generateSigningKey(alg)
		if err != nil {
			return SSHCA{}, err
		}
		defer zeroizeString(&keyPEM)
		if ca.signer, err = s.encryptSigner([]byte(keyPEM)); err != nil {
			return SSHCA{}, err
		}
	}
	pub, err := ssh.NewPublicKey(signer.Public())
	if err != nil {
		return SSHCA{}, err
	}
	der, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return SSHCA{}, err
	}
	ca.PublicKey = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))) + " vecta-ssh-ca:" + strings.ReplaceAll(name, " ", "_")
	ca.PublicKeyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	ca.Fingerprint = ssh.FingerprintSHA256(pub)
	if err := s.store.CreateSSHCA(ctx, ca); err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			return SSHCA{}, refuseSSH(http.StatusConflict, "name_taken", "an SSH CA named %q exists", name)
		}
		return SSHCA{}, err
	}
	return ca, nil
}

// UpdateSSHCA changes a CA's policy or status; its key stays.
func (s *Service) UpdateSSHCA(ctx context.Context, tenantID, id string, req UpdateSSHCARequest) (SSHCA, error) {
	ca, err := s.store.GetSSHCA(ctx, tenantID, id)
	if err != nil {
		return SSHCA{}, err
	}
	status := strings.ToLower(strings.TrimSpace(req.Status))
	if status == "" {
		status = ca.Status
	}
	if status != sshCAActive && status != sshCADisabled {
		return SSHCA{}, refuseSSH(http.StatusBadRequest, "invalid_status", "status is active or disabled")
	}
	types, principals, exts, maxSeconds := req.CertTypes, req.AllowedPrincipals, req.DefaultExtensions, req.MaxValiditySeconds
	if types == nil {
		types = ca.CertTypes
	}
	if principals == nil {
		principals = ca.AllowedPrincipals
	}
	if exts == nil {
		exts = ca.DefaultExtensions
	}
	if maxSeconds == 0 {
		maxSeconds = ca.MaxValiditySeconds
	}
	if ca.CertTypes, ca.AllowedPrincipals, ca.DefaultExtensions, ca.MaxValiditySeconds, err = sshPolicy(types, principals, exts, maxSeconds); err != nil {
		return SSHCA{}, err
	}
	ca.Status = status
	if err := s.store.UpdateSSHCAPolicy(ctx, ca); err != nil {
		return SSHCA{}, err
	}
	return s.store.GetSSHCA(ctx, tenantID, id)
}

// sshCASigner opens a CA's key for the user in ctx; an HSM key signs in
// keycore under that user's grant.
func (s *Service) sshCASigner(ctx context.Context, ca SSHCA) (crypto.Signer, error) {
	if ca.KeyBackend == "hsm" && ca.signer.KeyVersion == signerVersionHSM {
		keys, ok := s.keycore.(HSMKeyStore)
		if !ok {
			return nil, errors.New("HSM CA keys need keycore, which is not configured")
		}
		block, _ := pem.Decode([]byte(ca.PublicKeyPEM))
		if block == nil {
			return nil, errors.New("the SSH CA's public key is unreadable")
		}
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		return &hsmSigner{keys: keys, tenantID: ca.TenantID, keyID: ca.KeyRef, pub: pub, ctx: ctx, usage: "certificate-sign"}, nil
	}
	raw, err := s.decryptSigner(ca.sealedAsCA())
	if err != nil {
		return nil, err
	}
	defer pkgcrypto.Zeroize(raw)
	return parseSignerPEM(raw)
}

// sealedAsCA carries the CA's sealed key in the X.509 CA shape the
// envelope code reads.
func (ca SSHCA) sealedAsCA() CA {
	return CA{ID: ca.ID, TenantID: ca.TenantID, KeyBackend: ca.KeyBackend, KeyRef: ca.KeyRef,
		SignerWrappedDEK: ca.signer.WrappedDEK, SignerWrappedDEKIV: ca.signer.WrappedDEKIV,
		SignerCiphertext: ca.signer.Ciphertext, SignerDataIV: ca.signer.DataIV,
		SignerKeyVersion: ca.signer.KeyVersion, SignerFingerprint: ca.signer.Fingerprint}
}

// sshSignerFor wraps the CA key for SSH. RSA signs rsa-sha2-512, never the
// SHA-1 ssh-rsa.
func sshSignerFor(signer crypto.Signer) (ssh.Signer, error) {
	sig, err := ssh.NewSignerFromSigner(signer)
	if err != nil {
		return nil, err
	}
	if sig.PublicKey().Type() == ssh.KeyAlgoRSA {
		alg, ok := sig.(ssh.AlgorithmSigner)
		if !ok {
			return nil, errors.New("the RSA CA key can't sign rsa-sha2-512")
		}
		return ssh.NewSignerWithAlgorithms(alg, []string{ssh.KeyAlgoRSASHA512})
	}
	return sig, nil
}

// SignSSH issues a certificate for a public key, within the CA's policy.
func (s *Service) SignSSH(ctx context.Context, tenantID, caID, actor string, req SignSSHRequest) (SSHCertificate, string, error) {
	ca, err := s.store.GetSSHCA(ctx, tenantID, caID)
	if err != nil {
		return SSHCertificate{}, "", err
	}
	if ca.Status != sshCAActive {
		return SSHCertificate{}, "", refuseSSH(http.StatusConflict, "ca_disabled", "the SSH CA %q is disabled", ca.Name)
	}
	certType := strings.ToLower(strings.TrimSpace(req.CertType))
	if certType == "" {
		certType = sshCertUser
	}
	typeAllowed := false
	for _, t := range ca.CertTypes {
		typeAllowed = typeAllowed || t == certType
	}
	if !typeAllowed {
		return SSHCertificate{}, "", refuseSSH(http.StatusForbidden, "cert_type_not_allowed", "the SSH CA %q doesn't sign %s certificates", ca.Name, certType)
	}

	subject, _, _, _, err := ssh.ParseAuthorizedKey([]byte(strings.TrimSpace(req.PublicKey)))
	if err != nil {
		return SSHCertificate{}, "", refuseSSH(http.StatusBadRequest, "invalid_public_key", "public_key is one OpenSSH public key line (id_ed25519.pub): %v", err)
	}
	if _, isCert := subject.(*ssh.Certificate); isCert || !sshSubjectKeyTypes[subject.Type()] {
		return SSHCertificate{}, "", refuseSSH(http.StatusBadRequest, "key_type_not_allowed", "a certificate is issued for ed25519, ECDSA or RSA (2048 bits or more) keys, not %s", subject.Type())
	}
	if subject.Type() == ssh.KeyAlgoRSA {
		if k, ok := subject.(ssh.CryptoPublicKey); !ok || !rsaAtLeast(k.CryptoPublicKey(), 2048) {
			return SSHCertificate{}, "", refuseSSH(http.StatusBadRequest, "weak_public_key", "an RSA key is 2048 bits or more")
		}
	}
	if ssh.FingerprintSHA256(subject) == ca.Fingerprint {
		return SSHCertificate{}, "", refuseSSH(http.StatusBadRequest, "invalid_public_key", "that is the CA's own key")
	}

	if len(req.Principals) == 0 || len(req.Principals) > sshMaxPrincipals {
		return SSHCertificate{}, "", refuseSSH(http.StatusBadRequest, "principals_required", "a certificate names 1 to %d principals (user names or host names)", sshMaxPrincipals)
	}
	principals := []string{}
	for _, p := range req.Principals {
		p = strings.TrimSpace(p)
		if err := validPrincipal(p); err != nil || strings.ContainsAny(p, "*?") {
			return SSHCertificate{}, "", refuseSSH(http.StatusBadRequest, "invalid_principal", "principal %q is a plain name, without spaces, commas or wildcards", p)
		}
		if !principalAllowed(ca, p) {
			return SSHCertificate{}, "", refuseSSH(http.StatusForbidden, "principal_not_allowed", "the SSH CA %q doesn't sign for %q", ca.Name, p)
		}
		principals = append(principals, p)
	}

	validity := req.ValidSeconds
	if validity == 0 {
		validity = ca.MaxValiditySeconds
	}
	if validity < int64(sshMinValidity/time.Second) || validity > ca.MaxValiditySeconds {
		return SSHCertificate{}, "", refuseSSH(http.StatusBadRequest, "validity_too_long", "valid_seconds is between %d and the CA's %d", int64(sshMinValidity/time.Second), ca.MaxValiditySeconds)
	}

	exts := req.Extensions
	if exts == nil && certType == sshCertUser {
		exts = ca.DefaultExtensions
	}
	if certType == sshCertHost && len(exts) > 0 {
		return SSHCertificate{}, "", refuseSSH(http.StatusBadRequest, "extension_not_allowed", "host certificates carry no extensions")
	}
	if exts, err = sshExtensions(exts); err != nil {
		return SSHCertificate{}, "", err
	}
	options := map[string]string{}
	if fc := strings.TrimSpace(req.ForceCommand); fc != "" {
		if certType != sshCertUser || len(fc) > 1024 || strings.ContainsAny(fc, "\x00\r\n") {
			return SSHCertificate{}, "", refuseSSH(http.StatusBadRequest, "invalid_option", "force_command is one line of at most 1024 characters, on user certificates")
		}
		options["force-command"] = fc
	}
	if len(req.SourceAddress) > 0 {
		if certType != sshCertUser {
			return SSHCertificate{}, "", refuseSSH(http.StatusBadRequest, "invalid_option", "source_address is for user certificates")
		}
		addrs := make([]string, 0, len(req.SourceAddress))
		for _, a := range req.SourceAddress {
			a = strings.TrimSpace(a)
			if _, _, err := net.ParseCIDR(a); err != nil && net.ParseIP(a) == nil {
				return SSHCertificate{}, "", refuseSSH(http.StatusBadRequest, "invalid_option", "source_address %q is not an address or CIDR", a)
			}
			addrs = append(addrs, a)
		}
		options["source-address"] = strings.Join(addrs, ",")
	}

	serial, err := sshSerial()
	if err != nil {
		return SSHCertificate{}, "", err
	}
	keyID := strings.TrimSpace(req.KeyID)
	if keyID == "" {
		keyID = fmt.Sprintf("%s:%s:%d", tenantID, actor, serial)
	}
	if len(keyID) > 256 || strings.ContainsAny(keyID, "\x00\r\n") {
		return SSHCertificate{}, "", refuseSSH(http.StatusBadRequest, "invalid_key_id", "key_id is one line of at most 256 characters")
	}

	now := time.Now().UTC().Truncate(time.Second)
	after, before := now.Add(-sshBackdate), now.Add(time.Duration(validity)*time.Second)
	extMap := map[string]string{}
	for _, e := range exts {
		extMap[e] = ""
	}
	cert := &ssh.Certificate{
		Key: subject, Serial: serial, KeyId: keyID, ValidPrincipals: principals,
		ValidAfter: uint64(after.Unix()), ValidBefore: uint64(before.Unix()),
		Permissions: ssh.Permissions{CriticalOptions: options, Extensions: extMap},
		CertType:    map[string]uint32{sshCertUser: ssh.UserCert, sshCertHost: ssh.HostCert}[certType],
	}
	cryptoSigner, err := s.sshCASigner(ctx, ca)
	if err != nil {
		return SSHCertificate{}, "", err
	}
	signer, err := sshSignerFor(cryptoSigner)
	if err != nil {
		return SSHCertificate{}, "", err
	}
	if err := cert.SignCert(pkgcrypto.Reader, signer); err != nil {
		return SSHCertificate{}, "", fmt.Errorf("sign the certificate: %w", err)
	}
	rec := SSHCertificate{
		ID: newID("sshcert"), TenantID: tenantID, CAID: ca.ID, Serial: strconv.FormatUint(serial, 10), CertType: certType,
		KeyID: keyID, Principals: principals, KeyType: subject.Type(), KeyFingerprint: ssh.FingerprintSHA256(subject),
		Extensions: exts, CriticalOptions: options, ValidAfter: after, ValidBefore: before, IssuedBy: actor, IssuedAt: now,
	}
	if err := s.store.CreateSSHCertificate(ctx, rec); err != nil {
		return SSHCertificate{}, "", err
	}
	return rec, strings.TrimSpace(string(ssh.MarshalAuthorizedKey(cert))), nil
}

// rsaAtLeast reports whether pub is an RSA key of at least bits (the size is
// read through the key's own method; services don't import crypto/rsa).
func rsaAtLeast(pub crypto.PublicKey, bits int) bool {
	k, ok := pub.(interface{ Size() int })
	return ok && k.Size()*8 >= bits
}

// sshSerial is a random non-zero 63-bit serial.
func sshSerial() (uint64, error) {
	for {
		raw, err := pkgcrypto.RandomBytes(8)
		if err != nil {
			return 0, err
		}
		if v := binary.BigEndian.Uint64(raw) >> 1; v != 0 {
			return v, nil
		}
	}
}

// RevokeSSHCertificate revokes one certificate; it is in the CA's KRL from
// then until it expires.
func (s *Service) RevokeSSHCertificate(ctx context.Context, tenantID, id, actor, reason string) (SSHCertificate, error) {
	reason = strings.TrimSpace(reason)
	if len(reason) > 256 {
		return SSHCertificate{}, refuseSSH(http.StatusBadRequest, "invalid_reason", "reason is at most 256 characters")
	}
	c, err := s.store.GetSSHCertificate(ctx, tenantID, id)
	if err != nil {
		return SSHCertificate{}, err
	}
	if c.RevokedAt != nil {
		return SSHCertificate{}, refuseSSH(http.StatusConflict, "already_revoked", "the certificate was revoked at %s", c.RevokedAt.Format(time.RFC3339))
	}
	if err := s.store.RevokeSSHCertificate(ctx, tenantID, id, actor, reason, time.Now().UTC().Truncate(time.Microsecond)); err != nil {
		return SSHCertificate{}, err
	}
	return s.store.GetSSHCertificate(ctx, tenantID, id)
}

// sshKRL builds the CA's OpenSSH key revocation list (PROTOCOL.krl): one
// certificates section for the CA key, listing the serials of revoked
// certificates that haven't expired. sshd reads it with RevokedKeys.
func (s *Service) sshKRL(ctx context.Context, ca SSHCA, now time.Time) ([]byte, int, error) {
	revoked, err := s.store.ListSSHCertificates(ctx, ca.TenantID, ca.ID, true, 1<<20)
	if err != nil {
		return nil, 0, err
	}
	caPub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(ca.PublicKey))
	if err != nil {
		return nil, 0, err
	}
	var serials []byte
	n := 0
	for _, c := range revoked {
		if !c.ValidBefore.After(now) {
			continue
		}
		v, err := strconv.ParseUint(c.Serial, 10, 64)
		if err != nil {
			return nil, 0, fmt.Errorf("certificate %s: serial %q", c.ID, c.Serial)
		}
		serials = binary.BigEndian.AppendUint64(serials, v)
		n++
	}
	str := func(b []byte, v []byte) []byte { return append(binary.BigEndian.AppendUint32(b, uint32(len(v))), v...) }
	var certs []byte
	certs = str(certs, caPub.Marshal()) // ca_key
	certs = str(certs, nil)             // reserved
	if n > 0 {
		certs = append(certs, 0x20) // KRL_SECTION_CERT_SERIAL_LIST
		certs = str(certs, serials)
	}
	out := []byte("SSHKRL\n\x00")
	out = binary.BigEndian.AppendUint32(out, 1)                  // format version
	out = binary.BigEndian.AppendUint64(out, uint64(now.Unix())) // krl_version
	out = binary.BigEndian.AppendUint64(out, uint64(now.Unix())) // generated_date
	out = binary.BigEndian.AppendUint64(out, 0)                  // flags
	out = str(out, nil)                                          // reserved
	out = str(out, []byte("vecta-kms ssh ca "+ca.ID))            // comment
	out = append(out, 1)                                         // KRL_SECTION_CERTIFICATES
	out = str(out, certs)
	return out, n, nil
}

// ---- routes ----

func (h *Handler) RegisterSSHRoutes(k *route.Router) {
	k.Handle("GET /certs/ssh/cas", route.Spec{Action: "ssh_cas_listed", Permission: permSSHRead, Resource: "ssh_ca"}, h.listSSHCAs)
	k.Handle("POST /certs/ssh/cas", route.Spec{Action: "ssh_ca_created", Permission: permSSHWrite, Resource: "ssh_ca", Severity: "warning"}, h.createSSHCA)
	k.Handle("GET /certs/ssh/cas/{id}", route.Spec{Action: "ssh_ca_read", Permission: permSSHRead, Resource: "ssh_ca", TargetParam: "id"}, h.getSSHCA)
	k.Handle("PUT /certs/ssh/cas/{id}", route.Spec{Action: "ssh_ca_updated", Permission: permSSHWrite, Resource: "ssh_ca", TargetParam: "id", Severity: "warning"}, h.updateSSHCA)
	k.Handle("POST /certs/ssh/cas/{id}/sign", route.Spec{Action: "ssh_certificate_issued", Permission: permSSHSign, Resource: "ssh_ca", TargetParam: "id", Severity: "warning"}, h.signSSH)
	k.Handle("GET /certs/ssh/cas/{id}/certificates", route.Spec{Action: "ssh_certificates_listed", Permission: permSSHRead, Resource: "ssh_ca", TargetParam: "id"}, h.listSSHCertificates)
	k.Handle("GET /certs/ssh/cas/{id}/krl", route.Spec{Action: "ssh_krl_read", Permission: permSSHRead, Resource: "ssh_ca", TargetParam: "id"}, h.getSSHKRL)
	k.Handle("POST /certs/ssh/certificates/{id}/revoke", route.Spec{Action: "ssh_certificate_revoked", Permission: permSSHWrite, Resource: "ssh_certificate", TargetParam: "id", Severity: "warning"}, h.revokeSSH)
}

// sshFail answers a service error: a policy refusal is audited as refused
// with its reason, a missing CA or certificate is 404.
func sshFail(c *route.Call, err error, what string) {
	var r *sshRefusal
	switch {
	case errors.As(err, &r):
		c.Refuse(r.status, r.reason, r.detail)
	case errors.Is(err, errStoreNotFound):
		c.Error(http.StatusNotFound, "not_found", what+" not found")
	default:
		c.Error(http.StatusInternalServerError, "ssh_ca_failed", err.Error())
	}
}

func (h *Handler) listSSHCAs(c *route.Call) {
	items, err := h.svc.store.ListSSHCAs(c.R.Context(), c.Tenant)
	if err != nil {
		sshFail(c, err, "SSH CA")
		return
	}
	c.Detail("count", len(items))
	c.JSON(http.StatusOK, map[string]interface{}{"items": items})
}

func (h *Handler) createSSHCA(c *route.Call) {
	var in CreateSSHCARequest
	if !c.Decode(&in) {
		return
	}
	c.Detail("name", in.Name)
	c.Detail("algorithm", in.Algorithm)
	c.Detail("key_backend", in.KeyBackend)
	ca, err := h.svc.CreateSSHCA(c.R.Context(), c.Tenant, c.Actor(), in)
	if err != nil {
		sshFail(c, err, "SSH CA")
		return
	}
	c.Target(ca.ID)
	c.Detail("fingerprint", ca.Fingerprint)
	c.Detail("cert_types", ca.CertTypes)
	c.Detail("allowed_principals", ca.AllowedPrincipals)
	c.Detail("max_validity_seconds", ca.MaxValiditySeconds)
	c.JSON(http.StatusCreated, map[string]interface{}{"ssh_ca": ca})
}

func (h *Handler) getSSHCA(c *route.Call) {
	ca, err := h.svc.store.GetSSHCA(c.R.Context(), c.Tenant, c.R.PathValue("id"))
	if err != nil {
		sshFail(c, err, "SSH CA")
		return
	}
	key := strings.Join(strings.Fields(ca.PublicKey)[:2], " ")
	c.JSON(http.StatusOK, map[string]interface{}{"ssh_ca": ca, "trust": map[string]string{
		// Lines to install on servers (user CA) and clients (host CA).
		"trusted_user_ca_keys": ca.PublicKey,
		"known_hosts":          "@cert-authority * " + key,
	}})
}

func (h *Handler) updateSSHCA(c *route.Call) {
	var in UpdateSSHCARequest
	if !c.Decode(&in) {
		return
	}
	ca, err := h.svc.UpdateSSHCA(c.R.Context(), c.Tenant, c.R.PathValue("id"), in)
	if err != nil {
		sshFail(c, err, "SSH CA")
		return
	}
	c.Detail("status", ca.Status)
	c.Detail("cert_types", ca.CertTypes)
	c.Detail("allowed_principals", ca.AllowedPrincipals)
	c.Detail("max_validity_seconds", ca.MaxValiditySeconds)
	c.Detail("default_extensions", ca.DefaultExtensions)
	c.JSON(http.StatusOK, map[string]interface{}{"ssh_ca": ca})
}

func (h *Handler) signSSH(c *route.Call) {
	var in SignSSHRequest
	if !c.Decode(&in) {
		return
	}
	c.Detail("cert_type", in.CertType)
	c.Detail("principals", in.Principals)
	rec, cert, err := h.svc.SignSSH(c.R.Context(), c.Tenant, c.R.PathValue("id"), c.Actor(), in)
	if err != nil {
		sshFail(c, err, "SSH CA")
		return
	}
	c.Detail("certificate_id", rec.ID)
	c.Detail("serial", rec.Serial)
	c.Detail("cert_type", rec.CertType)
	c.Detail("key_id", rec.KeyID)
	c.Detail("key_fingerprint", rec.KeyFingerprint)
	c.Detail("valid_before", rec.ValidBefore.Format(time.RFC3339))
	c.Detail("extensions", rec.Extensions)
	c.Detail("critical_options", rec.CriticalOptions)
	c.JSON(http.StatusCreated, map[string]interface{}{"certificate": cert, "ssh_certificate": rec})
}

func (h *Handler) listSSHCertificates(c *route.Call) {
	limit, _ := strconv.Atoi(c.R.URL.Query().Get("limit"))
	if limit <= 0 || limit > sshListLimit {
		limit = sshListLimit
	}
	if _, err := h.svc.store.GetSSHCA(c.R.Context(), c.Tenant, c.R.PathValue("id")); err != nil {
		sshFail(c, err, "SSH CA")
		return
	}
	items, err := h.svc.store.ListSSHCertificates(c.R.Context(), c.Tenant, c.R.PathValue("id"), c.R.URL.Query().Get("revoked") == "true", limit)
	if err != nil {
		sshFail(c, err, "SSH CA")
		return
	}
	c.Detail("count", len(items))
	c.JSON(http.StatusOK, map[string]interface{}{"items": items})
}

func (h *Handler) getSSHKRL(c *route.Call) {
	ca, err := h.svc.store.GetSSHCA(c.R.Context(), c.Tenant, c.R.PathValue("id"))
	if err != nil {
		sshFail(c, err, "SSH CA")
		return
	}
	krl, n, err := h.svc.sshKRL(c.R.Context(), ca, time.Now().UTC())
	if err != nil {
		sshFail(c, err, "SSH CA")
		return
	}
	c.Detail("revoked", n)
	c.W.Header().Set("Content-Type", "application/octet-stream")
	c.W.Header().Set("Content-Disposition", `attachment; filename="`+ca.ID+`.krl"`)
	c.W.WriteHeader(http.StatusOK)
	_, _ = c.W.Write(krl)
}

func (h *Handler) revokeSSH(c *route.Call) {
	var in struct {
		Reason string `json:"reason"`
	}
	if !c.Decode(&in) {
		return
	}
	rec, err := h.svc.RevokeSSHCertificate(c.R.Context(), c.Tenant, c.R.PathValue("id"), c.Actor(), in.Reason)
	if err != nil {
		sshFail(c, err, "SSH certificate")
		return
	}
	c.Detail("ca_id", rec.CAID)
	c.Detail("serial", rec.Serial)
	c.Detail("reason", rec.RevokeReason)
	c.JSON(http.StatusOK, map[string]interface{}{"ssh_certificate": rec})
}
