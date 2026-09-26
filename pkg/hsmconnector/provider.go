package hsmconnector

import (
	"bytes"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/miekg/pkcs11"

	pkgcrypto "vecta-kms/pkg/crypto"
	"vecta-kms/pkg/hsm"
)

// The PKCS#11 side of the connector. Each vendor library is loaded once and
// initialised once. Per slot, one session stays open after login: PKCS#11
// logs a token out when its last session closes, and each request opens its
// own short session on top of it. Every object the platform creates is a
// token object, sensitive and never extractable.

var errExists = errors.New("an object with this label already exists in the HSM")

type slotKey struct {
	library string
	slot    uint
}

type module struct {
	ctx      *pkcs11.Ctx
	mu       sync.Mutex
	anchored map[uint]pkcs11.SessionHandle
}

type Provider struct {
	mu      sync.Mutex
	modules map[string]*module
}

func NewProvider() *Provider { return &Provider{modules: map[string]*module{}} }

func (p *Provider) module(library string) (*module, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if m, ok := p.modules[library]; ok {
		return m, nil
	}
	ctx := pkcs11.New(library)
	if ctx == nil {
		return nil, fmt.Errorf("cannot load PKCS#11 library %s", library)
	}
	if err := ctx.Initialize(); err != nil && !isRV(err, pkcs11.CKR_CRYPTOKI_ALREADY_INITIALIZED) {
		ctx.Destroy()
		return nil, fmt.Errorf("C_Initialize: %w", err)
	}
	m := &module{ctx: ctx, anchored: map[uint]pkcs11.SessionHandle{}}
	p.modules[library] = m
	return m, nil
}

func isRV(err error, rv uint) bool {
	var e pkcs11.Error
	return errors.As(err, &e) && uint(e) == rv
}

// findSlot resolves the configured slot ID, or the slot whose token has the
// configured label.
func (m *module) findSlot(cfg TenantConfig) (uint, error) {
	if s := strings.TrimSpace(cfg.SlotID); s != "" {
		id, err := strconv.ParseUint(s, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("slot_id %q is not a number", s)
		}
		return uint(id), nil
	}
	label := strings.TrimSpace(firstNonEmpty(cfg.TokenLabel, cfg.PartitionLabel))
	if label == "" {
		return 0, errors.New("the HSM profile names neither a slot ID nor a token label")
	}
	slots, err := m.ctx.GetSlotList(true)
	if err != nil {
		return 0, fmt.Errorf("C_GetSlotList: %w", err)
	}
	for _, s := range slots {
		info, err := m.ctx.GetTokenInfo(s)
		if err == nil && strings.TrimSpace(info.Label) == label {
			return s, nil
		}
	}
	return 0, fmt.Errorf("no token labelled %q", label)
}

// session opens a session on the tenant's token, logged in as the user.
func (p *Provider) session(cfg TenantConfig) (*pkcs11.Ctx, pkcs11.SessionHandle, func(), error) {
	m, err := p.module(cfg.Library)
	if err != nil {
		return nil, 0, nil, err
	}
	slot, err := m.findSlot(cfg)
	if err != nil {
		return nil, 0, nil, err
	}
	flags := uint(pkcs11.CKF_SERIAL_SESSION)
	if !cfg.ReadOnly {
		flags |= pkcs11.CKF_RW_SESSION
	}
	m.mu.Lock()
	if _, ok := m.anchored[slot]; !ok {
		anchor, err := m.ctx.OpenSession(slot, flags)
		if err != nil {
			m.mu.Unlock()
			return nil, 0, nil, fmt.Errorf("C_OpenSession: %w", err)
		}
		if err := m.ctx.Login(anchor, pkcs11.CKU_USER, cfg.PIN); err != nil && !isRV(err, pkcs11.CKR_USER_ALREADY_LOGGED_IN) {
			_ = m.ctx.CloseSession(anchor)
			m.mu.Unlock()
			return nil, 0, nil, fmt.Errorf("C_Login: %w", err)
		}
		m.anchored[slot] = anchor
	}
	m.mu.Unlock()
	sh, err := m.ctx.OpenSession(slot, flags)
	if err != nil {
		return nil, 0, nil, fmt.Errorf("C_OpenSession: %w", err)
	}
	return m.ctx, sh, func() { _ = m.ctx.CloseSession(sh) }, nil
}

// find returns the objects of class (or any class when class < 0) labelled
// label.
func find(ctx *pkcs11.Ctx, sh pkcs11.SessionHandle, class int, label string) ([]pkcs11.ObjectHandle, error) {
	tmpl := []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_LABEL, label)}
	if class >= 0 {
		tmpl = append(tmpl, pkcs11.NewAttribute(pkcs11.CKA_CLASS, uint(class)))
	}
	if err := ctx.FindObjectsInit(sh, tmpl); err != nil {
		return nil, fmt.Errorf("C_FindObjectsInit: %w", err)
	}
	defer ctx.FindObjectsFinal(sh) //nolint:errcheck
	var out []pkcs11.ObjectHandle
	for {
		objs, _, err := ctx.FindObjects(sh, 16)
		if err != nil {
			return nil, fmt.Errorf("C_FindObjects: %w", err)
		}
		if len(objs) == 0 {
			return out, nil
		}
		out = append(out, objs...)
	}
}

func findOne(ctx *pkcs11.Ctx, sh pkcs11.SessionHandle, class int, label string) (pkcs11.ObjectHandle, error) {
	objs, err := find(ctx, sh, class, label)
	if err != nil {
		return 0, err
	}
	switch len(objs) {
	case 0:
		return 0, hsm.ErrNotFound
	case 1:
		return objs[0], nil
	}
	return 0, fmt.Errorf("%d objects are labelled %q; refusing to guess", len(objs), label)
}

func keyTemplateCommon(label string) []*pkcs11.Attribute {
	return []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_ID, []byte(label)),
	}
}

func privateTemplate(label string) []*pkcs11.Attribute {
	return append(keyTemplateCommon(label),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
	)
}

// generate creates a key (or key pair) labelled label.
func generate(ctx *pkcs11.Ctx, sh pkcs11.SessionHandle, label, algorithm string) (hsm.GenerateResult, error) {
	if objs, err := find(ctx, sh, -1, label); err != nil {
		return hsm.GenerateResult{}, err
	} else if len(objs) > 0 {
		return hsm.GenerateResult{}, errExists
	}
	res := hsm.GenerateResult{Label: label}
	kind, size, _ := strings.Cut(algorithm, "-")
	switch kind {
	case "AES":
		bits, _ := strconv.Atoi(size)
		tmpl := append(privateTemplate(label),
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_AES),
			pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, bits/8),
			pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
			pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
			pkcs11.NewAttribute(pkcs11.CKA_WRAP, false),
			pkcs11.NewAttribute(pkcs11.CKA_UNWRAP, false),
		)
		obj, err := ctx.GenerateKey(sh, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_KEY_GEN, nil)}, tmpl)
		if err != nil {
			return res, fmt.Errorf("C_GenerateKey: %w", err)
		}
		res.KCV = aesKCV(ctx, sh, obj)
	case "RSA":
		bits, _ := strconv.Atoi(size)
		pub := append(keyTemplateCommon(label),
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
			pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
			pkcs11.NewAttribute(pkcs11.CKA_MODULUS_BITS, bits),
			pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, []byte{1, 0, 1}),
		)
		priv := append(privateTemplate(label),
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
			pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		)
		pubObj, _, err := ctx.GenerateKeyPair(sh, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN, nil)}, pub, priv)
		if err != nil {
			return res, fmt.Errorf("C_GenerateKeyPair: %w", err)
		}
		attrs, err := ctx.GetAttributeValue(sh, pubObj, []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_MODULUS, nil), pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, nil),
		})
		if err != nil {
			return res, fmt.Errorf("C_GetAttributeValue: %w", err)
		}
		if res.PublicKey, err = pkgcrypto.PKIXFromRSAComponents(attrs[0].Value, attrs[1].Value); err != nil {
			return res, err
		}
	case "ECDSA":
		curve := size // "P256" | "P384"
		params, err := pkgcrypto.ECCurveParamsDER(curve)
		if err != nil {
			return res, err
		}
		pub := append(keyTemplateCommon(label),
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
			pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
			pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, params),
		)
		priv := append(privateTemplate(label),
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
			pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		)
		pubObj, _, err := ctx.GenerateKeyPair(sh, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_EC_KEY_PAIR_GEN, nil)}, pub, priv)
		if err != nil {
			return res, fmt.Errorf("C_GenerateKeyPair: %w", err)
		}
		attrs, err := ctx.GetAttributeValue(sh, pubObj, []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, nil)})
		if err != nil {
			return res, fmt.Errorf("C_GetAttributeValue: %w", err)
		}
		if res.PublicKey, err = pkgcrypto.PKIXFromECPoint(curve, attrs[0].Value); err != nil {
			return res, err
		}
	default:
		return res, fmt.Errorf("algorithm %s can't be generated in the HSM", algorithm)
	}
	return res, nil
}

// aesKCV is the key check value, E(K, 0^128)[:3], computed in the HSM. It's
// best effort: an HSM that refuses ECB leaves it empty.
func aesKCV(ctx *pkcs11.Ctx, sh pkcs11.SessionHandle, obj pkcs11.ObjectHandle) []byte {
	if err := ctx.EncryptInit(sh, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_ECB, nil)}, obj); err != nil {
		return nil
	}
	out, err := ctx.Encrypt(sh, make([]byte, 16))
	if err != nil || len(out) < 3 {
		return nil
	}
	return out[:3]
}

const (
	gcmIVSize            = 12
	ckrAEADDecryptFailed = 0x35 // PKCS#11 3.0; not in the Go binding's constants
)

// encrypt runs AES-GCM with a 96-bit IV from the HSM's own generator and a
// 128-bit tag; the result is ciphertext || tag.
func encrypt(ctx *pkcs11.Ctx, sh pkcs11.SessionHandle, label string, plaintext, aad []byte) ([]byte, []byte, error) {
	obj, err := findOne(ctx, sh, pkcs11.CKO_SECRET_KEY, label)
	if err != nil {
		return nil, nil, err
	}
	iv, err := ctx.GenerateRandom(sh, gcmIVSize)
	if err != nil {
		return nil, nil, fmt.Errorf("C_GenerateRandom: %w", err)
	}
	params := pkcs11.NewGCMParams(iv, aad, 128)
	defer params.Free()
	if err := ctx.EncryptInit(sh, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_GCM, params)}, obj); err != nil {
		return nil, nil, fmt.Errorf("C_EncryptInit: %w", err)
	}
	ct, err := ctx.Encrypt(sh, plaintext)
	if err != nil {
		return nil, nil, fmt.Errorf("C_Encrypt: %w", err)
	}
	if used := params.IV(); len(used) == gcmIVSize {
		iv = used // an HSM may substitute its own IV
	}
	return iv, ct, nil
}

var errAuthFailed = errors.New("authentication failed: wrong key, IV, AAD or tampered ciphertext")

func decrypt(ctx *pkcs11.Ctx, sh pkcs11.SessionHandle, label string, iv, ciphertext, aad []byte) ([]byte, error) {
	obj, err := findOne(ctx, sh, pkcs11.CKO_SECRET_KEY, label)
	if err != nil {
		return nil, err
	}
	if len(iv) != gcmIVSize {
		return nil, fmt.Errorf("iv must be %d bytes", gcmIVSize)
	}
	params := pkcs11.NewGCMParams(iv, aad, 128)
	defer params.Free()
	if err := ctx.DecryptInit(sh, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_GCM, params)}, obj); err != nil {
		return nil, fmt.Errorf("C_DecryptInit: %w", err)
	}
	pt, err := ctx.Decrypt(sh, ciphertext)
	if err != nil {
		// DecryptInit accepted the key and parameters, so a failing GCM
		// decrypt is a tag mismatch. Vendors report it differently:
		// CKR_ENCRYPTED_DATA_INVALID, CKR_AEAD_DECRYPT_FAILED (PKCS#11 3.0,
		// 0x35), or, SoftHSM2 among them, CKR_GENERAL_ERROR / FUNCTION_FAILED.
		for _, rv := range []uint{pkcs11.CKR_ENCRYPTED_DATA_INVALID, pkcs11.CKR_ENCRYPTED_DATA_LEN_RANGE, ckrAEADDecryptFailed, pkcs11.CKR_GENERAL_ERROR, pkcs11.CKR_FUNCTION_FAILED} {
			if isRV(err, rv) {
				return nil, errAuthFailed
			}
		}
		return nil, fmt.Errorf("C_Decrypt: %w", err)
	}
	return pt, nil
}

type hashSpec struct {
	mech, mgf uint
	size      int
}

var hashes = map[string]hashSpec{
	"SHA-256": {pkcs11.CKM_SHA256, pkcs11.CKG_MGF1_SHA256, 32},
	"SHA-384": {pkcs11.CKM_SHA384, pkcs11.CKG_MGF1_SHA384, 48},
	"SHA-512": {pkcs11.CKM_SHA512, pkcs11.CKG_MGF1_SHA512, 64},
}

// keyInfo reads an object's key type and, for EC, its curve.
func keyInfo(ctx *pkcs11.Ctx, sh pkcs11.SessionHandle, obj pkcs11.ObjectHandle) (uint, string, error) {
	attrs, err := ctx.GetAttributeValue(sh, obj, []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, nil)})
	if err != nil {
		return 0, "", fmt.Errorf("C_GetAttributeValue: %w", err)
	}
	kt := bytesToUint(attrs[0].Value)
	if kt != pkcs11.CKK_EC {
		return kt, "", nil
	}
	attrs, err = ctx.GetAttributeValue(sh, obj, []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, nil)})
	if err != nil {
		return 0, "", fmt.Errorf("C_GetAttributeValue: %w", err)
	}
	for _, c := range []string{"P256", "P384"} {
		if want, _ := pkgcrypto.ECCurveParamsDER(c); bytes.Equal(want, attrs[0].Value) {
			return kt, c, nil
		}
	}
	return 0, "", errors.New("unsupported EC curve on HSM key")
}

func bytesToUint(b []byte) uint {
	// CK_ULONG in host byte order (little-endian on the supported platforms).
	var v uint
	for i := len(b) - 1; i >= 0; i-- {
		v = v<<8 | uint(b[i])
	}
	return v
}

func mechanismFor(kt uint, hash string, digest []byte) (*pkcs11.Mechanism, error) {
	h, ok := hashes[hash]
	if !ok {
		return nil, fmt.Errorf("hash must be SHA-256, SHA-384 or SHA-512")
	}
	if len(digest) != h.size {
		return nil, fmt.Errorf("digest must be %d bytes for %s", h.size, hash)
	}
	switch kt {
	case pkcs11.CKK_RSA:
		return pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_PSS, pkcs11.NewPSSParams(h.mech, h.mgf, uint(h.size))), nil
	case pkcs11.CKK_EC:
		return pkcs11.NewMechanism(pkcs11.CKM_ECDSA, nil), nil
	}
	return nil, errors.New("the HSM key can't sign")
}

// sign signs a digest: RSA-PSS (salt = hash length) or ECDSA, returned as
// ASN.1 DER.
func sign(ctx *pkcs11.Ctx, sh pkcs11.SessionHandle, label, hash string, digest []byte) ([]byte, error) {
	obj, err := findOne(ctx, sh, pkcs11.CKO_PRIVATE_KEY, label)
	if err != nil {
		return nil, err
	}
	kt, _, err := keyInfo(ctx, sh, obj)
	if err != nil {
		return nil, err
	}
	mech, err := mechanismFor(kt, hash, digest)
	if err != nil {
		return nil, err
	}
	if err := ctx.SignInit(sh, []*pkcs11.Mechanism{mech}, obj); err != nil {
		return nil, fmt.Errorf("C_SignInit: %w", err)
	}
	sig, err := ctx.Sign(sh, digest)
	if err != nil {
		return nil, fmt.Errorf("C_Sign: %w", err)
	}
	if kt == pkcs11.CKK_EC {
		return pkgcrypto.ECDSARawToASN1(sig)
	}
	return sig, nil
}

func verify(ctx *pkcs11.Ctx, sh pkcs11.SessionHandle, label, hash string, digest, signature []byte) (bool, error) {
	obj, err := findOne(ctx, sh, pkcs11.CKO_PUBLIC_KEY, label)
	if err != nil {
		return false, err
	}
	kt, curve, err := keyInfo(ctx, sh, obj)
	if err != nil {
		return false, err
	}
	mech, err := mechanismFor(kt, hash, digest)
	if err != nil {
		return false, err
	}
	if kt == pkcs11.CKK_EC {
		if signature, err = pkgcrypto.ECDSAASN1ToRaw(curve, signature); err != nil {
			return false, nil
		}
	}
	if err := ctx.VerifyInit(sh, []*pkcs11.Mechanism{mech}, obj); err != nil {
		return false, fmt.Errorf("C_VerifyInit: %w", err)
	}
	if err := ctx.Verify(sh, digest, signature); err != nil {
		if isRV(err, pkcs11.CKR_SIGNATURE_INVALID) || isRV(err, pkcs11.CKR_SIGNATURE_LEN_RANGE) {
			return false, nil
		}
		return false, fmt.Errorf("C_Verify: %w", err)
	}
	return true, nil
}

// destroy removes every object labelled label and returns how many.
func destroy(ctx *pkcs11.Ctx, sh pkcs11.SessionHandle, label string) (int, error) {
	objs, err := find(ctx, sh, -1, label)
	if err != nil {
		return 0, err
	}
	if len(objs) == 0 {
		return 0, hsm.ErrNotFound
	}
	for _, o := range objs {
		if err := ctx.DestroyObject(sh, o); err != nil {
			return 0, fmt.Errorf("C_DestroyObject: %w", err)
		}
	}
	return len(objs), nil
}

// status describes the library and token.
func (p *Provider) status(cfg TenantConfig) (hsm.Status, error) {
	st := hsm.Status{Configured: true, ProviderName: cfg.Provider, Library: cfg.Library}
	m, err := p.module(cfg.Library)
	if err != nil {
		return st, err
	}
	if info, err := m.ctx.GetInfo(); err == nil {
		st.Manufacturer = strings.TrimSpace(info.ManufacturerID)
		st.CryptokiVer = fmt.Sprintf("%d.%d", info.CryptokiVersion.Major, info.CryptokiVersion.Minor)
	}
	ctx, sh, release, err := p.session(cfg)
	if err != nil {
		return st, err
	}
	defer release()
	st.Connected = true
	if slot, err := m.findSlot(cfg); err == nil {
		if ti, err := ctx.GetTokenInfo(slot); err == nil {
			st.TokenLabel = strings.TrimSpace(ti.Label)
			st.Model = strings.TrimSpace(ti.Model)
			st.SerialNumber = strings.TrimSpace(ti.SerialNumber)
			st.Manufacturer = firstNonEmpty(strings.TrimSpace(ti.ManufacturerID), st.Manufacturer)
			st.Firmware = fmt.Sprintf("%d.%d", ti.FirmwareVersion.Major, ti.FirmwareVersion.Minor)
		}
	}
	if _, err := findOne(ctx, sh, pkcs11.CKO_SECRET_KEY, hsm.TenantKeyLabel(cfg.TenantID)); err == nil {
		st.TenantKeyReady = true
	}
	return st, nil
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
