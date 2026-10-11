package hsmconnector

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"

	"github.com/miekg/pkcs11"

	pkgcrypto "vecta-kms/pkg/crypto"
	"vecta-kms/pkg/hsm"
	"vecta-kms/pkg/route"
)

// Bring your own key from the HSM to a cloud KMS. The cloud hands out an RSA
// import key; the HSM wraps its own key to it with C_WrapKey, so the key's
// value never exists outside the HSM or the cloud's HSM. Only keys generated
// for this (CKA_EXTRACTABLE true, CKA_SENSITIVE true) can be wrapped; every
// other platform key is never extractable and the HSM refuses.
//
// The schemes are pkg/crypto's cloud wrapping schemes. rsa-aes-kwp-* is
// CKM_RSA_AES_KEY_WRAP built from two mechanisms every HSM has: a session
// AES-256 key wraps the target with CKM_AES_KEY_WRAP_PAD, and RSA-OAEP wraps
// that AES key to the cloud's key. Both temporary objects are destroyed.

var errNotExtractable = errors.New("this HSM key was not generated for cloud import (it is not extractable); create the key with cloud import allowed")

func oaepMechanism(sha1 bool) *pkcs11.Mechanism {
	if sha1 {
		return pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_OAEP, pkcs11.NewOAEPParams(pkcs11.CKM_SHA_1, pkcs11.CKG_MGF1_SHA1, pkcs11.CKZ_DATA_SPECIFIED, nil))
	}
	return pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_OAEP, pkcs11.NewOAEPParams(pkcs11.CKM_SHA256, pkcs11.CKG_MGF1_SHA256, pkcs11.CKZ_DATA_SPECIFIED, nil))
}

// wrapTarget finds the object to wrap: the secret key, or the private half
// of a key pair, labelled label.
func wrapTarget(ctx *pkcs11.Ctx, sh pkcs11.SessionHandle, label string) (pkcs11.ObjectHandle, error) {
	obj, err := findOne(ctx, sh, pkcs11.CKO_SECRET_KEY, label)
	if errors.Is(err, hsm.ErrNotFound) {
		return findOne(ctx, sh, pkcs11.CKO_PRIVATE_KEY, label)
	}
	return obj, err
}

// wrapForCloud wraps the key labelled label to the cloud's RSA key.
func wrapForCloud(ctx *pkcs11.Ctx, sh pkcs11.SessionHandle, label string, cloudKey []byte, scheme string) ([]byte, error) {
	sha1, kwp := false, false
	switch scheme {
	case pkgcrypto.CloudWrapRSAOAEPSHA256:
	case pkgcrypto.CloudWrapRSAOAEPSHA1:
		sha1 = true
	case pkgcrypto.CloudWrapRSAAESKWP256:
		kwp = true
	case pkgcrypto.CloudWrapRSAAESKWPSHA1:
		sha1, kwp = true, true
	default:
		return nil, fmt.Errorf("unknown cloud wrapping scheme %q", scheme)
	}
	pub, err := pkgcrypto.ParseCloudWrappingKey(cloudKey)
	if err != nil {
		return nil, err
	}
	if pub.N.BitLen() < 2048 {
		return nil, errors.New("the cloud's wrapping key must be RSA of at least 2048 bits")
	}
	target, err := wrapTarget(ctx, sh, label)
	if err != nil {
		return nil, err
	}
	n, e := pkgcrypto.RSAPublicComponents(pub)
	rsaObj, err := ctx.CreateObject(sh, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false),
		pkcs11.NewAttribute(pkcs11.CKA_WRAP, true),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, false),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, false),
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS, n),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, e),
	})
	if err != nil {
		return nil, fmt.Errorf("C_CreateObject (cloud wrapping key): %w", err)
	}
	defer ctx.DestroyObject(sh, rsaObj) //nolint:errcheck
	if !kwp {
		out, err := ctx.WrapKey(sh, []*pkcs11.Mechanism{oaepMechanism(sha1)}, rsaObj, target)
		return out, wrapError(err)
	}
	aesObj, err := ctx.GenerateKey(sh, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_KEY_GEN, nil)}, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_AES),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, 32),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, true),
		pkcs11.NewAttribute(pkcs11.CKA_WRAP, true),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, false),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, false),
	})
	if err != nil {
		return nil, fmt.Errorf("C_GenerateKey (temporary AES key): %w", err)
	}
	defer ctx.DestroyObject(sh, aesObj) //nolint:errcheck
	tail, err := ctx.WrapKey(sh, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_KEY_WRAP_PAD, nil)}, aesObj, target)
	if err != nil {
		return nil, wrapError(err)
	}
	head, err := ctx.WrapKey(sh, []*pkcs11.Mechanism{oaepMechanism(sha1)}, rsaObj, aesObj)
	if err != nil {
		return nil, fmt.Errorf("C_WrapKey (RSA-OAEP, temporary AES key): %w", err)
	}
	return append(head, tail...), nil
}

func wrapError(err error) error {
	if err == nil {
		return nil
	}
	if isRV(err, pkcs11.CKR_KEY_UNEXTRACTABLE) || isRV(err, pkcs11.CKR_KEY_NOT_WRAPPABLE) {
		return errNotExtractable
	}
	return fmt.Errorf("C_WrapKey: %w", err)
}

// digestKey is SHA-256 over the key's value, computed in the HSM
// (C_DigestKey). Salesforce Shield takes it with the wrapped key to check
// what it unwrapped.
func digestKey(ctx *pkcs11.Ctx, sh pkcs11.SessionHandle, label string) ([]byte, error) {
	obj, err := findOne(ctx, sh, pkcs11.CKO_SECRET_KEY, label)
	if err != nil {
		return nil, err
	}
	if err := ctx.DigestInit(sh, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_SHA256, nil)}); err != nil {
		return nil, fmt.Errorf("C_DigestInit: %w", err)
	}
	if err := ctx.DigestKey(sh, obj); err != nil {
		_, _ = ctx.DigestFinal(sh)
		return nil, wrapError(fmt.Errorf("C_DigestKey: %w", err))
	}
	return ctx.DigestFinal(sh)
}

// wrapForImport is POST /hsm/keys/wrap-for-import: keycore asks the HSM to
// wrap a key it created with cloud import allowed. The wrapped key is safe
// to hand to the cloud; nothing else leaves.
func (h *Handler) wrapForImport(c *route.Call) {
	in, ctx, sh, release, ok := h.begin(c, keyManager, true)
	if !ok {
		return
	}
	defer release()
	c.Detail("scheme", in.Scheme)
	cloudKey, ok := decode(c, "wrapping_key_b64", in.WrappingKeyB64)
	if !ok {
		return
	}
	if fp, err := pkgcrypto.ParseCloudWrappingKey(cloudKey); err == nil {
		if f, err := pkgcrypto.FingerprintPublicKey(fp); err == nil {
			c.Detail("wrapping_key_sha256", f)
		}
	}
	wrapped, err := wrapForCloud(ctx, sh, in.Label, cloudKey, in.Scheme)
	if errors.Is(err, errNotExtractable) {
		c.Refuse(http.StatusConflict, "key_not_extractable", err.Error())
		return
	}
	if err != nil {
		if errors.Is(err, hsm.ErrNotFound) {
			h.fail(c, err)
			return
		}
		c.Error(http.StatusBadRequest, "wrap_failed", err.Error())
		return
	}
	out := map[string]interface{}{"wrapped_b64": base64.StdEncoding.EncodeToString(wrapped), "scheme": in.Scheme}
	if in.Digest == "sha256" {
		sum, err := digestKey(ctx, sh, in.Label)
		if err != nil {
			h.fail(c, err)
			return
		}
		out["material_sha256_b64"] = base64.StdEncoding.EncodeToString(sum)
	}
	id := h.identity(c)
	c.Detail("hsm_serial", id.SerialNumber)
	out["hsm"] = id
	c.JSON(http.StatusOK, out)
}
