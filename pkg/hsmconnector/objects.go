package hsmconnector

import (
	"bytes"
	"crypto/x509"
	"encoding/hex"
	"strings"
	"time"

	"github.com/miekg/pkcs11"

	pkgcrypto "vecta-kms/pkg/crypto"
	"vecta-kms/pkg/hsm"
)

// Reading objects back from the HSM: the attributes of a key the KMS
// generated (proof it was made on the token, sensitive and never
// extractable) and the keys and certificates already in a partition.

// maxObjects bounds a partition listing.
const maxObjects = 2000

var classNames = map[uint]string{
	pkcs11.CKO_SECRET_KEY: "secret_key", pkcs11.CKO_PRIVATE_KEY: "private_key",
	pkcs11.CKO_PUBLIC_KEY: "public_key", pkcs11.CKO_CERTIFICATE: "certificate", pkcs11.CKO_DATA: "data",
}

var keyTypeNames = map[uint]string{
	pkcs11.CKK_AES: "AES", pkcs11.CKK_RSA: "RSA", pkcs11.CKK_EC: "EC", pkcs11.CKK_DES3: "DES3",
	pkcs11.CKK_GENERIC_SECRET: "GENERIC_SECRET", pkcs11.CKK_DSA: "DSA", pkcs11.CKK_DH: "DH",
}

// attr reads one attribute; nil when the library doesn't report it. Read
// one at a time: a library may fail the whole call for one attribute that
// doesn't apply to the object.
func attr(ctx *pkcs11.Ctx, sh pkcs11.SessionHandle, obj pkcs11.ObjectHandle, typ uint) []byte {
	a, err := ctx.GetAttributeValue(sh, obj, []*pkcs11.Attribute{pkcs11.NewAttribute(typ, nil)})
	if err != nil || len(a) == 0 {
		return nil
	}
	return a[0].Value
}

func boolAttr(ctx *pkcs11.Ctx, sh pkcs11.SessionHandle, obj pkcs11.ObjectHandle, typ uint) *bool {
	v := attr(ctx, sh, obj, typ)
	if len(v) != 1 {
		return nil
	}
	b := v[0] != 0
	return &b
}

// describe reads an object's attributes. It never reads CKA_VALUE of a key.
func describe(ctx *pkcs11.Ctx, sh pkcs11.SessionHandle, obj pkcs11.ObjectHandle) hsm.ObjectInfo {
	info := hsm.ObjectInfo{
		Label: string(attr(ctx, sh, obj, pkcs11.CKA_LABEL)),
		IDHex: hex.EncodeToString(attr(ctx, sh, obj, pkcs11.CKA_ID)),
		Class: "other",
	}
	class := bytesToUint(attr(ctx, sh, obj, pkcs11.CKA_CLASS))
	if n, ok := classNames[class]; ok {
		info.Class = n
	}
	info.Token = boolAttr(ctx, sh, obj, pkcs11.CKA_TOKEN)
	info.Private = boolAttr(ctx, sh, obj, pkcs11.CKA_PRIVATE)
	if class == pkcs11.CKO_CERTIFICATE {
		info.Certificate = certInfo(attr(ctx, sh, obj, pkcs11.CKA_VALUE))
		return info
	}
	if class != pkcs11.CKO_SECRET_KEY && class != pkcs11.CKO_PRIVATE_KEY && class != pkcs11.CKO_PUBLIC_KEY {
		return info
	}
	kt := bytesToUint(attr(ctx, sh, obj, pkcs11.CKA_KEY_TYPE))
	info.KeyType = keyTypeNames[kt]
	if info.KeyType == "" {
		info.KeyType = "0x" + hex.EncodeToString(attr(ctx, sh, obj, pkcs11.CKA_KEY_TYPE))
	}
	switch kt {
	case pkcs11.CKK_RSA:
		if n := attr(ctx, sh, obj, pkcs11.CKA_MODULUS); len(n) > 0 {
			info.SizeBits = len(bytes.TrimLeft(n, "\x00")) * 8
		} else if b := attr(ctx, sh, obj, pkcs11.CKA_MODULUS_BITS); len(b) > 0 {
			info.SizeBits = int(bytesToUint(b))
		}
	case pkcs11.CKK_EC:
		params := attr(ctx, sh, obj, pkcs11.CKA_EC_PARAMS)
		for c, bits := range map[string]int{"P256": 256, "P384": 384} {
			if want, _ := pkgcrypto.ECCurveParamsDER(c); bytes.Equal(want, params) {
				info.Curve, info.SizeBits = c, bits
			}
		}
	default:
		if b := attr(ctx, sh, obj, pkcs11.CKA_VALUE_LEN); len(b) > 0 {
			info.SizeBits = int(bytesToUint(b)) * 8
		}
	}
	if class != pkcs11.CKO_PUBLIC_KEY {
		info.Sensitive = boolAttr(ctx, sh, obj, pkcs11.CKA_SENSITIVE)
		info.Extractable = boolAttr(ctx, sh, obj, pkcs11.CKA_EXTRACTABLE)
		info.AlwaysSensitive = boolAttr(ctx, sh, obj, pkcs11.CKA_ALWAYS_SENSITIVE)
		info.NeverExtractable = boolAttr(ctx, sh, obj, pkcs11.CKA_NEVER_EXTRACTABLE)
	}
	info.Local = boolAttr(ctx, sh, obj, pkcs11.CKA_LOCAL)
	info.Encrypt = boolAttr(ctx, sh, obj, pkcs11.CKA_ENCRYPT)
	info.Decrypt = boolAttr(ctx, sh, obj, pkcs11.CKA_DECRYPT)
	info.Sign = boolAttr(ctx, sh, obj, pkcs11.CKA_SIGN)
	info.Verify = boolAttr(ctx, sh, obj, pkcs11.CKA_VERIFY)
	info.Wrap = boolAttr(ctx, sh, obj, pkcs11.CKA_WRAP)
	info.Unwrap = boolAttr(ctx, sh, obj, pkcs11.CKA_UNWRAP)
	return info
}

func certInfo(der []byte) *hsm.CertInfo {
	if len(der) == 0 {
		return nil
	}
	sum, _ := pkgcrypto.Hash("SHA-256", der)
	ci := &hsm.CertInfo{SHA256: hex.EncodeToString(sum)}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		ci.Subject = "(unparseable certificate)"
		return ci
	}
	ci.Subject, ci.Issuer = cert.Subject.String(), cert.Issuer.String()
	ci.Serial = strings.ToUpper(cert.SerialNumber.Text(16))
	ci.NotBefore, ci.NotAfter = cert.NotBefore.UTC().Format(time.RFC3339), cert.NotAfter.UTC().Format(time.RFC3339)
	return ci
}

// inspect describes every object labelled label.
func inspect(ctx *pkcs11.Ctx, sh pkcs11.SessionHandle, label string) ([]hsm.ObjectInfo, error) {
	objs, err := find(ctx, sh, -1, label)
	if err != nil {
		return nil, err
	}
	if len(objs) == 0 {
		return nil, hsm.ErrNotFound
	}
	out := make([]hsm.ObjectInfo, 0, len(objs))
	for _, o := range objs {
		info := describe(ctx, sh, o)
		info.Managed = true
		out = append(out, info)
	}
	return out, nil
}

// listObjects returns the keys and certificates visible to the tenant's
// login. The tenant's own KMS objects are marked managed; objects the KMS
// didn't create are listed as found; other tenants' KMS objects on a shared
// partition are left out.
func listObjects(ctx *pkcs11.Ctx, sh pkcs11.SessionHandle, tenant string) ([]hsm.ObjectInfo, bool, error) {
	if err := ctx.FindObjectsInit(sh, nil); err != nil {
		return nil, false, err
	}
	var handles []pkcs11.ObjectHandle
	truncated := false
	for {
		batch, _, err := ctx.FindObjects(sh, 100)
		if err != nil {
			_ = ctx.FindObjectsFinal(sh)
			return nil, false, err
		}
		if len(batch) == 0 {
			break
		}
		handles = append(handles, batch...)
		if len(handles) >= maxObjects {
			handles, truncated = handles[:maxObjects], true
			break
		}
	}
	_ = ctx.FindObjectsFinal(sh)
	own := hsm.TenantPrefix(tenant)
	out := make([]hsm.ObjectInfo, 0, len(handles))
	for _, o := range handles {
		label := string(attr(ctx, sh, o, pkcs11.CKA_LABEL))
		if strings.HasPrefix(label, "vecta:") && !strings.HasPrefix(label, own) {
			continue
		}
		info := describe(ctx, sh, o)
		if info.Class == "data" || info.Class == "other" {
			continue
		}
		info.Managed = strings.HasPrefix(label, own)
		out = append(out, info)
	}
	return out, truncated, nil
}

// identity reads the token's identity for cfg.
func (p *Provider) identity(cfg TenantConfig) hsm.Identity {
	m, err := p.module(cfg.Library)
	if err != nil {
		return hsm.Identity{}
	}
	slot, err := m.findSlot(cfg)
	if err != nil {
		return hsm.Identity{}
	}
	ti, err := m.ctx.GetTokenInfo(slot)
	if err != nil {
		return hsm.Identity{}
	}
	return hsm.Identity{
		Manufacturer: strings.TrimSpace(ti.ManufacturerID), Model: strings.TrimSpace(ti.Model),
		SerialNumber: strings.TrimSpace(ti.SerialNumber), TokenLabel: strings.TrimSpace(ti.Label),
	}
}
