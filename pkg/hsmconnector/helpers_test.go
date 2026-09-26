package hsmconnector

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"errors"

	"github.com/miekg/pkcs11"
)

func valueAttr() []*pkcs11.Attribute {
	return []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_VALUE, nil)}
}

// verifySoftware checks an HSM signature with Go's own implementation.
func verifySoftware(pub interface{}, digest, sig []byte) error {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return rsa.VerifyPSS(k, crypto.SHA256, digest, sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(k, digest, sig) {
			return errors.New("ecdsa signature invalid")
		}
		return nil
	}
	return errors.New("unexpected public key type")
}
