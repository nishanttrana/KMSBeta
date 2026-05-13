package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
)

// CompositeSignature is the on-the-wire bundle for hybrid signatures.
// Both legs sign the same message; verifiers accept the bundle when
// either leg validates, which lets verifiers transition off classical
// primitives independently of signers. The Encoding field is reserved
// for future variants (e.g., the IETF composite-signatures draft) so
// today's "concat" format isn't a permanent commitment.
type CompositeSignature struct {
	Encoding         string `json:"encoding"`            // "vecta-composite-v1"
	ClassicalAlg     string `json:"classical_algorithm"`
	PQCAlg           string `json:"pqc_algorithm"`
	ClassicalSigB64  string `json:"classical_signature"`
	PQCSigB64        string `json:"pqc_signature"`
	MessageHashB64   string `json:"message_hash"`
}

// NewCompositeSignature wraps two raw signatures and the canonicalised
// message hash. The hash is included so verifiers can sanity-check that
// both legs operated on the same input without re-running the hash.
func NewCompositeSignature(classicalAlg, pqcAlg string, classicalSig, pqcSig, messageHash []byte) CompositeSignature {
	return CompositeSignature{
		Encoding:        "vecta-composite-v1",
		ClassicalAlg:    classicalAlg,
		PQCAlg:          pqcAlg,
		ClassicalSigB64: base64.StdEncoding.EncodeToString(classicalSig),
		PQCSigB64:       base64.StdEncoding.EncodeToString(pqcSig),
		MessageHashB64:  base64.StdEncoding.EncodeToString(messageHash),
	}
}

// Marshal returns the canonical JSON encoding suitable for transport or
// persistence. Verifiers parse via UnmarshalCompositeSignature.
func (s CompositeSignature) Marshal() ([]byte, error) {
	return json.Marshal(s)
}

// UnmarshalCompositeSignature parses the JSON encoding.
func UnmarshalCompositeSignature(raw []byte) (CompositeSignature, error) {
	var out CompositeSignature
	if err := json.Unmarshal(raw, &out); err != nil {
		return CompositeSignature{}, err
	}
	if out.Encoding != "vecta-composite-v1" {
		return CompositeSignature{}, errors.New("unsupported composite signature encoding")
	}
	return out, nil
}

// Verifier is the per-leg verification helper. The caller supplies one
// implementation per algorithm; ComposeVerify accepts the signature as
// valid if either leg verifies cleanly. This is the "transition off
// classical independently" property in action.
type Verifier func(messageHash, signature []byte) error

// MLDSAVerifier returns a Verifier callback bound to a public key and
// context string. The signature-context bytes must match the value used
// at signing time (FIPS 204 §3.2); we hard-code the application label
// "vecta-kms-composite/v1" so any leg of the composite is bound to the
// composite scheme and cannot be lifted into a different signing context.
func MLDSAVerifier(algorithm string, publicKey []byte) Verifier {
	ctx := []byte("vecta-kms-composite/v1")
	return func(messageHash, signature []byte) error {
		return MLDSAVerify(algorithm, publicKey, messageHash, ctx, signature)
	}
}

// MLDSAComposeSign produces a CompositeSignature whose PQC leg is a real
// ML-DSA signature. The classical leg is supplied as raw bytes by the
// caller so this helper stays decoupled from the classical signer
// (ECDSA, RSA, Ed25519 — operators choose). messageHash is what both
// legs sign over; bundling it into the composite means verifiers can
// validate either leg against the same canonical input.
func MLDSAComposeSign(pqcAlgorithm string, pqcPrivateKey []byte, classicalAlgorithm string, classicalSignature, messageHash []byte) (CompositeSignature, error) {
	ctx := []byte("vecta-kms-composite/v1")
	pqcSig, err := MLDSASign(pqcAlgorithm, pqcPrivateKey, messageHash, ctx)
	if err != nil {
		return CompositeSignature{}, err
	}
	return NewCompositeSignature(classicalAlgorithm, pqcAlgorithm, classicalSignature, pqcSig, messageHash), nil
}

// ComposeVerify validates a composite signature against the supplied
// per-leg verifiers. Returns nil if either succeeds.
func ComposeVerify(sig CompositeSignature, classical, pqc Verifier) error {
	hash, err := base64.StdEncoding.DecodeString(sig.MessageHashB64)
	if err != nil {
		return errors.New("composite verify: malformed message hash")
	}
	if classical != nil {
		classicalSig, err := base64.StdEncoding.DecodeString(sig.ClassicalSigB64)
		if err == nil {
			if err := classical(hash, classicalSig); err == nil {
				return nil
			}
		}
	}
	if pqc != nil {
		pqcSig, err := base64.StdEncoding.DecodeString(sig.PQCSigB64)
		if err == nil {
			if err := pqc(hash, pqcSig); err == nil {
				return nil
			}
		}
	}
	return errors.New("composite verify: neither leg verified")
}
