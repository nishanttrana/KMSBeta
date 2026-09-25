package crypto

import (
	"crypto/mlkem"
	"errors"
)

// KEM sealing moves a secret to one recipient process, for example a keycore
// master key to a joining cluster node (docs/CLUSTERING.md). Every step is in
// the FIPS 140-3 Go Cryptographic Module: ML-KEM-768 (FIPS 203) encapsulation,
// HKDF-SHA256, AES-256-GCM with a module-generated IV. label names the secret's
// purpose and aad binds the transfer context (node ids, join token), so a
// sealed secret cannot be replayed into another purpose or join.

const kemSealInfo = "vecta/kem-seal/v1|"

var errKEMSealed = errors.New("crypto: sealed secret is malformed or was not sealed to this recipient")

// KEMRecipient holds an ML-KEM-768 decapsulation key. Keep it in memory only,
// for one transfer.
type KEMRecipient struct {
	dk *mlkem.DecapsulationKey768
}

func NewKEMRecipient() (*KEMRecipient, error) {
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, err
	}
	return &KEMRecipient{dk: dk}, nil
}

// EncapsulationKey is the public key a sender seals to.
func (r *KEMRecipient) EncapsulationKey() []byte {
	return r.dk.EncapsulationKey().Bytes()
}

func kemSealKey(shared []byte, label string) ([]byte, error) {
	defer Zeroize(shared)
	return HKDFSHA256(shared, nil, []byte(kemSealInfo+label), 32)
}

// KEMSeal seals plaintext to the holder of encapsulationKey.
func KEMSeal(encapsulationKey, plaintext, aad []byte, label string) ([]byte, error) {
	ek, err := mlkem.NewEncapsulationKey768(encapsulationKey)
	if err != nil {
		return nil, err
	}
	shared, ct := ek.Encapsulate()
	key, err := kemSealKey(shared, label)
	if err != nil {
		return nil, err
	}
	defer Zeroize(key)
	blob, err := Seal(key, plaintext, aad)
	if err != nil {
		return nil, err
	}
	return append(ct, blob...), nil
}

// Open recovers a secret sealed to this recipient with the same label and aad.
func (r *KEMRecipient) Open(sealed, aad []byte, label string) ([]byte, error) {
	if len(sealed) <= mlkem.CiphertextSize768 {
		return nil, errKEMSealed
	}
	shared, err := r.dk.Decapsulate(sealed[:mlkem.CiphertextSize768])
	if err != nil {
		return nil, errKEMSealed
	}
	key, err := kemSealKey(shared, label)
	if err != nil {
		return nil, err
	}
	defer Zeroize(key)
	out, err := Open(key, sealed[mlkem.CiphertextSize768:], aad)
	if err != nil {
		return nil, errKEMSealed
	}
	return out, nil
}
