package main

import (
	"crypto/mlkem"
	"errors"
	"fmt"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
)

// PQCKeyPair is the canonical representation of a generated PQC keypair.
// PublicKey and PrivateKey are the wire-format byte representations
// (NIST FIPS 203/204 encoding); higher layers wrap them under the
// MEK before persistence so this file never sees raw private material
// outside the generation moment.
type PQCKeyPair struct {
	Algorithm  string // "ML-KEM-768", "ML-KEM-1024", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87"
	PublicKey  []byte
	PrivateKey []byte
}

// GenerateMLKEM768 produces a NIST FIPS 203 ML-KEM-768 keypair from the
// stdlib (crypto/mlkem). FIPS 203 is the standardised version of
// CRYSTALS-Kyber; ML-KEM-768 is the parameter set NIST recommends for
// "Category 3" security (128-bit classical strength against quantum).
func GenerateMLKEM768() (*PQCKeyPair, error) {
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, fmt.Errorf("ml-kem-768 generate: %w", err)
	}
	return &PQCKeyPair{
		Algorithm:  "ML-KEM-768",
		PublicKey:  dk.EncapsulationKey().Bytes(),
		PrivateKey: dk.Bytes(),
	}, nil
}

// GenerateMLKEM1024 produces a NIST Category-5 (256-bit-equivalent)
// ML-KEM-1024 keypair. Picked when the operator's data classification
// or policy demands the strongest available standardised PQC KEM.
func GenerateMLKEM1024() (*PQCKeyPair, error) {
	dk, err := mlkem.GenerateKey1024()
	if err != nil {
		return nil, fmt.Errorf("ml-kem-1024 generate: %w", err)
	}
	return &PQCKeyPair{
		Algorithm:  "ML-KEM-1024",
		PublicKey:  dk.EncapsulationKey().Bytes(),
		PrivateKey: dk.Bytes(),
	}, nil
}

// MLKEMEncapsulate produces a shared key and ciphertext using the
// recipient's public encapsulation key. The caller XORs/derives a
// symmetric key from sharedKey via HKDF; the raw value is never used
// directly. ciphertext is the wire blob the recipient needs to
// decapsulate to recover sharedKey.
func MLKEMEncapsulate(algorithm string, publicKey []byte) (sharedKey, ciphertext []byte, err error) {
	switch algorithm {
	case "ML-KEM-768":
		ek, err := mlkem.NewEncapsulationKey768(publicKey)
		if err != nil {
			return nil, nil, fmt.Errorf("ml-kem-768 decode pk: %w", err)
		}
		shared, ct := ek.Encapsulate()
		return shared, ct, nil
	case "ML-KEM-1024":
		ek, err := mlkem.NewEncapsulationKey1024(publicKey)
		if err != nil {
			return nil, nil, fmt.Errorf("ml-kem-1024 decode pk: %w", err)
		}
		shared, ct := ek.Encapsulate()
		return shared, ct, nil
	default:
		return nil, nil, errors.New("unsupported ML-KEM algorithm")
	}
}

// MLKEMDecapsulate recovers the shared key from a ciphertext using the
// recipient's private decapsulation key. The recipient validates the
// resulting key by deriving the same downstream KDF as the sender.
func MLKEMDecapsulate(algorithm string, privateKey, ciphertext []byte) ([]byte, error) {
	switch algorithm {
	case "ML-KEM-768":
		dk, err := mlkem.NewDecapsulationKey768(privateKey)
		if err != nil {
			return nil, fmt.Errorf("ml-kem-768 decode sk: %w", err)
		}
		return dk.Decapsulate(ciphertext)
	case "ML-KEM-1024":
		dk, err := mlkem.NewDecapsulationKey1024(privateKey)
		if err != nil {
			return nil, fmt.Errorf("ml-kem-1024 decode sk: %w", err)
		}
		return dk.Decapsulate(ciphertext)
	default:
		return nil, errors.New("unsupported ML-KEM algorithm")
	}
}

// GenerateMLDSA generates a FIPS 204 ML-DSA keypair for the requested
// parameter set. ML-DSA is the standardised CRYSTALS-Dilithium scheme;
// 44/65/87 correspond to NIST Categories 2/3/5 (~128/192/256-bit
// classical-equivalent strength).
func GenerateMLDSA(algorithm string) (*PQCKeyPair, error) {
	switch algorithm {
	case "ML-DSA-44":
		pk, sk, err := mldsa44.GenerateKey(nil)
		if err != nil {
			return nil, fmt.Errorf("ml-dsa-44 generate: %w", err)
		}
		pkBytes, _ := pk.MarshalBinary()
		skBytes, _ := sk.MarshalBinary()
		return &PQCKeyPair{Algorithm: algorithm, PublicKey: pkBytes, PrivateKey: skBytes}, nil
	case "ML-DSA-65":
		pk, sk, err := mldsa65.GenerateKey(nil)
		if err != nil {
			return nil, fmt.Errorf("ml-dsa-65 generate: %w", err)
		}
		pkBytes, _ := pk.MarshalBinary()
		skBytes, _ := sk.MarshalBinary()
		return &PQCKeyPair{Algorithm: algorithm, PublicKey: pkBytes, PrivateKey: skBytes}, nil
	case "ML-DSA-87":
		pk, sk, err := mldsa87.GenerateKey(nil)
		if err != nil {
			return nil, fmt.Errorf("ml-dsa-87 generate: %w", err)
		}
		pkBytes, _ := pk.MarshalBinary()
		skBytes, _ := sk.MarshalBinary()
		return &PQCKeyPair{Algorithm: algorithm, PublicKey: pkBytes, PrivateKey: skBytes}, nil
	default:
		return nil, errors.New("unsupported ML-DSA algorithm")
	}
}

// MLDSASign signs msg using the supplied private key. ctx is the FIPS 204
// "context string" — callers should always pass a non-empty value tied
// to the application domain (e.g. "vecta-kms-audit-chain/v1") so a
// signature minted for one purpose cannot be replayed in another.
func MLDSASign(algorithm string, privateKey, msg, ctx []byte) ([]byte, error) {
	switch algorithm {
	case "ML-DSA-44":
		var sk mldsa44.PrivateKey
		if err := sk.UnmarshalBinary(privateKey); err != nil {
			return nil, err
		}
		sig := make([]byte, mldsa44.SignatureSize)
		if err := mldsa44.SignTo(&sk, msg, ctx, false, sig); err != nil {
			return nil, err
		}
		return sig, nil
	case "ML-DSA-65":
		var sk mldsa65.PrivateKey
		if err := sk.UnmarshalBinary(privateKey); err != nil {
			return nil, err
		}
		sig := make([]byte, mldsa65.SignatureSize)
		if err := mldsa65.SignTo(&sk, msg, ctx, false, sig); err != nil {
			return nil, err
		}
		return sig, nil
	case "ML-DSA-87":
		var sk mldsa87.PrivateKey
		if err := sk.UnmarshalBinary(privateKey); err != nil {
			return nil, err
		}
		sig := make([]byte, mldsa87.SignatureSize)
		if err := mldsa87.SignTo(&sk, msg, ctx, false, sig); err != nil {
			return nil, err
		}
		return sig, nil
	default:
		return nil, errors.New("unsupported ML-DSA algorithm")
	}
}

// MLDSAVerify returns nil when the signature validates and a non-nil
// error otherwise. Like MLDSASign, the ctx must match the value used at
// signing time.
func MLDSAVerify(algorithm string, publicKey, msg, ctx, sig []byte) error {
	switch algorithm {
	case "ML-DSA-44":
		var pk mldsa44.PublicKey
		if err := pk.UnmarshalBinary(publicKey); err != nil {
			return err
		}
		if !mldsa44.Verify(&pk, msg, ctx, sig) {
			return errors.New("ml-dsa-44 verify failed")
		}
		return nil
	case "ML-DSA-65":
		var pk mldsa65.PublicKey
		if err := pk.UnmarshalBinary(publicKey); err != nil {
			return err
		}
		if !mldsa65.Verify(&pk, msg, ctx, sig) {
			return errors.New("ml-dsa-65 verify failed")
		}
		return nil
	case "ML-DSA-87":
		var pk mldsa87.PublicKey
		if err := pk.UnmarshalBinary(publicKey); err != nil {
			return err
		}
		if !mldsa87.Verify(&pk, msg, ctx, sig) {
			return errors.New("ml-dsa-87 verify failed")
		}
		return nil
	default:
		return errors.New("unsupported ML-DSA algorithm")
	}
}
