package main

import (
	"context"
	"crypto/fips140"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"vecta-kms/pkg/crypto"
)

// Wrap and unwrap with a named algorithm (wrap_algorithm on POST
// /keys/{id}/wrap and /unwrap): A256KW and A256KWP under an AES-256 key,
// RSA-OAEP-256 and RSA-OAEP under an RSA key. A caller that speaks a fixed
// wire format needs these; Azure Managed HSM external key management sends
// them through the HYOK service (13.30.0-beta). The output is exactly the
// named algorithm's, with no IV or version beside it, so an unwrap without a
// version tries the current version and then older ones, newest first, and
// takes the first whose integrity check passes. A failed attempt rolls back
// and counts nothing.

var errJWAMismatch = errors.New("the wrapped key does not open under this key version")

// errDecryptMismatch: an any-version decrypt (DecryptRequest.AnyVersion)
// found no version of the key that opens the ciphertext.
var errDecryptMismatch = errors.New("the ciphertext does not open under any version of this key")

// checkWrapAlgorithm validates a wrap_algorithm for an operation, and
// refuses one that strict FIPS mode doesn't allow.
func checkWrapAlgorithm(operation, alg string) error {
	if !crypto.JWAIsAES(alg) && !crypto.JWAIsRSA(alg) {
		return fmt.Errorf("wrap_algorithm %q is not one of A256KW, A256KWP, RSA-OAEP-256, RSA-OAEP", alg)
	}
	if operation != "wrap" && operation != "unwrap" {
		return errors.New("wrap_algorithm applies only to wrap and unwrap")
	}
	if crypto.JWANeedsModuleOutside(alg) && fips140.Enforced() {
		return fipsModeViolationError{Operation: "key." + operation, Algorithm: alg}
	}
	return nil
}

// wrapAlgorithmFitsKey refuses an AES algorithm on an RSA key and the reverse.
func wrapAlgorithmFitsKey(algorithm, alg string) error {
	a := strings.ToUpper(algorithm)
	switch {
	case crypto.JWAIsAES(alg) && strings.Contains(a, "AES") && !strings.Contains(a, "AES-128") && !strings.Contains(a, "AES-192"):
		return nil
	case crypto.JWAIsRSA(alg) && strings.Contains(a, "RSA"):
		return nil
	}
	return fmt.Errorf("wrap_algorithm %s does not apply to a %s key", alg, algorithm)
}

func jwaWrapMaterial(k Key, raw []byte, alg string, plain []byte) ([]byte, error) {
	if err := wrapAlgorithmFitsKey(k.Algorithm, alg); err != nil {
		return nil, err
	}
	if crypto.JWAIsAES(alg) {
		key, err := normalizeAESKeyForAlgorithm(raw, k.Algorithm)
		if err != nil {
			return nil, err
		}
		defer crypto.Zeroize(key)
		return crypto.JWAWrapAES(alg, key, plain)
	}
	if isPublicKeyType(k.KeyType) {
		pub, err := parseRSAPublicMaterial(raw)
		if err != nil {
			return nil, err
		}
		return crypto.JWAWrapRSA(alg, pub, plain)
	}
	priv, err := parseRSAPrivateMaterial(raw)
	if err != nil {
		return nil, err
	}
	return crypto.JWAWrapRSA(alg, &priv.PublicKey, plain)
}

func jwaUnwrapMaterial(k Key, raw []byte, alg string, wrapped []byte) ([]byte, error) {
	if err := wrapAlgorithmFitsKey(k.Algorithm, alg); err != nil {
		return nil, err
	}
	if crypto.JWAIsAES(alg) {
		key, err := normalizeAESKeyForAlgorithm(raw, k.Algorithm)
		if err != nil {
			return nil, err
		}
		defer crypto.Zeroize(key)
		plain, err := crypto.JWAUnwrapAES(alg, key, wrapped)
		if err != nil {
			return nil, errJWAMismatch
		}
		return plain, nil
	}
	if isPublicKeyType(k.KeyType) {
		return nil, errors.New("rsa unwrap requires private key material")
	}
	priv, err := parseRSAPrivateMaterial(raw)
	if err != nil {
		return nil, err
	}
	plain, err := crypto.JWAUnwrapRSA(alg, priv, wrapped)
	if err != nil {
		return nil, errJWAMismatch
	}
	return plain, nil
}

// refuseHSMWrapAlgorithm: an HSM-resident key wraps only with the HSM's own
// mechanisms, which this path doesn't drive.
func (s *Service) refuseHSMWrapAlgorithm(ctx context.Context, tenantID, keyID, operation string) error {
	return s.refuseHSM(ctx, tenantID, keyID, operation, http.StatusConflict, "wrap_algorithm_not_supported",
		"a key held in an HSM does not wrap with wrap_algorithm; use a key held by the KMS")
}

// unwrapJWA opens wrapped with the stated version, or with the newest
// version that opens it.
func (s *Service) unwrapJWA(ctx context.Context, key Key, keyID string, req DecryptRequest, wrapped []byte) (CryptoTxResult, error) {
	alg := req.WrapAlgorithm
	attempt := func(version int) (CryptoTxResult, error) {
		return s.runCryptoTxAt(ctx, req.TenantID, keyID, "unwrap", version, func(k Key, kv KeyVersion) (CryptoTxResult, error) {
			if kv.Protection == protectionHSMResident {
				return CryptoTxResult{}, s.refuseHSMWrapAlgorithm(ctx, req.TenantID, keyID, "unwrap")
			}
			if err := s.enforceVersionAlgorithm(ctx, req.TenantID, key, k, "key.decrypt"); err != nil {
				return CryptoTxResult{}, err
			}
			raw, err := s.decryptMaterial(kv)
			if err != nil {
				return CryptoTxResult{}, err
			}
			defer crypto.Zeroize(raw)
			plain, err := jwaUnwrapMaterial(k, raw, alg, wrapped)
			if err != nil {
				return CryptoTxResult{}, err
			}
			return CryptoTxResult{Payload: plain}, nil
		})
	}
	if req.Version > 0 {
		return attempt(req.Version)
	}
	for v := key.CurrentVersion; v >= 1; v-- {
		out, err := attempt(v)
		if err == nil {
			return out, nil
		}
		// Another version may hold the key that wrapped it; anything else
		// (refusal, limit, unusable key) ends the search.
		if !errors.Is(err, errJWAMismatch) && !errors.Is(err, errVersionRefused) && !errors.Is(err, errStoreNotFound) {
			return CryptoTxResult{}, err
		}
	}
	return CryptoTxResult{}, errJWAMismatch
}
