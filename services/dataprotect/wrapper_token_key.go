package main

import (
	"context"
	"net/http"
	"sync"

	"vecta-kms/pkg/mek"
)

// wrapperTokenPurpose is the keycore system key purpose the wrapper token
// signing key is derived from (POST /system-keys/ensure, then service-derive
// bound to kms-dataprotect). Until 13.41.0-beta the key was derived from the
// wrapper's tenant, wrapper and app IDs whenever DATAPROTECT_WRAPPER_JWT_SECRET
// was unset, and no deployment set it: anyone who knew those identifiers could
// sign a wrapper token (docs/SECURITY/DATAPROTECT_KEY_DERIVATION.md).
const wrapperTokenPurpose = "wrapper-token"

// wrapperTokenKeys signs with the system key's current version and verifies a
// token with the version named in its kid, so tokens outlive a rotation.
type wrapperTokenKeys struct {
	src       mek.Source
	mu        sync.Mutex
	keyID     string
	byVersion map[int][]byte
}

func errWrapperTokenKey() error {
	return newServiceError(http.StatusServiceUnavailable, "keycore_unavailable", "wrapper token signing key is unavailable")
}

// current returns the version and key new tokens are signed with.
func (k *wrapperTokenKeys) current(ctx context.Context) (int, []byte, error) {
	if k == nil || k.src == nil {
		return 0, nil, errWrapperTokenKey()
	}
	keyID, version, err := k.src.EnsureKey(ctx)
	if err != nil || version <= 0 {
		return 0, nil, errWrapperTokenKey()
	}
	k.mu.Lock()
	k.keyID = keyID
	k.mu.Unlock()
	key, err := k.version(ctx, version)
	return version, key, err
}

// version returns the key at version, derived once per process.
func (k *wrapperTokenKeys) version(ctx context.Context, version int) ([]byte, error) {
	if k == nil || k.src == nil || version <= 0 {
		return nil, errWrapperTokenKey()
	}
	k.mu.Lock()
	key, keyID := k.byVersion[version], k.keyID
	k.mu.Unlock()
	if key != nil {
		return key, nil
	}
	if keyID == "" {
		id, _, err := k.src.EnsureKey(ctx)
		if err != nil {
			return nil, errWrapperTokenKey()
		}
		keyID = id
	}
	key, got, err := k.src.Derive(ctx, keyID, version)
	if err != nil || got != version || len(key) != 32 {
		return nil, errWrapperTokenKey()
	}
	k.mu.Lock()
	k.keyID = keyID
	if k.byVersion == nil {
		k.byVersion = map[int][]byte{}
	}
	k.byVersion[version] = key
	k.mu.Unlock()
	return key, nil
}
