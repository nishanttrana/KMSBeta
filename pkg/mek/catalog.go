package mek

import (
	"encoding/base64"
	"os"
	"strings"

	pkgcrypto "vecta-kms/pkg/crypto"
)

// Table describes one table of envelope-encrypted rows: the DEK of each row
// is wrapped under the service's master key (pkgcrypto envelope format).
// Names are code constants, never input; they're validated by Validate.
type Table struct {
	Name       string   // table
	Keys       []string // primary-key columns, for keyset paging and the conditional update
	Tenant     string   // tenant column
	Item       string   // column naming the protected item (audited, tracked when exposed)
	ItemType   string   // e.g. "secret", "ca_signing_key"
	WrappedDEK string   // column holding the wrapped DEK
	WrappedIV  string   // column holding the wrap IV
	Base64     bool     // DEK and IV are stored as base64 text
	Where      string   // optional constant filter selecting rows under the master key
}

// ServiceTables is one service's master-key configuration: the tables it
// protects and the keys earlier releases used.
type ServiceTables struct {
	Service       string // audit namespace and keycore purpose prefix, e.g. "secrets"
	ClientID      string // service identity, e.g. "kms-secrets"
	StateTable    string
	ExposureTable string
	Tables        []Table
	// DevSeed is the literal earlier releases hashed into a public fallback
	// key (SHA-256) when the environment key was unset.
	DevSeed string
	// LegacyEnv is the environment variable earlier releases read the key
	// from (first 32 bytes of its base64), used only to migrate off it.
	LegacyEnv string
	// ExtraPublic lists other public keys earlier releases could fall back to.
	ExtraPublic [][]byte
}

// Catalog is every service whose stored data is protected by a master key.
// Services read their entry; governance uses it to re-protect backups.
var Catalog = map[string]ServiceTables{
	"secrets": {
		Service: "secrets", ClientID: "kms-secrets",
		StateTable: "secrets_mek_state", ExposureTable: "secrets_mek_exposure",
		Tables: []Table{{
			Name: "secret_values", Keys: []string{"tenant_id", "secret_id", "version"}, Tenant: "tenant_id",
			Item: "secret_id", ItemType: "secret", WrappedDEK: "wrapped_dek", WrappedIV: "wrapped_dek_iv",
		}},
		DevSeed:   "vecta-secrets-dev-mek",
		LegacyEnv: "SECRETS_MEK_B64",
	},
	"cloud": {
		Service: "cloud", ClientID: "kms-cloud",
		StateTable: "cloud_mek_state", ExposureTable: "cloud_mek_exposure",
		Tables: []Table{{
			Name: "cloud_accounts", Keys: []string{"tenant_id", "id"}, Tenant: "tenant_id",
			Item: "id", ItemType: "cloud_account_credentials", WrappedDEK: "creds_wrapped_dek", WrappedIV: "creds_wrapped_dek_iv",
		}},
		DevSeed:   "vecta-cloud-dev-mek",
		LegacyEnv: "CLOUD_MEK_B64",
		// cloud's NewService fell back to this literal for a short key.
		ExtraPublic: [][]byte{[]byte("0123456789ABCDEF0123456789ABCDEF")}, // conformance:legacy-public-key
	},
	"ekm": {
		Service: "ekm", ClientID: "kms-ekm",
		StateTable: "ekm_mek_state", ExposureTable: "ekm_mek_exposure",
		Tables: []Table{{
			Name: "ekm_bitlocker_recovery_keys", Keys: []string{"tenant_id", "id"}, Tenant: "tenant_id",
			Item: "id", ItemType: "bitlocker_recovery_key", WrappedDEK: "wrapped_dek", WrappedIV: "wrapped_dek_iv", Base64: true,
		}},
		DevSeed:   "vecta-ekm-dev-mek",
		LegacyEnv: "EKM_MEK_B64",
	},
	"certs": {
		Service: "cert", ClientID: "kms-certs",
		StateTable: "cert_mek_state", ExposureTable: "cert_mek_exposure",
		// Only "legacy" signer rows are under the master key; the rest are
		// under the sealed certs root key (CRWK) and are not touched.
		Tables: []Table{{
			Name: "cert_cas", Keys: []string{"tenant_id", "id"}, Tenant: "tenant_id",
			Item: "id", ItemType: "ca_signing_key", WrappedDEK: "signer_wrapped_dek", WrappedIV: "signer_wrapped_dek_iv",
			Where: "LOWER(COALESCE(signer_kek_version, '')) LIKE 'legacy%'",
		}},
		DevSeed:   "vecta-certs-dev-mek",
		LegacyEnv: "CERTS_MEK_B64",
	},
}

// LegacyKey is a key earlier releases wrapped data under. Data under a
// public key must be treated as exposed to anyone who has had a copy of it.
type LegacyKey struct {
	Name   string // "dev_mek", "public_fallback", "env_mek", "previous_version"
	Key    []byte
	Public bool
}

// legacyKeys returns the keys to migrate off, public ones first.
func (st ServiceTables) legacyKeys(getenv func(string) string) []LegacyKey {
	var out []LegacyKey
	if st.DevSeed != "" {
		sum, err := pkgcrypto.Hash("SHA-256", []byte(st.DevSeed)) // conformance:legacy-public-key
		if err != nil {
			panic("mek: SHA-256 unavailable: " + err.Error())
		}
		out = append(out, LegacyKey{Name: "dev_mek", Key: sum, Public: true})
	}
	for _, k := range st.ExtraPublic {
		out = append(out, LegacyKey{Name: "public_fallback", Key: k, Public: true})
	}
	if st.LegacyEnv != "" && getenv != nil {
		if raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(getenv(st.LegacyEnv))); err == nil && len(raw) >= 32 {
			out = append(out, LegacyKey{Name: "env_mek", Key: raw[:32]})
		}
	}
	return out
}

// LegacyKeysFromEnv is legacyKeys over the process environment.
func (st ServiceTables) LegacyKeysFromEnv() []LegacyKey { return st.legacyKeys(os.Getenv) }
