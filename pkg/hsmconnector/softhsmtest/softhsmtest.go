// Package softhsmtest starts a real hsm-connector (pkg/hsmconnector) on
// SoftHSM2, a real PKCS#11 library, for the tests of services that use the
// HSM (keycore, governance). CI installs SoftHSM2; a test skips without it.
package softhsmtest

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"

	pkgauth "vecta-kms/pkg/auth"
	"vecta-kms/pkg/hsmconnector"
)

const pinVar = "SOFTHSMTEST_PIN"

var (
	once     sync.Once
	lib      string
	initErr  error
	provider *hsmconnector.Provider
)

// setup creates one token for the test process: SoftHSM2 reads its
// configuration once, at C_Initialize.
func setup() {
	lib = os.Getenv("SOFTHSM_LIB")
	if lib == "" {
		lib = "/usr/lib/softhsm/libsofthsm2.so"
	}
	real, err := filepath.EvalSymlinks(lib)
	if err != nil {
		initErr = fmt.Errorf("SoftHSM2 not installed (apt install softhsm2): %w", err)
		return
	}
	dir, err := os.MkdirTemp("", "softhsmtest")
	if err != nil {
		initErr = err
		return
	}
	tokens := filepath.Join(dir, "tokens")
	conf := filepath.Join(dir, "softhsm2.conf")
	if err := os.Mkdir(tokens, 0o700); err != nil {
		initErr = err
		return
	}
	if err := os.WriteFile(conf, []byte("directories.tokendir = "+tokens+"\nobjectstore.backend = file\nlog.level = ERROR\n"), 0o600); err != nil {
		initErr = err
		return
	}
	os.Setenv("SOFTHSM2_CONF", conf)                   //nolint:errcheck
	os.Setenv("HSM_LIBRARY_ROOTS", filepath.Dir(real)) //nolint:errcheck
	os.Setenv(pinVar, "271828")                        //nolint:errcheck
	if out, err := exec.Command("softhsm2-util", "--init-token", "--free", "--label", "vecta-test",
		"--pin", "271828", "--so-pin", "3141592").CombinedOutput(); err != nil {
		initErr = fmt.Errorf("softhsm2-util: %v %s", err, out)
		return
	}
	// A second token, reached only through an HSM credential.
	if out, err := exec.Command("softhsm2-util", "--init-token", "--free", "--label", CredentialToken,
		"--pin", credentialPIN, "--so-pin", "3141592").CombinedOutput(); err != nil {
		initErr = fmt.Errorf("softhsm2-util: %v %s", err, out)
		return
	}
	provider = hsmconnector.NewProvider()
}

// CredentialToken is the label of the token HSM credentials point at; the
// tenants' profiles are on "vecta-test".
const (
	CredentialToken = "vecta-cred"
	credentialPIN   = "161803"
)

// Connections is the HSM credential store for a test connector: tenant →
// credential ID. Each resolves to the second token, as a pkcs11_hsm
// credential's fields would.
type Connections map[string][]string

func (c Connections) LoadConnection(_ context.Context, tenant, id string) (hsmconnector.TenantConfig, error) {
	for _, known := range c[tenant] {
		if known == id {
			return hsmconnector.FromCredential(tenant, id, map[string]string{"library_path": lib, "token_label": CredentialToken, "pin": credentialPIN})
		}
	}
	return hsmconnector.TenantConfig{}, hsmconnector.ErrConnectionNotFound
}

// Configs gives the listed tenants an HSM profile on the test token.
type Configs map[string]bool

func (c Configs) Load(_ context.Context, tenant string) (hsmconnector.TenantConfig, error) {
	if !c[tenant] {
		return hsmconnector.TenantConfig{}, hsmconnector.ErrNotConfigured
	}
	return hsmconnector.Resolve(hsmconnector.TenantConfig{
		TenantID: tenant, Provider: "softhsm2", Library: lib, TokenLabel: "vecta-test", PINEnvVar: pinVar,
	})
}

// Start serves a connector for tenants. Requests arrive as the platform
// service caller (the connector's own tests cover authentication).
func Start(t testing.TB, caller string, tenants ...string) *httptest.Server {
	return StartWith(t, caller, nil, tenants...)
}

// StartWith is Start with HSM credentials: conns' tenants can also create
// keys on the second token by naming a credential.
func StartWith(t testing.TB, caller string, conns Connections, tenants ...string) *httptest.Server {
	t.Helper()
	once.Do(setup)
	if initErr != nil {
		t.Skip(initErr.Error())
	}
	configs := Configs{}
	for _, tn := range tenants {
		configs[tn] = true
	}
	h := hsmconnector.NewHandler(configs, provider, nil, nil)
	h.SetConnections(conns)
	claims := &pkgauth.Claims{TenantID: "root", Role: "client-service", ClientID: caller, Permissions: []string{"service.internal"}}
	claims.Subject = caller
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r.WithContext(pkgauth.ContextWithClaims(r.Context(), claims)))
	}))
	t.Cleanup(srv.Close)
	return srv
}
