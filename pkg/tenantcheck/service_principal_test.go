package tenantcheck

import (
	"testing"

	pkgauth "vecta-kms/pkg/auth"
)

func TestIsServicePrincipal(t *testing.T) {
	t.Setenv("INTERNAL_SERVICE_TENANT", "root")
	svc := []string{ServicePermission}
	cases := []struct {
		name string
		c    *pkgauth.Claims
		want bool
	}{
		{"nil", nil, false},
		{"bootstrap service identity", &pkgauth.Claims{Role: "client-service", ClientID: "kms-ekm", TenantID: "root", Permissions: svc}, true},
		{"external client role only (must NOT be trusted)", &pkgauth.Claims{Role: "client-service", ClientID: "app-1", TenantID: "t1", Permissions: []string{"kms.read"}}, false},
		{"external client with reserved perm but wrong tenant", &pkgauth.Claims{Role: "client-service", ClientID: "kms-ekm", TenantID: "t1", Permissions: svc}, false},
		{"non kms- client id", &pkgauth.Claims{Role: "client-service", ClientID: "evil", TenantID: "root", Permissions: svc}, false},
		{"user token with reserved perm", &pkgauth.Claims{Role: "admin", ClientID: "kms-x", TenantID: "root", Permissions: svc}, false},
		{"legacy role 'service' alone", &pkgauth.Claims{Role: "service", ClientID: "kms-ekm", TenantID: "root"}, false},
	}
	for _, tc := range cases {
		if got := IsServicePrincipal(tc.c); got != tc.want {
			t.Errorf("%s: got %v want %v", tc.name, got, tc.want)
		}
	}
}

func TestStripReserved(t *testing.T) {
	out := StripReserved([]string{"kms.read", " Service.Internal ", "kms.write"})
	if len(out) != 2 {
		t.Fatalf("reserved permission not stripped: %v", out)
	}
}
