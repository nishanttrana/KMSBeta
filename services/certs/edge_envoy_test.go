package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"vecta-kms/pkg/svctls"
)

// The real edge: Envoy (VECTA_TEST_ENVOY_IMAGE, e.g. envoyproxy/envoy:v1.39.1)
// runs the repository's envoy.yaml, SDS files and entry.sh, with the
// certificates and group list certs writes. The profile certs publishes is
// measured by handshake, and a change is applied by a hot restart: the
// container never restarts.
func TestEdgeProfileAppliedByRealEnvoy(t *testing.T) {
	image := strings.TrimSpace(os.Getenv("VECTA_TEST_ENVOY_IMAGE"))
	if image == "" {
		t.Skip("set VECTA_TEST_ENVOY_IMAGE to an Envoy image (docker required)")
	}
	repo, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	f := newMTLSFixture(t)
	ctx := context.Background()
	cfg := f.cfg
	cfg.Enabled, cfg.TenantID, cfg.RootCAName = true, "root", "vecta-runtime-root"
	if err := f.svc.MaterializeRuntimeCerts(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	root, sub, err := f.svc.EnsureInternalPKI(ctx, "root")
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteTrustBundle(f.trust, root, sub); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.SetEdgeKX(ctx, svctls.KXPQCRequired, "test", "admin"); err != nil {
		t.Fatal(err)
	}

	docker := func(args ...string) string {
		t.Helper()
		out, err := exec.Command("docker", args...).CombinedOutput()
		if err != nil {
			t.Fatalf("docker %s: %v\n%s", args[0], err, out)
		}
		return strings.TrimSpace(string(out))
	}
	name := "vecta-edge-test-" + strings.ToLower(newID("e")[2:10])
	// The certificates live in a named volume, as in compose: Envoy's SDS
	// reloads on a rename inside its watched directory, which a macOS bind
	// mount doesn't deliver. sync copies what certs wrote on the host into
	// the volume the way certs writes (temporary file, then rename).
	vol := name + "-certs"
	docker("volume", "create", vol)
	t.Cleanup(func() { _ = exec.Command("docker", "volume", "rm", "-f", vol).Run() })
	sync := func() {
		t.Helper()
		docker("run", "--rm", "-v", cfg.MaterializeDir+":/src:ro", "-v", vol+":/dst", "--entrypoint", "/bin/sh", image, "-ec",
			`cd /src && find . -type f | while read f; do mkdir -p "/dst/$(dirname "$f")"; cp "$f" "/dst/$f.tmp"; mv "/dst/$f.tmp" "/dst/$f"; done`)
	}
	sync()
	docker("run", "-d", "--name", name, "-p", "127.0.0.1::443",
		"-e", "EDGE_POLICY_INTERVAL_S=1",
		"-v", filepath.Join(repo, "infra/envoy/envoy.yaml")+":/etc/envoy/envoy.yaml:ro",
		"-v", filepath.Join(repo, "infra/envoy/entry.sh")+":/etc/envoy/entry.sh:ro",
		"-v", filepath.Join(repo, "infra/envoy/sds")+":/etc/envoy/sds:ro",
		"-v", vol+":/run/vecta/runtime-certs:ro",
		"-v", f.trust+":/run/vecta/trust:ro",
		"--entrypoint", "/bin/sh", image, "/etc/envoy/entry.sh")
	t.Cleanup(func() {
		if t.Failed() {
			out, _ := exec.Command("docker", "logs", name).CombinedOutput()
			t.Logf("envoy logs:\n%s", out)
		}
		_ = exec.Command("docker", "rm", "-f", name).Run()
	})
	_ = sync
	port := docker("port", name, "443/tcp")
	port = port[strings.LastIndex(port, ":")+1:]
	t.Setenv("CERTS_EDGE_PROBE_TARGETS", "envoy=localhost:"+strings.Split(port, "\n")[0])

	measured := func(profile string) bool {
		if err := f.svc.ProbeEdge(ctx); err != nil {
			return false
		}
		v, err := f.svc.EdgeInventory(ctx)
		if err != nil || len(v.Listeners) != 1 || v.Listeners[0].Observed == nil {
			return false
		}
		return v.Listeners[0].Observed.KXProfile == profile && v.Applied
	}
	waitFor := func(profile string) {
		t.Helper()
		deadline := time.Now().Add(90 * time.Second)
		for !measured(profile) {
			if time.Now().After(deadline) {
				v, _ := f.svc.EdgeInventory(ctx)
				t.Fatalf("Envoy never measured as %s: %+v", profile, v.Listeners[0].Observed)
			}
			time.Sleep(time.Second)
		}
	}

	waitFor(svctls.KXPQCRequired)
	if _, err := f.svc.SetEdgeKX(ctx, svctls.KXClassical, "test", "admin"); err != nil {
		t.Fatal(err)
	}
	waitFor(svctls.KXClassical)
	v, _ := f.svc.EdgeInventory(ctx)
	if g := v.Listeners[0].Observed.ServerGroups; strings.Contains(strings.Join(g, ","), "MLKEM") {
		t.Fatalf("classical edge still accepts ML-KEM: %v", g)
	}
	if n := docker("inspect", "-f", "{{.RestartCount}} {{.State.Running}}", name); n != "0 true" {
		t.Fatalf("the change must be a hot restart, not a container restart: %s", n)
	}
	// entry.sh confirms the new epoch once it has run for 5 s.
	for deadline := time.Now().Add(20 * time.Second); ; time.Sleep(time.Second) {
		logs, _ := exec.Command("docker", "logs", name).CombinedOutput()
		if strings.Contains(string(logs), "hot restart, epoch 1") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("entry.sh did not hot-restart:\n%s", logs)
		}
	}
	if n := docker("inspect", "-f", "{{.RestartCount}} {{.State.Running}}", name); n != "0 true" {
		t.Fatalf("the container must keep running: %s", n)
	}

	// A list Envoy must not take is ignored: the groups in force stay.
	if err := os.WriteFile(filepath.Join(f.trust, svctls.EdgeCurvesFileName), []byte("X25519,secp112r1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(20 * time.Second); ; time.Sleep(time.Second) {
		logs, _ := exec.Command("docker", "logs", name).CombinedOutput()
		if strings.Contains(string(logs), "unsupported group: secp112r1") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("entry.sh did not reject the list:\n%s", logs)
		}
	}
	if !measured(svctls.KXClassical) {
		t.Fatal("a rejected list must leave the groups in force")
	}

	// An external CA's certificate for this node's own key: Envoy serves it
	// after certs installs it (SDS reload). The probe pins the installed
	// certificate, so it measures only once Envoy serves the new one.
	f.svc.runtimeCfg = cfg
	if _, _, err := f.svc.SetEdgeCertificateSource(ctx, "root", "", edgeCertChoice{Source: edgeSourceExternal}); err != nil {
		t.Fatal(err)
	}
	csr, err := f.svc.CreateEdgeCSR(ctx, "", "localhost", []string{"localhost"}, "", "test")
	if err != nil {
		t.Fatal(err)
	}
	ext, err := f.svc.CreateCA(ctx, CreateCARequest{TenantID: "customer", Name: "Customer Issuing CA", CALevel: "root",
		Algorithm: "ECDSA-P256", KeyBackend: "software", Subject: "CN=Customer Issuing CA"})
	if err != nil {
		t.Fatal(err)
	}
	signed, _, err := f.svc.IssueCertificate(ctx, IssueCertificateRequest{TenantID: "customer", CAID: ext.ID, CertType: "tls-server",
		SubjectCN: "localhost", SANs: []string{"localhost"}, CSRPem: csr.CSRPEM, ValidityDays: 30})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.InstallEdgeCertificate(ctx, "", signed.CertPEM, ext.CertPEM); err != nil {
		t.Fatal(err)
	}
	sync()
	waitFor(svctls.KXClassical)
	if v, _ := f.svc.EdgeInventory(ctx); !v.Certificate.Served || v.Certificate.Installed.Issuer != "CN=Customer Issuing CA" {
		t.Fatalf("Envoy must serve the installed external certificate: %+v", v.Certificate)
	}

	// X25519 alone is measured in every FIPS mode (a hand-built hello when
	// Go won't offer it): Envoy given X25519 and P-256 is measured accepting
	// exactly those.
	if err := os.WriteFile(filepath.Join(f.trust, svctls.EdgeCurvesFileName), []byte("X25519,P-256\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(30 * time.Second); ; time.Sleep(time.Second) {
		_ = f.svc.ProbeEdge(ctx)
		v, _ := f.svc.EdgeInventory(ctx)
		if o := v.Listeners[0].Observed; o != nil && strings.Join(o.ServerGroups, ",") == "X25519,CurveP256" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("X25519 not measured: %+v", v.Listeners[0].Observed)
		}
	}
}
