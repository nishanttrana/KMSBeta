package clientip

import (
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The edge's connection manager with the one setting that matters here, as
// in infra/envoy/envoy.yaml. Envoy answers itself and returns, in a response
// header, the X-Forwarded-For it would have sent upstream.
const edgeBootstrap = `static_resources:
  listeners:
  - address: { socket_address: { address: 0.0.0.0, port_value: 10000 } }
    filter_chains:
    - filters:
      - name: envoy.filters.network.http_connection_manager
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
          stat_prefix: edge
          use_remote_address: true
          route_config:
            virtual_hosts:
            - name: all
              domains: ["*"]
              routes:
              - match: { prefix: "/" }
                direct_response: { status: 200 }
                response_headers_to_add:
                - header: { key: "x-sent-upstream", value: "%REQ(X-FORWARDED-FOR)%" }
          http_filters:
          - name: envoy.filters.http.router
            typed_config: { "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router }
`

// The premise of this package, on the real edge proxy
// (VECTA_TEST_ENVOY_IMAGE, e.g. envoyproxy/envoy:v1.39.1): with the setting
// the platform's edge runs with, Envoy keeps whatever the caller wrote in
// X-Forwarded-For and appends the address it accepted the connection from.
// Only the last entry is the edge's; From returns it whatever came before.
func TestEdgeAppendsTheAddressItSawOnRealEnvoy(t *testing.T) {
	image := strings.TrimSpace(os.Getenv("VECTA_TEST_ENVOY_IMAGE"))
	if image == "" {
		t.Skip("set VECTA_TEST_ENVOY_IMAGE to an Envoy image (docker required)")
	}
	// The edge must still run with the setting this test runs Envoy with, and
	// with nothing that changes how the header is built.
	prod, err := os.ReadFile(filepath.Join("..", "..", "infra", "envoy", "envoy.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(prod), "use_remote_address: true") {
		t.Fatal("infra/envoy/envoy.yaml no longer sets use_remote_address: the edge would stop appending the address it saw")
	}
	for _, changes := range []string{"xff_num_trusted_hops", "skip_xff_append", "original_ip_detection_extensions"} {
		if strings.Contains(string(prod), changes) {
			t.Fatalf("infra/envoy/envoy.yaml sets %s: pkg/clientip and this test must be revisited with it", changes)
		}
	}

	cfg := filepath.Join(t.TempDir(), "envoy.yaml")
	if err := os.WriteFile(cfg, []byte(edgeBootstrap), 0o644); err != nil {
		t.Fatal(err)
	}
	name := fmt.Sprintf("vecta-clientip-envoy-%d", time.Now().UnixNano())
	docker := func(args ...string) string {
		t.Helper()
		out, err := exec.Command("docker", args...).CombinedOutput()
		if err != nil {
			t.Fatalf("docker %s: %v\n%s", args[0], err, out)
		}
		return strings.TrimSpace(string(out))
	}
	docker("run", "-d", "--name", name, "-p", "127.0.0.1::10000", "-v", cfg+":/etc/envoy/envoy.yaml:ro", image)
	t.Cleanup(func() {
		if t.Failed() {
			out, _ := exec.Command("docker", "logs", "--tail", "20", name).CombinedOutput()
			t.Logf("envoy logs:\n%s", out)
		}
		_ = exec.Command("docker", "rm", "-f", name).Run()
	})
	edge := "http://" + strings.Split(docker("port", name, "10000/tcp"), "\n")[0]

	// through sends a request through the edge and returns the header a
	// service behind it would receive, and what From makes of it.
	through := func(forwarded ...string) ([]string, string) {
		t.Helper()
		req, _ := http.NewRequest(http.MethodGet, edge+"/", nil)
		for _, v := range forwarded {
			req.Header.Add(Header, v)
		}
		req.Header.Set("X-Real-IP", "203.0.113.9")
		req.Header.Set("X-Envoy-External-Address", "203.0.113.9")
		var lastErr error
		for i := 0; i < 80; i++ {
			resp, err := http.DefaultClient.Do(req)
			if err == nil {
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
				if sent := resp.Header.Get("X-Sent-Upstream"); resp.StatusCode == http.StatusOK && sent != "" {
					behind, _ := http.NewRequest(http.MethodGet, "/", nil)
					behind.RemoteAddr = "172.18.0.9:41000" // the edge, as a service sees it
					behind.Header.Set(Header, sent)
					return strings.Split(strings.ReplaceAll(sent, " ", ""), ","), From(behind)
				}
				lastErr = fmt.Errorf("status %d, header %q", resp.StatusCode, resp.Header.Get("X-Sent-Upstream"))
			} else {
				lastErr = err
			}
			time.Sleep(250 * time.Millisecond)
		}
		t.Fatalf("the edge did not answer: %v", lastErr)
		return nil, ""
	}

	// No header from the caller: the edge names the address it saw.
	entries, plain := through()
	seen, err := netip.ParseAddr(plain)
	if err != nil || len(entries) != 1 || entries[0] != plain {
		t.Fatalf("without a caller's header the edge must send one entry, the address it saw: header=%q from=%q", entries, plain)
	}

	// Whatever the caller writes stays in front; the edge's entry is last.
	entries, got := through("203.0.113.9", "10.9.9.9, 127.0.0.1")
	if strings.Join(entries, ",") != "203.0.113.9,10.9.9.9,127.0.0.1,"+seen.String() {
		t.Fatalf("the edge must keep the caller's entries and append its own: %q", entries)
	}
	if got != seen.String() {
		t.Fatalf("From returned %q; the edge saw %s and the caller wrote the rest", got, seen)
	}
}
