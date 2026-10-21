package correlation

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// The edge's header removal line, read from the production config.
var removeLine = regexp.MustCompile(`(?m)^\s*request_headers_to_remove:\s*\[(.*)\]\s*$`)

func edgeRemoves(t *testing.T) string {
	t.Helper()
	prod, err := os.ReadFile(filepath.Join("..", "..", "infra", "envoy", "envoy.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	m := removeLine.FindAllStringSubmatch(string(prod), -1)
	if len(m) != 1 {
		t.Fatalf("infra/envoy/envoy.yaml has %d request_headers_to_remove lines; this test reads exactly one", len(m))
	}
	return m[0][1]
}

// A value a service receives in Header must come from another platform
// service, so the edge removes it from every outside request.
func TestEdgeRemovesTheCorrelationHeader(t *testing.T) {
	if !strings.Contains(strings.ToLower(edgeRemoves(t)), `"`+strings.ToLower(Header)+`"`) {
		t.Fatalf("infra/envoy/envoy.yaml no longer removes %s from outside requests: a caller could join its events to another request", Header)
	}
}

// The same on the real edge proxy (VECTA_TEST_ENVOY_IMAGE): the production
// removal line on a route to an upstream, which reports what it received.
func TestEdgeRemovesTheCorrelationHeaderOnRealEnvoy(t *testing.T) {
	image := strings.TrimSpace(os.Getenv("VECTA_TEST_ENVOY_IMAGE"))
	if image == "" {
		t.Skip("set VECTA_TEST_ENVOY_IMAGE to an Envoy image (docker required)")
	}
	bootstrap := fmt.Sprintf(`static_resources:
  listeners:
  - address: { socket_address: { address: 0.0.0.0, port_value: 10000 } }
    filter_chains:
    - filters:
      - name: envoy.filters.network.http_connection_manager
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
          stat_prefix: edge
          route_config:
            virtual_hosts:
            - name: kms_api
              domains: ["*"]
              request_headers_to_remove: [%s]
              routes:
              - match: { prefix: "/" }
                route: { cluster: upstream }
          http_filters:
          - name: envoy.filters.http.router
            typed_config: { "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router }
  - address: { socket_address: { address: 127.0.0.1, port_value: 10001 } }
    filter_chains:
    - filters:
      - name: envoy.filters.network.http_connection_manager
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
          stat_prefix: upstream
          route_config:
            virtual_hosts:
            - name: all
              domains: ["*"]
              routes:
              - match: { prefix: "/" }
                direct_response: { status: 200 }
                response_headers_to_add:
                - header: { key: "x-got-correlation", value: "[%%REQ(X-CORRELATION-ID)%%]" }
                - header: { key: "x-got-probe", value: "[%%REQ(X-PROBE)%%]" }
          http_filters:
          - name: envoy.filters.http.router
            typed_config: { "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router }
  clusters:
  - name: upstream
    type: STATIC
    load_assignment:
      cluster_name: upstream
      endpoints:
      - lb_endpoints:
        - endpoint: { address: { socket_address: { address: 127.0.0.1, port_value: 10001 } } }
`, edgeRemoves(t))
	cfg := filepath.Join(t.TempDir(), "envoy.yaml")
	if err := os.WriteFile(cfg, []byte(bootstrap), 0o644); err != nil {
		t.Fatal(err)
	}
	name := fmt.Sprintf("vecta-correlation-envoy-%d", time.Now().UnixNano())
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

	req, _ := http.NewRequest(http.MethodGet, edge+"/", nil)
	req.Header.Set(Header, "corr_forged_by_caller")
	req.Header.Set("X-Probe", "p1")
	var lastErr error
	for i := 0; i < 80; i++ {
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			// The probe proves the request reached the upstream with the
			// caller's other headers intact.
			if resp.StatusCode == http.StatusOK && resp.Header.Get("X-Got-Probe") == "[p1]" {
				if got := resp.Header.Get("X-Got-Correlation"); got != "[]" {
					t.Fatalf("the upstream received %s %s; the edge must remove it", Header, got)
				}
				return
			}
			lastErr = fmt.Errorf("status %d, probe %q", resp.StatusCode, resp.Header.Get("X-Got-Probe"))
		} else {
			lastErr = err
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatalf("the edge did not answer: %v", lastErr)
}
