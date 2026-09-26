// Package clusterroute decides, on a cluster member, which HTTP requests run
// locally and which are forwarded to the primary (docs/CLUSTERING.md, slice 3).
//
// The primary is the only lifecycle writer. On a member, every request that
// can change shared state is forwarded; reads and the operations listed in
// Local run locally. The default is to forward, so a new write endpoint can
// never silently diverge a member's copy of replicated data.
package clusterroute

import (
	"net/http"
	"strings"
)

// Services maps a service binary to its internal HTTP URL on a node. The
// primary's cluster-manager proxies forwarded requests there.
var Services = map[string]string{
	"kms-ai-gateway":        "http://ai-gateway:8320",
	"kms-audit":             "http://audit:8070",
	"kms-auth":              "http://auth:8001",
	"kms-autokey":           "http://autokey:8260",
	"kms-backup":            "http://backup:8290",
	"kms-certs":             "http://certs:8030",
	"kms-cloud":             "http://cloud:8080",
	"kms-compliance":        "http://compliance:8110",
	"kms-confidential":      "http://confidential:8240",
	"kms-dataprotect":       "http://dataprotect:8200",
	"kms-discovery":         "http://discovery:8100",
	"kms-ekm":               "http://ekm:8130",
	"kms-featureforge":      "http://featureforge:8300",
	"kms-governance":        "http://governance:8050",
	"kms-hyok":              "http://hyok:8120",
	"kms-key-access":        "http://keyaccess:8270",
	"kms-keycore":           "http://keycore:8010",
	"kms-kmip":              "http://kmip:8160",
	"kms-payment":           "http://payment:8170",
	"kms-policy":            "http://policy:8040",
	"kms-posture":           "http://posture:8220",
	"kms-pqc":               "http://pqc:8060",
	"kms-reporting":         "http://reporting:8140",
	"kms-sbom":              "http://sbom:8180",
	"kms-secrets":           "http://secrets:8020",
	"kms-signing":           "http://signing:8280",
	"kms-workload-identity": "http://workload:8250",
}

// NeverForward services act only on their own node: cluster membership, the
// node's software HSM, and node supervisors.
var NeverForward = map[string]string{
	"kms-cluster-manager": "cluster membership is per node",
	"kms-software-vault":  "the node's software HSM",
	"kms-reconciler":      "reconciles this node",
	"kms-watchdog":        "supervises this node",
}

// Local lists write routes that run on a member. Each either performs a
// crypto operation that writes only node-local tables, or acts on node-local
// state. Patterns are "METHOD /path" with {x} matching one path segment.
var Local = map[string][]string{
	"kms-keycore": {
		"POST /keys/{id}/encrypt", "POST /keys/{id}/decrypt",
		"POST /keys/{id}/sign", "POST /keys/{id}/verify",
		"POST /keys/{id}/mac", "POST /keys/{id}/wrap",
		"POST /keys/{id}/derive", "POST /keys/{id}/service-derive",
		"POST /keys/{id}/attest", "POST /keys/{id}/verify-material",
		"POST /crypto/hash", "POST /crypto/random",
		// Master-key transfer acts on this node's keycore during a join.
		"POST /cluster/mek/join-key", "POST /cluster/mek/export", "POST /cluster/mek/import",
	},
	"kms-dataprotect": {
		"POST /fpe/encrypt", "POST /fpe/decrypt",
		"POST /mask", "POST /mask/preview", "POST /redact", "POST /redact/detect",
		"POST /app/encrypt-fields", "POST /app/decrypt-fields",
		"POST /app/envelope-encrypt", "POST /app/envelope-decrypt",
		"POST /app/searchable-encrypt", "POST /app/searchable-decrypt",
	},
	"kms-auth": {
		// Sessions and the tokens this node's services verify are node-local.
		"POST /auth/login", "POST /auth/logout", "POST /auth/refresh",
		"POST /auth/client-token", "POST /auth/cluster/mint",
	},
	"kms-governance": {
		// This node's settings (network, FDE, SNMP, entropy) are node-local.
		"PUT /governance/system/state", "POST /governance/system/snmp/test",
		"POST /governance/system/network/apply", "POST /governance/system/fde/integrity-check",
		"POST /governance/system/fde/rotate-key", "POST /governance/system/fde/test-recovery",
	},
	"kms-audit": {
		// Every node appends and verifies its own audit chain; search and
		// tests only read.
		"POST /audit/publish", "POST /audit/search",
		"POST /audit/merkle/build", "POST /audit/merkle/verify",
		"POST /ops-metrics/record", "POST /alerts/test-rule",
		"POST /alerts/channels/test", "POST /webhooks/{id}/test",
	},
}

func isWrite(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return false
	}
	return true
}

func matchPattern(pattern, method, path string) bool {
	pm, pp, ok := strings.Cut(pattern, " ")
	if !ok || pm != method {
		return false
	}
	want := strings.Split(strings.Trim(pp, "/"), "/")
	got := strings.Split(strings.Trim(path, "/"), "/")
	if len(want) != len(got) {
		return false
	}
	for i := range want {
		if strings.HasPrefix(want[i], "{") && strings.HasSuffix(want[i], "}") {
			if got[i] == "" {
				return false
			}
			continue
		}
		if want[i] != got[i] {
			return false
		}
	}
	return true
}

// Decision is what a member does with a request.
type Decision int

const (
	RunLocal Decision = iota
	Forward
	// Refuse: a write the primary must perform, for a service that cannot be
	// forwarded (no internal URL). Safer than a divergent local write.
	Refuse
)

// Decide classifies a request arriving at service on a cluster member.
func Decide(service, method, path string) Decision {
	if !isWrite(method) {
		return RunLocal
	}
	if _, never := NeverForward[service]; never {
		return RunLocal
	}
	for _, p := range Local[service] {
		if matchPattern(p, method, path) {
			return RunLocal
		}
	}
	if _, ok := Services[service]; !ok {
		return Refuse
	}
	return Forward
}
