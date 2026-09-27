package main

import (
	"os"
	"regexp"
	"testing"

	kmip "github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/ttlv"
)

// Query advertises exactly the operations the executor routes: an operation
// that is listed but not served would be a false capability claim.
func TestQueryAdvertisesOnlyRoutedOperations(t *testing.T) {
	src, err := os.ReadFile("handler.go")
	if err != nil {
		t.Fatal(err)
	}
	routed := map[kmip.Operation]bool{}
	for _, m := range regexp.MustCompile(`exec\.Route\(kmip\.Operation(\w+),`).FindAllStringSubmatch(string(src), -1) {
		routed[kmipOperationByName(t, m[1])] = true
	}
	ops := supportedKMIPOperations()
	if len(ops) != len(routed) {
		t.Fatalf("advertised %d operations, routed %d", len(ops), len(routed))
	}
	for _, op := range ops {
		if !routed[op] {
			t.Fatalf("%s is advertised but not routed", ttlv.EnumStr(op))
		}
	}
}

func kmipOperationByName(t *testing.T, name string) kmip.Operation {
	t.Helper()
	for op := kmip.Operation(1); op < 0x40; op++ {
		if ttlv.EnumStr(op) == name {
			return op
		}
	}
	t.Fatalf("unknown operation %s", name)
	return 0
}
