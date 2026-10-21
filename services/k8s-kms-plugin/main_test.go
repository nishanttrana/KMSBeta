package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestConfigNeedsItsFieldsAndRefusesUnknownOnes(t *testing.T) {
	dir := t.TempDir()
	write := func(s string) string {
		p := filepath.Join(dir, "c.json")
		if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	c, err := load(write(`{"server":"https://kms","tenant_id":"t1","key_id":"k","client_id":"c","api_key_file":"/etc/k"}`))
	if err != nil || c.Socket != "/var/run/vecta-kms/kms.sock" {
		t.Fatalf("valid config: %+v %v", c, err)
	}
	if _, err := load(write(`{"server":"https://kms","tenant_id":"t1","key_id":"k","client_id":"c"}`)); err == nil {
		t.Fatal("a config without an api key file was accepted")
	}
	if _, err := load(write(`{"server":"https://kms","tenant_id":"t1","key_id":"k","client_id":"c","api_key_file":"/k","api_key":"inline"}`)); err == nil {
		t.Fatal("an inline api key was accepted")
	}
}
