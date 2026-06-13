package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGatherInlineContent(t *testing.T) {
	items, err := gatherScanContent(LeakScanTarget{Name: "diff", Type: "git_repo"}, "aws_secret_access_key = \"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\"", "patch.diff")
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].path != "patch.diff" {
		t.Fatalf("unexpected items: %+v", items)
	}
	if len(scanContent(items[0].path, items[0].data)) == 0 {
		t.Fatal("expected the inline content to yield a finding")
	}
}

func TestGatherRejectsRemoteWithoutFetcher(t *testing.T) {
	t.Setenv("LEAK_SCAN_ROOT", t.TempDir())
	_, err := gatherScanContent(LeakScanTarget{Name: "repo", Type: "git_repo", URI: "https://github.com/acme/repo.git"}, "", "")
	if err == nil {
		t.Fatal("expected an honest error for remote git without a configured fetcher")
	}
}

func TestGatherRequiresScanRoot(t *testing.T) {
	t.Setenv("LEAK_SCAN_ROOT", "")
	_, err := gatherScanContent(LeakScanTarget{Name: "f", Type: "env_file", URI: "secrets.env"}, "", "")
	if err == nil {
		t.Fatal("expected error when no content source is available")
	}
}

func TestGatherRejectsTraversal(t *testing.T) {
	root := t.TempDir()
	t.Setenv("LEAK_SCAN_ROOT", root)
	// Write a secret OUTSIDE the root that traversal would try to reach.
	outside := filepath.Join(filepath.Dir(root), "outside.env")
	_ = os.WriteFile(outside, []byte("aws_access_key_id = AKIAIOSFODNN7EXAMPLE"), 0o600)
	defer os.Remove(outside)

	_, err := gatherScanContent(LeakScanTarget{Name: "x", Type: "env_file", URI: "../outside.env"}, "", "")
	if err == nil {
		t.Fatal("expected traversal outside scan root to be rejected")
	}
}

func TestGatherScansLocalDirectory(t *testing.T) {
	root := t.TempDir()
	t.Setenv("LEAK_SCAN_ROOT", root)
	// A file with a secret, a binary file (skipped), and a vendored dir (skipped).
	if err := os.WriteFile(filepath.Join(root, "config.env"), []byte("github_token=ghp_1234567890abcdefghijklmnopqrstuvwxyz\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "image.bin"), []byte{0x00, 0x01, 0x02, 0x00}, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "vendor"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "vendor", "leak.env"), []byte("aws_access_key_id = AKIAIOSFODNN7EXAMPLE"), 0o600); err != nil {
		t.Fatal(err)
	}

	items, err := gatherScanContent(LeakScanTarget{Name: "repo", Type: "git_repo", URI: "."}, "", "")
	if err != nil {
		t.Fatal(err)
	}
	// Only config.env should be gathered (binary + vendored excluded).
	found := map[string]bool{}
	for _, it := range items {
		found[it.path] = true
	}
	if !found["config.env"] {
		t.Errorf("expected config.env to be scanned, got %v", found)
	}
	if found[filepath.Join("vendor", "leak.env")] {
		t.Error("vendored directory should have been skipped")
	}
	if found["image.bin"] {
		t.Error("binary file should have been skipped")
	}

	// And the gathered file yields the real finding.
	total := 0
	for _, it := range items {
		total += len(scanContent(it.path, it.data))
	}
	if total == 0 {
		t.Error("expected at least one finding from the scanned directory")
	}
}
