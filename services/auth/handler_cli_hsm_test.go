package main

import "testing"

func TestParsePKCS11Slots(t *testing.T) {
	raw := `
Available slots:
Slot 0 (0x0): SoftHSM slot ID 0x0
  token label        : kms-prod
  token manufacturer : SoftHSM project
  token model        : SoftHSM v2
  serial num         : 1234abcd
Slot 1 (0x1): SoftHSM slot ID 0x1
  token label        : <empty>
  token manufacturer : SoftHSM project
  token model        : SoftHSM v2
  serial num         : 9abc0001
`
	items := parsePKCS11Slots(raw)
	if len(items) != 2 {
		t.Fatalf("expected 2 slot items, got %d", len(items))
	}
	if items[0].SlotID != "0" {
		t.Fatalf("expected first slot id 0, got %q", items[0].SlotID)
	}
	if items[0].TokenLabel != "kms-prod" {
		t.Fatalf("expected first token label kms-prod, got %q", items[0].TokenLabel)
	}
	if !items[0].TokenPresent {
		t.Fatalf("expected first slot to be token-present")
	}
	if items[0].Partition != "kms-prod" {
		t.Fatalf("expected first partition kms-prod, got %q", items[0].Partition)
	}
	if items[1].TokenPresent {
		t.Fatalf("expected second slot token_present false")
	}
	if items[1].TokenLabel != "" {
		t.Fatalf("expected second token label empty, got %q", items[1].TokenLabel)
	}
}
