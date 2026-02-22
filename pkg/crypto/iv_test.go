package crypto

import "testing"

func TestGenerateIVAllModes(t *testing.T) {
	internal, err := GenerateIV(IVInternal, nil, nil, nil)
	if err != nil || len(internal) != 16 {
		t.Fatalf("internal iv invalid err=%v len=%d", err, len(internal))
	}

	extIn := []byte("0123456789ABCDEF")
	external, err := GenerateIV(IVExternal, nil, extIn, nil)
	if err != nil {
		t.Fatalf("external iv error: %v", err)
	}
	if string(external) != string(extIn) {
		t.Fatal("external iv mismatch")
	}

	d1, err := GenerateIV(IVDeterministic, []byte("key"), nil, []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	d2, err := GenerateIV(IVDeterministic, []byte("key"), nil, []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	if !ConstantTimeEqual(d1, d2) {
		t.Fatal("deterministic iv should match")
	}
}
