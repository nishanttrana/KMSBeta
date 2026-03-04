package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"
)

func leafHash(data string) string {
	h := sha256.Sum256([]byte(data))
	return hex.EncodeToString(h[:])
}

func TestMerkleTreeBuild(t *testing.T) {
	leaves := make([]string, 8)
	for i := range leaves {
		leaves[i] = leafHash(fmt.Sprintf("event-%d", i))
	}

	tree := BuildMerkleTree(leaves)
	root := tree.Root()
	if root == "" {
		t.Fatal("tree root is empty")
	}
	t.Logf("Root: %s", root)
	t.Logf("Layers: %d", len(tree.Layers))

	// Deterministic
	tree2 := BuildMerkleTree(leaves)
	if tree2.Root() != root {
		t.Fatal("non-deterministic root")
	}
}

func TestMerkleProofVerify(t *testing.T) {
	leaves := make([]string, 8)
	for i := range leaves {
		leaves[i] = leafHash(fmt.Sprintf("event-%d", i))
	}

	tree := BuildMerkleTree(leaves)

	for i := 0; i < len(leaves); i++ {
		proof, ok := GenerateProof(tree, i)
		if !ok {
			t.Fatalf("leaf %d: generate proof failed", i)
		}
		if !VerifyProof(proof) {
			t.Fatalf("leaf %d: proof verification FAILED", i)
		}
		t.Logf("Leaf %d: %d siblings, verified OK", i, len(proof.Siblings))
	}
}

func TestMerkleProofTampered(t *testing.T) {
	leaves := make([]string, 8)
	for i := range leaves {
		leaves[i] = leafHash(fmt.Sprintf("event-%d", i))
	}

	tree := BuildMerkleTree(leaves)
	proof, ok := GenerateProof(tree, 3)
	if !ok {
		t.Fatal("generate proof failed")
	}

	// Tamper root
	tampered := proof
	tampered.Root = "deadbeef" + proof.Root[8:]
	if VerifyProof(tampered) {
		t.Fatal("tampered root should NOT verify")
	}

	// Tamper sibling
	tampered2 := MerkleProof{
		LeafHash:  proof.LeafHash,
		LeafIndex: proof.LeafIndex,
		Root:      proof.Root,
		Siblings:  make([]ProofSibling, len(proof.Siblings)),
	}
	copy(tampered2.Siblings, proof.Siblings)
	tampered2.Siblings[0].Hash = "0000000000000000000000000000000000000000000000000000000000000000"
	if VerifyProof(tampered2) {
		t.Fatal("tampered sibling should NOT verify")
	}

	t.Log("Tamper detection: OK")
}

func TestMerkleOddLeaves(t *testing.T) {
	leaves := make([]string, 7)
	for i := range leaves {
		leaves[i] = leafHash(fmt.Sprintf("odd-%d", i))
	}

	tree := BuildMerkleTree(leaves)
	if tree.Root() == "" {
		t.Fatal("odd-leaf tree root is empty")
	}

	for i := 0; i < len(leaves); i++ {
		proof, ok := GenerateProof(tree, i)
		if !ok {
			t.Fatalf("odd leaf %d: proof failed", i)
		}
		if !VerifyProof(proof) {
			t.Fatalf("odd leaf %d: verify failed", i)
		}
	}
	t.Logf("7 odd leaves: all proofs verified")
}

func TestMerkleSingleLeaf(t *testing.T) {
	leaves := []string{leafHash("single")}

	tree := BuildMerkleTree(leaves)
	proof, ok := GenerateProof(tree, 0)
	if !ok {
		t.Fatal("single leaf proof generation failed")
	}
	if !VerifyProof(proof) {
		t.Fatal("single leaf proof should verify")
	}
	t.Logf("Single leaf: root=%s, siblings=%d", proof.Root, len(proof.Siblings))
}

func TestMerkleEmptyTree(t *testing.T) {
	tree := BuildMerkleTree(nil)
	if tree.Root() != "" {
		t.Fatal("empty tree should have empty root")
	}

	_, ok := GenerateProof(tree, 0)
	if ok {
		t.Fatal("empty tree proof should fail")
	}
}
