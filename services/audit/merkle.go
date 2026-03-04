package main

import (
	"crypto/sha256"
	"encoding/hex"
)

// MerkleTree holds the complete set of nodes for a binary hash tree.
// Leaves are SHA-256 hashes of audit event chain_hash values.
// Internal nodes are SHA-256(left || right).
// Odd leaf counts are handled by duplicating the last leaf.
type MerkleTree struct {
	Leaves []string   // leaf hashes (hex)
	Layers [][]string // layers[0] = leaves, layers[len-1] = [root]
}

// BuildMerkleTree constructs a complete Merkle tree from leaf hashes.
func BuildMerkleTree(leaves []string) MerkleTree {
	if len(leaves) == 0 {
		return MerkleTree{}
	}

	// Copy leaves so we don't mutate the input
	current := make([]string, len(leaves))
	copy(current, leaves)

	layers := [][]string{current}

	for len(current) > 1 {
		// If odd number, duplicate last
		if len(current)%2 != 0 {
			current = append(current, current[len(current)-1])
		}
		var next []string
		for i := 0; i < len(current); i += 2 {
			parent := merkleHash(current[i], current[i+1])
			next = append(next, parent)
		}
		layers = append(layers, next)
		current = next
	}

	return MerkleTree{Leaves: leaves, Layers: layers}
}

// Root returns the Merkle root hash, or empty string if tree is empty.
func (t MerkleTree) Root() string {
	if len(t.Layers) == 0 {
		return ""
	}
	top := t.Layers[len(t.Layers)-1]
	if len(top) == 0 {
		return ""
	}
	return top[0]
}

// MerkleProof contains the sibling hashes needed to verify inclusion.
type MerkleProof struct {
	LeafHash  string          `json:"leaf_hash"`
	LeafIndex int             `json:"leaf_index"`
	Siblings  []ProofSibling  `json:"siblings"`
	Root      string          `json:"root"`
}

type ProofSibling struct {
	Hash     string `json:"hash"`
	Position string `json:"position"` // "left" or "right"
}

// GenerateProof generates an inclusion proof for the leaf at the given index.
func GenerateProof(tree MerkleTree, index int) (MerkleProof, bool) {
	if len(tree.Layers) == 0 || index < 0 || index >= len(tree.Leaves) {
		return MerkleProof{}, false
	}

	proof := MerkleProof{
		LeafHash:  tree.Leaves[index],
		LeafIndex: index,
		Root:      tree.Root(),
	}

	idx := index
	for layer := 0; layer < len(tree.Layers)-1; layer++ {
		level := tree.Layers[layer]
		// Pad for odd layers
		padded := level
		if len(padded)%2 != 0 {
			padded = append(padded, padded[len(padded)-1])
		}

		var sibling ProofSibling
		if idx%2 == 0 {
			// Sibling is on the right
			sibling = ProofSibling{Hash: padded[idx+1], Position: "right"}
		} else {
			// Sibling is on the left
			sibling = ProofSibling{Hash: padded[idx-1], Position: "left"}
		}
		proof.Siblings = append(proof.Siblings, sibling)
		idx /= 2
	}

	return proof, true
}

// VerifyProof checks that a Merkle inclusion proof is valid.
func VerifyProof(proof MerkleProof) bool {
	if proof.Root == "" || proof.LeafHash == "" {
		return false
	}

	current := proof.LeafHash
	for _, sib := range proof.Siblings {
		if sib.Position == "left" {
			current = merkleHash(sib.Hash, current)
		} else {
			current = merkleHash(current, sib.Hash)
		}
	}
	return current == proof.Root
}

// merkleHash computes SHA-256(left || right) and returns hex.
func merkleHash(left, right string) string {
	h := sha256.New()
	h.Write([]byte(left))
	h.Write([]byte(right))
	return hex.EncodeToString(h.Sum(nil))
}
