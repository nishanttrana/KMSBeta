// Preview features: they store configuration but enforce or execute nothing.
// Mirrors pkg/features.Preview (Go); scripts/conformance.sh fails when the two
// lists differ. docs/PREVIEW_FEATURES.md

export type PreviewFeature = { id: string; name: string; limitation: string };

export const PREVIEW_FEATURES: PreviewFeature[] = [
  { id: "keycore.federation", name: "Key federation / multi-KMS failover", limitation: "Providers, mappings and failovers are stored; no key is replicated and no failover happens." },
  { id: "keycore.binding_policy", name: "Key binding policies", limitation: "Stored only; key operations do not evaluate them." },
  { id: "keycore.sharing_grant", name: "Fine-grained key sharing grants", limitation: "Stored only; use key access grants for enforced sharing." },
  { id: "keycore.edge", name: "Edge & IoT agents, leases and receipts", limitation: "Stored only; there is no edge runtime." },
  { id: "keycore.advanced_encryption_modes", name: "Homomorphic / functional encryption modes", limitation: "Registered as controls; no homomorphic or functional encryption is performed. Searchable HMAC tokens are available." },
];

export function previewFeature(id: string): PreviewFeature | undefined {
  return PREVIEW_FEATURES.find((f) => f.id === id);
}
