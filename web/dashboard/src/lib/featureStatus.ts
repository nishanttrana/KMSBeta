// Preview features: they store configuration but enforce or execute nothing.
// Mirrors pkg/features.Preview (Go); scripts/conformance.sh fails when the two
// lists differ. docs/PREVIEW_FEATURES.md

export type PreviewFeature = { id: string; name: string; limitation: string };

export const PREVIEW_FEATURES: PreviewFeature[] = [
  { id: "keycore.federation", name: "Key federation / multi-KMS failover", limitation: "Providers, mappings and failovers are stored; no key is replicated and no failover happens." },
  { id: "keycore.advanced_encryption_modes", name: "Homomorphic / functional encryption modes", limitation: "Registered as controls; no homomorphic or functional encryption is performed. Searchable HMAC tokens are available." },
];

export function previewFeature(id: string): PreviewFeature | undefined {
  return PREVIEW_FEATURES.find((f) => f.id === id);
}
