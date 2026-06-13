// Typed client for keycore's external credential -> key binding registry.
// Declaring a binding lets the unified console correlate a leaked credential
// with anomalous usage of the KMS key that protects it.

import type { AuthSession } from "./auth";
import { serviceRequest } from "./serviceApi";

export interface CredentialBinding {
  id: string;
  fingerprint: string;
  credential_type: string;
  key_id: string;
  label: string;
  created_by: string;
  created_at: string;
}

// bindCredentialToKey registers a credential as protected by keyId. Provide
// either the raw value (hashed server-side, never stored) or a precomputed
// SHA-256 fingerprint — when correlating an existing leak finding, pass its
// secret_fingerprint.
export async function bindCredentialToKey(
  session: AuthSession,
  keyId: string,
  body: { fingerprint?: string; value?: string; credential_type?: string; label?: string }
): Promise<CredentialBinding> {
  const res = await serviceRequest<any>(session, "keycore", `/keys/${keyId}/credential-bindings`, {
    method: "POST",
    body: JSON.stringify(body),
  });
  return res.binding;
}

export async function listCredentialBindings(session: AuthSession, keyId: string): Promise<CredentialBinding[]> {
  const res = await serviceRequest<any>(session, "keycore", `/keys/${keyId}/credential-bindings`);
  return res.bindings ?? [];
}

export async function deleteCredentialBinding(session: AuthSession, bindingId: string): Promise<void> {
  await serviceRequest(session, "keycore", `/credential-bindings/${bindingId}`, { method: "DELETE" });
}
