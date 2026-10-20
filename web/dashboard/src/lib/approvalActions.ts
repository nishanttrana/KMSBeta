// The actions services submit to governance for approval, offered as
// trigger choices in Approvals → Policies (13.27.0-beta). A policy's trigger
// patterns pick the policy only when the caller names none (governance
// FindPolicyForAction); `when` says when that is. Every entry is proven by
// tests/unit/approvalActions.test.ts against the Go code that sends it.
// Administration's old list offered names no service sends (user.create,
// system.backup, ...), so a policy built from them never held anything.

export type ApprovalActionGroup = {
  group: string;
  when: string;
  actions: Array<{ action: string; label: string }>;
};

export const APPROVAL_ACTIONS: ApprovalActionGroup[] = [
  {
    group: "Key operations",
    when: "a key that requires approval and names no approval policy",
    actions: [
      { action: "key.encrypt", label: "Encrypt" },
      { action: "key.decrypt", label: "Decrypt" },
      { action: "key.wrap", label: "Wrap" },
      { action: "key.unwrap", label: "Unwrap" },
      { action: "key.sign", label: "Sign" },
      { action: "key.verify", label: "Verify" },
      { action: "key.derive", label: "Derive" },
      { action: "key.kem-encapsulate", label: "KEM encapsulate" },
      { action: "key.kem-decapsulate", label: "KEM decapsulate" },
      { action: "key.destroy", label: "Destroy (when Posture forces quorum on destructive operations)" },
      { action: "key.update-access-policy", label: "Change a key's access grants (when grant changes need approval)" },
    ],
  },
  {
    group: "Autokey",
    when: "a provisioning request whose policy, template and settings name no approval policy",
    actions: [{ action: "autokey.provision", label: "Provision a key handle" }],
  },
  {
    group: "Posture remediation",
    when: "a remediation action that needs approval",
    actions: [
      { action: "posture.escalate-remediation", label: "Escalate a remediation" },
      { action: "posture.*", label: "Any posture remediation" },
    ],
  },
  {
    group: "Playbook actions",
    when: "a playbook step that pauses for approval (always for these six; others when the playbook asks)",
    actions: [
      { action: "playbook.deactivate-key", label: "Deactivate key" },
      { action: "playbook.byok-revoke", label: "Revoke cloud BYOK key material" },
      { action: "playbook.revoke-certificate", label: "Revoke certificate" },
      { action: "playbook.disable-user", label: "Disable user" },
      { action: "playbook.revoke-api-key", label: "Revoke API key" },
      { action: "playbook.revoke-client", label: "Revoke REST client" },
      { action: "playbook.*", label: "Any playbook action" },
    ],
  },
];
