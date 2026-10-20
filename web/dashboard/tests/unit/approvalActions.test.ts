import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { APPROVAL_ACTIONS } from "../../src/lib/approvalActions";

// Every trigger offered in Approvals → Policies is an action a service
// really submits for approval: each names the Go file and the code that
// sends it, so removing that code fails this test (13.27.0-beta).
const SENDERS: Record<string, [string, string][]> = {
  "key.*": [["services/keycore/governance_approvals.go", 'action := "key." + strings.ToLower(strings.TrimSpace(in.Operation))']],
  "key.encrypt": [["services/keycore/keycore.go", 'operation = "encrypt"']],
  "key.decrypt": [["services/keycore/keycore.go", 'operation = "decrypt"']],
  "key.wrap": [["services/keycore/data_key.go", 'Operation: "wrap"']],
  "key.unwrap": [["services/ekm/service.go", 'Operation:         "unwrap"']],
  "key.sign": [["services/keycore/keycore.go", 'operation = "sign"']],
  "key.verify": [["services/keycore/keycore.go", 'operation = "verify"']],
  "key.derive": [["services/keycore/keycore.go", 'operation = "derive"']],
  "key.kem-encapsulate": [["services/keycore/keycore.go", 'ensureApprovalAllowed(ctx, key, req.TenantID, "kem-encapsulate"']],
  "key.kem-decapsulate": [["services/keycore/keycore.go", 'ensureApprovalAllowed(ctx, key, req.TenantID, "kem-decapsulate"']],
  "key.destroy": [["services/keycore/keycore.go", 'enforcePostureQuorumOnDestroy(ctx, tenantID, key, "destroy"']],
  "key.update-access-policy": [["services/keycore/access_hardening.go", 'Operation:      "update_access_policy"']],
  "autokey.provision": [["services/autokey/service.go", 'Action:         "autokey.provision"']],
  "posture.*": [["services/posture/approvals.go", 'return "posture." + actionType']],
  "posture.escalate-remediation": [["services/posture/service.go", 'ActionType:         "escalate_remediation"']],
  "playbook.*": [["services/compliance/playbook_executor.go", 'Action: "playbook." + a.Type']],
};
for (const t of ["deactivate_key", "byok_revoke", "revoke_certificate", "disable_user", "revoke_api_key", "revoke_client"]) {
  SENDERS[`playbook.${t.replace(/_/g, "-")}`] = [["services/compliance/playbook_catalog.go", `{Type: "${t}",`]];
}
const ROOT = resolve(__dirname, "../../../..");

describe("approval trigger catalogue", () => {
  const offered = APPROVAL_ACTIONS.flatMap((g) => g.actions.map((a) => a.action));

  it("offers only actions a service sends, each proven in the Go code", () => {
    for (const action of offered) {
      const proofs = SENDERS[action];
      expect(proofs, `${action} has no sender`).toBeDefined();
      for (const [file, snippet] of [...proofs!, ...(action.startsWith("key.") ? SENDERS["key.*"]! : [])]) {
        expect(readFileSync(resolve(ROOT, file), "utf8"), `${action}: ${file}`).toContain(snippet);
      }
    }
  });

  it("the six playbook actions offered as always pausing really are marked required", () => {
    const catalog = readFileSync(resolve(ROOT, "services/compliance/playbook_catalog.go"), "utf8").split("\n");
    for (const t of ["deactivate_key", "byok_revoke", "revoke_certificate", "disable_user", "revoke_api_key", "revoke_client"]) {
      const line = catalog.find((l) => l.includes(`{Type: "${t}",`));
      expect(line, t).toContain('Approval: "required"');
    }
  });

  it("names each action once, in governance's normal form (- not _)", () => {
    expect(new Set(offered).size).toBe(offered.length);
    for (const a of offered) expect(a).toBe(a.toLowerCase().replace(/_/g, "-"));
  });
});
