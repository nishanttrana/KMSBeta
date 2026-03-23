// @ts-nocheck -- legacy tab: strict typing deferred, do not add new suppressions
import { useEffect, useMemo, useState } from "react";
import {
  evaluateConfidentialRelease,
  getConfidentialPolicy,
  getConfidentialSummary,
  listConfidentialReleases,
  updateConfidentialPolicy
} from "../../../lib/confidential";
import { errMsg } from "../runtimeUtils";
import { C } from "../theme";
import { B, Btn, Card, Chk, FG, Inp, Section, Sel, Stat, Tabs, Txt } from "../legacyPrimitives";

const PROVIDER_OPTIONS = [
  ["aws_nitro_enclaves", "AWS Nitro Enclaves"],
  ["aws_nitro_tpm", "AWS NitroTPM"],
  ["azure_secure_key_release", "Azure Secure Key Release"],
  ["gcp_confidential_space", "GCP Confidential Space"],
  ["generic", "Generic Claims / Measurements"]
];

const DEFAULT_POLICY = {
  tenant_id: "",
  enabled: false,
  provider: "aws_nitro_enclaves",
  mode: "enforce",
  key_scopes: [],
  approved_images: [],
  approved_subjects: [],
  allowed_attesters: [],
  required_measurements: { pcr0: "", pcr8: "" },
  required_claims: {},
  require_secure_boot: true,
  require_debug_disabled: true,
  max_evidence_age_sec: 300,
  cluster_scope: "cluster_wide",
  allowed_cluster_nodes: [],
  fallback_action: "deny"
};

function listToCsv(value: any): string {
  return Array.isArray(value) ? value.map((item) => String(item || "").trim()).filter(Boolean).join(", ") : "";
}

function csvToList(value: string): string[] {
  return String(value || "").split(",").map((item) => item.trim()).filter(Boolean);
}

function prettyJson(value: any): string {
  if (!value || typeof value !== "object") {
    return "{}";
  }
  return JSON.stringify(value, null, 2);
}

function parseJsonObject(raw: string, label: string): Record<string, string> {
  const trimmed = String(raw || "").trim();
  if (!trimmed) {
    return {};
  }
  let parsed: any = {};
  try {
    parsed = JSON.parse(trimmed);
  } catch {
    throw new Error(`${label} must be valid JSON`);
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error(`${label} must be a JSON object`);
  }
  return Object.entries(parsed).reduce((acc: Record<string, string>, [key, value]) => {
    const nextKey = String(key || "").trim();
    const nextValue = typeof value === "string" ? value : JSON.stringify(value);
    if (nextKey && String(nextValue || "").trim()) {
      acc[nextKey] = String(nextValue);
    }
    return acc;
  }, {});
}

function decisionColor(decision: string): string {
  const value = String(decision || "").trim().toLowerCase();
  if (value === "release") return "green";
  if (value === "review") return "amber";
  return "red";
}

function shortTs(value: any): string {
  const raw = String(value || "").trim();
  if (!raw) return "-";
  const dt = new Date(raw);
  if (Number.isNaN(dt.getTime())) return raw;
  return dt.toLocaleString();
}

function providerDocumentHint(provider: string): string {
  switch (String(provider || "").trim()) {
    case "aws_nitro_enclaves":
    case "aws_nitro_tpm":
      return "Paste the base64-encoded AWS Nitro COSE_Sign1 attestation document. Bound user_data JSON can carry image ref, image digest, workload identity, and cluster node.";
    case "azure_secure_key_release":
      return "Paste the signed Azure Attestation JWT from your Secure Key Release or MAA flow. The service will verify the issuer metadata and JWKS before evaluating policy.";
    case "gcp_confidential_space":
      return "Paste the signed GCP Confidential Space attestation JWT. The service will verify the Google issuer, JWKS, and signed claims before evaluating policy.";
    default:
      return "Generic mode accepts manually supplied claims and measurements from your own attestation broker.";
  }
}

export const ConfidentialComputeTab = ({ session, onToast }: any) => {
  const [view, setView] = useState("Attestation Policy");
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [evaluating, setEvaluating] = useState(false);
  const [summary, setSummary] = useState<any>(null);
  const [policy, setPolicy] = useState<any>(DEFAULT_POLICY);
  const [releases, setReleases] = useState<any[]>([]);
  const [decision, setDecision] = useState<any>(null);
  const [filterText, setFilterText] = useState("");
  const [imageCsv, setImageCsv] = useState("");
  const [scopeCsv, setScopeCsv] = useState("");
  const [subjectCsv, setSubjectCsv] = useState("");
  const [attesterCsv, setAttesterCsv] = useState("");
  const [clusterNodeCsv, setClusterNodeCsv] = useState("");
  const [claimsJson, setClaimsJson] = useState("{}");
  const [measurementsJson, setMeasurementsJson] = useState("{\n  \"pcr0\": \"\",\n  \"pcr8\": \"\"\n}");
  const [evalClaimsJson, setEvalClaimsJson] = useState("{\n  \"environment\": \"prod\",\n  \"team\": \"payments\"\n}");
  const [evalMeasurementsJson, setEvalMeasurementsJson] = useState("{\n  \"pcr0\": \"baseline-image-hash\",\n  \"pcr8\": \"secure-boot-chain-hash\"\n}");
  const [releaseInput, setReleaseInput] = useState<any>({
    key_id: "key-prod-root",
    key_scope: "payments-prod",
    provider: "aws_nitro_enclaves",
    attestation_document: "",
    attestation_format: "auto",
    workload_identity: "spiffe://root/workloads/payments-authorizer",
    attester: "arn:aws:iam::123456789012:role/nitro-attestation",
    image_ref: "123456789012.dkr.ecr.us-east-1.amazonaws.com/payments/authorizer:v1.4.2",
    image_digest: "sha256:1f2d3c4b5a6978877665544332211000aabbccddeeff00112233445566778899",
    audience: "kms-key-release",
    nonce: "nonce-demo-001",
    evidence_issued_at: new Date().toISOString(),
    secure_boot: true,
    debug_disabled: true,
    cluster_node_id: "vecta-kms-01",
    requester: "",
    release_reason: "Authorize payment service in enclave runtime",
    dry_run: true
  });

  const refresh = async (silent = false) => {
    if (!session?.token) {
      setSummary(null);
      setPolicy(DEFAULT_POLICY);
      setReleases([]);
      return;
    }
    if (!silent) setLoading(true);
    try {
      const [nextPolicy, nextSummary, nextReleases] = await Promise.all([
        getConfidentialPolicy(session),
        getConfidentialSummary(session),
        listConfidentialReleases(session, 100)
      ]);
      const hydratedPolicy = { ...DEFAULT_POLICY, ...(nextPolicy || {}), tenant_id: session.tenantId };
      setPolicy(hydratedPolicy);
      setSummary(nextSummary || null);
      setReleases(Array.isArray(nextReleases) ? nextReleases : []);
      setImageCsv(listToCsv(hydratedPolicy.approved_images));
      setScopeCsv(listToCsv(hydratedPolicy.key_scopes));
      setSubjectCsv(listToCsv(hydratedPolicy.approved_subjects));
      setAttesterCsv(listToCsv(hydratedPolicy.allowed_attesters));
      setClusterNodeCsv(listToCsv(hydratedPolicy.allowed_cluster_nodes));
      setClaimsJson(prettyJson(hydratedPolicy.required_claims));
      setMeasurementsJson(prettyJson(hydratedPolicy.required_measurements));
      setReleaseInput((prev: any) => ({
        ...prev,
        provider: String(hydratedPolicy.provider || prev.provider || "aws_nitro_enclaves"),
        key_scope: String(hydratedPolicy.key_scopes?.[0] || prev.key_scope || ""),
        requester: String(prev.requester || session.username || "")
      }));
    } catch (error) {
      onToast?.(`Confidential Compute load failed: ${errMsg(error)}`);
    } finally {
      if (!silent) setLoading(false);
    }
  };

  useEffect(() => {
    void refresh(false);
  }, [session?.tenantId, session?.token]);

  const filteredReleases = useMemo(() => {
    const query = String(filterText || "").trim().toLowerCase();
    if (!query) {
      return releases;
    }
    return releases.filter((item: any) => {
      const haystack = [
        item?.id,
        item?.key_id,
        item?.key_scope,
        item?.provider,
        item?.verification_issuer,
        item?.workload_identity,
        item?.cluster_node_id,
        item?.decision,
        ...(Array.isArray(item?.reasons) ? item.reasons : [])
      ].join(" ").toLowerCase();
      return haystack.includes(query);
    });
  }, [filterText, releases]);

  const evaluationProvider = String(releaseInput.provider || policy.provider || "generic");
  const providerRequiresDocument = evaluationProvider !== "generic";

  const summaryCards = [
    { label: "Policy", value: summary?.policy_enabled ? "On" : "Off", sub: summary?.provider || policy.provider || "—", color: summary?.policy_enabled ? "green" : "amber" },
    { label: "Approved Images", value: String(summary?.approved_image_count || 0), sub: `${summary?.key_scope_count || 0} key scopes`, color: "accent" },
    { label: "Releases 24h", value: String(summary?.release_count_24h || 0), sub: `${summary?.cryptographically_verified_count_24h || 0} verified`, color: "green" },
    { label: "Denies 24h", value: String(summary?.deny_count_24h || 0), sub: summary?.latest_decision ? `Latest: ${summary.latest_decision}` : "No decisions yet", color: "red" },
    { label: "Cluster Nodes", value: String(summary?.unique_cluster_nodes || 0), sub: summary?.last_decision_at ? shortTs(summary.last_decision_at) : "No release history", color: "blue" }
  ];

  const savePolicy = async () => {
    if (!session?.token) return;
    setSaving(true);
    try {
      const payload = {
        ...policy,
        tenant_id: session.tenantId,
        key_scopes: csvToList(scopeCsv),
        approved_images: csvToList(imageCsv),
        approved_subjects: csvToList(subjectCsv),
        allowed_attesters: csvToList(attesterCsv),
        allowed_cluster_nodes: csvToList(clusterNodeCsv),
        required_claims: parseJsonObject(claimsJson, "Required claims"),
        required_measurements: parseJsonObject(measurementsJson, "Required measurements"),
        updated_by: session.username
      };
      const saved = await updateConfidentialPolicy(session, payload);
      setPolicy({ ...DEFAULT_POLICY, ...saved });
      onToast?.("Confidential Compute policy saved");
      await refresh(true);
    } catch (error) {
      onToast?.(`Confidential Compute save failed: ${errMsg(error)}`);
    } finally {
      setSaving(false);
    }
  };

  const runEvaluation = async () => {
    if (!session?.token) return;
    setEvaluating(true);
    try {
      const payload: any = {
        ...releaseInput,
        tenant_id: session.tenantId,
        provider: evaluationProvider
      };
      if (providerRequiresDocument) {
        payload.claims = {};
        payload.measurements = {};
        payload.workload_identity = "";
        payload.attester = "";
        payload.image_ref = "";
        payload.image_digest = "";
        payload.evidence_issued_at = "";
        payload.secure_boot = false;
        payload.debug_disabled = false;
      } else {
        payload.claims = parseJsonObject(evalClaimsJson, "Release claims");
        payload.measurements = parseJsonObject(evalMeasurementsJson, "Release measurements");
      }
      const result = await evaluateConfidentialRelease(session, payload);
      setDecision(result || null);
      onToast?.(`Attested release decision: ${String(result?.decision || "unknown").toUpperCase()}`);
      await refresh(true);
    } catch (error) {
      onToast?.(`Attested release evaluation failed: ${errMsg(error)}`);
    } finally {
      setEvaluating(false);
    }
  };

  return (
    <div>
      <Section
        title="Confidential Compute"
        actions={
          <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
            {loading ? <B c="blue" pulse>Syncing</B> : <B c={summary?.policy_enabled ? "green" : "amber"}>{summary?.policy_enabled ? "Policy Active" : "Policy Disabled"}</B>}
            <Btn onClick={() => void refresh(false)}>Refresh</Btn>
          </div>
        }
      >
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(180px,1fr))", gap: 10, marginBottom: 16 }}>
          {summaryCards.map((item) => (
            <Stat key={item.label} l={item.label} v={item.value} s={item.sub} c={item.color} />
          ))}
        </div>
        <Card style={{ padding: 16, background: `linear-gradient(135deg, ${C.card} 0%, rgba(40,95,145,.12) 100%)`, marginBottom: 14 }}>
          <div style={{ fontSize: 16, fontWeight: 700, color: C.text, marginBottom: 6 }}>Attested key release for verified workloads</div>
          <div style={{ fontSize: 11, color: C.dim, lineHeight: 1.6 }}>
            Gate key release on enclave or TEE evidence instead of host-only identity. Tenant policy controls provider, approved images,
            workload subject claims, PCR or measurement matching, cluster-node allowlists, and runtime safety checks like secure boot and debug-disabled posture.
          </div>
          <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginTop: 12 }}>
            <B c="accent">Tenant scoped</B>
            <B c="blue">Cluster aware</B>
            <B c="green">Audit logged</B>
            <B c="amber">Release history retained</B>
          </div>
        </Card>
        <Tabs tabs={["Attestation Policy", "Evaluate Release", "Release History"]} active={view} onChange={setView} />
      </Section>

      {view === "Attestation Policy" ? (
        <Section
          title="Attestation Policy"
          actions={
            <div style={{ display: "flex", gap: 8 }}>
              <Btn onClick={() => void refresh(false)}>Reload</Btn>
              <Btn primary onClick={() => void savePolicy()} disabled={saving}>{saving ? "Saving..." : "Save Policy"}</Btn>
            </div>
          }
        >
          <div style={{ display: "grid", gridTemplateColumns: "1.25fr .95fr", gap: 14 }}>
            <Card>
              <div style={{ fontSize: 12, fontWeight: 700, color: C.text, marginBottom: 12 }}>Tenant Policy Controls</div>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
                <FG label="Tenant">
                  <Inp value={session?.tenantId || ""} readOnly />
                </FG>
                <FG label="Provider">
                  <Sel value={policy.provider || "aws_nitro_enclaves"} onChange={(e) => setPolicy((prev: any) => ({ ...prev, provider: e.target.value }))}>
                    {PROVIDER_OPTIONS.map(([value, label]) => <option key={value} value={value}>{label}</option>)}
                  </Sel>
                </FG>
              </div>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 12 }}>
                <FG label="Mode">
                  <Sel value={policy.mode || "enforce"} onChange={(e) => setPolicy((prev: any) => ({ ...prev, mode: e.target.value }))}>
                    <option value="enforce">Enforce</option>
                    <option value="monitor">Monitor / review only</option>
                  </Sel>
                </FG>
                <FG label="Cluster Scope">
                  <Sel value={policy.cluster_scope || "cluster_wide"} onChange={(e) => setPolicy((prev: any) => ({ ...prev, cluster_scope: e.target.value }))}>
                    <option value="cluster_wide">Cluster wide</option>
                    <option value="node_allowlist">Node allowlist</option>
                  </Sel>
                </FG>
                <FG label="Fallback Action">
                  <Sel value={policy.fallback_action || "deny"} onChange={(e) => setPolicy((prev: any) => ({ ...prev, fallback_action: e.target.value }))}>
                    <option value="deny">Deny</option>
                    <option value="review">Review</option>
                  </Sel>
                </FG>
              </div>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
                <FG label="Approved Key Scopes" hint="Scopes or explicit key IDs allowed for attested release">
                  <Txt rows={3} value={scopeCsv} onChange={(e) => setScopeCsv(e.target.value)} mono={false} />
                </FG>
                <FG label="Approved Images" hint="Image ref, digest, or ref@digest">
                  <Txt rows={3} value={imageCsv} onChange={(e) => setImageCsv(e.target.value)} mono={false} />
                </FG>
                <FG label="Approved Subjects" hint="SPIFFE IDs, workload subjects, or enclave identities">
                  <Txt rows={3} value={subjectCsv} onChange={(e) => setSubjectCsv(e.target.value)} mono={false} />
                </FG>
                <FG label="Allowed Attesters" hint="Trusted issuer or attestation authority IDs">
                  <Txt rows={3} value={attesterCsv} onChange={(e) => setAttesterCsv(e.target.value)} mono={false} />
                </FG>
              </div>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
                <FG label="Required Claims JSON" hint='Example: {"environment":"prod","team":"payments"}'>
                  <Txt rows={7} value={claimsJson} onChange={(e) => setClaimsJson(e.target.value)} />
                </FG>
                <FG label="Required Measurements JSON" hint='Example: {"pcr0":"...","pcr8":"..."}'>
                  <Txt rows={7} value={measurementsJson} onChange={(e) => setMeasurementsJson(e.target.value)} />
                </FG>
              </div>
            </Card>

            <Card>
              <div style={{ fontSize: 12, fontWeight: 700, color: C.text, marginBottom: 12 }}>Runtime Safeguards</div>
              <FG label="Allowed Cluster Nodes" hint="Required only when cluster scope is node allowlist">
                <Txt rows={3} value={clusterNodeCsv} onChange={(e) => setClusterNodeCsv(e.target.value)} mono={false} />
              </FG>
              <FG label="Max Evidence Age (seconds)">
                <Inp
                  type="number"
                  min={30}
                  max={86400}
                  value={String(policy.max_evidence_age_sec || 300)}
                  onChange={(e) => setPolicy((prev: any) => ({ ...prev, max_evidence_age_sec: Number(e.target.value || 300) }))}
                />
              </FG>
              <div style={{ display: "grid", gap: 10, marginBottom: 12 }}>
                <label style={{ display: "flex", alignItems: "center", gap: 10, fontSize: 11, color: C.text }}>
                  <Chk checked={Boolean(policy.enabled)} onChange={(e) => setPolicy((prev: any) => ({ ...prev, enabled: e.target.checked }))} />
                  Enable attested key release for this tenant
                </label>
                <label style={{ display: "flex", alignItems: "center", gap: 10, fontSize: 11, color: C.text }}>
                  <Chk checked={Boolean(policy.require_secure_boot)} onChange={(e) => setPolicy((prev: any) => ({ ...prev, require_secure_boot: e.target.checked }))} />
                  Require secure boot evidence
                </label>
                <label style={{ display: "flex", alignItems: "center", gap: 10, fontSize: 11, color: C.text }}>
                  <Chk checked={Boolean(policy.require_debug_disabled)} onChange={(e) => setPolicy((prev: any) => ({ ...prev, require_debug_disabled: e.target.checked }))} />
                  Require debug disabled
                </label>
              </div>
              <div style={{ borderTop: `1px solid ${C.border}`, paddingTop: 12 }}>
                <div style={{ fontSize: 11, fontWeight: 700, color: C.text, marginBottom: 8 }}>Provider Notes</div>
                <div style={{ fontSize: 10, color: C.dim, lineHeight: 1.7 }}>
                  <div>AWS Nitro Enclaves / NitroTPM: the service verifies the COSE signature and AWS certificate chain, then evaluates PCRs plus bound user_data.</div>
                  <div>Azure Secure Key Release: the service verifies the attestation JWT against the issuer discovery document and JWKS from your Azure Attestation endpoint.</div>
                  <div>GCP Confidential Space: the service verifies the Google attestation JWT and derives image, workload, secure-boot, and debug claims from signed evidence.</div>
                  <div>Generic: manual claims and measurements remain available when you use your own attestation broker instead of a native cloud document.</div>
                </div>
              </div>
            </Card>
          </div>
        </Section>
      ) : null}

      {view === "Evaluate Release" ? (
        <Section
          title="Evaluate Attested Release"
          actions={<Btn primary onClick={() => void runEvaluation()} disabled={evaluating}>{evaluating ? "Evaluating..." : "Evaluate Release"}</Btn>}
        >
          <div style={{ display: "grid", gridTemplateColumns: "1.15fr .85fr", gap: 14 }}>
            <Card>
              <div style={{ fontSize: 12, fontWeight: 700, color: C.text, marginBottom: 12 }}>Release Request</div>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
                <FG label="Key ID">
                  <Inp value={releaseInput.key_id} onChange={(e) => setReleaseInput((prev: any) => ({ ...prev, key_id: e.target.value }))} />
                </FG>
                <FG label="Key Scope">
                  <Inp value={releaseInput.key_scope} onChange={(e) => setReleaseInput((prev: any) => ({ ...prev, key_scope: e.target.value }))} />
                </FG>
                <FG label="Provider">
                  <Sel value={releaseInput.provider} onChange={(e) => setReleaseInput((prev: any) => ({ ...prev, provider: e.target.value }))}>
                    {PROVIDER_OPTIONS.map(([value, label]) => <option key={value} value={value}>{label}</option>)}
                  </Sel>
                </FG>
                <FG label="Cluster Node ID">
                  <Inp value={releaseInput.cluster_node_id} onChange={(e) => setReleaseInput((prev: any) => ({ ...prev, cluster_node_id: e.target.value }))} />
                </FG>
                <FG label="Audience">
                  <Inp value={releaseInput.audience} onChange={(e) => setReleaseInput((prev: any) => ({ ...prev, audience: e.target.value }))} />
                </FG>
                <FG label="Nonce">
                  <Inp value={releaseInput.nonce} onChange={(e) => setReleaseInput((prev: any) => ({ ...prev, nonce: e.target.value }))} />
                </FG>
                <FG label="Requester">
                  <Inp value={releaseInput.requester} onChange={(e) => setReleaseInput((prev: any) => ({ ...prev, requester: e.target.value }))} />
                </FG>
                {providerRequiresDocument ? (
                  <FG label="Attestation Format">
                    <Sel value={releaseInput.attestation_format || "auto"} onChange={(e) => setReleaseInput((prev: any) => ({ ...prev, attestation_format: e.target.value }))}>
                      <option value="auto">Auto detect</option>
                      <option value="jwt">JWT</option>
                      <option value="cose_sign1">COSE Sign1</option>
                    </Sel>
                  </FG>
                ) : (
                  <FG label="Evidence Issued At">
                    <Inp value={releaseInput.evidence_issued_at} onChange={(e) => setReleaseInput((prev: any) => ({ ...prev, evidence_issued_at: e.target.value }))} />
                  </FG>
                )}
                {!providerRequiresDocument ? (
                  <>
                    <FG label="Workload Identity">
                      <Inp value={releaseInput.workload_identity} onChange={(e) => setReleaseInput((prev: any) => ({ ...prev, workload_identity: e.target.value }))} />
                    </FG>
                    <FG label="Attester">
                      <Inp value={releaseInput.attester} onChange={(e) => setReleaseInput((prev: any) => ({ ...prev, attester: e.target.value }))} />
                    </FG>
                    <FG label="Image Ref">
                      <Inp value={releaseInput.image_ref} onChange={(e) => setReleaseInput((prev: any) => ({ ...prev, image_ref: e.target.value }))} />
                    </FG>
                    <FG label="Image Digest">
                      <Inp value={releaseInput.image_digest} onChange={(e) => setReleaseInput((prev: any) => ({ ...prev, image_digest: e.target.value }))} mono />
                    </FG>
                  </>
                ) : null}
              </div>
              <FG label="Release Reason">
                <Inp value={releaseInput.release_reason} onChange={(e) => setReleaseInput((prev: any) => ({ ...prev, release_reason: e.target.value }))} />
              </FG>
              {providerRequiresDocument ? (
                <>
                  <FG label="Provider Attestation Document" hint={providerDocumentHint(evaluationProvider)}>
                    <Txt rows={12} value={releaseInput.attestation_document || ""} onChange={(e) => setReleaseInput((prev: any) => ({ ...prev, attestation_document: e.target.value }))} />
                  </FG>
                  <Card style={{ padding: 12, marginTop: 10, background: `linear-gradient(135deg, ${C.card} 0%, rgba(44,109,178,.10) 100%)` }}>
                    <div style={{ fontSize: 10, color: C.dim, lineHeight: 1.7 }}>
                      Workload identity, attester, image metadata, evidence timestamp, secure-boot posture, debug state, and measurements will be derived from the signed provider document.
                      This request only supplies the expected audience, expected nonce, key scope, cluster node, and operator context for the release decision.
                    </div>
                  </Card>
                </>
              ) : (
                <>
                  <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
                    <FG label="Claims JSON">
                      <Txt rows={8} value={evalClaimsJson} onChange={(e) => setEvalClaimsJson(e.target.value)} />
                    </FG>
                    <FG label="Measurements JSON">
                      <Txt rows={8} value={evalMeasurementsJson} onChange={(e) => setEvalMeasurementsJson(e.target.value)} />
                    </FG>
                  </div>
                  <div style={{ display: "flex", gap: 14, flexWrap: "wrap", marginTop: 4 }}>
                    <label style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 11, color: C.text }}>
                      <Chk checked={Boolean(releaseInput.secure_boot)} onChange={(e) => setReleaseInput((prev: any) => ({ ...prev, secure_boot: e.target.checked }))} />
                      Secure boot asserted
                    </label>
                    <label style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 11, color: C.text }}>
                      <Chk checked={Boolean(releaseInput.debug_disabled)} onChange={(e) => setReleaseInput((prev: any) => ({ ...prev, debug_disabled: e.target.checked }))} />
                      Debug disabled
                    </label>
                    <label style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 11, color: C.text }}>
                      <Chk checked={Boolean(releaseInput.dry_run)} onChange={(e) => setReleaseInput((prev: any) => ({ ...prev, dry_run: e.target.checked }))} />
                      Dry run only
                    </label>
                  </div>
                </>
              )}
              {providerRequiresDocument ? (
                <div style={{ display: "flex", gap: 14, flexWrap: "wrap", marginTop: 12 }}>
                  <label style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 11, color: C.text }}>
                    <Chk checked={Boolean(releaseInput.dry_run)} onChange={(e) => setReleaseInput((prev: any) => ({ ...prev, dry_run: e.target.checked }))} />
                    Dry run only
                  </label>
                </div>
              ) : null}
            </Card>

            <Card>
              <div style={{ fontSize: 12, fontWeight: 700, color: C.text, marginBottom: 10 }}>Decision Output</div>
              {!decision ? (
                <div style={{ fontSize: 11, color: C.dim, lineHeight: 1.7 }}>
                  Run a release evaluation to see the attestation verdict, cryptographic verification status, issuer, key ID, evidence hashes, derived workload metadata, cluster node decision, and the effective tenant policy version that was applied.
                </div>
              ) : (
                <>
                  <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 10 }}>
                    <B c={decisionColor(decision.decision)}>{String(decision.decision || "deny").toUpperCase()}</B>
                    <B c={decision.allowed ? "green" : "amber"}>{decision.allowed ? "Allowed" : "Blocked"}</B>
                    <B c={decision.cryptographically_verified ? "green" : "red"}>{decision.cryptographically_verified ? "Provider verified" : "Unverified"}</B>
                    <span style={{ fontSize: 10, color: C.dim }}>{shortTs(decision.evaluated_at)}</span>
                  </div>
                  <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10, marginBottom: 12 }}>
                    <Stat l="Provider" v={decision.provider || "-"} c="accent" />
                    <Stat l="Cluster Node" v={decision.cluster_node_id || "-"} c="blue" />
                  </div>
                  <FG label="Policy Version">
                    <Inp value={String(decision.policy_version || "")} readOnly mono />
                  </FG>
                  <FG label="Measurement Hash">
                    <Inp value={String(decision.measurement_hash || "")} readOnly mono />
                  </FG>
                  <FG label="Claims Hash">
                    <Inp value={String(decision.claims_hash || "")} readOnly mono />
                  </FG>
                  <FG label="Verification Issuer">
                    <Inp value={String(decision.verification_issuer || "")} readOnly />
                  </FG>
                  <FG label="Verification Key ID">
                    <Inp value={String(decision.verification_key_id || "")} readOnly mono />
                  </FG>
                  <FG label="Attestation Document Hash">
                    <Inp value={String(decision.attestation_document_hash || "")} readOnly mono />
                  </FG>
                  <FG label="Verification Mode">
                    <Inp value={String(decision.verification_mode || "")} readOnly />
                  </FG>
                  <div style={{ marginTop: 12 }}>
                    <div style={{ fontSize: 10, fontWeight: 700, color: C.text, marginBottom: 6 }}>Reasons</div>
                    {(Array.isArray(decision.reasons) && decision.reasons.length ? decision.reasons : ["No blocking reasons"]).map((item: string) => (
                      <div key={item} style={{ fontSize: 10, color: C.dim, marginBottom: 5, lineHeight: 1.5 }}>• {item}</div>
                    ))}
                  </div>
                  <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10, marginTop: 12 }}>
                    <Card style={{ padding: 10 }}>
                      <div style={{ fontSize: 10, fontWeight: 700, color: C.text, marginBottom: 6 }}>Matched Claims</div>
                      {(decision.matched_claims || []).length ? decision.matched_claims.map((item: string) => <div key={item} style={{ fontSize: 10, color: C.green, marginBottom: 4 }}>{item}</div>) : <div style={{ fontSize: 10, color: C.dim }}>None</div>}
                    </Card>
                    <Card style={{ padding: 10 }}>
                      <div style={{ fontSize: 10, fontWeight: 700, color: C.text, marginBottom: 6 }}>Matched Measurements</div>
                      {(decision.matched_measurements || []).length ? decision.matched_measurements.map((item: string) => <div key={item} style={{ fontSize: 10, color: C.green, marginBottom: 4 }}>{item}</div>) : <div style={{ fontSize: 10, color: C.dim }}>None</div>}
                    </Card>
                  </div>
                </>
              )}
            </Card>
          </div>
        </Section>
      ) : null}

      {view === "Release History" ? (
        <Section title="Release History" actions={<Btn onClick={() => void refresh(false)}>Refresh History</Btn>}>
          <div style={{ marginBottom: 12, maxWidth: 380 }}>
            <FG label="Search History">
              <Inp placeholder="Search by key, provider, node, decision, or reason" value={filterText} onChange={(e) => setFilterText(e.target.value)} />
            </FG>
          </div>
          <div style={{ display: "grid", gap: 10 }}>
            {!filteredReleases.length ? (
              <Card>
                <div style={{ fontSize: 12, color: C.dim }}>No attested key release history for this tenant yet.</div>
              </Card>
            ) : filteredReleases.map((item: any) => (
              <Card key={String(item.id || Math.random())} style={{ padding: 14 }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: 12 }}>
                  <div style={{ flex: 1 }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap", marginBottom: 6 }}>
                      <div style={{ fontSize: 13, fontWeight: 700, color: C.text }}>{String(item.key_id || "unknown-key")}</div>
                      <B c={decisionColor(item.decision)}>{String(item.decision || "deny").toUpperCase()}</B>
                      <B c="blue">{String(item.provider || "generic")}</B>
                      <B c={item.cryptographically_verified ? "green" : "red"}>{item.cryptographically_verified ? "Verified" : "Unverified"}</B>
                      {item.cluster_node_id ? <B c="accent">{String(item.cluster_node_id)}</B> : null}
                    </div>
                    <div style={{ fontSize: 10, color: C.dim, lineHeight: 1.7 }}>
                      <div>ID: <span style={{ color: C.text }}>{String(item.id || "-")}</span></div>
                      <div>Workload: <span style={{ color: C.text }}>{String(item.workload_identity || "-")}</span></div>
                      <div>Image: <span style={{ color: C.text }}>{String(item.image_ref || item.image_digest || "-")}</span></div>
                      <div>Issuer: <span style={{ color: C.text }}>{String(item.verification_issuer || "-")}</span></div>
                      <div>Policy Version: <span style={{ color: C.text }}>{String(item.policy_version || "-")}</span></div>
                      <div>Measurement Hash: <span style={{ color: C.text }}>{String(item.measurement_hash || "-")}</span></div>
                      <div>Doc Hash: <span style={{ color: C.text }}>{String(item.attestation_document_hash || "-")}</span></div>
                    </div>
                  </div>
                  <div style={{ minWidth: 180, textAlign: "right" }}>
                    <div style={{ fontSize: 10, color: C.muted }}>Evaluated</div>
                    <div style={{ fontSize: 11, color: C.text, marginTop: 4 }}>{shortTs(item.created_at)}</div>
                    {item.expires_at ? <div style={{ fontSize: 10, color: C.dim, marginTop: 8 }}>Expires {shortTs(item.expires_at)}</div> : null}
                  </div>
                </div>
                {(Array.isArray(item.reasons) && item.reasons.length) ? (
                  <div style={{ marginTop: 10, paddingTop: 10, borderTop: `1px solid ${C.border}` }}>
                    <div style={{ fontSize: 10, fontWeight: 700, color: C.text, marginBottom: 4 }}>Decision Reasons</div>
                    {item.reasons.slice(0, 4).map((reason: string) => (
                      <div key={reason} style={{ fontSize: 10, color: C.dim, lineHeight: 1.5, marginBottom: 4 }}>• {reason}</div>
                    ))}
                  </div>
                ) : null}
              </Card>
            ))}
          </div>
        </Section>
      ) : null}
    </div>
  );
};
