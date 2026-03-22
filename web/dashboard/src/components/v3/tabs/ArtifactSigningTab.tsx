// @ts-nocheck
import { useEffect, useMemo, useState } from "react";
import { B, Btn, Card, Chk, FG, Inp, Row2, Row3, Section, Sel, Stat, Tabs, Txt, usePromptDialog } from "../legacyPrimitives";
import { C } from "../theme";
import { errMsg } from "../runtimeUtils";
import {
  deleteSigningProfile,
  getSigningSettings,
  getSigningSummary,
  listSigningProfiles,
  listSigningRecords,
  signBlob,
  signGitArtifact,
  updateSigningSettings,
  upsertSigningProfile,
  verifySigningRecord
} from "../../../lib/signing";

function csvToList(value: any): string[] {
  return String(value || "").split(",").map((item) => item.trim()).filter(Boolean);
}

function listToCsv(value: any): string {
  return Array.isArray(value) ? value.map((item) => String(item || "").trim()).filter(Boolean).join(", ") : "";
}

function fmtTS(value: any): string {
  const raw = String(value || "").trim();
  if (!raw) return "-";
  const dt = new Date(raw);
  if (Number.isNaN(dt.getTime())) return raw;
  return dt.toLocaleString();
}

const DEFAULT_SETTINGS = {
  enabled: false,
  default_profile_id: "",
  require_transparency: true,
  allowed_identity_modes: ["oidc", "workload"]
};

const DEFAULT_PROFILE = {
  id: "",
  name: "",
  artifact_type: "blob",
  key_id: "",
  signing_algorithm: "ecdsa-sha384",
  identity_mode: "oidc",
  allowed_workload_patterns_csv: "",
  allowed_oidc_issuers_csv: "",
  allowed_subject_patterns_csv: "",
  allowed_repositories_csv: "",
  transparency_required: true,
  enabled: true,
  description: ""
};

const DEFAULT_SIGN = {
  profile_id: "",
  artifact_type: "blob",
  artifact_name: "",
  payload: "",
  repository: "",
  commit_sha: "",
  oci_reference: "",
  identity_mode: "oidc",
  oidc_issuer: "",
  oidc_subject: "",
  workload_identity: ""
};

export const ArtifactSigningTab = ({ session, onToast }: any) => {
  const promptDialog = usePromptDialog();
  const [tab, setTab] = useState("Overview");
  const [loading, setLoading] = useState(false);
  const [busy, setBusy] = useState(false);
  const [summary, setSummary] = useState<any>(null);
  const [settingsDraft, setSettingsDraft] = useState<any>(DEFAULT_SETTINGS);
  const [profiles, setProfiles] = useState<any[]>([]);
  const [records, setRecords] = useState<any[]>([]);
  const [profileDraft, setProfileDraft] = useState<any>(DEFAULT_PROFILE);
  const [signDraft, setSignDraft] = useState<any>(DEFAULT_SIGN);

  const load = async (silent = false) => {
    if (!session?.token) {
      setSummary(null);
      setSettingsDraft(DEFAULT_SETTINGS);
      setProfiles([]);
      setRecords([]);
      return;
    }
    if (!silent) setLoading(true);
    try {
      const [summaryOut, settingsOut, profilesOut, recordsOut] = await Promise.all([
        getSigningSummary(session),
        getSigningSettings(session),
        listSigningProfiles(session),
        listSigningRecords(session, { limit: 100 })
      ]);
      setSummary(summaryOut || null);
      setSettingsDraft({ ...DEFAULT_SETTINGS, ...(settingsOut || {}) });
      setProfiles(Array.isArray(profilesOut) ? profilesOut : []);
      setRecords(Array.isArray(recordsOut) ? recordsOut : []);
    } catch (error) {
      onToast?.(`Artifact signing load failed: ${errMsg(error)}`);
    } finally {
      if (!silent) setLoading(false);
    }
  };

  useEffect(() => { void load(true); }, [session?.token, session?.tenantId]);

  const saveSettings = async () => {
    setBusy(true);
    try {
      await updateSigningSettings(session, {
        ...settingsDraft,
        tenant_id: session.tenantId,
        updated_by: session.username
      });
      onToast?.("Artifact signing settings saved");
      await load(true);
    } catch (error) {
      onToast?.(`Artifact signing settings save failed: ${errMsg(error)}`);
    } finally {
      setBusy(false);
    }
  };

  const saveProfile = async () => {
    setBusy(true);
    try {
      const saved = await upsertSigningProfile(session, {
        id: profileDraft?.id || undefined,
        tenant_id: session.tenantId,
        name: String(profileDraft?.name || "").trim(),
        artifact_type: profileDraft?.artifact_type || "blob",
        key_id: String(profileDraft?.key_id || "").trim(),
        signing_algorithm: String(profileDraft?.signing_algorithm || "ecdsa-sha384").trim(),
        identity_mode: profileDraft?.identity_mode || "oidc",
        allowed_workload_patterns: csvToList(profileDraft?.allowed_workload_patterns_csv),
        allowed_oidc_issuers: csvToList(profileDraft?.allowed_oidc_issuers_csv),
        allowed_subject_patterns: csvToList(profileDraft?.allowed_subject_patterns_csv),
        allowed_repositories: csvToList(profileDraft?.allowed_repositories_csv),
        transparency_required: Boolean(profileDraft?.transparency_required),
        enabled: Boolean(profileDraft?.enabled),
        description: String(profileDraft?.description || "").trim(),
        updated_by: session.username
      });
      onToast?.("Signing profile saved");
      setProfileDraft(DEFAULT_PROFILE);
      setSignDraft((p: any) => ({ ...p, profile_id: saved?.id || p?.profile_id || "" }));
      await load(true);
    } catch (error) {
      onToast?.(`Signing profile save failed: ${errMsg(error)}`);
    } finally {
      setBusy(false);
    }
  };

  const editProfile = (item: any) => {
    setProfileDraft({
      id: item?.id || "",
      name: item?.name || "",
      artifact_type: item?.artifact_type || "blob",
      key_id: item?.key_id || "",
      signing_algorithm: item?.signing_algorithm || "ecdsa-sha384",
      identity_mode: item?.identity_mode || "oidc",
      allowed_workload_patterns_csv: listToCsv(item?.allowed_workload_patterns),
      allowed_oidc_issuers_csv: listToCsv(item?.allowed_oidc_issuers),
      allowed_subject_patterns_csv: listToCsv(item?.allowed_subject_patterns),
      allowed_repositories_csv: listToCsv(item?.allowed_repositories),
      transparency_required: item?.transparency_required !== false,
      enabled: item?.enabled !== false,
      description: item?.description || ""
    });
    setTab("Profiles");
  };

  const removeProfile = async (item: any) => {
    const ok = await promptDialog.confirm({ title: "Delete Signing Profile", message: `Delete ${String(item?.name || item?.id || "").trim()}?`, danger: true, confirmLabel: "Delete" });
    if (!ok) return;
    setBusy(true);
    try {
      await deleteSigningProfile(session, String(item?.id || ""));
      onToast?.("Signing profile deleted");
      await load(true);
    } catch (error) {
      onToast?.(`Signing profile delete failed: ${errMsg(error)}`);
    } finally {
      setBusy(false);
    }
  };

  const submitSign = async () => {
    setBusy(true);
    try {
      const fn = signDraft?.artifact_type === "git" ? signGitArtifact : signBlob;
      const out = await fn(session, {
        profile_id: signDraft?.profile_id || undefined,
        artifact_type: signDraft?.artifact_type,
        artifact_name: signDraft?.artifact_name,
        payload: signDraft?.payload,
        repository: signDraft?.repository || undefined,
        commit_sha: signDraft?.commit_sha || undefined,
        oci_reference: signDraft?.oci_reference || undefined,
        identity_mode: signDraft?.identity_mode || undefined,
        oidc_issuer: signDraft?.oidc_issuer || undefined,
        oidc_subject: signDraft?.oidc_subject || undefined,
        workload_identity: signDraft?.workload_identity || undefined,
        requested_by: session.username
      });
      onToast?.(`Artifact signed: ${String(out?.record?.id || "").trim()}`);
      setSignDraft((p: any) => ({ ...DEFAULT_SIGN, profile_id: p?.profile_id || "" }));
      await load(true);
      setTab("Records");
    } catch (error) {
      onToast?.(`Artifact sign failed: ${errMsg(error)}`);
    } finally {
      setBusy(false);
    }
  };

  const verifyRecord = async (item: any) => {
    setBusy(true);
    try {
      const out = await verifySigningRecord(session, String(item?.id || ""));
      onToast?.(out?.valid ? "Signature verified" : "Signature verification failed");
      await load(true);
    } catch (error) {
      onToast?.(`Verify failed: ${errMsg(error)}`);
    } finally {
      setBusy(false);
    }
  };

  const artifactCounts = useMemo(() => Array.isArray(summary?.artifact_counts) ? summary.artifact_counts : [], [summary]);

  return (
    <div>
      {promptDialog.ui}
      <Section title="Artifact Signing" actions={<div style={{ display: "flex", gap: 8 }}>
        <Btn small onClick={() => void load(false)} disabled={loading || busy}>{loading ? "Refreshing..." : "Refresh"}</Btn>
        <Btn small primary onClick={() => void saveSettings()} disabled={busy}>{busy ? "Saving..." : "Save Settings"}</Btn>
      </div>}>
        <Tabs tabs={["Overview", "Profiles", "Records"]} active={tab} onChange={setTab} />
      </Section>

      {tab === "Overview" && <>
        <div style={{ display: "flex", gap: 10, flexWrap: "wrap", marginBottom: 14 }}>
          <Stat l="Signed / 24h" v={summary?.record_count_24h || 0} c="accent" />
          <Stat l="Profiles" v={summary?.profile_count || 0} c="blue" />
          <Stat l="Transparency Logged" v={summary?.transparency_logged_24h || 0} c="green" />
          <Stat l="Workload Signed" v={summary?.workload_signed_24h || 0} c="purple" />
          <Stat l="OIDC Signed" v={summary?.oidc_signed_24h || 0} c="amber" />
          <Stat l="Verify Failures" v={summary?.verification_failures_24h || 0} c="red" />
        </div>
        <Card style={{ padding: 14, marginBottom: 14 }}>
          <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap", marginBottom: 8 }}>
            <B c={settingsDraft?.enabled ? "green" : "amber"}>{settingsDraft?.enabled ? "Enabled" : "Disabled"}</B>
            <B c={settingsDraft?.require_transparency ? "blue" : "purple"}>{settingsDraft?.require_transparency ? "Transparency Required" : "Transparency Optional"}</B>
          </div>
          <div style={{ fontSize: 11, color: C.dim, lineHeight: 1.6 }}>
            Use this service to sign blobs, Git commit manifests, or OCI references without handing private key material to build systems. Profiles bind identities, repositories, and KMS key IDs; every signature is logged with transparency-style metadata so supply-chain evidence can be audited later.
          </div>
          <div style={{ marginTop: 10, fontSize: 10, color: C.muted }}>
            {artifactCounts.length ? artifactCounts.map((item: any) => `${item.artifact_type}: ${item.count_24h}`).join(" • ") : "No recent artifact types signed yet."}
          </div>
        </Card>

        <Section title="Sign Artifact" actions={<Btn small primary onClick={() => void submitSign()} disabled={busy}>{busy ? "Signing..." : "Sign"}</Btn>}>
          <Card style={{ padding: 14 }}>
            <Row3>
              <FG label="Profile">
                <Sel value={signDraft?.profile_id || ""} onChange={(e) => setSignDraft((p: any) => ({ ...p, profile_id: e.target.value }))}>
                  <option value="">Select profile</option>
                  {profiles.map((item: any) => <option key={item.id} value={item.id}>{`${item.name} (${item.artifact_type})`}</option>)}
                </Sel>
              </FG>
              <FG label="Artifact Type">
                <Sel value={signDraft?.artifact_type || "blob"} onChange={(e) => setSignDraft((p: any) => ({ ...p, artifact_type: e.target.value }))}>
                  <option value="blob">Blob</option>
                  <option value="git">Git</option>
                  <option value="oci">OCI</option>
                </Sel>
              </FG>
              <FG label="Identity Mode">
                <Sel value={signDraft?.identity_mode || "oidc"} onChange={(e) => setSignDraft((p: any) => ({ ...p, identity_mode: e.target.value }))}>
                  <option value="oidc">OIDC</option>
                  <option value="workload">Workload</option>
                </Sel>
              </FG>
            </Row3>
            <FG label="Artifact Name"><Inp value={signDraft?.artifact_name || ""} onChange={(e) => setSignDraft((p: any) => ({ ...p, artifact_name: e.target.value }))} placeholder="release-bundle.tar.gz" /></FG>
            <FG label="Payload"><Txt rows={5} mono={false} value={signDraft?.payload || ""} onChange={(e) => setSignDraft((p: any) => ({ ...p, payload: e.target.value }))} placeholder="Paste blob manifest, Git metadata payload, or OCI manifest text." /></FG>
            <Row3>
              <FG label="Repository"><Inp value={signDraft?.repository || ""} onChange={(e) => setSignDraft((p: any) => ({ ...p, repository: e.target.value }))} placeholder="github.com/org/repo" /></FG>
              <FG label="Commit SHA"><Inp value={signDraft?.commit_sha || ""} onChange={(e) => setSignDraft((p: any) => ({ ...p, commit_sha: e.target.value }))} placeholder="abc123..." /></FG>
              <FG label="OCI Reference"><Inp value={signDraft?.oci_reference || ""} onChange={(e) => setSignDraft((p: any) => ({ ...p, oci_reference: e.target.value }))} placeholder="ghcr.io/org/app:1.2.3" /></FG>
            </Row3>
            {signDraft?.identity_mode === "workload" ? (
              <FG label="Workload Identity"><Inp value={signDraft?.workload_identity || ""} onChange={(e) => setSignDraft((p: any) => ({ ...p, workload_identity: e.target.value }))} placeholder="spiffe://tenant/workloads/build-runner" /></FG>
            ) : (
              <Row2>
                <FG label="OIDC Issuer"><Inp value={signDraft?.oidc_issuer || ""} onChange={(e) => setSignDraft((p: any) => ({ ...p, oidc_issuer: e.target.value }))} placeholder="https://token.actions.githubusercontent.com" /></FG>
                <FG label="OIDC Subject"><Inp value={signDraft?.oidc_subject || ""} onChange={(e) => setSignDraft((p: any) => ({ ...p, oidc_subject: e.target.value }))} placeholder="repo:org/repo:ref:refs/heads/main" /></FG>
              </Row2>
            )}
          </Card>
        </Section>
      </>}

      {tab === "Profiles" && <Section title="Signing Profiles" actions={<Btn small primary onClick={() => void saveProfile()} disabled={busy}>{busy ? "Saving..." : "Save Profile"}</Btn>}>
        <Card style={{ padding: 14, marginBottom: 12 }}>
          <Row3>
            <FG label="Name"><Inp value={profileDraft?.name || ""} onChange={(e) => setProfileDraft((p: any) => ({ ...p, name: e.target.value }))} placeholder="github-release" /></FG>
            <FG label="Artifact Type"><Sel value={profileDraft?.artifact_type || "blob"} onChange={(e) => setProfileDraft((p: any) => ({ ...p, artifact_type: e.target.value }))}><option value="blob">Blob</option><option value="git">Git</option><option value="oci">OCI</option></Sel></FG>
            <FG label="Key ID"><Inp value={profileDraft?.key_id || ""} onChange={(e) => setProfileDraft((p: any) => ({ ...p, key_id: e.target.value }))} placeholder="key_signing_01" /></FG>
          </Row3>
          <Row3>
            <FG label="Signing Algorithm"><Inp value={profileDraft?.signing_algorithm || ""} onChange={(e) => setProfileDraft((p: any) => ({ ...p, signing_algorithm: e.target.value }))} placeholder="ecdsa-sha384" /></FG>
            <FG label="Identity Mode"><Sel value={profileDraft?.identity_mode || "oidc"} onChange={(e) => setProfileDraft((p: any) => ({ ...p, identity_mode: e.target.value }))}><option value="oidc">OIDC</option><option value="workload">Workload</option></Sel></FG>
            <FG label="Transparency"><Chk label="Require transparency metadata" checked={Boolean(profileDraft?.transparency_required)} onChange={() => setProfileDraft((p: any) => ({ ...p, transparency_required: !Boolean(p?.transparency_required) }))} /></FG>
          </Row3>
          <Row2>
            <FG label="Allowed Repositories"><Inp value={profileDraft?.allowed_repositories_csv || ""} onChange={(e) => setProfileDraft((p: any) => ({ ...p, allowed_repositories_csv: e.target.value }))} placeholder="github.com/org/*, ghcr.io/org/*" /></FG>
            <FG label="Allowed Workload Patterns"><Inp value={profileDraft?.allowed_workload_patterns_csv || ""} onChange={(e) => setProfileDraft((p: any) => ({ ...p, allowed_workload_patterns_csv: e.target.value }))} placeholder="spiffe://tenant/workloads/*" /></FG>
          </Row2>
          <Row2>
            <FG label="Allowed OIDC Issuers"><Inp value={profileDraft?.allowed_oidc_issuers_csv || ""} onChange={(e) => setProfileDraft((p: any) => ({ ...p, allowed_oidc_issuers_csv: e.target.value }))} placeholder="https://token.actions.githubusercontent.com" /></FG>
            <FG label="Allowed Subject Patterns"><Inp value={profileDraft?.allowed_subject_patterns_csv || ""} onChange={(e) => setProfileDraft((p: any) => ({ ...p, allowed_subject_patterns_csv: e.target.value }))} placeholder="repo:org/repo:*" /></FG>
          </Row2>
          <Row2>
            <Chk label="Enabled" checked={Boolean(profileDraft?.enabled)} onChange={() => setProfileDraft((p: any) => ({ ...p, enabled: !Boolean(p?.enabled) }))} />
            <Chk label="Tenant requires transparency by default" checked={Boolean(settingsDraft?.require_transparency)} onChange={() => setSettingsDraft((p: any) => ({ ...p, require_transparency: !Boolean(p?.require_transparency) }))} />
          </Row2>
          <FG label="Description"><Txt rows={3} mono={false} value={profileDraft?.description || ""} onChange={(e) => setProfileDraft((p: any) => ({ ...p, description: e.target.value }))} placeholder="Release signing profile for production build pipelines." /></FG>
        </Card>
        <div style={{ display: "grid", gap: 8 }}>
          {profiles.map((item: any) => (
            <Card key={item.id} style={{ padding: 12 }}>
              <div style={{ display: "flex", justifyContent: "space-between", gap: 8, marginBottom: 8 }}>
                <div>
                  <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
                    <span style={{ fontSize: 12, fontWeight: 700, color: C.text }}>{item.name}</span>
                    <B c={item.enabled ? "green" : "red"}>{item.enabled ? "Enabled" : "Disabled"}</B>
                    <B c="blue">{item.artifact_type}</B>
                    <B c="purple">{item.identity_mode}</B>
                  </div>
                  <div style={{ fontSize: 10, color: C.dim, marginTop: 4 }}>{`${item.key_id} • ${item.signing_algorithm}`}</div>
                </div>
                <div style={{ display: "flex", gap: 6 }}>
                  <Btn small onClick={() => editProfile(item)}>Edit</Btn>
                  <Btn small danger onClick={() => void removeProfile(item)}>Delete</Btn>
                </div>
              </div>
              {item.description ? <div style={{ fontSize: 10, color: C.muted }}>{item.description}</div> : null}
            </Card>
          ))}
          {!profiles.length ? <Card style={{ padding: 18, textAlign: "center", color: C.muted }}>No signing profiles configured yet.</Card> : null}
        </div>
      </Section>}

      {tab === "Records" && <Section title="Recent Signatures">
        <div style={{ display: "grid", gap: 8 }}>
          {records.map((item: any) => (
            <Card key={item.id} style={{ padding: 12 }}>
              <div style={{ display: "flex", justifyContent: "space-between", gap: 8, marginBottom: 8 }}>
                <div>
                  <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
                    <span style={{ fontSize: 12, fontWeight: 700, color: C.text }}>{item.artifact_name}</span>
                    <B c="blue">{item.artifact_type}</B>
                    <B c={item.verification_status === "failed" ? "red" : "green"}>{item.verification_status || "logged"}</B>
                  </div>
                  <div style={{ fontSize: 10, color: C.dim, marginTop: 4 }}>{`${item.key_id} • ${item.identity_mode} • ${fmtTS(item.created_at)}`}</div>
                </div>
                <Btn small onClick={() => void verifyRecord(item)} disabled={busy}>{busy ? "Verifying..." : "Verify"}</Btn>
              </div>
              <div style={{ fontSize: 10, color: C.muted, lineHeight: 1.6 }}>
                {`${item.digest_sha256} • transparency ${item.transparency_entry_id || "-"} #${item.transparency_index || 0}`}
              </div>
            </Card>
          ))}
          {!records.length ? <Card style={{ padding: 18, textAlign: "center", color: C.muted }}>No artifact signatures recorded yet.</Card> : null}
        </div>
      </Section>}
    </div>
  );
};
