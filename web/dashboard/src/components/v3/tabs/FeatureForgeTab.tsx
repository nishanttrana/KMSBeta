// @ts-nocheck -- tab follows the established legacy-tab style in this codebase
import { useCallback, useEffect, useMemo, useState } from "react";
import {
  Sparkles, Send, ShieldCheck, ShieldAlert, CheckCircle2, XCircle, Clock,
  GitBranch, Cpu, ChevronRight, ChevronDown
} from "lucide-react";
import { Btn, Card, Txt, Section, B, Stat, FG } from "../legacyPrimitives";
import { C } from "../theme";
import { errMsg } from "../runtimeUtils";
import {
  listFFCatalog,
  listFFIntents,
  submitFFIntent,
  approveFFIntent,
  promoteFFIntent,
  type FFCatalogAction,
  type FFIntent,
  type FFEvent,
  type FFApproval
} from "../../../lib/featureforge";

const STAGE_TONE: Record<string, string> = {
  deployed_prod: C.green,
  staged: C.accent,
  tested_ok: C.accent,
  dryrun_ok: C.accent,
  policy_ok: C.accent,
  awaiting_prod: C.amber,
  rejected: C.red,
  failed: C.red
};

function stageBadge(stage: string) {
  const s = String(stage || "");
  if (s === "deployed_prod") return "green";
  if (s === "rejected" || s === "failed") return "red";
  if (s === "awaiting_prod") return "amber";
  return "accent";
}

function stageLabel(stage: string) {
  return String(stage || "").replace(/_/g, " ");
}

export const FeatureForgeTab = ({ session, onToast }: any) => {
  const tenantId = session?.tenantId || "";
  const actor = session?.username || "";
  const [text, setText] = useState("");
  const [catalog, setCatalog] = useState<FFCatalogAction[]>([]);
  const [intents, setIntents] = useState<FFIntent[]>([]);
  const [trailById, setTrailById] = useState<Record<string, FFEvent[]>>({});
  const [approvalsById, setApprovalsById] = useState<Record<string, FFApproval[]>>({});
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});
  const [busy, setBusy] = useState(false);
  const [loading, setLoading] = useState(false);

  const toast = useCallback(
    (msg: string, kind: "ok" | "err" = "ok") => {
      if (typeof onToast === "function") onToast(msg, kind);
    },
    [onToast]
  );

  const refresh = useCallback(async () => {
    if (!session?.token) return;
    setLoading(true);
    try {
      const [cat, list] = await Promise.all([
        listFFCatalog(session).catch(() => []),
        listFFIntents(session, tenantId).catch(() => [])
      ]);
      setCatalog(cat);
      setIntents(list);
    } catch (e) {
      toast(errMsg(e), "err");
    } finally {
      setLoading(false);
    }
  }, [session, tenantId, toast]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const submit = useCallback(async () => {
    const t = text.trim();
    if (!t) return;
    setBusy(true);
    try {
      const r = await submitFFIntent(session, tenantId, actor, t);
      setTrailById((prev) => ({ ...prev, [r.intent.id]: r.trail || [] }));
      setExpanded((prev) => ({ ...prev, [r.intent.id]: true }));
      setText("");
      if (r.intent.stage === "rejected") {
        toast("Intent rejected by guardrails — see the trail.", "err");
      } else {
        toast(`Intent ${r.intent.id} reached "${stageLabel(r.intent.stage)}".`, "ok");
      }
      await refresh();
    } catch (e) {
      toast(errMsg(e), "err");
    } finally {
      setBusy(false);
    }
  }, [text, session, tenantId, actor, toast, refresh]);

  const approve = useCallback(
    async (id: string) => {
      setBusy(true);
      try {
        const r = await approveFFIntent(session, id, actor);
        setTrailById((prev) => ({ ...prev, [id]: r.trail || [] }));
        setApprovalsById((prev) => ({ ...prev, [id]: r.approvals || [] }));
        toast(`Approval by ${actor} recorded for ${id}.`, "ok");
        await refresh();
      } catch (e) {
        toast(errMsg(e), "err");
      } finally {
        setBusy(false);
      }
    },
    [session, actor, toast, refresh]
  );

  const promote = useCallback(
    async (id: string) => {
      setBusy(true);
      try {
        const r = await promoteFFIntent(session, id, actor);
        setTrailById((prev) => ({ ...prev, [id]: r.trail || [] }));
        setApprovalsById((prev) => ({ ...prev, [id]: r.approvals || [] }));
        if (r.intent.stage === "awaiting_prod") {
          const hasSecond = (r.approvals || []).length > 0;
          toast(
            hasSecond
              ? "Promotion opened a governance approval — awaiting quorum."
              : "Promotion is gated: a second principal must approve first.",
            "ok"
          );
        } else if (r.intent.stage === "deployed_prod") {
          toast(`Intent ${id} deployed to production.`, "ok");
        }
        await refresh();
      } catch (e) {
        toast(errMsg(e), "err");
      } finally {
        setBusy(false);
      }
    },
    [session, actor, toast, refresh]
  );

  const toggle = useCallback((id: string) => {
    setExpanded((prev) => ({ ...prev, [id]: !prev[id] }));
  }, []);

  const stats = useMemo(() => {
    const staged = intents.filter((i) => i.stage === "staged").length;
    const awaiting = intents.filter((i) => i.stage === "awaiting_prod").length;
    const prod = intents.filter((i) => i.stage === "deployed_prod").length;
    const rejected = intents.filter((i) => i.stage === "rejected" || i.stage === "failed").length;
    return { staged, awaiting, prod, rejected };
  }, [intents]);

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
      {/* Intent input */}
      <Section
        title="Describe a feature"
        actions={<Btn small onClick={() => void refresh()} disabled={loading}>Refresh</Btn>}
      >
        <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
          <FG
            label="What do you want the KMS to do?"
            hint='Config intents (e.g. "block RSA-1024") apply locally. Feature intents (e.g. "add an EdDSA signing endpoint") build via the external MCP server. Everything is guardrailed and gated before production.'
          >
            <Txt
              placeholder='block RSA-1024 for this tenant'
              rows={3}
              mono={false}
              value={text}
              onChange={(e: any) => setText(e.target.value)}
              onKeyDown={(e: any) => {
                if ((e.metaKey || e.ctrlKey) && e.key === "Enter") void submit();
              }}
            />
          </FG>
          <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
            <Btn primary onClick={() => void submit()} disabled={busy || !text.trim()}>
              <Send size={13} style={{ marginRight: 6 }} /> Forge feature
            </Btn>
            <span style={{ fontSize: 10, color: C.dim }}>Cmd/Ctrl + Enter</span>
          </div>
        </div>
      </Section>

      {/* Stats */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 10 }}>
        <Stat l="Staged" v={String(stats.staged)} c="accent" i={ShieldCheck} />
        <Stat l="Awaiting prod" v={String(stats.awaiting)} c="amber" i={Clock} />
        <Stat l="In production" v={String(stats.prod)} c="green" i={CheckCircle2} />
        <Stat l="Rejected" v={String(stats.rejected)} c="red" i={XCircle} />
      </div>

      {/* Intents list */}
      <Section title="Recent intents">
        {intents.length === 0 ? (
          <div style={{ fontSize: 11, color: C.dim, padding: 8 }}>
            No intents yet. Describe a feature above to get started.
          </div>
        ) : (
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            {intents.map((it) => {
              const trail = trailById[it.id] || [];
              const approvals = approvalsById[it.id] || [];
              const isOpen = !!expanded[it.id];
              const canPromote = it.stage === "staged" || it.stage === "awaiting_prod";
              const canApprove = canPromote && actor && actor !== it.actor &&
                !approvals.some((a) => a.approver === actor);
              return (
                <Card key={it.id} style={{ borderColor: STAGE_TONE[it.stage] || C.border }}>
                  <div
                    style={{ display: "flex", alignItems: "center", gap: 8, cursor: "pointer" }}
                    onClick={() => toggle(it.id)}
                  >
                    {isOpen ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                    {it.mode === "scaffold" ? <Cpu size={14} color={C.accent} /> : <Sparkles size={14} color={C.accent} />}
                    <span style={{ fontSize: 11, color: C.text, flex: 1 }}>{it.raw_text}</span>
                    <B c={stageBadge(it.stage)}>{stageLabel(it.stage)}</B>
                  </div>
                  <div style={{ display: "flex", gap: 12, marginTop: 6, fontSize: 10, color: C.dim, flexWrap: "wrap" }}>
                    <span>id: {it.id}</span>
                    <span>mode: {it.mode}</span>
                    {it.action && <span>action: {it.action}</span>}
                    <span>confidence: {(it.confidence * 100).toFixed(0)}%</span>
                    {it.mcp_job_id && <span>mcp job: {it.mcp_job_id}</span>}
                  </div>

                  {isOpen && (
                    <div style={{ marginTop: 10, borderTop: `1px solid ${C.border}`, paddingTop: 10 }}>
                      {/* params */}
                      {it.params && Object.keys(it.params).length > 0 && (
                        <div style={{ marginBottom: 8 }}>
                          <div style={{ fontSize: 10, color: C.dim, marginBottom: 3 }}>Parameters</div>
                          <pre style={{ fontSize: 10, color: C.text, margin: 0, fontFamily: "'JetBrains Mono',monospace" }}>
                            {JSON.stringify(it.params, null, 2)}
                          </pre>
                        </div>
                      )}
                      {/* guardrail trail */}
                      <div style={{ fontSize: 10, color: C.dim, marginBottom: 4 }}>Guardrail trail</div>
                      <div style={{ display: "flex", flexDirection: "column", gap: 3 }}>
                        {(trail.length ? trail : it.reasons.map((r) => ({ stage: it.stage, outcome: "", detail: r }))).map(
                          (ev: any, idx: number) => (
                            <div key={idx} style={{ display: "flex", gap: 8, fontSize: 10 }}>
                              <span style={{ color: STAGE_TONE[ev.stage] || C.dim, minWidth: 110 }}>
                                {stageLabel(ev.stage)}
                              </span>
                              <span style={{ color: C.text }}>{ev.detail}</span>
                            </div>
                          )
                        )}
                      </div>
                      {/* approvals */}
                      {approvals.length > 0 && (
                        <div style={{ marginTop: 8, fontSize: 10, color: C.dim }}>
                          Approved by {approvals.map((a) => a.approver).join(", ")}
                        </div>
                      )}
                      {/* approve / promote */}
                      <div style={{ marginTop: 10, display: "flex", gap: 8, alignItems: "center" }}>
                        {canApprove && (
                          <Btn small onClick={() => void approve(it.id)} disabled={busy}>
                            <ShieldCheck size={12} style={{ marginRight: 5 }} /> Approve (2nd principal)
                          </Btn>
                        )}
                        {canPromote && (
                          <Btn small primary onClick={() => void promote(it.id)} disabled={busy}>
                            {it.stage === "awaiting_prod" ? (
                              <>
                                <ShieldAlert size={12} style={{ marginRight: 5 }} /> Re-check approval
                              </>
                            ) : (
                              <>
                                <GitBranch size={12} style={{ marginRight: 5 }} /> Promote to prod
                              </>
                            )}
                          </Btn>
                        )}
                        {it.stage === "awaiting_prod" && (
                          <span style={{ fontSize: 10, color: C.amber }}>
                            {it.approval_id
                              ? `Needs governance quorum (${it.approval_id}).`
                              : "Needs a second principal's approval."}
                          </span>
                        )}
                        {it.stage === "deployed_prod" && (
                          <span style={{ fontSize: 10, color: C.green }}>Live in production.</span>
                        )}
                      </div>
                    </div>
                  )}
                </Card>
              );
            })}
          </div>
        )}
      </Section>

      {/* Catalog */}
      <Section title="Config action catalog (allow-list)">
        <div style={{ fontSize: 10, color: C.dim, marginBottom: 8 }}>
          Config mode can only produce one of these reviewed actions. Anything outside the list is rejected.
        </div>
        <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
          {catalog.map((a) => (
            <div key={a.name} style={{ display: "flex", gap: 10, alignItems: "center", fontSize: 11 }}>
              <span style={{ color: C.text, fontFamily: "'JetBrains Mono',monospace", minWidth: 220 }}>{a.name}</span>
              <span style={{ color: C.dim, flex: 1 }}>{a.summary}</span>
              {a.requires_quorum && <B c="amber">quorum</B>}
              {a.applier === "policy" ? <B c="green">live</B> : <B c="dim">stub</B>}
            </div>
          ))}
        </div>
      </Section>
    </div>
  );
};
