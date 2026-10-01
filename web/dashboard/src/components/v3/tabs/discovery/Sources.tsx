import { useState } from "react";
import { Play, Plus, Terminal, X } from "lucide-react";
import { Btn, Inp, Modal } from "../../legacyPrimitives";
import { C } from "../../theme";
import { errMsg } from "../../runtimeUtils";
import { addDiscoveryTarget, removeDiscoveryTarget, type DiscoverySource, type DiscoveryTarget } from "../../../../lib/discovery";
import type { AuthSession } from "../../../../lib/auth";
import { MONO, SCANNABLE, relTime, sourceMeta } from "./meta";

const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;

function sourceLine(s: DiscoverySource): string {
  const d = s.detail || {};
  if (s.error) return "Unavailable";
  switch (s.id) {
    case "network": {
      if (!s.configured) return "No targets yet";
      const parts = [d.hosts ? plural(d.hosts, "host") : "", d.ranges ? plural(d.ranges, "range") : "", d.ssh ? `${d.ssh} SSH` : "", d.operator_endpoints ? `+${d.operator_endpoints} operator` : ""];
      return parts.filter(Boolean).join(" · ");
    }
    case "cloud":
      return s.configured ? `${plural(d.accounts, "account")} · ${(d.providers || []).join(", ")}` : "No accounts connected";
    case "certs":
      return plural(d.certificates || 0, "certificate");
    case "code":
      return s.configured ? "Repository mounted" : "Not mounted";
    default:
      return "Keys, certificates, keystores";
  }
}

type CardsProps = {
  sources: DiscoverySource[];
  assetCounts: Record<string, number>;
  running: boolean;
  uploading: boolean;
  onScan: (types: string[]) => void;
  onTargets: () => void;
  onCodeSetup: () => void;
  onPickFiles: () => void;
  onUpload: (files: File[]) => void;
  onNavigate?: (tab: string) => void;
};

export function SourceCards({ sources, assetCounts, running, uploading, onScan, onTargets, onCodeSetup, onPickFiles, onUpload, onNavigate }: CardsProps) {
  const [dragging, setDragging] = useState(false);
  const action = (s: DiscoverySource) => {
    switch (s.id) {
      case "network": return { label: "Targets", run: onTargets };
      case "cloud": return { label: s.configured ? "Accounts" : "Connect", run: () => onNavigate?.("byok") };
      case "certs": return { label: "Open PKI", run: () => onNavigate?.("certificates") };
      case "code": return { label: s.configured ? "Details" : "Set up", run: onCodeSetup };
      default: return { label: uploading ? "Uploading..." : "Upload", run: onPickFiles };
    }
  };
  return (
    <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: 10 }}>
      {sources.map((s) => {
        const M = sourceMeta(s.id);
        const Icon = M.icon;
        const a = action(s);
        const last = s.last_scan;
        const isUpload = s.id === "upload";
        const state = s.error ? { t: "Unavailable", c: C.redFg } : s.configured ? { t: "Ready", c: C.greenFg } : { t: "Set up", c: C.muted };
        return (
          <div key={s.id}
            onDragOver={isUpload ? (e) => { e.preventDefault(); setDragging(true); } : undefined}
            onDragLeave={isUpload ? () => setDragging(false) : undefined}
            onDrop={isUpload ? (e) => { e.preventDefault(); setDragging(false); onUpload(Array.from(e.dataTransfer.files)); } : undefined}
            style={{ background: C.card, border: `1px ${dragging && isUpload ? "dashed" : "solid"} ${dragging && isUpload ? C.accentFg : C.border}`, borderRadius: "var(--radius-md)", padding: 14, display: "flex", flexDirection: "column", gap: 8, boxShadow: "var(--shadow-sm)", minWidth: 0 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
              <span style={{ width: 30, height: 30, borderRadius: 8, background: C.accentDim, color: C.accentFg, display: "inline-flex", alignItems: "center", justifyContent: "center", flexShrink: 0 }}><Icon size={15} /></span>
              <div style={{ minWidth: 0, flex: 1 }}>
                <div style={{ fontSize: 12.5, fontWeight: 600, color: C.text }}>{M.label}</div>
                <div style={{ fontSize: 10.5, color: C.muted, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }} title={s.error || sourceLine(s)}>{sourceLine(s)}</div>
              </div>
              <span style={{ fontSize: 18, fontWeight: 650, color: C.text, fontVariantNumeric: "tabular-nums" }} title="assets in the inventory">{(assetCounts[s.id] || 0).toLocaleString()}</span>
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 10.5, color: C.muted, minHeight: 14 }}>
              <span style={{ width: 6, height: 6, borderRadius: 3, background: state.c }} />
              <span style={{ color: state.c, fontWeight: 600 }}>{state.t}</span>
              <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: last?.error ? C.redFg : C.muted }} title={last?.error || ""}>
                {isUpload ? "· drop files here" : !s.configured ? "" : last ? `· ${last.error ? "errors" : plural(last.assets, "asset")} ${relTime(last.at)}` : "· never scanned"}
              </span>
            </div>
            <div style={{ display: "flex", gap: 6, marginTop: "auto" }}>
              <Btn small onClick={a.run} disabled={isUpload && uploading}>{a.label}</Btn>
              {SCANNABLE.includes(s.id) && (
                <Btn small onClick={() => onScan([s.id])} disabled={running || !s.configured} title={s.configured ? `Scan ${M.label}` : "Set this source up first"}><Play size={11} />Scan</Btn>
              )}
            </div>
          </div>
        );
      })}
    </div>
  );
}

// rangeSize: how many addresses a target expands to (services/discovery prefixHosts).
function rangeSize(host: string): number {
  const bits = Number(host.split("/")[1]);
  if (!host.includes("/") || !Number.isInteger(bits)) return 1;
  const v6 = host.includes(":");
  const n = 2 ** ((v6 ? 128 : 32) - bits);
  return !v6 && bits <= 30 ? n - 2 : n;
}

const DEFAULT_PORT = { tls: "443", ssh: "22" } as const;

type TargetsProps = {
  open: boolean;
  onClose: () => void;
  session: AuthSession;
  targets: DiscoveryTarget[];
  error: string;
  operatorEndpoints: number;
  onChanged: () => void;
  onToast?: (msg: string) => void;
};

export function TargetsModal({ open, onClose, session, targets, error, operatorEndpoints, onChanged, onToast }: TargetsProps) {
  const [proto, setProto] = useState<"tls" | "ssh">("tls");
  const [host, setHost] = useState("");
  const [port, setPort] = useState<string>(DEFAULT_PORT.tls);
  const [busy, setBusy] = useState(false);
  const pick = (p: "tls" | "ssh") => {
    if (port === DEFAULT_PORT[proto]) setPort(DEFAULT_PORT[p]);
    setProto(p);
  };
  const add = async () => {
    if (!host.trim() || !port) return;
    setBusy(true);
    try {
      await addDiscoveryTarget(session, host.trim(), Number(port), proto);
      setHost("");
      onChanged();
    } catch (e) {
      onToast?.(`Add target failed: ${errMsg(e)}`);
    } finally {
      setBusy(false);
    }
  };
  const remove = async (t: DiscoveryTarget) => {
    try {
      await removeDiscoveryTarget(session, t.id);
      onChanged();
    } catch (e) {
      onToast?.(`Remove target failed: ${errMsg(e)}`);
    }
  };
  const seg = (p: "tls" | "ssh") => (
    <button type="button" onClick={() => pick(p)} style={{ border: "none", borderRadius: 6, padding: "6px 12px", fontSize: 11, fontWeight: 600, cursor: "pointer", background: proto === p ? C.accentDim : "transparent", color: proto === p ? C.accentFg : C.muted }}>{p.toUpperCase()}</button>
  );
  return (
    <Modal open={open} onClose={onClose} title="Network targets" wide>
      <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap", marginBottom: 6 }}>
        <div style={{ display: "inline-flex", padding: 2, border: `1px solid ${C.border}`, borderRadius: 8 }}>{seg("tls")}{seg("ssh")}</div>
        <div style={{ flex: 1, minWidth: 200 }}>
          <Inp mono placeholder="host, IP or range (10.0.4.0/24)" value={host} onChange={(e) => setHost(e.target.value)} onKeyDown={(e) => { if (e.key === "Enter") void add(); }} />
        </div>
        <Inp mono w={80} placeholder="port" inputMode="numeric" value={port} onChange={(e) => setPort(e.target.value.replace(/[^0-9]/g, ""))} />
        <Btn primary onClick={() => void add()} disabled={busy || !host.trim() || !port}><Plus size={12} />{busy ? "Adding..." : "Add"}</Btn>
      </div>
      <div style={{ fontSize: 10.5, color: C.muted, marginBottom: 12 }}>Ranges up to 256 addresses. Loopback, link-local and KMS platform addresses are refused.</div>
      {error ? (
        <div style={{ fontSize: 11, color: C.redFg }}>Targets unavailable: {error}</div>
      ) : targets.length ? (
        <div style={{ border: `1px solid ${C.border}`, borderRadius: 8, overflow: "hidden" }}>
          {targets.map((t, i) => {
            const n = rangeSize(t.host);
            return (
              <div key={t.id} style={{ display: "grid", gridTemplateColumns: "52px 1fr auto 28px", alignItems: "center", gap: 10, padding: "8px 12px", borderTop: i ? `1px solid ${C.border}` : "none" }}>
                <span style={{ display: "inline-flex", alignItems: "center", gap: 4, fontSize: 10, fontWeight: 700, color: t.protocol === "ssh" ? C.purpleFg : C.blueFg }}>{t.protocol === "ssh" && <Terminal size={11} />}{(t.protocol || "tls").toUpperCase()}</span>
                <span style={{ fontFamily: MONO, fontSize: 11.5, color: C.text, overflow: "hidden", textOverflow: "ellipsis" }}>{t.host.includes(":") && !t.host.includes("/") ? `[${t.host}]` : t.host}:{t.port}</span>
                <span style={{ fontSize: 10.5, color: C.muted }}>{t.host.includes("/") ? `range · ${n.toLocaleString()} addresses` : ""}</span>
                <button type="button" aria-label={`Remove ${t.host}:${t.port}`} onClick={() => void remove(t)} style={{ background: "none", border: "none", color: C.muted, cursor: "pointer", display: "inline-flex" }}><X size={13} /></button>
              </div>
            );
          })}
        </div>
      ) : (
        <div style={{ fontSize: 11, color: C.muted, textAlign: "center", padding: 18, border: `1px dashed ${C.border}`, borderRadius: 8 }}>No targets yet</div>
      )}
      {operatorEndpoints > 0 && <div style={{ fontSize: 10.5, color: C.muted, marginTop: 10 }}>+{operatorEndpoints} operator endpoints from DISCOVERY_TLS_ENDPOINTS</div>}
    </Modal>
  );
}

export function CodeSetupModal({ open, onClose, configured, onUpload }: { open: boolean; onClose: () => void; configured: boolean; onUpload: () => void }) {
  const step = (n: number, text: string) => (
    <div style={{ display: "flex", gap: 10, alignItems: "baseline", fontSize: 12, color: C.text, marginBottom: 8 }}>
      <span style={{ width: 18, height: 18, borderRadius: 9, background: C.accentDim, color: C.accentFg, fontSize: 10, fontWeight: 700, display: "inline-flex", alignItems: "center", justifyContent: "center", flexShrink: 0 }}>{n}</span>{text}
    </div>
  );
  return (
    <Modal open={open} onClose={onClose} title="Source code scanning">
      {configured && <div style={{ fontSize: 11.5, color: C.greenFg, marginBottom: 12 }}>A repository is mounted. Scan it from the Source code card.</div>}
      {step(1, "Mount the repository read-only into the discovery service")}
      {step(2, "Set WORKSPACE_ROOT to the mount path")}
      {step(3, "Restart discovery, then scan")}
      <pre style={{ fontFamily: MONO, fontSize: 11, color: C.text, background: C.bg, border: `1px solid ${C.border}`, borderRadius: 8, padding: 12, margin: "8px 0 12px", overflowX: "auto" }}>{`discovery:
  volumes:
    - /srv/repos:/workspace:ro
  environment:
    WORKSPACE_ROOT: /workspace`}</pre>
      <div style={{ fontSize: 11, color: C.muted, marginBottom: 12 }}>Findings keep the file, line and a fingerprint, never the secret.</div>
      <Btn onClick={() => { onClose(); onUpload(); }}>Upload files instead</Btn>
    </Modal>
  );
}
