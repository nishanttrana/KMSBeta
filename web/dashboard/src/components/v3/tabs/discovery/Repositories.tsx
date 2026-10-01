import { useEffect, useState } from "react";
import { CheckCircle2, Lock, Plus, X } from "lucide-react";
import { Btn, Inp, Modal, Sel } from "../../legacyPrimitives";
import { C } from "../../theme";
import { errMsg } from "../../runtimeUtils";
import {
  addDiscoveryRepository, listGitConnections, removeDiscoveryRepository, testDiscoveryRepository,
  type DiscoveryRepository, type GitConnection,
} from "../../../../lib/discovery";
import type { AuthSession } from "../../../../lib/auth";
import { MONO } from "./meta";

const PROVIDERS = [["", "Detect from host"], ["github", "GitHub"], ["gitlab", "GitLab"], ["bitbucket", "Bitbucket"], ["gitea", "Gitea / Forgejo"]] as const;
const PROVIDER_LABEL: Record<string, string> = { github: "GitHub", gitlab: "GitLab", bitbucket: "Bitbucket", gitea: "Gitea" };

type Props = {
  open: boolean;
  onClose: () => void;
  session: AuthSession;
  repositories: DiscoveryRepository[];
  error: string;
  onChanged: () => void;
  onToast?: (msg: string) => void;
  onNavigate?: (tab: string) => void;
};

type TestState = { busy?: boolean; ok?: string; fail?: string };

export function RepositoriesModal({ open, onClose, session, repositories, error, onChanged, onToast, onNavigate }: Props) {
  const [url, setUrl] = useState("");
  const [ref, setRef] = useState("");
  const [provider, setProvider] = useState("");
  const [connection, setConnection] = useState("");
  const [busy, setBusy] = useState(false);
  const [connections, setConnections] = useState<GitConnection[]>([]);
  const [connError, setConnError] = useState("");
  const [tests, setTests] = useState<Record<string, TestState>>({});

  useEffect(() => {
    if (!open) return;
    listGitConnections(session)
      .then((c) => { setConnections(c); setConnError(""); })
      .catch((e) => { setConnections([]); setConnError(errMsg(e)); });
  // eslint-disable-next-line react-hooks/exhaustive-deps -- reviewed: reload the connection list each time the dialog opens.
  }, [open, session?.tenantId, session?.token]);

  const add = async () => {
    if (!url.trim()) return;
    setBusy(true);
    try {
      await addDiscoveryRepository(session, { url: url.trim(), ref: ref.trim(), provider, connection_id: connection });
      setUrl(""); setRef("");
      onChanged();
    } catch (e) {
      onToast?.(`Add repository failed: ${errMsg(e)}`);
    } finally {
      setBusy(false);
    }
  };
  const remove = async (r: DiscoveryRepository) => {
    try {
      await removeDiscoveryRepository(session, r.id);
      onChanged();
    } catch (e) {
      onToast?.(`Remove repository failed: ${errMsg(e)}`);
    }
  };
  const test = async (r: DiscoveryRepository) => {
    setTests((t) => ({ ...t, [r.id]: { busy: true } }));
    try {
      const res = await testDiscoveryRepository(session, r.id);
      setTests((t) => ({ ...t, [r.id]: { ok: res.commit ? `commit ${res.commit.slice(0, 10)}` : "readable" } }));
    } catch (e) {
      setTests((t) => ({ ...t, [r.id]: { fail: errMsg(e) } }));
    }
  };
  const connName = (id: string) => connections.find((c) => c.id === id)?.name || id;

  return (
    <Modal open={open} onClose={onClose} title="Git repositories" width={860}>
      <div style={{ display: "grid", gridTemplateColumns: "minmax(220px,2.2fr) minmax(90px,.9fr) minmax(120px,1fr) minmax(150px,1.2fr) auto", gap: 8, alignItems: "center", marginBottom: 6 }}>
        <Inp mono placeholder="https://github.com/acme/app" value={url} onChange={(e) => setUrl(e.target.value)} onKeyDown={(e) => { if (e.key === "Enter") void add(); }} />
        <Inp mono placeholder="branch (default)" value={ref} onChange={(e) => setRef(e.target.value)} />
        <Sel value={provider} onChange={(e) => setProvider(e.target.value)}>
          {PROVIDERS.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
        </Sel>
        <Sel value={connection} onChange={(e) => setConnection(e.target.value)}>
          <option value="">Public (no token)</option>
          {connections.map((c) => <option key={c.id} value={c.id}>{c.name} · {c.endpoint}</option>)}
        </Sel>
        <Btn primary onClick={() => void add()} disabled={busy || !url.trim()}><Plus size={12} />{busy ? "Adding..." : "Add"}</Btn>
      </div>
      <div style={{ display: "flex", justifyContent: "space-between", gap: 12, fontSize: 10.5, color: C.muted, marginBottom: 12 }}>
        <span>{connError ? `Connections unavailable: ${connError}` : "The files at the branch's latest commit are scanned in memory. A private repository reads with a Git connection's token."}</span>
        <button type="button" onClick={() => onNavigate?.("playbooks")} style={{ background: "none", border: "none", color: C.accentFg, cursor: "pointer", fontSize: 10.5, padding: 0, whiteSpace: "nowrap" }}>New Git connection</button>
      </div>
      {error ? (
        <div style={{ fontSize: 11, color: C.redFg }}>Repositories unavailable: {error}</div>
      ) : repositories.length ? (
        <div style={{ border: `1px solid ${C.border}`, borderRadius: 8, overflow: "hidden" }}>
          {repositories.map((r, i) => {
            const t = tests[r.id] || {};
            return (
              <div key={r.id} style={{ borderTop: i ? `1px solid ${C.border}` : "none", padding: "8px 12px" }}>
                <div style={{ display: "grid", gridTemplateColumns: "70px 1fr auto auto 28px", alignItems: "center", gap: 10 }}>
                  <span style={{ fontSize: 10, fontWeight: 700, color: C.blueFg }}>{PROVIDER_LABEL[r.provider] ?? r.provider}</span>
                  <span style={{ fontFamily: MONO, fontSize: 11.5, color: C.text, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                    {r.url.replace(/^https:\/\//, "")}{r.ref ? <span style={{ color: C.muted }}> @ {r.ref}</span> : null}
                  </span>
                  <span style={{ display: "inline-flex", alignItems: "center", gap: 5, fontSize: 10.5, color: C.muted }}>
                    {r.connection_id ? <><Lock size={11} />{connName(r.connection_id)}</> : "public"}
                  </span>
                  <Btn small onClick={() => void test(r)} disabled={t.busy}>{t.busy ? "Testing..." : "Test"}</Btn>
                  <button type="button" aria-label={`Remove ${r.url}`} onClick={() => void remove(r)} style={{ background: "none", border: "none", color: C.muted, cursor: "pointer", display: "inline-flex" }}><X size={13} /></button>
                </div>
                {t.ok && <div style={{ display: "flex", alignItems: "center", gap: 5, fontSize: 10.5, color: C.greenFg, marginTop: 5, paddingLeft: 80 }}><CheckCircle2 size={11} />Readable · {t.ok}</div>}
                {t.fail && <div style={{ fontSize: 10.5, color: C.redFg, marginTop: 5, paddingLeft: 80, wordBreak: "break-word" }}>Not readable: {t.fail}</div>}
              </div>
            );
          })}
        </div>
      ) : (
        <div style={{ fontSize: 11, color: C.muted, textAlign: "center", padding: 18, border: `1px dashed ${C.border}`, borderRadius: 8 }}>No repositories yet</div>
      )}
    </Modal>
  );
}
