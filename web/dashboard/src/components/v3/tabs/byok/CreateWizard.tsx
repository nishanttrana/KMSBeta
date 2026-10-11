import { useEffect, useMemo, useState } from "react";
import type { AuthSession } from "../../../../lib/auth";
import { BYOKRunError, createBYOKKey, type BYOKProviderInfo, type BYOKRun } from "../../../../lib/byok";
import type { CloudAccount } from "../../../../lib/cloud";
import { listHSMTargets, topologyLabel, type HSMTarget } from "../../../../lib/credentials";
import { createKey } from "../../../../lib/keycore";
import { errMsg } from "../../runtimeUtils";
import { Btn, FG, Inp, Modal, Row2, Sel } from "../../legacyPrimitives";
import { C } from "../../theme";
import { MONO, cloudLabel } from "./meta";
import { RunSteps } from "./RunSteps";

type CatalogKey = { id: string; name: string; algo?: string; state?: string; exportAllowed?: boolean; inHSM?: boolean };

type Props = {
  session: AuthSession;
  accounts: CloudAccount[];
  providers: BYOKProviderInfo[];
  keyCatalog: CatalogKey[];
  onClose: () => void;
  onDone: (byokId: string) => void;
  onAddConnector: () => void;
  onToast?: ((msg: string) => void) | undefined;
};

type Source = "existing" | "kms" | "hsm";

const SPEC_OF: Record<string, string> = { "AES-256": "AES-256", "AES-256-GCM": "AES-256" };

// Bring your own key: pick the cloud, where the material comes from (an
// exportable KMS key, a new key from the KMS's DRBG, or a new key generated
// in a PKCS#11 HSM with cloud import allowed), then run the import.
export function BYOKCreateWizard({ session, accounts, providers, keyCatalog, onClose, onDone, onAddConnector, onToast }: Props) {
  const usable = accounts.filter((a) => providers.some((p) => p.provider === a.provider));
  const [accountId, setAccountId] = useState(usable[0]?.id ?? "");
  const [source, setSource] = useState<Source>("kms");
  const [keyId, setKeyId] = useState("");
  const [name, setName] = useState("");
  const [hsmTargets, setHSMTargets] = useState<HSMTarget[] | null>(null);
  const [hsmError, setHSMError] = useState("");
  const [hsmId, setHSMId] = useState<string | null>(null);
  const [alias, setAlias] = useState("");
  const [days, setDays] = useState("");
  const [certName, setCertName] = useState("");
  const [certPEM, setCertPEM] = useState("");
  const [busy, setBusy] = useState(false);
  const [run, setRun] = useState<BYOKRun | null>(null);
  const [error, setError] = useState("");

  const account = usable.find((a) => a.id === accountId);
  const caps = providers.find((p) => p.provider === account?.provider)?.capabilities;
  const exportable = useMemo(() => keyCatalog.filter((k) => k.exportAllowed && k.state !== "deleted" && k.state !== "destroyed"), [keyCatalog]);

  useEffect(() => {
    if (source !== "hsm" || hsmTargets) return;
    listHSMTargets(session)
      .then((t) => { setHSMTargets(t.targets); const first = t.targets.find((x) => x.usable); setHSMId(first ? first.id : null); })
      .catch((e) => setHSMError(errMsg(e)));
  }, [source, hsmTargets, session]);

  const submit = async () => {
    if (!account) return;
    setBusy(true);
    setError("");
    setRun(null);
    try {
      let id = keyId;
      if (source !== "existing") {
        // The KMS key comes first, with its own audit event in keycore.
        const created = await createKey(session, {
          name: name.trim() || `byok-${account.provider}-${Date.now().toString(36)}`, algorithm: "AES-256", key_type: "symmetric",
          purpose: "encrypt-decrypt", export_allowed: true, iv_mode: "internal", created_by: session.username || "dashboard-user",
          ...(source === "hsm" ? { hsm: true, hsm_connection_id: hsmId ?? "" } : {}),
        });
        id = created.key_id;
      }
      const n = Number(days);
      const out = await createBYOKKey(session, {
        account_id: account.id, key_id: id, alias: alias.trim(), ...(n > 0 ? { validity_days: n } : {}),
        ...(account.provider === "salesforce" ? { certificate_name: certName.trim(), certificate_pem: certPEM.trim() } : {}),
      });
      setRun(out.run);
      onToast?.(`Imported into ${cloudLabel(account.provider)}: ${out.key.cloud_key_id}`);
      onDone(out.key.id);
    } catch (e) {
      if (e instanceof BYOKRunError && e.run) setRun(e.run);
      setError(errMsg(e));
    } finally {
      setBusy(false);
    }
  };

  const ready = !!account && (source !== "existing" || !!keyId) && (source !== "hsm" || hsmId !== null)
    && (account?.provider !== "salesforce" || (certName.trim() !== "" && certPEM.trim() !== ""));

  return (
    <Modal open onClose={onClose} title="Bring your own key" wide>
      <div style={{ padding: 20, display: "grid", gap: 12 }}>
        {!usable.length ? (
          <div style={{ fontSize: 11.5, color: C.muted }}>
            No cloud connector yet. <span onClick={onAddConnector} style={{ color: C.accentFg, cursor: "pointer" }}>Add a connector</span> with a credential from Playbooks → Credentials.
          </div>
        ) : <>
          <Row2>
            <FG label="Cloud" required>
              <Sel value={accountId} onChange={(e) => setAccountId(e.target.value)}>
                {usable.map((a) => <option key={a.id} value={a.id}>{`${cloudLabel(a.provider)} · ${a.name}${a.default_region ? ` (${a.default_region})` : ""}`}</option>)}
              </Sel>
            </FG>
            <FG label="Key material from" required>
              <Sel value={source} onChange={(e) => setSource(e.target.value as Source)}>
                <option value="kms">New AES-256 key, KMS entropy</option>
                <option value="hsm">New AES-256 key, generated in an HSM</option>
                <option value="existing">An existing exportable KMS key</option>
              </Sel>
            </FG>
          </Row2>
          {caps && <div style={{ fontSize: 10.5, color: C.muted }}>
            {cloudLabel(account?.provider ?? "")} imports {caps.specs.join(", ")}{caps.rotate ? " · rotate" : ""}{caps.revoke ? (caps.revoke_deletes ? " · delete material" : " · disable") : ""}{caps.expiry ? " · expiry" : ""}
          </div>}

          {source === "existing" && <FG label="KMS key" required hint={exportable.length ? "Only keys whose export (KMS) or cloud import (HSM) is allowed can leave." : "No exportable key; create one here instead."}>
            <Sel value={keyId} onChange={(e) => setKeyId(e.target.value)}>
              <option value="">Choose a key</option>
              {exportable.filter((k) => !caps || caps.specs.includes(SPEC_OF[String(k.algo || "").toUpperCase()] ?? String(k.algo || ""))).map((k) =>
                <option key={k.id} value={k.id}>{`${k.name} (${k.algo || "?"})${k.inHSM ? " · HSM" : ""}`}</option>)}
            </Sel>
          </FG>}
          {source !== "existing" && <FG label="KMS key name"><Inp value={name} onChange={(e) => setName(e.target.value)} placeholder="orders-db-byok" /></FG>}
          {source === "hsm" && <FG label="HSM" required hint="Generated sensitive and extractable only for cloud import; it leaves the HSM wrapped to the cloud's key, inside the HSM.">
            {hsmError ? <div style={{ fontSize: 11, color: C.redFg }}>HSMs unavailable: {hsmError}</div> : (
              <Sel value={hsmId ?? ""} onChange={(e) => setHSMId(e.target.value)}>
                {(hsmTargets ?? []).map((t) => <option key={t.id || "profile"} value={t.id} disabled={!t.usable}>
                  {`${t.name} · ${t.kind === "tenant_profile" ? "tenant HSM" : topologyLabel(t.topology)}${t.status.connected ? "" : " · not connected"}${t.usable ? "" : ` · ${t.reason || "unusable"}`}`}
                </option>)}
                {hsmTargets && !hsmTargets.length && <option value="">No HSM: add a PKCS#11 HSM credential</option>}
              </Sel>
            )}
          </FG>}
          <Row2>
            <FG label="Alias in the cloud"><Inp value={alias} onChange={(e) => setAlias(e.target.value)} placeholder="orders-db" mono /></FG>
            {caps?.expiry ? <FG label="Material valid for (days)" hint="Empty: does not expire. At most 365.">
              <Inp value={days} onChange={(e) => setDays(e.target.value.replace(/\D/g, ""))} placeholder="365" />
            </FG> : <div />}
          </Row2>
          {account?.provider === "salesforce" && <>
            <FG label="BYOK certificate name" required hint="The BYOK-compatible certificate created in Salesforce Setup."><Inp value={certName} onChange={(e) => setCertName(e.target.value)} mono /></FG>
            <FG label="Certificate (PEM)" required>
              <textarea value={certPEM} onChange={(e) => setCertPEM(e.target.value)} rows={4} style={{ width: "100%", fontFamily: MONO, fontSize: 10, background: C.card, color: C.text, border: `1px solid ${C.border}`, borderRadius: 3, padding: 8, boxSizing: "border-box" }} />
            </FG>
          </>}
        </>}
        {error && <div style={{ fontSize: 11, color: C.redFg }}>{error}</div>}
        {run && <div style={{ border: `1px solid ${C.border}`, borderRadius: 4, padding: 10 }}><RunSteps run={run} /></div>}
        <div style={{ display: "flex", justifyContent: "flex-end", gap: 8 }}>
          <Btn onClick={onClose}>{run?.status === "succeeded" ? "Close" : "Cancel"}</Btn>
          {run?.status !== "succeeded" && <Btn primary disabled={!ready || busy} onClick={() => void submit()}>{busy ? "Importing…" : "Create and import"}</Btn>}
        </div>
      </div>
    </Modal>
  );
}
