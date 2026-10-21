import { useCallback, useEffect, useState } from "react";
import { Crown, ShieldAlert, Users, Vote } from "lucide-react";
import type { AuthSession } from "../../../lib/auth";
import { getFailoverStatus, promoteThisNode, type FailoverStatus } from "../../../lib/cluster";
import { errMsg } from "../runtimeUtils";
import { C } from "../theme";
import { B, Btn, Card, Section, Stat, usePromptDialog } from "../legacyPrimitives";

// Cluster → Failover (services/cluster-manager/failover.go). Shows this
// node's place in the cluster and promotes it. Promotion runs on the node
// being promoted, so this page acts on the node the console is signed in to.

const roleLabel: Record<string, string> = { primary: "Primary", follower: "Member", fenced: "Fenced", "": "Standalone" };
const ago = (ms?: number) => (typeof ms !== "number" ? "-" : ms < 1500 ? "just now" : `${Math.round(ms / 1000)} s ago`);

export function ClusterFailoverPanel({ session, onToast }: { session: AuthSession; onToast?: ((m: string) => void) | undefined }) {
  const [status, setStatus] = useState<FailoverStatus | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const dialog = usePromptDialog();

  const load = useCallback(async () => {
    try {
      setStatus(await getFailoverStatus(session));
      setError("");
    } catch (e) {
      setError(errMsg(e));
    }
  }, [session]);
  useEffect(() => {
    void load();
    const id = setInterval(() => void load(), 5000);
    return () => clearInterval(id);
  }, [load]);

  const promote = async (force: boolean) => {
    const ok = await dialog.confirm({
      title: force ? "Promote without the primary" : "Promote this node",
      message: force
        ? "The primary did not answer. Promoting now loses its writes that have not reached this node, and if it is still serving clients it keeps accepting writes until it learns of this promotion. Promote only if the primary is down or cut off from its clients."
        : "This node becomes the primary. If the current primary answers, it stops making changes first and this node waits for its last write (a switchover).",
      confirmLabel: force ? "Promote anyway" : "Promote", cancelLabel: "Cancel", danger: true,
    });
    if (!ok) return;
    setBusy(true);
    try {
      const r = await promoteThisNode(session, { force, reason: force ? "primary unreachable" : "switchover" });
      onToast?.(`This node is primary (epoch ${r.epoch})${r.caught_up ? ", with the old primary's last write" : ""}.`);
      await load();
    } catch (e) {
      const msg = errMsg(e);
      if (!force && msg.includes("force")) {
        setBusy(false);
        await promote(true);
        return;
      }
      onToast?.(`Promotion failed: ${msg}`);
    } finally {
      setBusy(false);
    }
  };

  if (error) {
    return <Card><div role="alert" style={{ fontSize: 12, color: C.redFg }}>Failover status unavailable: {error}</div></Card>;
  }
  if (!status) return <Card><div style={{ fontSize: 12, color: C.dim }}>Loading…</div></Card>;
  if (!status.configured || !status.node) {
    return <Card><div style={{ fontSize: 12, color: C.dim }}>Failover is not configured on this node.</div></Card>;
  }
  const n = status.node;
  const leaseLost = n.role === "primary" && Boolean(status.lease_required) && Boolean(n.writable_until) && new Date(String(n.writable_until)).getTime() < Date.now();
  return (<>
    {dialog.ui}
    <Section title="Failover" actions={<Btn small onClick={() => void load()}>Refresh</Btn>}>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(170px,1fr))", gap: 10, marginBottom: 14 }}>
        <Stat l="This node" v={roleLabel[n.role] ?? n.role} i={Crown} c={n.role === "fenced" ? "red" : "accent"} />
        <Stat l="Epoch" v={n.epoch} i={Vote} />
        <Stat l="Voters" v={`${status.voters ?? 0} (majority ${status.majority ?? 0})`} i={Users} />
        <Stat l="Failover" v={status.failover_mode === "automatic" ? "Automatic election" : "Manual promotion"} i={ShieldAlert} />
      </div>
      {n.role === "fenced" && (
        <Card style={{ marginBottom: 12 }}><div role="alert" data-keep style={{ fontSize: 12, color: C.redFg }}>
          Another node was promoted, so this node makes no changes. Rejoin it: on the current primary create a join bundle (Node Management → Add Instance), then paste it here.
        </div></Card>
      )}
      {leaseLost && (
        <Card style={{ marginBottom: 12 }}><div role="alert" data-keep style={{ fontSize: 12, color: C.amberFg }}>
          This primary cannot reach a majority of the cluster, so it makes no changes until it does. Crypto operations and reads continue.
        </div></Card>
      )}
      {n.role === "follower" && (
        <Card style={{ marginBottom: 12 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <div style={{ flex: 1, fontSize: 12, color: C.dim }}>
              Primary <b style={{ color: C.text }}>{n.primary_node_id}</b>, last heard {ago(n.last_primary_contact_ago_ms)}.
              {n.resubscribe_pending ? " Copying from the new primary." : ""}
              {!status.promotable ? " This node can't be promoted: set CLUSTER_ADVERTISE_URL and CLUSTER_PG_ADVERTISE_HOST." : ""}
            </div>
            <Btn danger disabled={busy || !status.promotable} onClick={() => void promote(false)}>{busy ? "Promoting…" : "Promote this node"}</Btn>
          </div>
        </Card>
      )}
      <Card style={{ padding: 0, overflow: "hidden" }}>
        {(status.peers || []).length === 0 && <div style={{ padding: 14, fontSize: 12, color: C.dim }}>No peers known yet.</div>}
        {(status.peers || []).map((p) => (
          <div key={p.node_id} data-testid={`failover-peer-${p.node_id}`} style={{ display: "grid", gridTemplateColumns: "1fr 2fr auto auto", gap: 10, alignItems: "center", padding: "9px 14px", borderBottom: `1px solid ${C.border}`, fontSize: 12 }}>
            <span style={{ fontFamily: "var(--font-mono)", color: C.text }}>{p.node_id}</span>
            <span style={{ color: C.dim, fontFamily: "var(--font-mono)", overflow: "hidden", textOverflow: "ellipsis" }}>{p.url || "no address: does not vote"}</span>
            <span style={{ color: C.dim }}>{typeof p.last_heartbeat_ago_ms === "number" ? `heartbeat ${ago(p.last_heartbeat_ago_ms)}` : ""}</span>
            <span>{p.is_primary ? <B c="blue">primary</B> : <B c="neutral">member</B>}</span>
          </div>
        ))}
      </Card>
    </Section>
  </>);
}
