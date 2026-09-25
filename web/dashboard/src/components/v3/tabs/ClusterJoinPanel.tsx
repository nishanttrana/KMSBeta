import { useState } from "react";
import { Btn, Chk, FG, Inp, Sel, Txt } from "../legacyPrimitives";
import { C } from "../theme";
import { errMsg } from "../runtimeUtils";
import { connectToCluster, createClusterJoinRequest } from "../../../lib/cluster";

// Secure join (docs/CLUSTERING.md). On the primary, issue a one-time join
// bundle; on the new node, paste it. The new node receives the master key and
// the data of its assigned components; its own copy of that data is replaced.

type Props = { session: any; profiles: any[]; onToast?: ((msg: string) => void) | undefined; onDone?: (() => void) | undefined };

export const ClusterJoinPanel = ({ session, profiles, onToast, onDone }: Props) => {
  const [mode, setMode] = useState<"issue" | "join">("issue");
  const [nodeID, setNodeID] = useState("");
  const [profileID, setProfileID] = useState(String(profiles?.[0]?.id || ""));
  const [bundle, setBundle] = useState("");
  const [paste, setPaste] = useState("");
  const [confirm, setConfirm] = useState(false);
  const [busy, setBusy] = useState(false);

  const issue = async () => {
    setBusy(true);
    try {
      const out = await createClusterJoinRequest(session, { target_node_id: nodeID.trim(), target_node_name: nodeID.trim(), profile_id: profileID, expires_minutes: 30 });
      if (!out.bundle) {
        onToast?.("Join token created, but this node is not configured as a primary (set CLUSTER_ADVERTISE_URL and TLS); no bundle issued.");
      }
      setBundle(out.bundle || "");
    } catch (error) {
      onToast?.(`Join request failed: ${errMsg(error)}`);
    } finally {
      setBusy(false);
    }
  };

  const join = async () => {
    setBusy(true);
    try {
      const out = await connectToCluster(session, { join_bundle: paste.trim(), confirm_replace: confirm });
      onToast?.(`Joined cluster (primary ${out.primary_node_id}); replicating ${out.subscribed.join(", ")}. Keycore restarts on the cluster master key.`);
      onDone?.();
    } catch (error) {
      onToast?.(`Join failed: ${errMsg(error)}`);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div style={{ display: "grid", gap: 10 }}>
      <div style={{ display: "flex", gap: 6 }}>
        <Btn small primary={mode === "issue"} onClick={() => setMode("issue")}>On this primary: add a node</Btn>
        <Btn small primary={mode === "join"} onClick={() => setMode("join")}>On a new node: join a cluster</Btn>
      </div>
      {mode === "issue" ? (
        <>
          <FG label="New node ID" required><Inp value={nodeID} onChange={(e: any) => setNodeID(e.target.value)} placeholder="vecta-kms-02" /></FG>
          <FG label="Features for the new node (replication profile)" required>
            <Sel value={profileID} onChange={(e: any) => setProfileID(e.target.value)}>
              {profiles.map((p: any) => <option key={p.id} value={p.id}>{p.name}</option>)}
            </Sel>
          </FG>
          <div style={{ fontSize: 10, color: C.dim }}>Core features (auth, keycore, policy, governance) always replicate. Only the selected profile's features' data goes to the new node; node-local data (local admin/CLI logins, sessions, node settings) never does.</div>
          <Btn primary disabled={busy || !nodeID.trim() || !profileID} onClick={() => void issue()}>{busy ? "Creating..." : "Create join bundle"}</Btn>
          {bundle && (
            <FG label="Join bundle (one-time, 30 minutes): paste it on the new node">
              <Txt value={bundle} readOnly rows={3} />
            </FG>
          )}
        </>
      ) : (
        <>
          <FG label="Join bundle from the primary" required><Txt value={paste} onChange={(e: any) => setPaste(e.target.value)} rows={3} placeholder="vecta-join-v1:..." /></FG>
          <div style={{ fontSize: 10, color: C.red, lineHeight: 1.5 }}>
            Joining replaces this node's master key and its data for the assigned features with the primary's. Keys created on this node before joining become unreadable. This node's local admin and CLI accounts are kept.
          </div>
          <Chk label="I understand; replace this node's data with the cluster's" checked={confirm} onChange={() => setConfirm(!confirm)} />
          <Btn primary disabled={busy || !confirm || !paste.trim().startsWith("vecta-join-v1:")} onClick={() => void join()}>{busy ? "Joining..." : "Join cluster"}</Btn>
        </>
      )}
    </div>
  );
};
