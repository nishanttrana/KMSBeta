import {
  Activity,
  ArrowLeftRight,
  Bell,
  Boxes,
  ClipboardCheck,
  CloudCog,
  Cpu,
  Database,
  DatabaseBackup,
  DatabaseZap,
  FileBadge,
  Fingerprint,
  Gauge,
  KeyRound,
  LayoutDashboard,
  LockKeyhole,
  Network,
  RefreshCw,
  ScanSearch,
  ScrollText,
  SlidersHorizontal,
  SquareTerminal,
  Stamp,
  Vault,
  Workflow,
} from "lucide-react";

// Six groups by job (13.23.0-beta; was six by product area plus a
// one-entry PKI group). Only the group holding the open module starts
// expanded. Recommendations is a sub-option of Command Center.
export const NAV = [
  { g: "Home", items: [
    { id: "home", icon: LayoutDashboard, label: "Command Center" },
    { id: "ops", icon: Activity, label: "Operations" },
    { id: "workbench", icon: SquareTerminal, label: "Workbench" },
  ]},
  { g: "Keys & certificates", items: [
    { id: "keys", icon: KeyRound, label: "Key Management" },
    { id: "certs", icon: FileBadge, label: "Certificates / PKI" },
    { id: "rotation", icon: RefreshCw, label: "Rotation & Scheduling" },
    { id: "crypto_agility", icon: ArrowLeftRight, label: "Crypto Agility" },
    { id: "discovery", icon: ScanSearch, label: "Crypto Discovery" },
  ]},
  { g: "Data & integrations", items: [
    { id: "vault", icon: Vault, label: "Secret Vault" },
    { id: "dataprotection", icon: DatabaseZap, label: "Data Protection" },
    { id: "cloudctl", icon: CloudCog, label: "Cloud Key Control" },
    { id: "ekm", icon: Database, label: "Enterprise KM" },
    { id: "hsm", icon: Cpu, label: "HSM" },
    { id: "workload", icon: Fingerprint, label: "Workload Identity" },
    { id: "confidential", icon: LockKeyhole, label: "Confidential Compute" },
  ]},
  { g: "Monitor", items: [
    { id: "audit", icon: ScrollText, label: "Audit Log" },
    { id: "alerts", icon: Bell, label: "Alert Center" },
    { id: "posture", icon: Gauge, label: "Posture" },
    { id: "compliance", icon: ClipboardCheck, label: "Compliance" },
    { id: "sbom", icon: Boxes, label: "SBOM / CBOM" },
  ]},
  { g: "Respond", items: [
    { id: "approvals", icon: Stamp, label: "Approvals" },
    { id: "playbooks", icon: Workflow, label: "Playbooks" },
  ]},
  { g: "Platform", items: [
    { id: "cluster", icon: Network, label: "Cluster" },
    { id: "backup", icon: DatabaseBackup, label: "Backup & Restore" },
    { id: "admin", icon: SlidersHorizontal, label: "Administration" },
  ]},
];

// Tabs merged into another; a saved or linked id opens the new home.
// Platform > Health went to Administration > Health (1.38.0-beta),
// Operations Metrics and Analytics to Overview > Operations (7.24.0-beta).
// Documentation was removed (7.35.0-beta); its ids open the Command Center.
// Recommendations became Command Center's sub-option (13.23.0-beta).
export const RETIRED_TABS: Record<string, string> = { health: "admin/health", ops_metrics: "ops", key_analytics: "ops", docs: "home", devsecops: "home", recommendations: "home/recommendations" };

// The address names the module and its sub-option (#certs/cert-enrollment).
// Each move adds a history entry, so Back returns to the previous view, and
// a pasted or edited address opens its view (13.21.0-beta); the address was
// only read at load and overwritten in place.
// Sub-options that moved to another module (13.26.0-beta: backups and
// approval policies each have one home).
export const RETIRED_SUBS: Record<string, string> = { "admin/backup": "backup/encrypted", "admin/approvals": "approvals/policies" };

export function parseNavHash(hash: string): { tab: string; sub: string } {
  const [rawTab = "", rawSub = ""] = decodeURIComponent(String(hash || "").replace(/^#/, "")).split("/");
  const [tab = "", retiredSub = ""] = (RETIRED_TABS[rawTab] ?? rawTab).split("/");
  const sub = rawSub || retiredSub;
  const moved = RETIRED_SUBS[`${tab}/${sub}`];
  if (moved) {
    const [movedTab = "", movedSub = ""] = moved.split("/");
    return { tab: movedTab, sub: movedSub };
  }
  return { tab, sub };
}
