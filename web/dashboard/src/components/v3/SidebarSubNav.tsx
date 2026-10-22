import {
  Activity,
  AlertTriangle,
  Building2,
  Cloud,
  Cpu,
  Database,
  DatabaseBackup,
  FileText,
  GitBranch,
  KeyRound,
  Layers,
  Link,
  List,
  ListChecks,
  Lock,
  Plug,
  Radio,
  RefreshCw,
  Search,
  Server,
  Settings,
  Shield,
  Stamp,
  ShieldCheck,
  Users,
  VenetianMask,
  Zap,
  type LucideIcon,
} from "lucide-react";
import { C } from "./theme";

// platformOnly views belong to the platform (root) tenant's administrators.
export type SubPane = { id: string; label: string; hint: string; icon: LucideIcon; feature?: string; platformOnly?: boolean };

// A module's views. They are listed in the sidebar under the module's name,
// never in a second column or a tab strip of the shell (owner directive,
// 2026-10-11; CLAUDE.md "Sub-options live in the sidebar").
export const SUB_PANES: Record<string, SubPane[]> = {
  // Audit Log's views (13.42.0-beta: they were a tab strip in the page).
  audit: [
    { id: "events", label: "Events", hint: "Every audit event, filtered and exported", icon: List },
    { id: "activity", label: "Activity", hint: "Audit charts over a window, each drilling into its events", icon: Activity },
    { id: "investigate", label: "Investigate", hint: "Who did what, on what, from where and how, for any person, object, address, session or request", icon: Search },
    { id: "checkpoints", label: "Checkpoints", hint: "Signed checkpoints of the audit chain", icon: ShieldCheck }
  ],
  workbench: [
    { id: "crypto", label: "Crypto Console", hint: "Interactive cryptographic operations and algorithm console", icon: Zap },
    { id: "restapi", label: "REST API", hint: "Authenticated API explorer and endpoint documentation", icon: FileText },
    { id: "tokenize", label: "Tokenize / Mask / Redact", hint: "Vault and vaultless tokenization with masking/redaction", icon: VenetianMask, feature: "data_protection" },
    { id: "dataenc", label: "Data Encryption", hint: "Field-level, envelope, searchable and FPE crypto", icon: Database, feature: "data_protection" },
    { id: "hyok-test", label: "HYOK Live Test", hint: "Interactive HYOK crypto test console for all protocols", icon: Zap }
  ],
  // Database credentials are short-lived logins (13.34.0-beta).
  vault: [
    { id: "secrets", label: "Secrets", hint: "Stored secrets, deleted secrets and access rules", icon: KeyRound },
    { id: "database", label: "Database credentials", hint: "Short-lived PostgreSQL logins", icon: Database }
  ],
  dataprotection: [
    { id: "fieldenc", label: "Field Encryption", hint: "Wrapper registration, challenge-response and local crypto lease control", icon: KeyRound, feature: "data_protection" },
    { id: "dataenc-policy", label: "Data Encryption Policy", hint: "Policy controls only for data encryption interfaces", icon: List, feature: "data_protection" },
    { id: "token-policy", label: "Token / Mask / Redact Policy", hint: "Policy controls only for tokenization, masking and redaction", icon: VenetianMask, feature: "data_protection" },
    { id: "pkcs11", label: "Java SDK", hint: "Java JCA provider download", icon: Plug }
  ],
  cloudctl: [
    { id: "byok", label: "BYOK", hint: "Cloud provider key import and sync", icon: Cloud, feature: "cloud_byok" },
    // Azure EKM is a HYOK protocol (13.30.0-beta): its card is on HYOK.
    { id: "hyok", label: "HYOK", hint: "Hold-your-own-key endpoints: DKE, Google EKM, Azure EKM, Salesforce, ServiceNow, Alibaba", icon: ShieldCheck, feature: "hyok_proxy" },
    { id: "google-cse", label: "Google CSE", hint: "Workspace Client-Side Encryption", icon: Shield, feature: "ekm_database" }
  ],
  ekm: [
    { id: "db", label: "EKM for DBs", hint: "MSSQL / Oracle TDE agents", icon: Database, feature: "ekm_database" },
    { id: "bitlocker", label: "BitLocker", hint: "Windows endpoint key lifecycle", icon: Lock, feature: "ekm_database" },
    { id: "kmip", label: "KMIP", hint: "Profiles, clients, mTLS onboarding", icon: Link, feature: "kmip_server" },
    { id: "kubernetes", label: "Kubernetes", hint: "KMS v2 plugin for kube-apiserver secret encryption", icon: Layers }
  ],
  certs: [
    { id: "cert-overview", label: "Certificate Operations", hint: "CA hierarchy, issuance, signing and certificate lifecycle", icon: FileText, feature: "certs" },
    { id: "cert-enrollment", label: "Enrollment Protocols", hint: "ACME, EST, SCEP, CMPv2 and runtime mTLS enrollment settings", icon: Link, feature: "certs" },
    { id: "cert-service-mtls", label: "Service mTLS", hint: "Internal certificates: key, PQC key exchange, rotation and restarts", icon: Shield, feature: "certs" }
  ],
  hsm: [
    { id: "hsm-aws", label: "AWS CloudHSM", hint: "Cluster endpoint, slot mapping and crypto user binding", icon: Cloud, feature: "hsm_hardware_or_software" },
    { id: "hsm-azure", label: "Azure Managed HSM", hint: "Managed HSM endpoint mapping and PKCS#11 bridge profile", icon: Cloud, feature: "hsm_hardware_or_software" },
    { id: "hsm-thales", label: "Thales Luna HSM", hint: "NTLS endpoint, Luna slot and partition settings", icon: Cpu, feature: "hsm_hardware_or_software" },
    { id: "hsm-utimaco", label: "Utimaco HSM", hint: "CryptoServer slot/partition profile and provider settings", icon: Cpu, feature: "hsm_hardware_or_software" },
    { id: "hsm-entrust", label: "Entrust nShield HSM", hint: "Security World connector, slot profile and token mapping", icon: ShieldCheck, feature: "hsm_hardware_or_software" },
    { id: "hsm-securosys", label: "Securosys Primus HSM", hint: "Primus PKCS#11 library, partition user and token label", icon: ShieldCheck, feature: "hsm_hardware_or_software" },
    { id: "hsm-generic", label: "Generic PKCS#11 HSM", hint: "Vendor-neutral PKCS#11 library onboarding profile", icon: Plug, feature: "hsm_hardware_or_software" }
  ],
  cluster: [
    { id: "topology", label: "Topology", hint: "Visual cluster map with node connections and health", icon: GitBranch, feature: "clustering" },
    { id: "nodes", label: "Node Management", hint: "Detailed node metrics and components", icon: Server, feature: "clustering" },
    { id: "failover", label: "Failover", hint: "This node's role, the voters, and promotion", icon: ShieldCheck, feature: "clustering" },
    { id: "profiles", label: "Deploy Profiles", hint: "Replication profiles with deployment tier presets", icon: Layers, feature: "clustering" },
    { id: "sync", label: "Sync Monitor", hint: "Real-time sync events, checkpoints, and replication lag", icon: RefreshCw, feature: "clustering" }
  ],
  playbooks: [
    { id: "overview", label: "Overview", hint: "Counts, runs awaiting approval and recent activity", icon: Activity },
    { id: "playbooks", label: "Playbooks", hint: "Triggers, actions and who authorised them", icon: ListChecks },
    { id: "runs", label: "Runs", hint: "Every run and its steps", icon: Zap },
    { id: "incidents", label: "Incidents", hint: "Alert Center incidents and the runs that responded", icon: AlertTriangle },
    { id: "connections", label: "Credentials", hint: "The one store for every external credential", icon: Link },
    { id: "streams", label: "Event streaming", hint: "Audit events to a SIEM or webhook", icon: Radio }
  ],
  // Approval policies have one home, Approvals (owner, 2026-10-20).
  approvals: [
    { id: "requests", label: "Requests", hint: "Approval requests and votes", icon: Stamp },
    { id: "policies", label: "Policies", hint: "Quorum policies that hold an operation for approval", icon: ListChecks },
    { id: "settings", label: "Settings", hint: "Approval delivery and expiry", icon: Settings }
  ],
  // Backups have one home, Backup & Restore (owner, 2026-10-20).
  backup: [
    { id: "encrypted", label: "Encrypted Backups", hint: "Create, verify, restore and download encrypted backups", icon: DatabaseBackup, platformOnly: true },
    { id: "schedules", label: "Schedules", hint: "Encrypted backups on a schedule, with retention", icon: RefreshCw, platformOnly: true }
  ],
  home: [
    { id: "overview", label: "Overview", hint: "Posture score, KPIs, top recommended actions and control coverage", icon: Activity },
    { id: "recommendations", label: "Recommendations", hint: "Every open recommendation, filterable", icon: ListChecks }
  ],
  // System Administration's sections are sub-options (13.23.0-beta): they
  // were a twelve-tab strip inside the page.
  admin: [
    { id: "health", label: "Health", hint: "Service health, heartbeats and reconcilers", icon: Activity, platformOnly: true },
    { id: "runtime", label: "Runtime Crypto", hint: "FIPS mode and runtime hardening", icon: Shield, platformOnly: true },
    { id: "snmp", label: "SNMP", hint: "SNMP trap targets", icon: Radio, platformOnly: true },
    { id: "tags", label: "Tags", hint: "Tag catalogue for keys and objects", icon: List, platformOnly: true },
    { id: "password", label: "Password Policy", hint: "Password rules for the platform tenant", icon: Lock, platformOnly: true },
    { id: "login", label: "Login Security", hint: "Lockout and session rules", icon: ShieldCheck, platformOnly: true },
    { id: "keyaccess", label: "Key Access Hardening", hint: "Default grants, replay window, interface binding", icon: KeyRound, platformOnly: true },
    { id: "cli", label: "CLI / HSM", hint: "CLI/SSH access and HSM connector", icon: Cpu, platformOnly: true },
    { id: "governance", label: "Governance", hint: "Approval notifications and delivery", icon: Stamp, platformOnly: true },
    { id: "alertrules", label: "Alert Rules", hint: "Rules that raise alerts from audit events", icon: AlertTriangle, platformOnly: true },
    { id: "tenant", label: "Tenant Administration", hint: "Tenants, their policies, backups and lifecycle", icon: Building2, platformOnly: true },
    { id: "users", label: "User Management", hint: "User and group administration with role assignments", icon: Users }
  ]
};

// The sub-options of one module, indented under its sidebar entry.
export function SidebarSubNav({ tabId, items, activeId, onSelect }: {
  tabId: string;
  items: SubPane[];
  activeId: string;
  onSelect: (id: string) => void;
}) {
  return (
    <div data-testid={`subnav-${tabId}`} style={{ margin: "1px 8px 4px 25px", paddingLeft: 7, borderLeft: `1px solid ${C.border}` }}>
      {items.map((item) => {
        const isActive = item.id === activeId;
        return (
          <button
            key={item.id}
            type="button"
            className="vk-nav-item"
            title={item.hint}
            aria-current={isActive ? "page" : undefined}
            onClick={() => onSelect(item.id)}
            style={{
              display: "flex", alignItems: "center", gap: 8, width: "100%",
              padding: "5px 8px", margin: "1px 0", border: 0, borderRadius: 3,
              background: isActive ? C.accentDim : "transparent",
              cursor: "pointer", textAlign: "left", font: "inherit",
            }}
          >
            <span className="vk-nav-icon" style={{ display: "inline-flex", color: isActive ? C.accentFg : C.muted, flexShrink: 0 }}>
              <item.icon size={13} strokeWidth={isActive ? 2.2 : 1.8} />
            </span>
            <span
              className="vk-nav-label"
              style={{
                fontSize: 12.5, color: isActive ? C.text : C.dim, fontWeight: isActive ? 600 : 450,
                whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis",
              }}
            >
              {item.label}
            </span>
          </button>
        );
      })}
    </div>
  );
}
