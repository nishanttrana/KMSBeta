import {
  Building2,
  Cloud,
  Cpu,
  Database,
  FileText,
  GitBranch,
  KeyRound,
  Layers,
  Link,
  List,
  Lock,
  Plug,
  RefreshCw,
  Server,
  Settings,
  Shield,
  ShieldCheck,
  Users,
  VenetianMask,
  Zap,
  type LucideIcon,
} from "lucide-react";
import { C } from "./theme";

export type SubPane = { id: string; label: string; hint: string; icon: LucideIcon; feature?: string };

// A module's views. They are listed in the sidebar under the module's name,
// never in a second column or a tab strip of the shell (owner directive,
// 2026-10-11; CLAUDE.md "Sub-options live in the sidebar").
export const SUB_PANES: Record<string, SubPane[]> = {
  workbench: [
    { id: "crypto", label: "Crypto Console", hint: "Interactive cryptographic operations and algorithm console", icon: Zap },
    { id: "restapi", label: "REST API", hint: "Authenticated API explorer and endpoint documentation", icon: FileText },
    { id: "tokenize", label: "Tokenize / Mask / Redact", hint: "Vault and vaultless tokenization with masking/redaction", icon: VenetianMask, feature: "data_protection" },
    { id: "dataenc", label: "Data Encryption", hint: "Field-level, envelope, searchable and FPE crypto", icon: Database, feature: "data_protection" },
    { id: "hyok-test", label: "HYOK Live Test", hint: "Interactive HYOK crypto test console for all protocols", icon: Zap }
  ],
  dataprotection: [
    { id: "fieldenc", label: "Field Encryption", hint: "Wrapper registration, challenge-response and local crypto lease control", icon: KeyRound, feature: "data_protection" },
    { id: "dataenc-policy", label: "Data Encryption Policy", hint: "Policy controls only for data encryption interfaces", icon: List, feature: "data_protection" },
    { id: "token-policy", label: "Token / Mask / Redact Policy", hint: "Policy controls only for tokenization, masking and redaction", icon: VenetianMask, feature: "data_protection" },
    { id: "pkcs11", label: "Java SDK", hint: "Java JCA provider download", icon: Plug }
  ],
  cloudctl: [
    { id: "byok", label: "BYOK", hint: "Cloud provider key import and sync", icon: Cloud, feature: "cloud_byok" },
    { id: "hyok", label: "HYOK", hint: "Hold-your-own-key policy and cryptographic controls", icon: ShieldCheck, feature: "hyok_proxy" },
    { id: "google-cse", label: "Google CSE", hint: "Workspace Client-Side Encryption", icon: Shield, feature: "ekm_database" },
    { id: "azure", label: "Azure EKM", hint: "Key Vault & Managed HSM integration", icon: Cloud, feature: "ekm_database" }
  ],
  ekm: [
    { id: "db", label: "EKM for DBs", hint: "MSSQL / Oracle TDE agents", icon: Database, feature: "ekm_database" },
    { id: "bitlocker", label: "BitLocker", hint: "Windows endpoint key lifecycle", icon: Lock, feature: "ekm_database" },
    { id: "kmip", label: "KMIP", hint: "Profiles, clients, mTLS onboarding", icon: Link, feature: "kmip_server" }
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
    { id: "nodes", label: "Node Management", hint: "Detailed node metrics, role changes, and components", icon: Server, feature: "clustering" },
    { id: "profiles", label: "Deploy Profiles", hint: "Replication profiles with deployment tier presets", icon: Layers, feature: "clustering" },
    { id: "sync", label: "Sync Monitor", hint: "Real-time sync events, checkpoints, and replication lag", icon: RefreshCw, feature: "clustering" }
  ],
  admin: [
    { id: "system", label: "System Administration", hint: "Platform health, runtime hardening, FIPS and governance settings", icon: Settings },
    { id: "tenant", label: "Tenant Administration", hint: "Tenant lifecycle disable/delete workflow", icon: Building2 },
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
              padding: "5px 8px", margin: "1px 0", border: 0, borderRadius: 6,
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
