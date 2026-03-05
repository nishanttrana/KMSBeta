// @ts-nocheck
import { useEffect, useMemo, useState } from "react";
import { ArrowDownToLine, Atom, Check, Cog, ExternalLink, MoreVertical, PenTool, Plus, RefreshCcw, X } from "lucide-react";
import {
  activateKey,
  createKey,
  deactivateKey,
  destroyKey,
  disableKey,
  exportKey,
  formKey,
  importKey,
  listKeyAccessGroups,
  listKeys,
  listKeyVersions,
  listTags,
  rotateKey,
  getKeyAccessPolicy,
  setKeyAccessPolicy,
  setKeyExportPolicy,
  setKeyUsageLimit,
  updateKeyActivation,
  upsertTag
} from "../../../lib/keycore";
import { listAuthUsers } from "../../../lib/authAdmin";
import { DEFAULT_KEY_COLUMN_VISIBILITY, KEY_ACCESS_OPERATION_OPTIONS, KEY_TABLE_COLUMNS } from "../constants";
import { errMsg } from "../runtimeUtils";
import { C } from "../theme";
import { B, Btn, Card, Chk, FG, Inp, Modal, Radio, Row2, Row3, Section, Sel, Stat, Txt } from "../legacyPrimitives";

function normalizeKeyState(state: string): string {
  const raw = String(state || "").toLowerCase().trim();
  if (raw === "destroyed" || raw === "deleted") {
    return "deleted";
  }
  if (raw === "destroy-pending" || raw === "delete-pending" || raw === "deletion-pending") {
    return "destroy-pending";
  }
  if (raw === "preactive" || raw === "pre-active") {
    return "pre-active";
  }
  if (raw === "retired" || raw === "deactivated") {
    return "deactivated";
  }
  if (raw === "generation" || raw === "generated") {
    return "pre-active";
  }
  return raw || "unknown";
}

function keyStateLabel(state: string): string {
  const norm = normalizeKeyState(state);
  switch (norm) {
    case "pre-active":
      return "Pre-active";
    case "active":
      return "Active";
    case "disabled":
      return "Disabled";
    case "deactivated":
      return "Deactivated (Retired)";
    case "destroy-pending":
      return "Delete Pending";
    case "deleted":
      return "Deleted";
    default:
      return norm
        .split("-")
        .map((part) => (part ? part[0].toUpperCase() + part.slice(1) : part))
        .join(" ");
  }
}

function keyStateTone(state: string): "green" | "amber" | "red" | "blue" | "muted" {
  const norm = normalizeKeyState(state);
  if (norm === "active") {
    return "green";
  }
  if (norm === "pre-active" || norm === "deactivated") {
    return "amber";
  }
  if (norm === "deleted") {
    return "muted";
  }
  if (norm === "destroy-pending" || norm === "disabled") {
    return "red";
  }
  return "blue";
}

function algorithmFamilyLabel(algorithm: string): string {
  const v = String(algorithm || "").toUpperCase();
  if (!v) {
    return "Other";
  }
  if (v.includes("AES")) {
    return "AES";
  }
  if (v.includes("RSA")) {
    return "RSA";
  }
  if (
    v.includes("ECDSA") ||
    v.includes("ECDH") ||
    v.includes("ECIES") ||
    v.includes("BRAINPOOL") ||
    v.includes("ED25519") ||
    v.includes("ED448") ||
    v.includes("X25519") ||
    v.includes("X448")
  ) {
    return "ECC";
  }
  if (
    v.includes("ML-KEM") ||
    v.includes("ML-DSA") ||
    v.includes("SLH-DSA") ||
    v.includes("HSS-LMS") ||
    v.includes("XMSS")
  ) {
    return "ML";
  }
  if (v.includes("HMAC")) {
    return "HMAC";
  }
  if (v.includes("CMAC") || v.includes("GMAC") || v.includes("POLY1305")) {
    return "MAC";
  }
  if (v.includes("DSA")) {
    return "DSA";
  }
  if (v.includes("3DES") || v.includes("DES")) {
    return "3DES";
  }
  if (v.includes("CHACHA20")) {
    return "ChaCha20";
  }
  if (v.includes("CAMELLIA")) {
    return "Camellia";
  }
  return "Other";
}

function keyInventoryAlgorithmDisplay(algorithm: string): { family: string; sizeCurve: string } {
  const raw = String(algorithm || "").trim();
  const upper = raw.toUpperCase();
  const family = algorithmFamilyLabel(raw);
  let sizeCurve = "-";

  if (family === "AES") {
    const match = upper.match(/AES[-_ ]?(\d{3})/);
    if (match?.[1]) {
      sizeCurve = match[1];
    }
  } else if (family === "RSA") {
    const match = upper.match(/RSA[-_ ]?(?:OAEP[-_ ]?)?(\d{3,4})/) || upper.match(/RSA[-_ ]?(\d{3,4})/);
    if (match?.[1]) {
      sizeCurve = match[1];
    }
  } else if (family === "ECC") {
    const fixed = ["ED25519", "ED448", "X25519", "X448"].find((name) => upper.includes(name));
    if (fixed) {
      sizeCurve = fixed;
    } else {
      const namedCurve =
        upper.match(/(P-?256|P-?384|P-?521)/)?.[1] ||
        upper.match(/(BRAINPOOL-?P?256R1|BRAINPOOL-?P?384R1)/)?.[1] ||
        upper.match(/(SECP256R1|SECP384R1|SECP521R1)/)?.[1];
      if (namedCurve) {
        sizeCurve = namedCurve
          .replace(/^P(?=\d)/, "P-")
          .replace(/^BRAINPOOLP/i, "BRAINPOOL-P");
      } else {
        const ecdsa = upper.match(/ECD(?:SA|H)?[-_ ]?P[-_ ]?(\d{3})/)?.[1];
        if (ecdsa) {
          sizeCurve = `P-${ecdsa}`;
        }
      }
    }
  } else if (family === "ML") {
    const match =
      upper.match(/(ML-KEM-\d+)/)?.[1] ||
      upper.match(/(ML-DSA-\d+)/)?.[1] ||
      upper.match(/(SLH-DSA-[0-9A-Z]+)/)?.[1] ||
      upper.match(/(HSS\/LMS)/)?.[1] ||
      upper.match(/(XMSS)/)?.[1];
    if (match) {
      sizeCurve = match;
    }
  } else if (family === "HMAC") {
    const match = upper.match(/(SHA3?-?\d{3})/)?.[1];
    if (match) {
      sizeCurve = match.replace(/^SHA(?=\d)/, "SHA-");
    }
  } else if (family === "DSA") {
    const match = upper.match(/DSA[-_ ]?(\d{3,4})/)?.[1];
    if (match) {
      sizeCurve = match;
    }
  }

  return { family, sizeCurve };
}

function toViewKey(k: any) {
  const ver = Number(k.current_version || 0);
  const labels = (k && typeof k.labels === "object" && k.labels) ? k.labels : {};
  const componentRole = String(labels.component_role || labels.component || "").toLowerCase();
  const algoDisplay = keyInventoryAlgorithmDisplay(String(k.algorithm || "unknown"));
  return {
    id: String(k.id || ""),
    name: String(k.name || "unnamed-key"),
    algo: String(k.algorithm || "unknown"),
    algoFamily: algoDisplay.family,
    algoSizeCurve: algoDisplay.sizeCurve,
    keyType: String(k.key_type || ""),
    state: normalizeKeyState(String(k.status || "unknown")),
    ver: ver > 0 ? `v${ver}` : "v1",
    kcv: String(k.kcv || ""),
    ops: String(k.ops_total || 0),
    created: String(k.created_at || "-"),
    rotated: String(k.updated_at || "-"),
    expires: String(k.expires_at || k.destroy_date || "Never"),
    destroyAt: String(k.destroy_date || ""),
    activationAt: String(k.activation_date || ""),
    tags: Array.isArray(k.tags) ? k.tags.map((t) => String(t)) : [],
    exportAllowed: Boolean(k.export_allowed),
    tenant: String(k.tenant_id || ""),
    purpose: String(k.purpose || "encrypt-decrypt"),
    labels,
    pairId: String(labels.pair_id || ""),
    componentRole: componentRole === "public" ? "public" : componentRole === "private" ? "private" : "",
    ivMode: String(k.iv_mode || "-"),
    opsLimit: k.ops_limit ? String(k.ops_limit) : "inf",
    opsWindow: String(k.ops_limit_window || "total"),
    approvalReq: Boolean(k.approval_required)
  };
}

function isFipsAlgorithm(algorithm: string): boolean {
  const v = String(algorithm || "").toUpperCase();
  if (!v) {
    return false;
  }
  if (
    v.includes("CHACHA20") ||
    v.includes("CAMELLIA") ||
    v.includes("ECIES") ||
    v.includes("BRAINPOOL") ||
    v.includes("KECCAK") ||
    v.includes("RIPEMD") ||
    v.includes("BLAKE") ||
    v.includes("POLY1305") ||
    (v.includes("AES") && v.includes("ECB"))
  ) {
    return false;
  }
  return (
    v.includes("AES") ||
    v.includes("RSA") ||
    v.includes("ECDSA") ||
    v.includes("ECDH") ||
    v.includes("HMAC") ||
    v.includes("CMAC") ||
    v.includes("GMAC") ||
    v.includes("ML-KEM") ||
    v.includes("ML-DSA") ||
    v.includes("SLH-DSA")
  );
}

function isAsymmetricKeyLike(key: any): boolean {
  const keyType = String(key?.keyType || "").toLowerCase();
  if (keyType.includes("asymmetric") || keyType.includes("public") || keyType.includes("private")) {
    return true;
  }
  const algo = String(key?.algo || "").toUpperCase();
  return (
    algo.includes("RSA") ||
    algo.includes("ECDSA") ||
    algo.includes("ED25519") ||
    algo.includes("ED448") ||
    algo.includes("X25519") ||
    algo.includes("X448") ||
    algo.includes("ECDH")
  );
}

function isPublicComponentLike(key: any): boolean {
  const role = String(key?.componentRole || "").toLowerCase();
  if (role === "public") {
    return true;
  }
  const keyType = String(key?.keyType || "").toLowerCase();
  return keyType.includes("public");
}

function composeCreateAlgorithm(
  algoType: string,
  family: string,
  keySpec: string,
  cipherMode: string
): string {
  const type = String(algoType || "").toLowerCase();
  const fam = String(family || "").toUpperCase();
  const spec = String(keySpec || "").trim();
  const mode = String(cipherMode || "GCM").toUpperCase();
  if (type === "symmetric") {
    if (fam === "AES") {
      return `AES-${spec || "256"}-${mode}`;
    }
    if (fam === "CHACHA20") {
      return "ChaCha20-Poly1305";
    }
    if (fam === "CAMELLIA") {
      return `Camellia-${spec || "256"}-${mode}`;
    }
    if (fam === "3DES") {
      return "3DES-CBC";
    }
    return `AES-${spec || "256"}-${mode}`;
  }
  if (type === "asymmetric") {
    if (fam === "RSA") {
      return `RSA-${spec || "2048"}`;
    }
    if (fam === "ECC") {
      if (spec === "Brainpool-P256r1" || spec === "Brainpool-P384r1") {
        return spec;
      }
      if (spec === "P-384") {
        return "ECDSA-P384";
      }
      if (spec === "P-521") {
        return "ECDSA-P521";
      }
      return "ECDSA-P256";
    }
    if (fam === "EDDSA") {
      return spec === "Ed448" ? "Ed448" : "Ed25519";
    }
    if (fam === "ECDH") {
      if (spec === "X25519" || spec === "X448") {
        return spec;
      }
      if (spec === "P-384") {
        return "ECDH-P384";
      }
      return "ECDH-P256";
    }
    if (fam === "DSA") {
      return "DSA-3072";
    }
    return `RSA-${spec || "2048"}`;
  }
  if (type === "pqc") {
    if (fam === "ML-KEM") {
      return `ML-KEM-${spec || "768"}`;
    }
    if (fam === "ML-DSA") {
      return `ML-DSA-${spec || "65"}`;
    }
    if (fam === "SLH-DSA") {
      return `SLH-DSA-${spec || "128s"}`;
    }
    if (fam === "HSS/LMS") {
      return `HSS-LMS-${spec || "SHA256-H10"}`;
    }
    if (fam === "XMSS") {
      return `XMSS-${spec || "SHA256-H10"}`;
    }
    if (fam === "HYBRID") {
      return spec || "ECDSA-P384 + ML-DSA-65";
    }
    return `ML-KEM-${spec || "768"}`;
  }
  if (fam === "CMAC") {
    return "CMAC-AES-256";
  }
  return `HMAC-${spec || "SHA256"}`;
}

function publicPurposeFromPrivate(purpose: string): string {
  const p = String(purpose || "").trim().toLowerCase();
  if (p === "sign-verify") {
    return "verify";
  }
  if (p === "encrypt-decrypt") {
    return "encrypt";
  }
  if (p === "key-agreement") {
    return "key-agreement";
  }
  return p || "verify";
}

function formatOpsValue(value: number): string {
  const n = Number(value || 0);
  if (n >= 1_000_000_000) {
    return `${(n / 1_000_000_000).toFixed(1).replace(/\.0$/, "")}B`;
  }
  if (n >= 1_000_000) {
    return `${(n / 1_000_000).toFixed(1).replace(/\.0$/, "")}M`;
  }
  if (n >= 1_000) {
    return `${(n / 1_000).toFixed(1).replace(/\.0$/, "")}K`;
  }
  return String(n);
}

function formatDestroyAt(value: string): string {
  const raw = String(value || "").trim();
  if (!raw) {
    return "-";
  }
  const dt = new Date(raw);
  if (Number.isNaN(dt.getTime())) {
    return raw;
  }
  return dt.toLocaleString();
}

function tagColorByName(tagCatalog: any[], name: string): string {
  const match=(Array.isArray(tagCatalog)?tagCatalog:[]).find((t)=>String(t?.name||"")===String(name||""));
  return String(match?.color||C.blue);
}

function toISODateTime(localValue: string): string | undefined {
  const raw = String(localValue || "").trim();
  if (!raw) {
    return undefined;
  }
  const dt = new Date(raw);
  if (Number.isNaN(dt.getTime())) {
    return undefined;
  }
  return dt.toISOString();
}

function toLocalDateTime(isoValue: string): string {
  const raw = String(isoValue || "").trim();
  if (!raw) {
    return "";
  }
  const dt = new Date(raw);
  if (Number.isNaN(dt.getTime())) {
    return "";
  }
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${dt.getFullYear()}-${pad(dt.getMonth() + 1)}-${pad(dt.getDate())}T${pad(dt.getHours())}:${pad(dt.getMinutes())}`;
}

function renderKeyOptions(keyChoices: any[]): any[] {
  if (!keyChoices.length) {
    return [<option key="no-customer-keys" value="">No customer keys available</option>];
  }
  return keyChoices.map((k) => (
    <option key={k.id} value={k.id}>
      {k.name} {k.algo ? `(${k.algo})` : ""}
    </option>
  ));
}

export const KeysTab=({session,keyCatalog,setKeyCatalog,tagCatalog,setTagCatalog,onToast})=>{

  const [modal,setModal]=useState(null);
  const [selectedKey,setSelectedKey]=useState(null);
  const [algoType,setAlgoType]=useState("symmetric");
  const [algo,setAlgo]=useState("AES-256-GCM");
  const [createAlgorithmFamily,setCreateAlgorithmFamily]=useState("AES");
  const [createKeySpec,setCreateKeySpec]=useState("256");
  const [purpose,setPurpose]=useState("encrypt-decrypt");
  const [opsLimitInput,setOpsLimitInput]=useState("");
  const [opsLimitWindow,setOpsLimitWindow]=useState("total");
  const [createActivationMode,setCreateActivationMode]=useState("immediate");
  const [createActivationDateTime,setCreateActivationDateTime]=useState("");
  const [createTags,setCreateTags]=useState<string[]>([]);
  const [showCreateTagPicker,setShowCreateTagPicker]=useState(false);
  const [approvalReq,setApprovalReq]=useState(false);
  const [rotationEnabled,setRotationEnabled]=useState(true);
  const [exportable,setExportable]=useState(false);
  const [createName,setCreateName]=useState("");
  const [creating,setCreating]=useState(false);
  const [rotating,setRotating]=useState(false);
  const [rotateType,setRotateType]=useState("standard");
  const [rotateOldVersionAction,setRotateOldVersionAction]=useState("deactivate");
  const [exporting,setExporting]=useState(false);
  const [exportWrappingKeyId,setExportWrappingKeyId]=useState("");
  const [exportMode,setExportMode]=useState("wrapped");
  const [keyVersions,setKeyVersions]=useState([]);
  const [statusUpdatingId,setStatusUpdatingId]=useState("");
  const [openActionMenuId,setOpenActionMenuId]=useState("");
  const [destroying,setDestroying]=useState(false);
  const [destroyConfirmName,setDestroyConfirmName]=useState("");
  const [destroyMode,setDestroyMode]=useState("scheduled");
  const [destroyAfterDays,setDestroyAfterDays]=useState(30);
  const [destroyJustification,setDestroyJustification]=useState("");
  const [destroyCheckWorkloads,setDestroyCheckWorkloads]=useState(false);
  const [destroyCheckBackup,setDestroyCheckBackup]=useState(false);
  const [destroyCheckIrreversible,setDestroyCheckIrreversible]=useState(false);
  const [policySaving,setPolicySaving]=useState(false);
  const [policyOpsLimitInput,setPolicyOpsLimitInput]=useState("");
  const [policyOpsWindow,setPolicyOpsWindow]=useState("total");
  const [policyActivationMode,setPolicyActivationMode]=useState("immediate");
  const [policyActivationDateTime,setPolicyActivationDateTime]=useState("");
  const [policyExportAllowed,setPolicyExportAllowed]=useState(false);
  const [policyLoading,setPolicyLoading]=useState(false);
  const [policyUsers,setPolicyUsers]=useState([]);
  const [policyGroups,setPolicyGroups]=useState([]);
  const [policyGrants,setPolicyGrants]=useState([]);
  const [policyNewSubjectType,setPolicyNewSubjectType]=useState("user");
  const [policyNewSubjectId,setPolicyNewSubjectId]=useState("");
  const [policyNewOperations,setPolicyNewOperations]=useState<string[]>(["encrypt"]);
  const [policyNewNotBefore,setPolicyNewNotBefore]=useState("");
  const [policyNewExpiresAt,setPolicyNewExpiresAt]=useState("");
  const [policyNewJustification,setPolicyNewJustification]=useState("");
  const [policyNewTicketId,setPolicyNewTicketId]=useState("");
  const [policyCreateGroupName,setPolicyCreateGroupName]=useState("");
  const [policyCreateGroupDescription,setPolicyCreateGroupDescription]=useState("");
  const [policyCreateGroupMembers,setPolicyCreateGroupMembers]=useState<string[]>([]);
  const [formName,setFormName]=useState("");
  const [formAlgorithm,setFormAlgorithm]=useState("AES-256-GCM");
  const [formPurpose,setFormPurpose]=useState("encrypt-decrypt");
  const [formComponentMode,setFormComponentMode]=useState("clear-generated");
  const [formParity,setFormParity]=useState("none");
  const [formComponentCount,setFormComponentCount]=useState(2);
  const [formActivationMode,setFormActivationMode]=useState("immediate");
  const [formActivationDateTime,setFormActivationDateTime]=useState("");
  const [formOpsLimitInput,setFormOpsLimitInput]=useState("");
  const [formOpsWindow,setFormOpsWindow]=useState("total");
  const [formExportable,setFormExportable]=useState(false);
  const [formApprovalReq,setFormApprovalReq]=useState(false);
  const [formTags,setFormTags]=useState<string[]>([]);
  const [formComponents,setFormComponents]=useState([
    {material:"",wrapped_material:"",material_iv:"",wrapping_key_id:""},
    {material:"",wrapped_material:"",material_iv:"",wrapping_key_id:""}
  ]);
  const [forming,setForming]=useState(false);
  const [importMethod,setImportMethod]=useState("raw");
  const [importName,setImportName]=useState("");
  const [importMaterial,setImportMaterial]=useState("");
  const [importAlgorithm,setImportAlgorithm]=useState("auto");
  const [importWrappingKeyId,setImportWrappingKeyId]=useState("");
  const [importMaterialIV,setImportMaterialIV]=useState("");
  const [importPurpose,setImportPurpose]=useState("encrypt-decrypt");
  const [importOrigin,setImportOrigin]=useState("external");
  const [importPassword,setImportPassword]=useState("");
  const [importExpectedKcv,setImportExpectedKcv]=useState("");
  const [importing,setImporting]=useState(false);
  const [search,setSearch]=useState("");
  const [statusFilter,setStatusFilter]=useState("all");
  const [algoFilter,setAlgoFilter]=useState("all");
  const [tagFilter,setTagFilter]=useState("all");
  const [pageSize,setPageSize]=useState(10);
  const [pageIndex,setPageIndex]=useState(0);
  const [refreshingKeys,setRefreshingKeys]=useState(false);
  const [showColumnMenu,setShowColumnMenu]=useState(false);
  const [columnMenuPos,setColumnMenuPos]=useState({top:0,left:0});
  const [actionMenuPos,setActionMenuPos]=useState({top:0,left:0});
  const [columnVisibility,setColumnVisibility]=useState(()=>{
    try{
      const raw=localStorage.getItem("vecta_key_table_columns");
      if(!raw){
        return {...DEFAULT_KEY_COLUMN_VISIBILITY};
      }
      const parsed=JSON.parse(raw);
      const next={...DEFAULT_KEY_COLUMN_VISIBILITY};
      Object.keys(next).forEach((col)=>{
        if(typeof parsed?.[col]==="boolean"){
          next[col]=Boolean(parsed[col]);
        }
      });
      return next;
    }catch{
      return {...DEFAULT_KEY_COLUMN_VISIBILITY};
    }
  });
  const keys=Array.isArray(keyCatalog)?keyCatalog:[];
  const [pqcAlgorithm,setPqcAlgorithm]=useState("ML-KEM-768");
  const [pqcHybridMode,setPqcHybridMode]=useState("pure");
  const [pqcName,setPqcName]=useState("");
  const [pqcPurpose,setPqcPurpose]=useState("key-agreement");
  const [pqcGenerating,setPqcGenerating]=useState(false);

  const resetDestroyForm=()=>{
    setDestroyConfirmName("");
    setDestroyMode("scheduled");
    setDestroyAfterDays(30);
    setDestroyJustification("");
    setDestroyCheckWorkloads(false);
    setDestroyCheckBackup(false);
    setDestroyCheckIrreversible(false);
  };

  const resetImportForm=()=>{
    setImportMethod("raw");
    setImportName("");
    setImportMaterial("");
    setImportAlgorithm("auto");
    setImportWrappingKeyId("");
    setImportMaterialIV("");
    setImportPurpose("encrypt-decrypt");
    setImportOrigin("external");
    setImportPassword("");
    setImportExpectedKcv("");
  };

  const algorithms=useMemo(()=>{
    const set=new Set<string>(["AES","RSA","ECC","ML","HMAC","MAC"]);
    keys.forEach((k)=>{
      if(k?.algo){
        set.add(algorithmFamilyLabel(String(k.algo)));
      }
    });
    return Array.from(set).sort((a,b)=>a.localeCompare(b));
  },[keys]);

  const createAlgorithmFamilies=useMemo(()=>{
    if(algoType==="symmetric"){
      return ["AES","ChaCha20","Camellia","3DES"];
    }
    if(algoType==="asymmetric"){
      return ["RSA","ECC","EdDSA","ECDH","DSA"];
    }
    if(algoType==="pqc"){
      return ["ML-KEM","ML-DSA","SLH-DSA","HSS/LMS","XMSS","Hybrid"];
    }
    return ["HMAC","CMAC"];
  },[algoType]);

  const createKeySpecOptions=useMemo(()=>{
    const fam=String(createAlgorithmFamily||"");
    if(algoType==="symmetric"){
      if(fam==="AES"){
        return ["128","192","256"];
      }
      if(fam==="ChaCha20"){
        return ["256"];
      }
      if(fam==="Camellia"){
        return ["256"];
      }
      return ["168"];
    }
    if(algoType==="asymmetric"){
      if(fam==="RSA"){
        return ["2048","3072","4096","8192"];
      }
      if(fam==="ECC"){
        return ["P-256","P-384","P-521","Brainpool-P256r1","Brainpool-P384r1"];
      }
      if(fam==="EdDSA"){
        return ["Ed25519","Ed448"];
      }
      if(fam==="ECDH"){
        return ["X25519","X448","P-256","P-384"];
      }
      return ["3072"];
    }
    if(algoType==="pqc"){
      if(fam==="ML-KEM"){
        return ["768","1024"];
      }
      if(fam==="ML-DSA"){
        return ["44","65","87"];
      }
      if(fam==="SLH-DSA"){
        return ["128s","128f","192s","192f","256s","256f"];
      }
      if(fam==="HSS/LMS"){
        return ["SHA256-H10","SHA256-H15","SHA256-H20"];
      }
      if(fam==="XMSS"){
        return ["SHA256-H10","SHA256-H16","SHA256-H20"];
      }
      return ["ECDSA-P384 + ML-DSA-65","RSA-3072 + ML-DSA-65","Ed25519 + ML-DSA-44","X25519 + ML-KEM-768"];
    }
    if(fam==="CMAC"){
      return ["AES-256"];
    }
    return ["SHA256","SHA384","SHA512","SHA3-256"];
  },[algoType,createAlgorithmFamily]);

  const resolvedCreateCipherMode=useMemo(()=>{
    if(algoType!=="symmetric"){
      return "GCM";
    }
    if(createAlgorithmFamily==="ChaCha20"){
      return "Poly1305";
    }
    if(createAlgorithmFamily==="3DES"){
      return "CBC";
    }
    return "GCM";
  },[algoType,createAlgorithmFamily]);

  const availableTags=useMemo(()=>{
    const seen=new Set<string>();
    const out:string[]=[];
    const pushTag=(raw:any)=>{
      const tag=String(raw||"").trim();
      if(!tag){
        return;
      }
      const key=tag.toLowerCase();
      if(seen.has(key)){
        return;
      }
      seen.add(key);
      out.push(tag);
    };
    if(Array.isArray(tagCatalog)&&tagCatalog.length){
      tagCatalog.forEach((t)=>pushTag(t?.name));
      return out.sort((a,b)=>a.localeCompare(b));
    }
    keys.forEach((k)=>{
      if(Array.isArray(k?.tags)){
        k.tags.forEach((tag)=>pushTag(tag));
      }
    });
    return out.sort((a,b)=>a.localeCompare(b));
  },[tagCatalog,keys]);

  const wrappingKeyChoices=useMemo(()=>{
    return keys.filter((k)=>{
      if(!k?.id||k.id===selectedKey?.id){
        return false;
      }
      if(normalizeKeyState(String(k.state||""))!=="active"){
        return false;
      }
      return String(k.purpose||"").toLowerCase().includes("wrap");
    });
  },[keys,selectedKey?.id]);

  const selectedAsymmetricComponents=useMemo(()=>{
    if(!selectedKey?.pairId){
      return [];
    }
    return keys
      .filter((item)=>String(item?.pairId||"")===String(selectedKey.pairId))
      .sort((a,b)=>{
        const ar=a.componentRole==="private"?0:a.componentRole==="public"?1:2;
        const br=b.componentRole==="private"?0:b.componentRole==="public"?1:2;
        if(ar!==br){
          return ar-br;
        }
        return String(a.id).localeCompare(String(b.id));
      });
  },[keys,selectedKey?.pairId]);

  const placeMenuFromButton=(button:HTMLElement, menuWidth:number, menuHeight:number)=>{
    const rect=button.getBoundingClientRect();
    const left=Math.max(8,Math.min(window.innerWidth-menuWidth-8,rect.right-menuWidth));
    let top=rect.bottom+6;
    if(top+menuHeight>window.innerHeight-8){
      top=Math.max(8,rect.top-menuHeight-6);
    }
    return {top,left};
  };

  const filteredKeys=useMemo(()=>{
    const q=search.trim().toLowerCase();
    return keys.filter((k)=>{
      const status=String(k?.state||"").toLowerCase();
      const algoName=String(k?.algo||"");
      const passStatus=statusFilter==="all"||status===statusFilter;
      const passAlgo=algoFilter==="all"||algorithmFamilyLabel(algoName)===algoFilter;
      const keyTags=Array.isArray(k?.tags)?k.tags.map((t)=>String(t).trim()).filter(Boolean):[];
      const keyTagsLower=keyTags.map((t)=>t.toLowerCase());
      const passTag=tagFilter==="all"||keyTagsLower.includes(String(tagFilter||"").toLowerCase());
      const passSearch=!q||[
        k?.name,
        k?.id,
        k?.algo,
        k?.kcv,
        k?.ver,
        k?.purpose,
        keyTags.join(" ")
      ].some((v)=>String(v||"").toLowerCase().includes(q));
      return passStatus&&passAlgo&&passTag&&passSearch;
    });
  },[keys,search,statusFilter,algoFilter,tagFilter]);

  const totalPages=useMemo(()=>{
    return Math.max(1,Math.ceil(filteredKeys.length/Math.max(1,pageSize)));
  },[filteredKeys.length,pageSize]);

  const currentPage=useMemo(()=>{
    return Math.min(Math.max(0,pageIndex),totalPages-1);
  },[pageIndex,totalPages]);

  const pagedKeys=useMemo(()=>{
    const start=currentPage*pageSize;
    const end=start+pageSize;
    return filteredKeys.slice(start,end);
  },[filteredKeys,currentPage,pageSize]);

  useEffect(()=>{
    const closeMenu=()=>{
      setOpenActionMenuId("");
      setShowColumnMenu(false);
    };
    window.addEventListener("click",closeMenu);
    return ()=>window.removeEventListener("click",closeMenu);
  },[]);

  useEffect(()=>{
    localStorage.setItem("vecta_key_table_columns",JSON.stringify(columnVisibility));
  },[columnVisibility]);

  useEffect(()=>{
    if(!session){
      return;
    }
    void refreshTagCatalog();
  },[session?.tenantId]);

  useEffect(()=>{
    if(algoType==="symmetric"){
      setCreateAlgorithmFamily("AES");
      setCreateKeySpec("256");
      return;
    }
    if(algoType==="asymmetric"){
      setCreateAlgorithmFamily("RSA");
      setCreateKeySpec("2048");
      return;
    }
    if(algoType==="pqc"){
      setCreateAlgorithmFamily("ML-KEM");
      setCreateKeySpec("768");
      return;
    }
    setCreateAlgorithmFamily("HMAC");
    setCreateKeySpec("SHA256");
  },[algoType]);

  useEffect(()=>{
    setAlgo(composeCreateAlgorithm(algoType,createAlgorithmFamily,createKeySpec,resolvedCreateCipherMode));
  },[algoType,createAlgorithmFamily,createKeySpec,resolvedCreateCipherMode]);

  useEffect(()=>{
    if(!createAlgorithmFamilies.includes(createAlgorithmFamily)){
      setCreateAlgorithmFamily(createAlgorithmFamilies[0]||"");
      return;
    }
    if(!createKeySpecOptions.includes(createKeySpec)){
      setCreateKeySpec(createKeySpecOptions[0]||"");
    }
  },[
    createAlgorithmFamilies,
    createAlgorithmFamily,
    createKeySpecOptions,
    createKeySpec
  ]);

  useEffect(()=>{
    if(modal==="detail"&&selectedKey?.id){
      void loadVersions(selectedKey.id);
      return;
    }
    if(modal!=="detail"){
      setKeyVersions([]);
    }
  },[modal,selectedKey?.id,session?.tenantId]);

  useEffect(()=>{
    setPageIndex(0);
  },[search,statusFilter,algoFilter,tagFilter,pageSize]);

  useEffect(()=>{
    if(pageIndex>totalPages-1){
      setPageIndex(Math.max(0,totalPages-1));
    }
  },[pageIndex,totalPages]);

  useEffect(()=>{
    if(modal!=="export"){
      return;
    }
    if(exportWrappingKeyId&&wrappingKeyChoices.some((item)=>item.id===exportWrappingKeyId)){
      return;
    }
    const fallback=wrappingKeyChoices[0]?.id||"";
    setExportWrappingKeyId(fallback);
  },[modal,wrappingKeyChoices,exportWrappingKeyId]);

  useEffect(()=>{
    if(modal!=="export"){
      return;
    }
    if(isPublicComponentLike(selectedKey)){
      setExportMode("public-plaintext");
      return;
    }
    setExportMode("wrapped");
  },[modal,selectedKey?.id]);

  useEffect(()=>{
    if(modal!=="import"){
      return;
    }
    if(importWrappingKeyId&&wrappingKeyChoices.some((item)=>item.id===importWrappingKeyId)){
      return;
    }
    if(importWrappingKeyId){
      setImportWrappingKeyId("");
    }
  },[modal,importWrappingKeyId,wrappingKeyChoices]);

  useEffect(()=>{
    const count=Math.max(2,Math.min(8,Number(formComponentCount)||2));
    if(formComponents.length===count){
      return;
    }
    setFormComponents((prev)=>{
      const next=[...prev];
      while(next.length<count){
        next.push({material:"",wrapped_material:"",material_iv:"",wrapping_key_id:""});
      }
      return next.slice(0,count);
    });
  },[formComponentCount,formComponents.length]);

  const refreshKeyCatalog=async(preferredKeyId)=>{
    const items=await listKeys(session,{includeDeleted:true});
    const mapped=items.map(toViewKey);
    setKeyCatalog(mapped);
    if(preferredKeyId){
      const updated=mapped.find((k)=>k.id===preferredKeyId);
      if(updated){
        setSelectedKey(updated);
      }else if(mapped.length){
        setSelectedKey(mapped[0]);
      }else{
        setSelectedKey(null);
      }
    }else if(!mapped.length){
      setSelectedKey(null);
    }
    return mapped;
  };

  const refreshTagCatalog=async()=>{
    if(!session){
      return [];
    }
    const items=await listTags(session);
    setTagCatalog(items);
    return items;
  };

  const loadVersions=async(keyId)=>{
    if(!session||!keyId){
      setKeyVersions([]);
      return;
    }
    try{
      const items=await listKeyVersions(session,keyId);
      setKeyVersions(Array.isArray(items)?items:[]);
    }catch{
      setKeyVersions([]);
    }
  };

  const refreshKeyInventory=async()=>{
    if(!session){
      onToast?.("Missing active session.");
      return;
    }
    setRefreshingKeys(true);
    try{
      await Promise.all([
        refreshKeyCatalog(selectedKey?.id),
        refreshTagCatalog()
      ]);
    }catch(error){
      onToast?.(`Key refresh failed: ${errMsg(error)}`);
    }finally{
      setRefreshingKeys(false);
    }
  };

  const addCustomerKey=async()=>{
    const name=createName.trim();
    if(!name){
      onToast?.("Enter a key name.");
      return;
    }
    const rawLimit=opsLimitInput.trim();
    const parsedLimit=rawLimit===""?0:Number(rawLimit);
    if(!Number.isFinite(parsedLimit)||parsedLimit<0){
      onToast?.("Operation limit must be 0 or a positive number.");
      return;
    }
    const opsLimit=Math.trunc(parsedLimit);
    const activationISO=createActivationMode==="scheduled"?toISODateTime(createActivationDateTime):undefined;
    if(createActivationMode==="scheduled"&&!activationISO){
      onToast?.("Choose valid activation date and time.");
      return;
    }
    if(!session){
      onToast?.("Missing active session.");
      return;
    }
    setCreating(true);
    try{
      const keyType=algoType==="symmetric"||algoType==="hmac"?"symmetric":"asymmetric";
      let focusKeyId="";
      if(algoType==="asymmetric"){
        const pairId=`pair_${Date.now().toString(36)}_${Math.random().toString(36).slice(2,8)}`;
        const common={
          name,
          algorithm:algo,
          tags:createTags,
          activation_mode:createActivationMode==="pre-active"?"pre-active":createActivationMode==="scheduled"?"scheduled":"immediate",
          activation_date:activationISO,
          iv_mode:"internal",
          created_by:session.username||"dashboard-user",
          ops_limit:opsLimit,
          ops_limit_window:opsLimitWindow,
          approval_required:approvalReq
        };
        const privateKey=await createKey(session,{
          ...common,
          key_type:"asymmetric-private",
          purpose,
          export_allowed:exportable,
          labels:{
            pair_id:pairId,
            component_role:"private",
            pair_name:name
          }
        });
        await createKey(session,{
          ...common,
          key_type:"asymmetric-public",
          purpose:publicPurposeFromPrivate(purpose),
          export_allowed:false,
          labels:{
            pair_id:pairId,
            component_role:"public",
            pair_name:name
          }
        });
        focusKeyId=privateKey.key_id;
      }else{
        const createdKey=await createKey(session,{
          name,
          algorithm:algo,
          key_type:keyType,
          purpose,
          tags:createTags,
          export_allowed:exportable,
          activation_mode:createActivationMode==="pre-active"?"pre-active":createActivationMode==="scheduled"?"scheduled":"immediate",
          activation_date:activationISO,
          iv_mode:"internal",
          created_by:session.username||"dashboard-user",
          ops_limit:opsLimit,
          ops_limit_window:opsLimitWindow,
          approval_required:approvalReq
        });
        focusKeyId=createdKey.key_id;
      }
      const mapped=await refreshKeyCatalog(focusKeyId);
      const created=mapped.find((k)=>k.id===focusKeyId)||mapped.find((k)=>k.name===name);
      if(created){
        setSelectedKey(created);
      }
      setCreateName("");
      setOpsLimitInput("");
      setOpsLimitWindow("total");
      setCreateActivationMode("immediate");
      setCreateActivationDateTime("");
      setCreateTags([]);
      setShowCreateTagPicker(false);
      setApprovalReq(false);
      setExportable(false);
      setModal(null);
      onToast?.(algoType==="asymmetric"?`Asymmetric key pair created: ${name}`:`Key created: ${name}`);
    }catch(error){
      onToast?.(`Create key failed: ${errMsg(error)}`);
    }finally{
      setCreating(false);
    }
  };

  const updateFormComponent=(index:number, field:string, value:string)=>{
    setFormComponents((prev)=>prev.map((item,i)=>i===index?{...item,[field]:value}:item));
  };

  const submitFormKey=async()=>{
    if(!session){
      onToast?.("Missing active session.");
      return;
    }
    const name=formName.trim();
    if(!name){
      onToast?.("Enter key name for formed key.");
      return;
    }
    const mode=String(formComponentMode||"clear-generated");
    const components=(Array.isArray(formComponents)?formComponents:[]).slice(0,Math.max(2,Math.min(8,Number(formComponentCount)||2)));
    if(components.length<2){
      onToast?.("At least two components are required.");
      return;
    }
    if(mode==="clear-user"){
      const missing=components.findIndex((c)=>!String(c.material||"").trim());
      if(missing>=0){
        onToast?.(`Component ${missing+1} clear material is required (hex or base64).`);
        return;
      }
    }
    if(mode==="encrypted-user"){
      const missing=components.findIndex((c)=>!String(c.wrapped_material||"").trim()||!String(c.material_iv||"").trim()||!String(c.wrapping_key_id||"").trim());
      if(missing>=0){
        onToast?.(`Component ${missing+1} needs wrapped material, IV, and wrapping key.`);
        return;
      }
    }
    const rawLimit=formOpsLimitInput.trim();
    const parsedLimit=rawLimit===""?0:Number(rawLimit);
    if(!Number.isFinite(parsedLimit)||parsedLimit<0){
      onToast?.("Operation limit must be 0 or a positive number.");
      return;
    }
    const activationISO=formActivationMode==="scheduled"?toISODateTime(formActivationDateTime):undefined;
    if(formActivationMode==="scheduled"&&!activationISO){
      onToast?.("Choose valid activation date and time.");
      return;
    }
    setForming(true);
    try{
      const response=await formKey(session,{
        name,
        algorithm:formAlgorithm,
        key_type:"symmetric",
        purpose:formPurpose,
        tags:formTags,
        export_allowed:formExportable,
        activation_mode:formActivationMode==="pre-active"?"pre-active":formActivationMode==="scheduled"?"scheduled":"immediate",
        activation_date:activationISO,
        iv_mode:"internal",
        created_by:session.username||"dashboard-user",
        ops_limit:Math.trunc(parsedLimit),
        ops_limit_window:formOpsWindow,
        approval_required:formApprovalReq,
        component_mode:mode==="clear-user"?"clear-user":mode==="encrypted-user"?"encrypted-user":"clear-generated",
        parity:(String(formAlgorithm||"").toUpperCase().includes("DES")?(formParity as any):"none"),
        components:components.map((component)=>({
          material:String(component.material||""),
          wrapped_material:String(component.wrapped_material||""),
          material_iv:String(component.material_iv||""),
          wrapping_key_id:String(component.wrapping_key_id||"")
        }))
      });
      const mapped=await refreshKeyCatalog(response.key_id);
      const created=mapped.find((k)=>k.id===response.key_id);
      if(created){
        setSelectedKey(created);
      }
      if(Array.isArray(response.generated_components)&&response.generated_components.length){
        onToast?.(`Key formed: ${name}. ${response.generated_components.length} generated components returned by backend.`);
      }else{
        onToast?.(`Key formed: ${name}`);
      }
      setFormName("");
      setFormAlgorithm("AES-256-GCM");
      setFormPurpose("encrypt-decrypt");
      setFormComponentMode("clear-generated");
      setFormParity("none");
      setFormComponentCount(2);
      setFormComponents([
        {material:"",wrapped_material:"",material_iv:"",wrapping_key_id:""},
        {material:"",wrapped_material:"",material_iv:"",wrapping_key_id:""}
      ]);
      setFormActivationMode("immediate");
      setFormActivationDateTime("");
      setFormOpsLimitInput("");
      setFormOpsWindow("total");
      setFormExportable(false);
      setFormApprovalReq(false);
      setFormTags([]);
      setModal(null);
    }catch(error){
      onToast?.(`Form key failed: ${errMsg(error)}`);
    }finally{
      setForming(false);
    }
  };

  const inferImportKeyType=(algorithmValue:string,methodValue:string)=>{
    const alg=String(algorithmValue||"").toUpperCase().trim();
    const method=String(methodValue||"").toLowerCase().trim();
    if(!alg){
      if(method==="raw"||method==="tr31"){
        return "symmetric";
      }
      return "";
    }
    if(
      alg.includes("RSA")||
      alg.includes("ECDSA")||
      alg.includes("ECDH")||
      alg.includes("ED25519")||
      alg.includes("ED448")||
      alg.includes("X25519")||
      alg.includes("X448")||
      alg.includes("ML-DSA")||
      alg.includes("SLH-DSA")
    ){
      return "asymmetric";
    }
    return "symmetric";
  };

  const submitImportKey=async()=>{
    if(!session){
      onToast?.("Missing active session.");
      return;
    }
    const name=importName.trim();
    if(!name){
      onToast?.("Enter key name for import.");
      return;
    }
    const material=importMaterial.trim();
    if(!material){
      onToast?.("Paste key material to import.");
      return;
    }
    const normalizedMethod=(["raw","pem","jwk","tr31","pkcs12"].includes(importMethod)?importMethod:"raw") as any;
    const algorithmValue=importAlgorithm==="auto"?"":importAlgorithm;
    const keyTypeValue=inferImportKeyType(algorithmValue,normalizedMethod);
    setImporting(true);
    try{
      const response=await importKey(session,{
        name,
        algorithm:algorithmValue,
        key_type:keyTypeValue,
        purpose:importPurpose.trim(),
        created_by:session.username||"dashboard-user",
        iv_mode:"internal",
        material,
        expected_kcv:importExpectedKcv.trim(),
        import_method:normalizedMethod,
        import_password:importPassword.trim(),
        wrapping_key_id:importWrappingKeyId.trim(),
        material_iv:importMaterialIV.trim(),
        origin:importOrigin.trim()
      });
      const mapped=await refreshKeyCatalog(response.key_id);
      const imported=mapped.find((k)=>k.id===response.key_id);
      if(imported){
        setSelectedKey(imported);
      }
      resetImportForm();
      setModal(null);
      onToast?.(`Key imported: ${name}`);
    }catch(error){
      onToast?.(`Import key failed: ${errMsg(error)}`);
    }finally{
      setImporting(false);
    }
  };

  const rotateSelectedKey=async()=>{
    if(!session||!selectedKey?.id){
      return;
    }
    if(rotateType==="pqc-migration"){
      onToast?.("PQC migration rotation is not available in this build yet.");
      return;
    }
    setRotating(true);
    try{
      const reason=rotateType==="rekey"?"rekey":"manual";
      await rotateKey(session,selectedKey.id,reason,rotateOldVersionAction==="keep-active"?"keep-active":rotateOldVersionAction==="destroy"?"destroy":"deactivate");
      await refreshKeyCatalog(selectedKey.id);
      await loadVersions(selectedKey.id);
      setModal(null);
      onToast?.(rotateType==="rekey"?`Key re-keyed: ${selectedKey.name}`:`Key rotated: ${selectedKey.name}`);
    }catch(error){
      onToast?.(`Rotate key failed: ${errMsg(error)}`);
    }finally{
      setRotating(false);
    }
  };

  const generatePQCKey=async()=>{
    if(!session){
      onToast?.("Missing active session.");
      return;
    }
    const name=String(pqcName||"").trim();
    if(!name){
      onToast?.("Enter key name.");
      return;
    }
    const algorithm=String(pqcAlgorithm||"ML-KEM-768");
    const pairId=`pair_${Date.now().toString(36)}_${Math.random().toString(36).slice(2,8)}`;
    const labels:any={pqc_hybrid_mode:pqcHybridMode};
    setPqcGenerating(true);
    try{
      if(String(algorithm).toUpperCase().includes("ML-KEM")){
        const privateKey=await createKey(session,{
          name,
          algorithm,
          key_type:"asymmetric-private",
          purpose:"key-agreement",
          tags:[],
          export_allowed:false,
          activation_mode:"immediate",
          iv_mode:"internal",
          created_by:session.username||"dashboard-user",
          labels:{...labels,pair_id:pairId,component_role:"private",pair_name:name}
        });
        await createKey(session,{
          name,
          algorithm,
          key_type:"asymmetric-public",
          purpose:"key-agreement",
          tags:[],
          export_allowed:false,
          activation_mode:"immediate",
          iv_mode:"internal",
          created_by:session.username||"dashboard-user",
          labels:{...labels,pair_id:pairId,component_role:"public",pair_name:name}
        });
        await refreshKeyCatalog(privateKey.key_id);
      }else{
        const out=await createKey(session,{
          name,
          algorithm,
          key_type:"asymmetric",
          purpose:pqcPurpose,
          tags:[],
          export_allowed:false,
          activation_mode:"immediate",
          iv_mode:"internal",
          created_by:session.username||"dashboard-user",
          labels
        });
        await refreshKeyCatalog(out.key_id);
      }
      setModal(null);
      setPqcName("");
      setPqcAlgorithm("ML-KEM-768");
      setPqcHybridMode("pure");
      setPqcPurpose("key-agreement");
      onToast?.(`PQC key generated: ${name}`);
    }catch(error){
      onToast?.(`Generate PQC key failed: ${errMsg(error)}`);
    }finally{
      setPqcGenerating(false);
    }
  };

  const exportSelectedKey=async()=>{
    if(!session||!selectedKey?.id){
      return;
    }
    const mode=exportMode==="public-plaintext"?"public-plaintext":"wrapped";
    const wrappingKeyId=String(exportWrappingKeyId||"").trim();
    if(mode==="wrapped"){
      if(!wrappingKeyId){
        onToast?.("Select a wrapping KEK.");
        return;
      }
      if(wrappingKeyId===selectedKey.id){
        onToast?.("Wrapping key cannot be the same as exported key.");
        return;
      }
    }
    setExporting(true);
    try{
      const payload=await exportKey(session,selectedKey.id,{
        export_mode:mode as any,
        wrapping_key_id:wrappingKeyId
      });
      const artifact={
        key_id:payload.key_id,
        tenant_id:session.tenantId,
        kcv:payload.kcv,
        wrapped_material:payload.wrapped_material,
        material_iv:payload.material_iv,
        wrapped_dek:payload.wrapped_dek,
        public_key_plaintext:payload.public_key_plaintext||"",
        plaintext_encoding:payload.plaintext_encoding||"",
        component_type:payload.component_type||"",
        wrapping_key_id:payload.wrapping_key_id||wrappingKeyId,
        wrapping_key_kcv:payload.wrapping_key_kcv||"",
        export_format:payload.export_format||mode,
        exported_at:new Date().toISOString()
      };
      const blob=new Blob([JSON.stringify(artifact,null,2)],{type:"application/json"});
      const url=URL.createObjectURL(blob);
      const a=document.createElement("a");
      const safeName=String(selectedKey.name||payload.key_id||"key-export").replace(/[^a-z0-9._-]+/gi,"-");
      a.href=url;
      a.download=mode==="public-plaintext"?`${safeName}.public.json`:`${safeName}.wrapped.json`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
      setModal(null);
      onToast?.(mode==="public-plaintext"?`Public key exported: ${selectedKey.name}`:`Key exported: ${selectedKey.name}`);
    }catch(error){
      onToast?.(`Export key failed: ${errMsg(error)}`);
    }finally{
      setExporting(false);
    }
  };

  const updateKeyStatus=async(targetKey,nextState)=>{
    if(!session||!targetKey?.id){
      return;
    }
    setOpenActionMenuId("");
    setStatusUpdatingId(targetKey.id);
    try{
      const next=normalizeKeyState(nextState);
      if(next==="active"){
        await activateKey(session,targetKey.id);
      }else if(next==="disabled"){
        await disableKey(session,targetKey.id);
      }else if(next==="deactivated"){
        await deactivateKey(session,targetKey.id);
      }else{
        onToast?.(`Unsupported status transition: ${nextState}`);
        return;
      }
      const mapped=await refreshKeyCatalog(targetKey.id);
      const updated=mapped.find((k)=>k.id===targetKey.id);
      if(updated){
        setSelectedKey(updated);
      }
      if(next==="active"){
        onToast?.(`Key activated: ${targetKey.name}`);
      }else if(next==="disabled"){
        onToast?.(`Key disabled: ${targetKey.name}`);
      }else{
        onToast?.(`Key deactivated: ${targetKey.name}`);
      }
    }catch(error){
      const next=normalizeKeyState(nextState);
      const action=next==="active"?"Activate":next==="disabled"?"Disable":"Deactivate";
      onToast?.(`${action} key failed: ${errMsg(error)}`);
    }finally{
      setStatusUpdatingId("");
    }
  };

  const loadKeyPolicyBindings=async(targetKey)=>{
    if(!session||!targetKey?.id){
      return;
    }
    setPolicyLoading(true);
    try{
      const [users,groups,policy]=await Promise.all([
        listAuthUsers(session,session.tenantId),
        listKeyAccessGroups(session),
        getKeyAccessPolicy(session,targetKey.id)
      ]);
      setPolicyUsers(Array.isArray(users)?users:[]);
      setPolicyGroups(Array.isArray(groups)?groups:[]);
      setPolicyGrants(Array.isArray(policy?.grants)?policy.grants.map((grant)=>({
        subject_type:String(grant?.subject_type||"user")==="group"?"group":"user",
        subject_id:String(grant?.subject_id||"").trim(),
        operations:Array.isArray(grant?.operations)&&grant.operations.length
          ?Array.from(new Set(grant.operations.map((op)=>String(op||"").trim().toLowerCase()).filter(Boolean)))
          :["encrypt"],
        not_before:String(grant?.not_before||"").trim(),
        expires_at:String(grant?.expires_at||"").trim(),
        justification:String(grant?.justification||"").trim(),
        ticket_id:String(grant?.ticket_id||"").trim()
      })).filter((grant)=>grant.subject_id):[]);
    }catch(error){
      setPolicyUsers([]);
      setPolicyGroups([]);
      setPolicyGrants([]);
      onToast?.(`Load key policy bindings failed: ${errMsg(error)}`);
    }finally{
      setPolicyLoading(false);
    }
  };

  const openPolicyEditor=async(targetKey)=>{
    if(!targetKey){
      return;
    }
    const rawLimit=String(targetKey.opsLimit||"");
    setPolicyOpsLimitInput(rawLimit==="inf"?"0":rawLimit);
    setPolicyOpsWindow(String(targetKey.opsWindow||"total"));
    const status=normalizeKeyState(String(targetKey.state||""));
    setPolicyExportAllowed(Boolean(targetKey.exportAllowed));
    if(status==="pre-active"){
      if(targetKey.activationAt){
        setPolicyActivationMode("scheduled");
        setPolicyActivationDateTime(toLocalDateTime(targetKey.activationAt));
      }else{
        setPolicyActivationMode("pre-active");
        setPolicyActivationDateTime("");
      }
    }else{
      setPolicyActivationMode("immediate");
      setPolicyActivationDateTime("");
    }
    setSelectedKey(targetKey);
    setOpenActionMenuId("");
    setPolicyNewSubjectType("user");
    setPolicyNewSubjectId("");
    setPolicyNewOperations(["encrypt"]);
    setPolicyNewNotBefore("");
    setPolicyNewExpiresAt("");
    setPolicyNewJustification("");
    setPolicyNewTicketId("");
    setPolicyCreateGroupName("");
    setPolicyCreateGroupDescription("");
    setPolicyCreateGroupMembers([]);
    setModal("edit-policy");
    await loadKeyPolicyBindings(targetKey);
  };

  const togglePolicyNewOperation=(operation:string)=>{
    const normalized=String(operation||"").trim().toLowerCase();
    if(!normalized){
      return;
    }
    setPolicyNewOperations((prev)=>{
      const current=Array.isArray(prev)?prev:[];
      if(current.includes(normalized)){
        const next=current.filter((op)=>op!==normalized);
        return next.length?next:["encrypt"];
      }
      return [...current,normalized];
    });
  };

  const addPolicyGrant=()=>{
    const subjectType=policyNewSubjectType==="group"?"group":"user";
    const subjectId=String(policyNewSubjectId||"").trim();
    const operations=Array.from(new Set((Array.isArray(policyNewOperations)?policyNewOperations:["encrypt"]).map((op)=>String(op||"").trim().toLowerCase()).filter(Boolean)));
    const notBeforeISO=policyNewNotBefore?toISODateTime(policyNewNotBefore):"";
    const expiresISO=policyNewExpiresAt?toISODateTime(policyNewExpiresAt):"";
    if(!subjectId){
      onToast?.("Select a user or group to assign.");
      return;
    }
    if(!operations.length){
      onToast?.("Select at least one allowed operation.");
      return;
    }
    if(policyNewNotBefore&&!notBeforeISO){
      onToast?.("Invalid grant start date/time.");
      return;
    }
    if(policyNewExpiresAt&&!expiresISO){
      onToast?.("Invalid grant expiry date/time.");
      return;
    }
    if(notBeforeISO&&expiresISO&&new Date(notBeforeISO).getTime()>new Date(expiresISO).getTime()){
      onToast?.("Grant expiry must be after grant start.");
      return;
    }
    setPolicyGrants((prev)=>{
      const items=Array.isArray(prev)?[...prev]:[];
      const idx=items.findIndex((grant)=>String(grant?.subject_type)===(subjectType)&&String(grant?.subject_id||"").trim()===subjectId);
      if(idx>=0){
        items[idx]={
          ...items[idx],
          operations,
          not_before:notBeforeISO,
          expires_at:expiresISO,
          justification:String(policyNewJustification||"").trim(),
          ticket_id:String(policyNewTicketId||"").trim()
        };
        return items;
      }
      return [...items,{
        subject_type:subjectType,
        subject_id:subjectId,
        operations,
        not_before:notBeforeISO,
        expires_at:expiresISO,
        justification:String(policyNewJustification||"").trim(),
        ticket_id:String(policyNewTicketId||"").trim()
      }];
    });
    setPolicyNewSubjectId("");
    setPolicyNewOperations(["encrypt"]);
    setPolicyNewNotBefore("");
    setPolicyNewExpiresAt("");
    setPolicyNewJustification("");
    setPolicyNewTicketId("");
  };

  const removePolicyGrant=(subjectType:string,subjectId:string)=>{
    const typeNorm=String(subjectType||"user").trim();
    const idNorm=String(subjectId||"").trim();
    setPolicyGrants((prev)=>(Array.isArray(prev)?prev:[]).filter((grant)=>!(
      String(grant?.subject_type||"").trim()===typeNorm&&String(grant?.subject_id||"").trim()===idNorm
    )));
  };

  const saveKeyPolicy=async()=>{
    if(!session||!selectedKey?.id){
      return;
    }
    const parsedLimit=Math.trunc(Number(policyOpsLimitInput||0));
    if(!Number.isFinite(parsedLimit)||parsedLimit<0){
      onToast?.("Ops limit must be 0 or a positive number.");
      return;
    }
    const status=normalizeKeyState(String(selectedKey.state||""));
    const canEditActivation=status==="pre-active";
    const activationISO=canEditActivation&&policyActivationMode==="scheduled"?toISODateTime(policyActivationDateTime):undefined;
    if(canEditActivation&&policyActivationMode==="scheduled"&&!activationISO){
      onToast?.("Choose valid activation date and time.");
      return;
    }
    setPolicySaving(true);
    try{
      await setKeyUsageLimit(session,selectedKey.id,parsedLimit,policyOpsWindow==="daily"?"daily":policyOpsWindow==="monthly"?"monthly":"total");
      await setKeyExportPolicy(session,selectedKey.id,policyExportAllowed);
      await setKeyAccessPolicy(session,selectedKey.id,(Array.isArray(policyGrants)?policyGrants:[]).map((grant)=>({
        subject_type:String(grant?.subject_type||"user")==="group"?"group":"user",
        subject_id:String(grant?.subject_id||"").trim(),
        operations:Array.from(new Set((Array.isArray(grant?.operations)?grant.operations:[]).map((op)=>String(op||"").trim().toLowerCase()).filter(Boolean))),
        not_before:String(grant?.not_before||"").trim()||undefined,
        expires_at:String(grant?.expires_at||"").trim()||undefined,
        justification:String(grant?.justification||"").trim()||undefined,
        ticket_id:String(grant?.ticket_id||"").trim()||undefined
      })).filter((grant)=>grant.subject_id&&grant.operations.length),session.username||"");
      if(canEditActivation){
        await updateKeyActivation(session,selectedKey.id,{
          mode:policyActivationMode==="pre-active"?"pre-active":policyActivationMode==="scheduled"?"scheduled":"immediate",
          activation_date:activationISO
        });
      }
      const mapped=await refreshKeyCatalog(selectedKey.id);
      const updated=mapped.find((k)=>k.id===selectedKey.id);
      if(updated){
        setSelectedKey(updated);
      }
      setModal(null);
      onToast?.(`Policy updated: ${selectedKey.name}`);
    }catch(error){
      onToast?.(`Update key policy failed: ${errMsg(error)}`);
    }finally{
      setPolicySaving(false);
    }
  };

  const destroySelectedKey=async()=>{
    if(!session||!selectedKey?.id){
      return;
    }
    if(destroyConfirmName.trim()!==String(selectedKey.name||"")){
      onToast?.("Type the exact key name to confirm destruction.");
      return;
    }
    if(!destroyCheckWorkloads||!destroyCheckBackup||!destroyCheckIrreversible){
      onToast?.("Complete all pre-destroy checks before continuing.");
      return;
    }
    const justification=destroyJustification.trim();
    if(!justification){
      onToast?.("Enter justification for key destruction.");
      return;
    }
    const daysNum=Math.trunc(Number(destroyAfterDays||0));
    if(destroyMode==="scheduled"&&(!Number.isFinite(daysNum)||daysNum<1||daysNum>3650)){
      onToast?.("Destroy-after days must be between 1 and 3650.");
      return;
    }
    setDestroying(true);
    try{
      const out=await destroyKey(session,selectedKey.id,{
        mode:destroyMode==="immediate"?"immediate":"scheduled",
        destroy_after_days:destroyMode==="scheduled"?daysNum:undefined,
        confirm_name:destroyConfirmName.trim(),
        justification,
        checks:{
          no_active_workloads:destroyCheckWorkloads,
          backup_completed:destroyCheckBackup,
          irreversible_ack:destroyCheckIrreversible
        }
      });
      await refreshKeyCatalog(selectedKey.id);
      setModal(null);
      resetDestroyForm();
      if(normalizeKeyState(String(out?.status||""))==="deleted"){
        onToast?.(`Key deleted immediately: ${selectedKey.name}`);
      }else if(out?.destroy_at){
        onToast?.(`Key scheduled for deletion on ${new Date(out.destroy_at).toLocaleString()}`);
      }else{
        onToast?.(`Key status set to delete-pending: ${selectedKey.name}`);
      }
    }catch(error){
      onToast?.(`Destroy key failed: ${errMsg(error)}`);
    }finally{
      setDestroying(false);
    }
  };

  const destroyDaysValid=destroyMode==="immediate"||(
    Number.isFinite(Number(destroyAfterDays||0))&&Number(destroyAfterDays)>=1&&Number(destroyAfterDays)<=3650
  );
  const destroyReady=Boolean(
    !destroying&&
    selectedKey?.name&&
    destroyConfirmName.trim()===String(selectedKey?.name||"")&&
    destroyCheckWorkloads&&destroyCheckBackup&&destroyCheckIrreversible&&
    destroyJustification.trim()&&
    destroyDaysValid
  );

  const visibleColumns=useMemo(()=>{
    return KEY_TABLE_COLUMNS.filter((col)=>Boolean(columnVisibility?.[col.id]));
  },[columnVisibility]);

  const toggleColumnVisibility=(columnId:string)=>{
    setColumnVisibility((prev)=>{
      const next={...prev,[columnId]:!Boolean(prev?.[columnId])};
      const anyVisible=Object.values(next).some((v)=>Boolean(v));
      if(!anyVisible){
        return prev;
      }
      return next;
    });
  };

  return <div>
    <div style={{display:"flex",gap:12,marginBottom:14}}>
      <Stat l="Total Keys" v={String(keys.length)} s="customer key catalog" c="accent" i="??"/>
      <Stat l="Active" v={String(keys.filter((k)=>String(k.state||"").toLowerCase()==="active").length)} s="live form entries" c="green" i="?"/>
      <Stat l="PQC Keys" v={String(keys.filter(k=>String(k.algo).toLowerCase().includes("ml-")||String(k.algo).toLowerCase().includes("slh")).length)} s="from customer keys" c="purple" i="?"/>
      <Stat l="Ops Today" v={String(keys.reduce((sum,k)=>sum+Number(k.ops||0),0))} s="based on current key set" c="blue" i="?"/>
    </div>

    <Section title="Key Inventory">
      <div style={{display:"flex",justifyContent:"space-between",gap:10,marginBottom:10,flexWrap:"wrap",alignItems:"center",position:"relative",zIndex:10}}>
        <div style={{display:"flex",gap:8,flexWrap:"wrap",alignItems:"center",flex:"1 1 680px"}}>
        <Inp
          placeholder="Search keys by name, ID, algorithm, KCV, tag..."
          w={360}
          value={search}
          onChange={(e)=>setSearch(e.target.value)}
          style={{height:40,borderRadius:10,fontSize:12}}
        />
        <Sel w={170} value={algoFilter} onChange={(e)=>setAlgoFilter(e.target.value)} style={{height:40,borderRadius:10,fontSize:12}}>
          <option value="all">All Algorithms</option>
          {algorithms.map((name)=><option key={name} value={name}>{name}</option>)}
        </Sel>
        <Sel w={170} value={statusFilter} onChange={(e)=>setStatusFilter(e.target.value)} style={{height:40,borderRadius:10,fontSize:12}}>
          <option value="all">All Status</option>
          <option value="pre-active">Pre-active</option>
          <option value="active">Active</option>
          <option value="disabled">Disabled</option>
          <option value="deactivated">Deactivated (Retired)</option>
          <option value="destroy-pending">Delete Pending</option>
          <option value="deleted">Deleted</option>
        </Sel>
        <Sel w={170} value={tagFilter} onChange={(e)=>setTagFilter(e.target.value)} style={{height:40,borderRadius:10,fontSize:12}}>
          <option value="all">All Tags</option>
          {availableTags.map((name)=><option key={name} value={name}>{name}</option>)}
        </Sel>
        </div>
        <div style={{display:"flex",gap:8,alignItems:"center",justifyContent:"flex-end",flexWrap:"wrap"}}>
          <Btn onClick={()=>void refreshKeyInventory()} style={{height:40,padding:"0 16px",borderRadius:10,fontSize:12,fontWeight:700,minWidth:108,color:C.text,border:`1px solid ${C.borderHi}`}} disabled={refreshingKeys}>
            <span style={{display:"inline-flex",alignItems:"center",gap:7}}><RefreshCcw size={13} strokeWidth={2.1}/>{refreshingKeys?"Refreshing...":"Refresh"}</span>
          </Btn>
          <Btn
            onClick={()=>setModal("create")}
            primary
            style={{height:40,padding:"0 20px",borderRadius:10,fontSize:12,fontWeight:700,minWidth:130}}
          >
            <span style={{display:"inline-flex",alignItems:"center",gap:7}}><Plus size={13} strokeWidth={2.2}/>Create Key</span>
          </Btn>
          <Btn onClick={()=>setModal("form-key")} style={{height:40,padding:"0 20px",borderRadius:10,fontSize:12,fontWeight:700,minWidth:112,color:C.text,border:`1px solid ${C.borderHi}`}}>
            <span style={{display:"inline-flex",alignItems:"center",gap:7}}><PenTool size={13} strokeWidth={2.1}/>Form Key</span>
          </Btn>
          <Btn onClick={()=>{resetImportForm();setModal("import");}} style={{height:40,padding:"0 20px",borderRadius:10,fontSize:12,fontWeight:700,minWidth:96,color:C.text,border:`1px solid ${C.borderHi}`}}>
            <span style={{display:"inline-flex",alignItems:"center",gap:7}}><ArrowDownToLine size={13} strokeWidth={2.1}/>Import</span>
          </Btn>
          <Btn onClick={()=>setModal("generate-pqc")} style={{height:40,padding:"0 20px",borderRadius:10,fontSize:12,fontWeight:700,minWidth:110,color:C.text,border:`1px solid ${C.borderHi}`}}>
            <span style={{display:"inline-flex",alignItems:"center",gap:7}}><Atom size={13} strokeWidth={2.1}/>PQC Key</span>
          </Btn>
        </div>
      </div>
      <div style={{background:C.card,borderRadius:12,border:`1px solid ${C.borderHi}`,overflowX:"auto",overflowY:"visible"}}>
        <table style={{width:"100%",borderCollapse:"collapse"}}><thead><tr style={{borderBottom:`1px solid ${C.borderHi}`}}>
          {visibleColumns.map((column)=><th key={column.id} style={{padding:"8px 10px",fontSize:9,color:C.muted,textAlign:"left",textTransform:"uppercase",letterSpacing:.8}}>{column.label}</th>)}
          <th style={{padding:"8px 10px",fontSize:9,color:C.muted,textAlign:"right",textTransform:"uppercase",letterSpacing:.8,width:48}}>
            <div style={{display:"inline-flex",position:"relative"}} onClick={(e)=>e.stopPropagation()}>
              <button
                onClick={(e)=>{
                  e.stopPropagation();
                  const next=!showColumnMenu;
                  if(next){
                    const pos=placeMenuFromButton(e.currentTarget as HTMLElement,210,340);
                    setColumnMenuPos(pos);
                  }
                  setShowColumnMenu(next);
                }}
                aria-label="Configure columns"
                style={{
                  background:"transparent",
                  border:`1px solid ${C.border}`,
                  borderRadius:7,
                  color:C.accent,
                  width:28,
                  height:24,
                  display:"inline-flex",
                  alignItems:"center",
                  justifyContent:"center",
                  cursor:"pointer"
                }}
              >
                <Cog size={13} strokeWidth={2}/>
              </button>
              {showColumnMenu&&<div style={{
                position:"fixed",
                top:columnMenuPos.top,
                left:columnMenuPos.left,
                zIndex:3000,
                minWidth:190,
                background:C.surface,
                border:`1px solid ${C.borderHi}`,
                borderRadius:8,
                boxShadow:"0 12px 24px rgba(0,0,0,.35)",
                padding:8,
                display:"grid",
                gap:5
              }}>
                <div style={{fontSize:10,color:C.dim,paddingBottom:4,borderBottom:`1px solid ${C.border}`}}>Visible Columns</div>
                {KEY_TABLE_COLUMNS.map((column)=><label key={column.id} style={{display:"flex",alignItems:"center",gap:7,fontSize:10,color:C.text,cursor:"pointer"}}>
                  <input
                    type="checkbox"
                    checked={Boolean(columnVisibility?.[column.id])}
                    onChange={()=>toggleColumnVisibility(column.id)}
                  />
                  <span>{column.label}</span>
                </label>)}
              </div>}
            </div>
          </th>
        </tr></thead><tbody>
          {pagedKeys.map((k)=>{
            const normState=normalizeKeyState(String(k.state||"unknown"));
            const stateLabel=keyStateLabel(normState);
            const tone=keyStateTone(normState);
            const isDeletePending=normState==="destroy-pending";
            const isDeletedState=normState==="deleted";
            const isDeletedLike=isDeletePending||isDeletedState;
            const canRotate=!isDeletedLike;
            const canExport=!isDeletedLike&&Boolean(k.exportAllowed);
            const canEditPolicy=normState==="active"||normState==="deactivated"||normState==="pre-active"||normState==="disabled";
            const canDelete=!isDeletedLike;
            const stateBusy=statusUpdatingId===k.id;
            const opsTotal=Number(k.ops||0);
            const opsLimit=Number(k.opsLimit||0);
            const opsWindow=String(k.opsWindow||"total").toLowerCase();
            const hasLimit=Number.isFinite(opsLimit)&&opsLimit>0;
            const opsPct=hasLimit?Math.min(100,Math.max(2,(opsTotal/opsLimit)*100)):Math.min(100,opsTotal>0?12:2);
            const windowLabel=opsWindow==="daily"?" / day":opsWindow==="monthly"?" / month":"";
            const opsText=hasLimit?`${formatOpsValue(opsTotal)} / ${formatOpsValue(opsLimit)}${windowLabel}`:`${formatOpsValue(opsTotal)} / Unlimited`;
            const fipsOk=isFipsAlgorithm(String(k.algo||""));
            const keyTags=Array.isArray(k.tags)?k.tags:[];
            const rowBg=isDeletedState?"rgba(100,116,139,.08)":"transparent";
            const rowText=isDeletedState?C.dim:C.text;
            const rowAccent=isDeletedState?C.muted:C.accent;
            const rowBorder=isDeletedState?"rgba(100,116,139,.20)":C.border;
            return <tr key={k.id} style={{borderBottom:`1px solid ${rowBorder}`,cursor:"pointer",background:rowBg,opacity:isDeletedState?0.86:1}} onClick={()=>{setSelectedKey(k);setModal("detail");}}>
              {columnVisibility.name&&<td style={{padding:"8px 10px"}}>
                <div style={{display:"flex",alignItems:"center",gap:6}}>
                  <div style={{fontSize:11,color:rowText,fontWeight:700}}>{k.name}</div>
                  {k.componentRole&&<span style={{padding:"1px 6px",borderRadius:999,border:`1px solid ${k.componentRole==="private"?C.pink:C.blue}`,background:`${k.componentRole==="private"?C.pink:C.blue}22`,fontSize:9,color:k.componentRole==="private"?C.pink:C.blue,textTransform:"capitalize"}}>{k.componentRole}</span>}
                </div>
                <div style={{fontSize:9,color:isDeletedState?C.muted:C.muted,fontFamily:"'JetBrains Mono',monospace"}}>{k.id}</div>
              </td>}
              {columnVisibility.algorithm&&<td style={{padding:"8px 10px",fontSize:10,color:rowAccent,fontWeight:700}}>{k.algoFamily||"-"}</td>}
              {columnVisibility.sizeCurve&&<td style={{padding:"8px 10px",fontSize:10,color:rowText,fontFamily:"'JetBrains Mono',monospace"}}>{k.algoSizeCurve||"-"}</td>}
              {columnVisibility.status&&<td style={{padding:"8px 10px"}}><B c={isDeletedState?"muted":tone}>{stateLabel}</B></td>}
              {columnVisibility.destroyAt&&<td style={{padding:"8px 10px",fontSize:10,color:isDeletePending?C.amber:rowText,fontFamily:"'JetBrains Mono',monospace"}}>
                {formatDestroyAt(k.destroyAt)}
              </td>}
              {columnVisibility.fips&&<td style={{padding:"8px 10px"}}>
                <span style={{
                  display:"inline-flex",
                  alignItems:"center",
                  justifyContent:"center",
                  width:22,
                  height:22,
                  borderRadius:7,
                  border:`1px solid ${isDeletedState?C.muted:(fipsOk?C.green:C.red)}`,
                  background:isDeletedState?"rgba(100,116,139,.10)":(fipsOk?C.greenDim:C.redDim),
                  color:isDeletedState?C.muted:(fipsOk?C.green:C.red)
                }}>
                  {fipsOk?<Check size={12} strokeWidth={2.5}/>:<X size={12} strokeWidth={2.5}/>}
                </span>
              </td>}
              {columnVisibility.kcv&&<td style={{padding:"8px 10px",fontSize:10,color:rowAccent,fontFamily:"'JetBrains Mono',monospace"}}>{k.kcv||"-"}</td>}
              {columnVisibility.version&&<td style={{padding:"8px 10px",fontSize:10,color:rowText,fontFamily:"'JetBrains Mono',monospace"}}>{k.ver}</td>}
              {columnVisibility.operations&&<td style={{padding:"8px 10px",minWidth:140}}>
                <div style={{fontSize:10,color:rowText,fontFamily:"'JetBrains Mono',monospace"}}>{opsText}</div>
                <div style={{marginTop:3,height:4,borderRadius:999,background:C.border,overflow:"hidden"}}>
                  <div style={{height:"100%",width:`${opsPct}%`,background:isDeletedState?C.muted:C.accent,borderRadius:999}}/>
                </div>
              </td>}
              {columnVisibility.tags&&<td style={{padding:"8px 10px",maxWidth:220}}>
                <div style={{display:"flex",gap:5,flexWrap:"wrap"}}>
                  {keyTags.slice(0,3).map((tag)=>(
                    <span key={`${k.id}-${tag}`} style={{padding:"2px 7px",borderRadius:999,border:`1px solid ${tagColorByName(tagCatalog,tag)}`,background:`${tagColorByName(tagCatalog,tag)}22`,fontSize:9,color:tagColorByName(tagCatalog,tag),whiteSpace:"nowrap"}}>
                      {tag}
                    </span>
                  ))}
                  {keyTags.length>3&&<span style={{fontSize:9,color:C.muted}}>{`+${keyTags.length-3}`}</span>}
                  {!keyTags.length&&<span style={{fontSize:9,color:C.muted}}>-</span>}
                </div>
              </td>}
              {columnVisibility.actions&&<td style={{padding:"8px 10px"}}>
                <div style={{display:"flex",justifyContent:"flex-end",position:"relative"}} onClick={(e)=>e.stopPropagation()}>
                  <button
                    onClick={(e)=>{
                      e.stopPropagation();
                      const isOpen=openActionMenuId===k.id;
                      if(isOpen){
                        setOpenActionMenuId("");
                        return;
                      }
                      const pos=placeMenuFromButton(e.currentTarget as HTMLElement,190,300);
                      setActionMenuPos(pos);
                      setOpenActionMenuId(k.id);
                    }}
                    aria-label="Key actions"
                    style={{
                      background:"transparent",
                      border:`1px solid ${C.border}`,
                      borderRadius:7,
                      color:isDeletedState?C.muted:C.accent,
                      width:28,
                      height:24,
                      display:"inline-flex",
                      alignItems:"center",
                      justifyContent:"center",
                      cursor:"pointer"
                    }}
                  >
                    <MoreVertical size={14} strokeWidth={2}/>
                  </button>
                  {openActionMenuId===k.id&&<div style={{
                    position:"fixed",
                    top:actionMenuPos.top,
                    left:actionMenuPos.left,
                    zIndex:3000,
                    minWidth:170,
                    background:C.surface,
                    border:`1px solid ${C.borderHi}`,
                    borderRadius:8,
                    boxShadow:"0 12px 24px rgba(0,0,0,.35)",
                    padding:4,
                    display:"grid",
                    gap:2
                  }}>
                    {canEditPolicy&&<button
                      onClick={(e)=>{
                        e.stopPropagation();
                        openPolicyEditor(k);
                      }}
                      style={{background:"transparent",border:"none",color:C.text,fontSize:10,textAlign:"left",padding:"6px 8px",cursor:"pointer",borderRadius:6}}
                    >
                      Edit Key Policy
                    </button>}
                    {canRotate&&<button
                      onClick={(e)=>{
                        e.stopPropagation();
                        setOpenActionMenuId("");
                        setSelectedKey(k);
                        setRotateOldVersionAction("deactivate");
                        setRotateType("standard");
                        setModal("rotate");
                      }}
                      style={{background:"transparent",border:"none",color:C.text,fontSize:10,textAlign:"left",padding:"6px 8px",cursor:"pointer",borderRadius:6}}
                    >
                      Rotate
                    </button>}
                    {normState==="active"&&<button
                      onClick={(e)=>{
                        e.stopPropagation();
                        updateKeyStatus(k,"deactivated");
                      }}
                      disabled={stateBusy}
                      style={{background:"transparent",border:"none",color:stateBusy?C.muted:C.text,fontSize:10,textAlign:"left",padding:"6px 8px",cursor:stateBusy?"not-allowed":"pointer",borderRadius:6}}
                    >
                      Deactivate
                    </button>}
                    {(normState==="deactivated"||normState==="pre-active"||normState==="disabled")&&<button
                      onClick={(e)=>{
                        e.stopPropagation();
                        updateKeyStatus(k,"active");
                      }}
                      disabled={stateBusy}
                      style={{background:"transparent",border:"none",color:stateBusy?C.muted:C.text,fontSize:10,textAlign:"left",padding:"6px 8px",cursor:stateBusy?"not-allowed":"pointer",borderRadius:6}}
                    >
                      Activate
                    </button>}
                    {(normState==="active"||normState==="deactivated"||normState==="pre-active")&&<button
                      onClick={(e)=>{
                        e.stopPropagation();
                        updateKeyStatus(k,"disabled");
                      }}
                      disabled={stateBusy}
                      style={{background:"transparent",border:"none",color:stateBusy?C.muted:C.text,fontSize:10,textAlign:"left",padding:"6px 8px",cursor:stateBusy?"not-allowed":"pointer",borderRadius:6}}
                    >
                      Disable
                    </button>}
                    {canExport?<button
                      onClick={(e)=>{
                        e.stopPropagation();
                        setOpenActionMenuId("");
                        setSelectedKey(k);
                        setExportWrappingKeyId("");
                        setExportMode(isPublicComponentLike(k)?"public-plaintext":"wrapped");
                        setModal("export");
                      }}
                      style={{background:"transparent",border:"none",color:C.text,fontSize:10,textAlign:"left",padding:"6px 8px",cursor:"pointer",borderRadius:6}}
                    >
                      Export
                    </button>:(!isDeletedLike&&<div style={{padding:"6px 8px",fontSize:10,color:C.muted}}>Export disabled</div>)}
                    {canDelete?<button
                      onClick={(e)=>{
                        e.stopPropagation();
                        setOpenActionMenuId("");
                        setSelectedKey(k);
                        resetDestroyForm();
                        setModal("destroy");
                      }}
                      style={{background:"transparent",border:"none",color:C.red,fontSize:10,textAlign:"left",padding:"6px 8px",cursor:"pointer",borderRadius:6}}
                    >
                      Delete
                    </button>:<div style={{padding:"6px 8px",fontSize:10,color:C.muted}}>Deleted (forensic record)</div>}
                  </div>}
                </div>
              </td>}
              <td style={{padding:"8px 10px",width:48}} />
            </tr>;
          })}
          {!keys.length&&<tr><td colSpan={visibleColumns.length+1} style={{padding:"10px",fontSize:10,color:C.muted}}>No keys yet. Create a key with your customer-defined name.</td></tr>}
          {keys.length>0&&!filteredKeys.length&&<tr><td colSpan={visibleColumns.length+1} style={{padding:"12px 10px",fontSize:10,color:C.muted}}>No keys found for current filters.</td></tr>}
        </tbody></table>
      </div>
      <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",gap:10,marginTop:8,flexWrap:"wrap"}}>
        <div style={{display:"flex",alignItems:"center",gap:8,fontSize:10,color:C.dim}}>
          <span>Rows per page</span>
          <Sel w={92} value={String(pageSize)} onChange={(e)=>setPageSize(Number(e.target.value||10))}>
            <option value="10">10</option>
            <option value="50">50</option>
            <option value="100">100</option>
          </Sel>
          <span>{filteredKeys.length?`${currentPage*pageSize+1}-${Math.min((currentPage+1)*pageSize,filteredKeys.length)} of ${filteredKeys.length}`:`0 of 0`}</span>
        </div>
        <div style={{display:"flex",alignItems:"center",gap:8}}>
          <Btn small onClick={()=>setPageIndex((prev)=>Math.max(0,prev-1))} disabled={currentPage<=0}>Prev</Btn>
          <div style={{fontSize:10,color:C.text,minWidth:70,textAlign:"center"}}>{`Page ${currentPage+1} / ${totalPages}`}</div>
          <Btn small onClick={()=>setPageIndex((prev)=>Math.min(totalPages-1,prev+1))} disabled={currentPage>=totalPages-1}>Next</Btn>
        </div>
      </div>
    </Section>

    {/*  CREATE KEY MODAL  */}
    <Modal open={modal==="create"} onClose={()=>setModal(null)} title="Create New Key" width={920}>
      <Row2>
        <FG label="Key Name" required><Inp placeholder="Enter key name" value={createName} onChange={e=>setCreateName(e.target.value)}/></FG>
        <FG label="Tenant" required><Sel><option>{session?.tenantId||"tenant"}</option></Sel></FG>
      </Row2>
      <FG label="Algorithm Family" required>
        <div style={{display:"flex",gap:8,marginBottom:8}}>
          {[["symmetric","Symmetric"],["asymmetric","Asymmetric"],["pqc","Post-Quantum"],["hmac","HMAC"]].map(([v,l])=>
            <Radio key={v} label={l} selected={algoType===v} onSelect={()=>setAlgoType(v)}/>)}
        </div>
      </FG>
      <Row2>
        <FG label="Algorithm" required hint={algoType==="pqc"?"NIST FIPS 203/204/205 approved":""}>
          <Sel value={createAlgorithmFamily} onChange={e=>setCreateAlgorithmFamily(e.target.value)}>
            {createAlgorithmFamilies.map((family)=><option key={family} value={family}>{family}</option>)}
          </Sel>
        </FG>
        <FG label={algoType==="asymmetric"?"Key Length / Curve":"Key Strength"} required>
          <Sel value={createKeySpec} onChange={e=>setCreateKeySpec(e.target.value)}>
            {createKeySpecOptions.map((spec)=><option key={spec} value={spec}>{spec}</option>)}
          </Sel>
        </FG>
      </Row2>
      <FG label="Purpose" required>
        <Sel value={purpose} onChange={e=>setPurpose(e.target.value)}>
          <option value="encrypt-decrypt">Encrypt / Decrypt</option>
          <option value="sign-verify">Sign / Verify</option>
          <option value="wrap-unwrap">Wrap / Unwrap (KEK)</option>
          <option value="mac">MAC Generate / Verify</option>
          <option value="key-agreement">Key Agreement (DH/ECDH/KEM)</option>
          <option value="derive">Key Derivation (HKDF)</option>
          <option value="all">All Operations</option>
        </Sel>
      </FG>
      <FG label="Key Derivation" hint="Optional: derive sub-keys from this master key">
        <Sel><option value="none">None</option><option value="hkdf-sha256">HKDF-SHA256</option><option value="hkdf-sha384">HKDF-SHA384</option><option value="kdf-counter">NIST SP 800-108 Counter Mode</option></Sel>
      </FG>
      <Row2>
        <FG label="Auto-Rotation">
          <Chk label="Enable automatic rotation" checked={rotationEnabled} onChange={()=>setRotationEnabled(!rotationEnabled)}/>
          {rotationEnabled&&<Sel><option>Every 90 days</option><option>Every 30 days</option><option>Every 180 days</option><option>Every 365 days</option><option>Custom...</option></Sel>}
        </FG>
        <FG label="Operation Limits" hint="0 = unlimited">
          <Row2>
            <Inp
              placeholder="Max ops total (e.g., 1000000)"
              type="number"
              min={0}
              value={opsLimitInput}
              onChange={(e)=>setOpsLimitInput(e.target.value)}
            />
            <Sel w="100%" value={opsLimitWindow} onChange={(e)=>setOpsLimitWindow(e.target.value)}>
              <option value="total">Per lifetime</option>
              <option value="daily">Per day</option>
              <option value="monthly">Per month</option>
            </Sel>
          </Row2>
        </FG>
      </Row2>
      <Row2>
        <FG label="Security Options">
          <Chk label="Require governance approval for all operations" checked={approvalReq} onChange={()=>setApprovalReq(!approvalReq)}/>
          <Chk label="Allow key export (wrapped)" checked={exportable} onChange={()=>setExportable(!exportable)}/>
          <Chk label="HSM-backed (store in external HSM)" checked={false}/>
          <Chk label="FIPS-only algorithms enforced" checked={true}/>
        </FG>
        <FG label="Activation">
          <Sel value={createActivationMode} onChange={(e)=>setCreateActivationMode(e.target.value)}>
            <option value="immediate">Activate immediately</option>
            <option value="pre-active">Pre-active (activate later)</option>
            <option value="scheduled">Activate on specific date and time...</option>
          </Sel>
          {createActivationMode==="scheduled"&&<div style={{marginTop:8}}>
            <Inp
              type="datetime-local"
              value={createActivationDateTime}
              onChange={(e)=>setCreateActivationDateTime(e.target.value)}
            />
          </div>}
        </FG>
      </Row2>
      <FG label="Tags" hint="Select tags from Administration catalog">
        <div style={{display:"flex",gap:6,flexWrap:"wrap",marginBottom:6}}>
          {createTags.map((tag)=>(
            <span
              key={tag}
              style={{
                display:"inline-flex",
                alignItems:"center",
                gap:6,
                padding:"3px 8px",
                borderRadius:999,
                background:`${tagColorByName(tagCatalog,tag)}22`,
                border:`1px solid ${tagColorByName(tagCatalog,tag)}`,
                color:tagColorByName(tagCatalog,tag),
                fontSize:10
              }}
            >
              {tag}
              <button
                onClick={()=>setCreateTags((prev)=>prev.filter((t)=>t!==tag))}
                style={{background:"transparent",border:"none",color:"inherit",cursor:"pointer",padding:0,lineHeight:1}}
              >
                <X size={10}/>
              </button>
            </span>
          ))}
          {!createTags.length&&<div style={{fontSize:10,color:C.muted}}>No tags selected.</div>}
        </div>
        <Btn small onClick={()=>setShowCreateTagPicker(!showCreateTagPicker)}>Add More Tags</Btn>
        {showCreateTagPicker&&<div style={{marginTop:8,maxHeight:120,overflowY:"auto",border:`1px solid ${C.border}`,borderRadius:8,padding:8,display:"grid",gap:6}}>
          {availableTags.map((tag)=>(
            <label key={tag} style={{display:"flex",alignItems:"center",gap:8,fontSize:10,color:C.text,cursor:"pointer"}}>
              <input
                type="checkbox"
                checked={createTags.includes(tag)}
                onChange={()=>setCreateTags((prev)=>prev.includes(tag)?prev.filter((t)=>t!==tag):[...prev,tag])}
              />
              <span style={{display:"inline-block",width:10,height:10,borderRadius:999,background:tagColorByName(tagCatalog,tag)}}/>
              <span>{tag}</span>
            </label>
          ))}
          {!availableTags.length&&<div style={{fontSize:10,color:C.muted}}>No tags available. Add tags in Administration.</div>}
        </div>}
      </FG>
      <FG label="Description"><Txt placeholder="Optional description for this key..." rows={2}/></FG>
      <div style={{display:"flex",justifyContent:"flex-end",gap:8,marginTop:8,paddingTop:12,borderTop:`1px solid ${C.border}`}}>
        <Btn onClick={()=>setModal(null)}>Cancel</Btn>
        <Btn primary onClick={addCustomerKey} disabled={creating}>{creating?"Creating...":"Create Key"}</Btn>
      </div>
    </Modal>

    {/*  FORM KEY MODAL  */}
    <Modal open={modal==="form-key"} onClose={()=>setModal(null)} title="Form Key from Components" width={920}>
      <Row2>
        <FG label="Key Name" required><Inp placeholder="Enter key name" value={formName} onChange={(e)=>setFormName(e.target.value)}/></FG>
        <FG label="Tenant" required><Sel><option>{session?.tenantId||"tenant"}</option></Sel></FG>
      </Row2>
      <Row2>
        <FG label="Algorithm" required>
          <Sel value={formAlgorithm} onChange={(e)=>setFormAlgorithm(e.target.value)}>
            <optgroup label="AES">
              <option>AES-128-GCM</option>
              <option>AES-192-GCM</option>
              <option>AES-256-GCM</option>
            </optgroup>
            <optgroup label="DES / TDES">
              <option>DES-CBC</option>
              <option>2DES-CBC</option>
              <option>3DES-CBC</option>
            </optgroup>
            <optgroup label="Other">
              <option>HMAC-SHA256</option>
            </optgroup>
          </Sel>
        </FG>
        <FG label="Purpose" required>
          <Sel value={formPurpose} onChange={(e)=>setFormPurpose(e.target.value)}>
            <option value="encrypt-decrypt">Encrypt / Decrypt</option>
            <option value="wrap-unwrap">Wrap / Unwrap (KEK)</option>
            <option value="sign-verify">Sign / Verify</option>
            <option value="mac">MAC Generate / Verify</option>
          </Sel>
        </FG>
      </Row2>
      <Row2>
        <FG label="Component Input Mode" required hint="Payment-style component entry for key ceremony.">
          <Sel value={formComponentMode} onChange={(e)=>setFormComponentMode(e.target.value)}>
            <option value="clear-generated">Generate clear components in KMS entropy</option>
            <option value="clear-user">Enter clear components (hex/base64)</option>
            <option value="encrypted-user">Enter encrypted components (payment ceremony)</option>
          </Sel>
        </FG>
        <FG label="Component Count" required hint="Minimum 2 components.">
          <Inp type="number" min={2} max={8} value={formComponentCount} onChange={(e)=>setFormComponentCount(Number(e.target.value||2))}/>
        </FG>
      </Row2>
      {String(formAlgorithm||"").toUpperCase().includes("DES")&&<FG label="DES Parity Check">
        <Sel value={formParity} onChange={(e)=>setFormParity(e.target.value)}>
          <option value="none">None</option>
          <option value="odd">Odd parity</option>
          <option value="even">Even parity</option>
        </Sel>
      </FG>}
      <FG label="Components" required>
        <div style={{display:"grid",gap:8}}>
          {formComponents.slice(0,Math.max(2,Math.min(8,Number(formComponentCount)||2))).map((component,idx)=>(
            <div key={`component-${idx}`} style={{border:`1px solid ${C.border}`,borderRadius:8,padding:10}}>
              <div style={{fontSize:10,color:C.text,fontWeight:700,marginBottom:6}}>{`Component ${idx+1}`}</div>
              {formComponentMode==="clear-generated"&&<div style={{fontSize:10,color:C.muted}}>Generated by KMS CSPRNG during submit.</div>}
              {formComponentMode==="clear-user"&&<Txt rows={2} placeholder="Clear component (hex or base64)" value={component.material} onChange={(e)=>updateFormComponent(idx,"material",e.target.value)}/>}
              {formComponentMode==="encrypted-user"&&<>
                <Txt rows={2} placeholder="Encrypted component block (hex or base64)" value={component.wrapped_material} onChange={(e)=>updateFormComponent(idx,"wrapped_material",e.target.value)}/>
                <Row2>
                  <Inp placeholder="Component IV / nonce (hex or base64)" value={component.material_iv} onChange={(e)=>updateFormComponent(idx,"material_iv",e.target.value)}/>
                  <Sel value={component.wrapping_key_id} onChange={(e)=>updateFormComponent(idx,"wrapping_key_id",e.target.value)}>
                    <option value="">Select wrapping key...</option>
                    {wrappingKeyChoices.map((item)=><option key={`${idx}-${item.id}`} value={item.id}>{`${item.name} (${item.id})`}</option>)}
                  </Sel>
                </Row2>
                <div style={{marginTop:6,fontSize:9,color:C.muted}}>Each component is decrypted under selected KEK, then all components are XOR-combined with optional DES parity enforcement.</div>
              </>}
            </div>
          ))}
        </div>
      </FG>
      <Row2>
        <FG label="Activation">
          <Sel value={formActivationMode} onChange={(e)=>setFormActivationMode(e.target.value)}>
            <option value="immediate">Activate immediately</option>
            <option value="pre-active">Pre-active</option>
            <option value="scheduled">Activate on specific date/time</option>
          </Sel>
          {formActivationMode==="scheduled"&&<div style={{marginTop:8}}>
            <Inp type="datetime-local" value={formActivationDateTime} onChange={(e)=>setFormActivationDateTime(e.target.value)}/>
          </div>}
        </FG>
        <FG label="Operation Limits" hint="0 = unlimited">
          <Row2>
            <Inp type="number" min={0} value={formOpsLimitInput} onChange={(e)=>setFormOpsLimitInput(e.target.value)} placeholder="Max operations"/>
            <Sel value={formOpsWindow} onChange={(e)=>setFormOpsWindow(e.target.value)}>
              <option value="total">Per lifetime</option>
              <option value="daily">Per day</option>
              <option value="monthly">Per month</option>
            </Sel>
          </Row2>
        </FG>
      </Row2>
      <FG label="Security Options">
        <Chk label="Allow key export (wrapped)" checked={formExportable} onChange={()=>setFormExportable(!formExportable)}/>
        <Chk label="Require governance approval for all operations" checked={formApprovalReq} onChange={()=>setFormApprovalReq(!formApprovalReq)}/>
      </FG>
      <FG label="Tags">
        <div style={{display:"grid",gap:6,maxHeight:140,overflowY:"auto",border:`1px solid ${C.border}`,borderRadius:8,padding:8}}>
          {availableTags.map((tag)=>(
            <label key={`form-tag-${tag}`} style={{display:"flex",alignItems:"center",gap:8,fontSize:10,color:C.text,cursor:"pointer"}}>
              <input
                type="checkbox"
                checked={formTags.includes(tag)}
                onChange={()=>setFormTags((prev)=>prev.includes(tag)?prev.filter((item)=>item!==tag):[...prev,tag])}
              />
              <span style={{display:"inline-block",width:10,height:10,borderRadius:999,background:tagColorByName(tagCatalog,tag)}}/>
              <span>{tag}</span>
            </label>
          ))}
          {!availableTags.length&&<div style={{fontSize:10,color:C.muted}}>No tags available. Add tags in Administration.</div>}
        </div>
      </FG>
      <div style={{display:"flex",justifyContent:"flex-end",gap:8,marginTop:8,paddingTop:12,borderTop:`1px solid ${C.border}`}}>
        <Btn onClick={()=>setModal(null)}>Cancel</Btn>
        <Btn primary onClick={submitFormKey} disabled={forming}>{forming?"Forming...":"Form Key"}</Btn>
      </div>
    </Modal>

    {/*  IMPORT KEY MODAL  */}
    <Modal open={modal==="import"} onClose={()=>setModal(null)} title="Import Key Material" width={920}>
      <FG label="Import Method" required>
        <div style={{display:"flex",gap:10,flexWrap:"wrap"}}>
          {[
            {id:"raw",label:"Raw Key Material (Base64/Hex)"},
            {id:"pem",label:"PKCS#8 / PEM"},
            {id:"jwk",label:"JWK (JSON Web Key)"},
            {id:"tr31",label:"TR-31 Key Block"},
            {id:"pkcs12",label:"PKCS#12 (.p12)"}
          ].map((item)=><Radio key={item.id} label={item.label} selected={importMethod===item.id} onSelect={()=>setImportMethod(item.id)}/>)}
        </div>
      </FG>
      <Row2>
        <FG label="Key Name" required><Inp placeholder="Enter key name" value={importName} onChange={(e)=>setImportName(e.target.value)}/></FG>
        <FG label="Tenant" required><Sel><option>{session?.tenantId||"tenant"}</option></Sel></FG>
      </Row2>
      <FG label="Key Material" required hint="Key material is envelope-encrypted immediately upon import. Plaintext never touches disk.">
        <Txt
          placeholder={
            importMethod==="pem"
              ?"Paste PEM / PKCS#8 key or certificate..."
              :importMethod==="jwk"
              ?"Paste full JWK JSON..."
              :importMethod==="tr31"
              ?"Paste TR-31 block (or JSON containing tr31/key_block)..."
              :importMethod==="pkcs12"
              ?"Paste base64/hex PKCS#12 (.p12) payload..."
              :"Paste base64/hex key material or wrapped artifact JSON..."
          }
          rows={5}
          value={importMaterial}
          onChange={(e)=>setImportMaterial(e.target.value)}
        />
      </FG>
      <Row2>
        <FG label="Algorithm" required hint="Use auto-detect when possible.">
          <Sel value={importAlgorithm} onChange={(e)=>setImportAlgorithm(e.target.value)}>
            <option value="auto">Auto-detect from format</option>
            <optgroup label="Symmetric">
              <option value="AES-128">AES-128</option>
              <option value="AES-192">AES-192</option>
              <option value="AES-256">AES-256</option>
              <option value="3DES">3DES</option>
              <option value="DES">DES</option>
              <option value="HMAC-SHA256">HMAC-SHA256</option>
            </optgroup>
            <optgroup label="Asymmetric">
              <option value="RSA-2048">RSA-2048</option>
              <option value="RSA-3072">RSA-3072</option>
              <option value="RSA-4096">RSA-4096</option>
              <option value="ECDSA-P256">ECDSA-P256</option>
              <option value="ECDSA-P384">ECDSA-P384</option>
              <option value="ECDSA-P521">ECDSA-P521</option>
              <option value="Ed25519">Ed25519</option>
            </optgroup>
            <optgroup label="PQC">
              <option value="ML-KEM-768">ML-KEM-768</option>
              <option value="ML-DSA-65">ML-DSA-65</option>
            </optgroup>
          </Sel>
        </FG>
        <FG label="Wrapping Key (if wrapped)" hint="Select KEK only when material is wrapped.">
          <Sel value={importWrappingKeyId} onChange={(e)=>setImportWrappingKeyId(e.target.value)}>
            <option value="">Not wrapped (raw import)</option>
            {wrappingKeyChoices.map((item)=><option key={item.id} value={item.id}>{`${item.name} (${item.id})`}</option>)}
          </Sel>
          {!wrappingKeyChoices.length&&<div style={{marginTop:6,fontSize:10,color:C.amber}}>No active wrap/unwrap key available.</div>}
        </FG>
      </Row2>
      <Row2>
        <FG label="Purpose">
          <Sel value={importPurpose} onChange={(e)=>setImportPurpose(e.target.value)}>
            <option value="encrypt-decrypt">encrypt-decrypt</option>
            <option value="sign-verify">sign-verify</option>
            <option value="wrap-unwrap">wrap-unwrap</option>
            <option value="mac">mac</option>
            <option value="key-agreement">key-agreement</option>
            <option value="derive">derive</option>
          </Sel>
        </FG>
        <FG label="Origin">
          <Sel value={importOrigin} onChange={(e)=>setImportOrigin(e.target.value)}>
            <option value="external">External - customer imported</option>
            <option value="byok">Cloud provider (BYOK re-import)</option>
            <option value="tr31">TR-31 key block</option>
            <option value="migration">Migration from external HSM/KMS</option>
          </Sel>
        </FG>
      </Row2>
      <Row2>
        <FG label="Expected KCV (optional)" hint="Hex KCV used for integrity check during import.">
          <Inp placeholder="e.g. A1B2C3" value={importExpectedKcv} onChange={(e)=>setImportExpectedKcv(e.target.value)}/>
        </FG>
        <FG label="Import Password (optional)" hint="Used for encrypted PEM/PKCS#12 payloads.">
          <Inp type="password" value={importPassword} onChange={(e)=>setImportPassword(e.target.value)} placeholder="Leave blank if not encrypted"/>
        </FG>
      </Row2>
      {importWrappingKeyId&&<FG label="Material IV / Nonce (optional)" hint="Required if wrapped material does not include JSON fields material_iv/wrapped_material.">
        <Inp placeholder="Base64 or hex IV/nonce for wrapped payload" value={importMaterialIV} onChange={(e)=>setImportMaterialIV(e.target.value)}/>
      </FG>}
      <div style={{display:"flex",justifyContent:"flex-end",gap:8,marginTop:8,paddingTop:12,borderTop:`1px solid ${C.border}`}}>
        <Btn onClick={()=>setModal(null)}>Cancel</Btn>
        <Btn primary onClick={submitImportKey} disabled={importing}>{importing?"Importing...":"Import Key"}</Btn>
      </div>
    </Modal>

    {/*  KEY DETAIL MODAL  */}
    <Modal open={modal==="detail"&&selectedKey} onClose={()=>setModal(null)} title={`Key: ${selectedKey?.name||""}`} wide>
      {selectedKey&&<>{(()=>{
        const selectedNormState=normalizeKeyState(String(selectedKey.state||"unknown"));
        const selectedCanEditPolicy=selectedNormState==="active"||selectedNormState==="deactivated"||selectedNormState==="pre-active"||selectedNormState==="disabled";
        const selectedDeletedLike=selectedNormState==="deleted"||selectedNormState==="destroy-pending";
        const selectedCanRotate=!selectedDeletedLike;
        const selectedCanExport=!selectedDeletedLike&&Boolean(selectedKey.exportAllowed);
        const selectedStateBusy=statusUpdatingId===selectedKey.id;
        return <><Row3>
        <FG label="Key ID"><div style={{fontFamily:"monospace",fontSize:11,color:C.accent}}>{selectedKey.id}</div></FG>
        <FG label="Algorithm"><div style={{fontSize:11,color:C.text}}>{selectedKey.algoFamily||"-"}</div></FG>
        <FG label="KCV"><div style={{fontFamily:"monospace",fontSize:11,color:C.green}}>{selectedKey.kcv}</div></FG>
      </Row3>
      <FG label="Size / Curve"><div style={{fontSize:11,color:C.text,fontFamily:"'JetBrains Mono',monospace"}}>{selectedKey.algoSizeCurve||"-"}</div></FG>
      <Row3>
        <FG label="State"><B c={keyStateTone(selectedNormState)}>{keyStateLabel(selectedNormState)}</B></FG>
        <FG label="Version"><div style={{fontSize:11,color:C.text}}>{selectedKey.ver}</div></FG>
        <FG label="Tenant"><div style={{fontSize:11,color:C.text}}>{selectedKey.tenant}</div></FG>
      </Row3>
      <Row3>
        <FG label="Purpose"><B c="blue">{selectedKey.purpose}</B></FG>
        <FG label="Ops Limit"><div style={{fontSize:11,color:C.text}}>{selectedKey.opsLimit==="inf"?"Unlimited":`${selectedKey.opsLimit} (${selectedKey.opsWindow||"total"})`}</div></FG>
      </Row3>
      <Row3>
        <FG label="Created"><div style={{fontSize:11,color:C.dim}}>{selectedKey.created}</div></FG>
        <FG label="Last Rotated"><div style={{fontSize:11,color:C.dim}}>{selectedKey.rotated}</div></FG>
        <FG label="Expires"><div style={{fontSize:11,color:selectedKey.expires==="-"?C.dim:C.amber}}>{selectedKey.expires}</div></FG>
      </Row3>
      <FG label="Total Operations"><div style={{fontSize:18,fontWeight:700,color:C.accent}}>{selectedKey.ops}</div></FG>
      <FG label="Tags">
        <div style={{display:"flex",gap:6,flexWrap:"wrap"}}>
          {(Array.isArray(selectedKey.tags)?selectedKey.tags:[]).map((tag)=>(
            <span key={tag} style={{padding:"3px 8px",borderRadius:999,border:`1px solid ${tagColorByName(tagCatalog,tag)}`,background:`${tagColorByName(tagCatalog,tag)}22`,fontSize:10,color:tagColorByName(tagCatalog,tag)}}>{tag}</span>
          ))}
          {!Array.isArray(selectedKey.tags)||!selectedKey.tags.length?<span style={{fontSize:10,color:C.muted}}>No tags</span>:null}
        </div>
      </FG>
      {selectedAsymmetricComponents.length>1&&<FG label="Asymmetric Components">
        <div style={{background:C.surface,borderRadius:7,padding:10,border:`1px solid ${C.border}`,display:"grid",gap:6}}>
          {selectedAsymmetricComponents.map((comp)=>{
            const compNorm=normalizeKeyState(String(comp.state||"unknown"));
            const compBusy=statusUpdatingId===comp.id;
            return <div key={comp.id} style={{display:"grid",gridTemplateColumns:"1fr auto",alignItems:"center",gap:8,padding:"6px 0",borderBottom:`1px solid ${C.border}`}}>
              <div>
                <div style={{display:"flex",alignItems:"center",gap:6}}>
                  <span style={{fontSize:10,color:C.text,fontWeight:700}}>{comp.name}</span>
                  <span style={{fontSize:9,color:comp.componentRole==="private"?C.pink:C.blue,textTransform:"capitalize"}}>{comp.componentRole||"component"}</span>
                </div>
                <div style={{fontSize:9,color:C.muted,fontFamily:"'JetBrains Mono',monospace"}}>{comp.id}</div>
              </div>
              <div style={{display:"flex",alignItems:"center",gap:6}}>
                <B c={keyStateTone(compNorm)}>{keyStateLabel(compNorm)}</B>
                {compNorm==="active"&&<Btn small onClick={()=>updateKeyStatus(comp,"deactivated")} disabled={compBusy}>{compBusy?"...":"Deactivate"}</Btn>}
                {(compNorm==="deactivated"||compNorm==="pre-active"||compNorm==="disabled")&&<Btn small onClick={()=>updateKeyStatus(comp,"active")} disabled={compBusy}>{compBusy?"...":"Activate"}</Btn>}
                {(compNorm==="active"||compNorm==="deactivated"||compNorm==="pre-active")&&<Btn small onClick={()=>updateKeyStatus(comp,"disabled")} disabled={compBusy}>{compBusy?"...":"Disable"}</Btn>}
              </div>
            </div>;
          })}
        </div>
      </FG>}
      <FG label="Key Versions">
        <div style={{background:C.surface,borderRadius:7,padding:10,border:`1px solid ${C.border}`}}>
          {[...keyVersions]
            .sort((a,b)=>Number(b.version||0)-Number(a.version||0))
            .map((v)=>{
              const vStatus=keyStateLabel(normalizeKeyState(String(v.status||"unknown")));
              const isCurrent=String(selectedKey?.ver||"")===(Number(v.version||0)>0?`v${v.version}`:"");
              const createdAt=v.created_at?new Date(v.created_at).toLocaleString():"-";
              const line=`v${v.version} - ${vStatus}${isCurrent?" (current)":""} - KCV: ${String(v.kcv||"-")} - Created: ${createdAt}`;
              return <div key={String(v.id||v.version)} style={{fontSize:10,color:C.dim,padding:"4px 0",borderBottom:`1px solid ${C.border}`,fontFamily:"monospace"}}>{line}</div>;
            })}
          {!Array.isArray(keyVersions)||!keyVersions.length?<div style={{fontSize:10,color:C.muted}}>No version history found.</div>:null}
        </div>
      </FG>
      <div style={{display:"flex",gap:6,marginTop:12}}>
        {selectedCanRotate&&<Btn primary onClick={()=>{setRotateOldVersionAction("deactivate");setRotateType("standard");setModal("rotate");}}><span style={{display:"inline-flex",alignItems:"center",gap:6}}><RefreshCcw size={12}/>Rotate</span></Btn>}
        {selectedCanExport&&<Btn onClick={()=>{setExportWrappingKeyId("");setExportMode(isPublicComponentLike(selectedKey)?"public-plaintext":"wrapped");setModal("export");}}><span style={{display:"inline-flex",alignItems:"center",gap:6}}><ExternalLink size={12}/>Export</span></Btn>}
        {selectedCanEditPolicy&&<Btn onClick={()=>openPolicyEditor(selectedKey)}>Edit Key Policy</Btn>}
        {selectedNormState==="active"&&<Btn onClick={()=>updateKeyStatus(selectedKey,"deactivated")} disabled={selectedStateBusy}>{selectedStateBusy?"Updating...":"Deactivate"}</Btn>}
        {(selectedNormState==="deactivated"||selectedNormState==="pre-active"||selectedNormState==="disabled")&&<Btn onClick={()=>updateKeyStatus(selectedKey,"active")} disabled={selectedStateBusy}>{selectedStateBusy?"Updating...":"Activate"}</Btn>}
        {(selectedNormState==="active"||selectedNormState==="deactivated"||selectedNormState==="pre-active")&&<Btn onClick={()=>updateKeyStatus(selectedKey,"disabled")} disabled={selectedStateBusy}>{selectedStateBusy?"Updating...":"Disable"}</Btn>}
        {!selectedDeletedLike&&<Btn danger onClick={()=>{resetDestroyForm();setModal("destroy");}}><span style={{display:"inline-flex",alignItems:"center",gap:6}}><X size={12}/>Delete</span></Btn>}
      </div></>;
      })()}</>}
    </Modal>

    {/*  EDIT KEY POLICY MODAL  */}
    <Modal open={modal==="edit-policy"&&selectedKey} onClose={()=>setModal(null)} title={`Edit Key Policy: ${selectedKey?.name||""}`}>
      <FG label="Operation Limits" hint="0 = unlimited">
        <Row2>
          <Inp
            placeholder="Max operations"
            type="number"
            min={0}
            value={policyOpsLimitInput}
            onChange={(e)=>setPolicyOpsLimitInput(e.target.value)}
          />
          <Sel w="100%" value={policyOpsWindow} onChange={(e)=>setPolicyOpsWindow(e.target.value)}>
            <option value="total">Per lifetime</option>
            <option value="daily">Per day</option>
            <option value="monthly">Per month</option>
          </Sel>
        </Row2>
      </FG>
      <FG label="Export Policy">
        <Chk label="Allow key export (wrapped)" checked={policyExportAllowed} onChange={()=>setPolicyExportAllowed(!policyExportAllowed)}/>
      </FG>
      <FG label="Key Access Assignments" hint="Only assigned users/groups can perform selected operations on this key.">
        {policyLoading&&<div style={{fontSize:10,color:C.dim}}>Loading key access policy...</div>}
        {!policyLoading&&<>
          <Row2>
            <Sel value={policyNewSubjectType} onChange={(e)=>{setPolicyNewSubjectType(e.target.value==="group"?"group":"user");setPolicyNewSubjectId("");}}>
              <option value="user">User</option>
              <option value="group">Group</option>
            </Sel>
            <Sel value={policyNewSubjectId} onChange={(e)=>setPolicyNewSubjectId(e.target.value)}>
              <option value="">{policyNewSubjectType==="group"?"Select group":"Select user"}</option>
              {policyNewSubjectType==="group"
                ?(Array.isArray(policyGroups)?policyGroups:[]).map((group)=><option key={group.id} value={group.id}>{`${group.name}${Number(group.member_count||0)>0?` (${group.member_count})`:""}`}</option>)
                :(Array.isArray(policyUsers)?policyUsers:[]).map((user)=><option key={user.id} value={user.id}>{`${user.username} (${user.role})`}</option>)}
            </Sel>
          </Row2>
          <div style={{marginTop:8,display:"grid",gridTemplateColumns:"repeat(3,minmax(0,1fr))",gap:6}}>
            {KEY_ACCESS_OPERATION_OPTIONS.map((item)=><Chk
              key={item.id}
              label={item.label}
              checked={(Array.isArray(policyNewOperations)?policyNewOperations:[]).includes(item.id)}
              onChange={()=>togglePolicyNewOperation(item.id)}
            />)}
          </div>
          <div style={{marginTop:8,display:"grid",gridTemplateColumns:"repeat(2,minmax(0,1fr))",gap:8}}>
            <FG label="Grant active from (optional)">
              <Inp type="datetime-local" value={policyNewNotBefore} onChange={(e)=>setPolicyNewNotBefore(e.target.value)}/>
            </FG>
            <FG label="Grant expires at (optional)">
              <Inp type="datetime-local" value={policyNewExpiresAt} onChange={(e)=>setPolicyNewExpiresAt(e.target.value)}/>
            </FG>
          </div>
          <Row2>
            <FG label="Justification (optional)">
              <Inp value={policyNewJustification} onChange={(e)=>setPolicyNewJustification(e.target.value)} placeholder="Reason for grant"/>
            </FG>
            <FG label="Ticket ID (optional)">
              <Inp value={policyNewTicketId} onChange={(e)=>setPolicyNewTicketId(e.target.value)} placeholder="INC-1234 / CHG-1234"/>
            </FG>
          </Row2>
          <div style={{display:"flex",justifyContent:"flex-end",marginTop:8}}>
            <Btn onClick={addPolicyGrant}>Add Assignment</Btn>
          </div>
          <div style={{display:"grid",gap:6,marginTop:10}}>
            {(Array.isArray(policyGrants)?policyGrants:[]).map((grant)=>{
              const subjectType=String(grant?.subject_type||"user")==="group"?"group":"user";
              const subjectID=String(grant?.subject_id||"").trim();
              const subjectLabel=subjectType==="group"
                ?((Array.isArray(policyGroups)?policyGroups:[]).find((group)=>String(group?.id||"")===subjectID)?.name||subjectID)
                :((Array.isArray(policyUsers)?policyUsers:[]).find((user)=>String(user?.id||"")===subjectID)?.username||subjectID);
              const operations=(Array.isArray(grant?.operations)?grant.operations:[]).map((op)=>KEY_ACCESS_OPERATION_OPTIONS.find((item)=>item.id===String(op||"").toLowerCase())?.label||String(op||"").toUpperCase()).join(", ");
              const windowParts=[
                String(grant?.not_before||"").trim()?`from ${new Date(String(grant?.not_before)).toLocaleString()}`:"",
                String(grant?.expires_at||"").trim()?`until ${new Date(String(grant?.expires_at)).toLocaleString()}`:""
              ].filter(Boolean).join(" ");
              const reason=String(grant?.justification||"").trim();
              const ticket=String(grant?.ticket_id||"").trim();
              const extra=[windowParts,reason?`reason: ${reason}`:"",ticket?`ticket: ${ticket}`:""].filter(Boolean).join(" | ");
              return <div key={`${subjectType}:${subjectID}`} style={{display:"grid",gridTemplateColumns:"1fr auto",alignItems:"center",gap:8,padding:"8px 10px",border:`1px solid ${C.border}`,borderRadius:8,background:C.surface}}>
                <div>
                  <div style={{fontSize:10,color:C.text,fontWeight:700}}>{`${subjectType==="group"?"Group":"User"}: ${subjectLabel}`}</div>
                  <div style={{fontSize:9,color:C.muted}}>{operations||"No operations"}{extra?` | ${extra}`:""}</div>
                </div>
                <Btn danger small onClick={()=>removePolicyGrant(subjectType,subjectID)}>Remove</Btn>
              </div>;
            })}
            {!Array.isArray(policyGrants)||!policyGrants.length?<div style={{fontSize:10,color:C.dim}}>No assignments yet. Unassigned keys are usable by creator/admin only.</div>:null}
          </div>
        </>}
      </FG>
      {normalizeKeyState(String(selectedKey?.state||""))==="pre-active"&&<FG label="Activation Policy">
        <Sel value={policyActivationMode} onChange={(e)=>setPolicyActivationMode(e.target.value)}>
          <option value="immediate">Activate immediately</option>
          <option value="pre-active">Pre-active (activate later)</option>
          <option value="scheduled">Activate on specific date and time...</option>
        </Sel>
        {policyActivationMode==="scheduled"&&<div style={{marginTop:8}}>
          <Inp
            type="datetime-local"
            value={policyActivationDateTime}
            onChange={(e)=>setPolicyActivationDateTime(e.target.value)}
          />
        </div>}
      </FG>}
      <div style={{display:"flex",justifyContent:"flex-end",gap:8,marginTop:8}}>
        <Btn onClick={()=>setModal(null)}>Cancel</Btn>
        <Btn primary onClick={saveKeyPolicy} disabled={policySaving}>{policySaving?"Saving...":"Save Policy"}</Btn>
      </div>
    </Modal>

    {/*  ROTATE KEY MODAL  */}
    <Modal open={modal==="rotate"} onClose={()=>setModal(null)} title={`Rotate Key: ${selectedKey?.name||""}`}>
      <FG label="Rotation Type">
        <Radio label="Standard Rotation - Generate new version, deactivate old" selected={rotateType==="standard"} onSelect={()=>setRotateType("standard")}/>
        <Radio label="Re-key - Generate new key material, same ID (for compromised keys)" selected={rotateType==="rekey"} onSelect={()=>setRotateType("rekey")}/>
        {isAsymmetricKeyLike(selectedKey)&&<Radio label="PQC Migration - Rotate to post-quantum algorithm (coming soon)" selected={rotateType==="pqc-migration"} onSelect={()=>setRotateType("pqc-migration")}/>}
      </FG>
      <FG label="New Algorithm" hint={isAsymmetricKeyLike(selectedKey)?"Usually same as current. Change for PQC migration.":"Symmetric rotation keeps same algorithm family."}>
        {isAsymmetricKeyLike(selectedKey)?
          <Sel><option>{selectedKey?.algo} (same)</option><option>ML-DSA-65 (PQC migration)</option><option>ECDSA-P384 + ML-DSA-65 (hybrid)</option></Sel>:
          <Sel><option>{selectedKey?.algo} (same)</option></Sel>}
      </FG>
      <FG label="Old Version Action">
        <Sel value={rotateOldVersionAction} onChange={(e)=>setRotateOldVersionAction(e.target.value)}>
          <option value="deactivate">Deactivate old version (recommended)</option>
          <option value="keep-active">Keep old version active (dual-active period)</option>
          <option value="destroy">Destroy old version immediately</option>
        </Sel>
      </FG>
      <Chk label="Notify BYOK cloud connectors to sync new version" checked={true}/>
      <Chk label="Notify HYOK endpoints of rotation" checked={false}/>
      <div style={{display:"flex",justifyContent:"flex-end",gap:8,marginTop:12}}><Btn onClick={()=>setModal(null)}>Cancel</Btn><Btn primary onClick={rotateSelectedKey} disabled={rotating}>{rotating?"Rotating...":"Rotate Key"}</Btn></div>
    </Modal>

    {/*  EXPORT KEY MODAL  */}
    <Modal open={modal==="export"} onClose={()=>setModal(null)} title={`Export Key: ${selectedKey?.name||""}`}>
      <div style={{background:C.amberDim,border:`1px solid ${C.amber}`,borderRadius:8,padding:10,marginBottom:12,fontSize:10,color:C.amber}}>
        {exportMode==="public-plaintext"
          ?"Warning: public key will be exported in plaintext (not wrapped)."
          :"Warning: key material will be exported wrapped. This is a HIGH severity audit event."}
      </div>
      <FG label="Export Mode" required>
        <Sel value={exportMode} onChange={(e)=>setExportMode(e.target.value)}>
          <option value="wrapped">Wrapped with KEK (default)</option>
          {isPublicComponentLike(selectedKey)&&<option value="public-plaintext">Public key plaintext export</option>}
        </Sel>
      </FG>
      {exportMode==="wrapped"&&<FG label="Wrapping Key (KEK)" required hint="The exported key material will be encrypted with this KEK. Self-wrapping is blocked.">
        <Sel value={exportWrappingKeyId} onChange={(e)=>setExportWrappingKeyId(e.target.value)}>
          <option value="">Select wrapping key...</option>
          {wrappingKeyChoices.map((item)=><option key={item.id} value={item.id}>{`${item.name} (${item.id})`}</option>)}
        </Sel>
        {!wrappingKeyChoices.length&&<div style={{marginTop:6,fontSize:10,color:C.amber}}>No active wrap/unwrap key available.</div>}
      </FG>}
      <FG label="Export Format">
        {exportMode==="public-plaintext"
          ?<Sel value="public-plaintext" disabled><option>Public key plaintext (base64)</option></Sel>
          :<Sel value="wrapped" disabled><option>Raw wrapped (base64)</option></Sel>}
      </FG>
      <FG label="Justification" required><Txt placeholder="Reason for export (required for audit)..." rows={2}/></FG>
      <div style={{display:"flex",justifyContent:"flex-end",gap:8,marginTop:8}}>
        <Btn onClick={()=>setModal(null)}>Cancel</Btn>
        <Btn primary onClick={exportSelectedKey} disabled={exporting}>{exporting?"Exporting...":"Export Key"}</Btn>
      </div>
    </Modal>

    {/*  DESTROY KEY MODAL  */}
    <Modal open={modal==="destroy"} onClose={()=>setModal(null)} title={`Destroy Key: ${selectedKey?.name||""}`}>
      <div style={{background:C.redDim,border:`1px solid ${C.red}`,borderRadius:8,padding:12,marginBottom:12,fontSize:11,color:C.red}}>
        <strong>CRITICAL: This action is irreversible.</strong><br/>All key material will be zeroized. Data encrypted with this key will become permanently unrecoverable.
      </div>
      <FG label="Destruction Method">
        <Radio label="Destroy After (days) - mark key pending and auto-delete later" selected={destroyMode==="scheduled"} onSelect={()=>setDestroyMode("scheduled")}/>
        {destroyMode==="scheduled"&&<div style={{marginTop:8}}>
          <Inp type="number" min={1} max={3650} value={destroyAfterDays} onChange={(e)=>setDestroyAfterDays(Number(e.target.value)||0)} placeholder="Enter number of days (1-3650)"/>
          <div style={{fontSize:9,color:C.muted,marginTop:4}}>Key remains blocked immediately and is permanently deleted after this many days.</div>
        </div>}
        <Radio label="Destroy Immediately - permanently delete now" selected={destroyMode==="immediate"} onSelect={()=>setDestroyMode("immediate")}/>
      </FG>
      <FG label="Pre-Destroy Checks">
        <Chk label="I confirm no active workloads depend on this key" checked={destroyCheckWorkloads} onChange={()=>setDestroyCheckWorkloads(!destroyCheckWorkloads)}/>
        <Chk label="I have verified backup/re-encryption is complete" checked={destroyCheckBackup} onChange={()=>setDestroyCheckBackup(!destroyCheckBackup)}/>
        <Chk label="I understand this is irreversible" checked={destroyCheckIrreversible} onChange={()=>setDestroyCheckIrreversible(!destroyCheckIrreversible)}/>
      </FG>
      <FG label="Type key name to confirm" required><Inp placeholder={selectedKey?.name} value={destroyConfirmName} onChange={(e)=>setDestroyConfirmName(e.target.value)}/></FG>
      <FG label="Justification" required><Txt placeholder="Reason for destruction (required for audit)..." rows={2} value={destroyJustification} onChange={(e)=>setDestroyJustification(e.target.value)}/></FG>
      <div style={{display:"flex",justifyContent:"flex-end",gap:8,marginTop:8}}>
        <Btn onClick={()=>setModal(null)}>Cancel</Btn>
        <Btn danger onClick={destroySelectedKey} disabled={!destroyReady}>{destroying?"Destroying...":destroyMode==="immediate"?"Destroy Immediately":"Schedule Destruction"}</Btn>
      </div>
    </Modal>

    {/*  GENERATE PQC KEY MODAL  */}
    <Modal open={modal==="generate-pqc"} onClose={()=>setModal(null)} title="Generate Post-Quantum Key" width={920}>
      <div style={{background:C.purpleDim,border:`1px solid ${C.purple}`,borderRadius:8,padding:10,marginBottom:12,fontSize:10,color:C.purple}}>Post-Quantum Cryptography - NIST FIPS 203/204/205 approved algorithms</div>
      <Row2>
        <FG label="PQC Algorithm" required>
          <Sel value={pqcAlgorithm} onChange={(e)=>setPqcAlgorithm(e.target.value)}>
            <option value="ML-KEM-768">ML-KEM-768 (FIPS 203)</option>
            <option value="ML-KEM-1024">ML-KEM-1024 (FIPS 203)</option>
          </Sel>
        </FG>
        <FG label="Hybrid Mode" hint="Combine PQC with classical for backward compatibility">
          <Sel value={pqcHybridMode} onChange={(e)=>setPqcHybridMode(e.target.value)}>
            <option value="pure">Pure PQC only</option>
            <option value="hybrid-ecdh">Hybrid: X25519 + ML-KEM-768</option>
          </Sel>
        </FG>
      </Row2>
      <Row2>
        <FG label="Key Name" required><Inp placeholder="Enter key name" value={pqcName} onChange={(e)=>setPqcName(e.target.value)}/></FG>
        <FG label="Purpose"><Sel value={pqcPurpose} onChange={(e)=>setPqcPurpose(e.target.value)}><option value="key-agreement">key-agreement</option><option value="key-encapsulation">key-encapsulation</option></Sel></FG>
      </Row2>
      <Chk label="Store in HSM (if HSM supports PQC)" checked={false}/>
      <Chk label="Auto-generate classical fallback key (for migration period)" checked={true}/>
      <div style={{display:"flex",justifyContent:"flex-end",gap:8,marginTop:12}}><Btn onClick={()=>setModal(null)}>Cancel</Btn><Btn primary onClick={generatePQCKey} disabled={pqcGenerating}>{pqcGenerating?"Generating...":"Generate PQC Key"}</Btn></div>
    </Modal>
  </div>;
};

