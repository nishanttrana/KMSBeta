// Enterprise KMS recommendation engine.
//
// Pure, deterministic rules over a snapshot of live platform state. Every rule
// cites the control it maps to (NIST SP 800-57/800-131A/IR 8547, PCI DSS 4.0,
// CNSA 2.0, DORA, CA/B Forum) and deep-links to the module where it is fixed.
//
// Honesty contract: a data source that could not be loaded is `undefined` in
// the snapshot and its rules are reported as "not assessed" — they never pass
// or fail on fabricated data, and never reduce the score.

export type Severity = "critical" | "high" | "medium" | "low";

export type RecCategory =
  | "Key lifecycle"
  | "Algorithms"
  | "Post-quantum"
  | "Access control"
  | "Certificates"
  | "Resilience"
  | "Posture";

export type Recommendation = {
  id: string;
  severity: Severity;
  category: RecCategory;
  title: string;
  why: string;
  fix: string;
  frameworks: string[];
  affected: number;
  evidence: string[];
  action: { tab: string; label: string };
};

export type ControlCheck = {
  id: string;
  label: string;
  category: RecCategory;
  status: "pass" | "fail" | "unknown";
};

export type SnapshotKey = {
  id: string;
  name: string;
  algorithm: string;
  status: string;
  export_allowed?: boolean;
  expires_at?: string;
  created_at?: string;
  updated_at?: string;
  current_version?: number;
  labels?: Record<string, string>;
  tags?: string[];
};

export type SnapshotCert = {
  id: string;
  subject_cn: string;
  algorithm: string;
  status: string;
  cert_class?: string;
  cert_type?: string;
  not_before?: string;
  not_after?: string;
};

export type PlatformSnapshot = {
  now: Date;
  keys?: SnapshotKey[] | undefined;
  certs?: SnapshotCert[] | undefined;
  rotationPolicies?: Array<{ enabled: boolean; target_type: string; auto_rotate: boolean; interval_days: number }> | undefined;
  /** Real encrypted backups (governance). The Backup tab's scheduler is a preview and never counts. */
  backups?: Array<{ status: string; completed_at?: string; created_at?: string }> | undefined;
  keyAccess?: {
    deny_by_default: boolean;
    require_approval_for_policy_change: boolean;
    grant_max_ttl_minutes: number;
    enforce_signed_requests: boolean;
  } | undefined;
  governancePolicies?: Array<{ status?: string | undefined }> | undefined;
  pqc?: { readiness_score: number; total_assets: number; classical_assets: number } | null | undefined;
  postureFindings?: Array<{ severity: string; status: string }> | undefined;
  cluster?: { total_nodes?: number | undefined; online_nodes?: number | undefined; degraded_nodes?: number | undefined; down_nodes?: number | undefined } | undefined;
  users?: Array<{ username: string; role: string; status: string; must_change_password: boolean }> | undefined;
  fipsEnabled?: boolean | undefined;
};

const DAY = 86_400_000;

const SEV_WEIGHT: Record<Severity, number> = { critical: 18, high: 9, medium: 4, low: 1.5 };
export const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low"];

function ts(v?: string): number | null {
  if (!v) return null;
  const n = Date.parse(v);
  return Number.isFinite(n) ? n : null;
}

function isActive(status: string): boolean {
  const s = String(status || "").toLowerCase();
  return s === "active" || s === "enabled" || s === "pre-active" || s === "preactive";
}

function sample(names: string[], max = 5): string[] {
  const out = names.slice(0, max);
  if (names.length > max) out.push(`+${names.length - max} more`);
  return out;
}

// ── Algorithm classification ─────────────────────────────────────────────
export function algoStrength(raw: string): "broken" | "legacy" | "sub-cnsa" | "ok" {
  const a = String(raw || "").toUpperCase().replace(/[_\s]/g, "-");
  if (!a) return "ok";
  if (/(^|[^A-Z])(DES|3DES|TDES|TDEA|DESEDE|RC4|MD5)([^A-Z]|$)/.test(a) || /SHA-?1([^0-9]|$)/.test(a)) return "broken";
  const rsa = a.match(/RSA-?(\d{3,5})/);
  if (rsa) {
    const bits = Number(rsa[1]);
    if (bits < 2048) return "broken";
    if (bits < 3072) return "legacy";
    return "ok";
  }
  if (/P-?192|P-?224|SECP192|SECP224/.test(a)) return "broken";
  if (/AES-?128/.test(a)) return "sub-cnsa";
  return "ok";
}

export function isQuantumVulnerable(raw: string): boolean {
  const a = String(raw || "").toUpperCase();
  if (/ML-?KEM|ML-?DSA|SLH-?DSA|KYBER|DILITHIUM|SPHINCS|FALCON|FN-?DSA|LMS|XMSS|HYBRID|COMPOSITE/.test(a)) return false;
  return /RSA|ECDSA|ECDH|^EC|EC-|P-?256|P-?384|P-?521|ED25519|ED448|X25519|X448|DSA|DH|SECP/.test(a);
}

function isAsymmetric(raw: string): boolean {
  return isQuantumVulnerable(raw) || /ML-?KEM|ML-?DSA|SLH-?DSA/.test(String(raw || "").toUpperCase());
}

// ── Engine ───────────────────────────────────────────────────────────────
export function evaluate(s: PlatformSnapshot): { recommendations: Recommendation[]; checks: ControlCheck[] } {
  const recs: Recommendation[] = [];
  const checks: ControlCheck[] = [];
  const now = s.now.getTime();
  const check = (id: string, label: string, category: RecCategory, known: boolean, failed: boolean) =>
    checks.push({ id, label, category, status: !known ? "unknown" : failed ? "fail" : "pass" });

  // ── Keys ──
  const keys = s.keys?.filter((k) => isActive(k.status));
  if (keys) {
    const broken = keys.filter((k) => algoStrength(k.algorithm) === "broken");
    check("algo-broken", "No broken algorithms in use", "Algorithms", true, broken.length > 0);
    if (broken.length) {
      recs.push({
        id: "algo-broken", severity: "critical", category: "Algorithms",
        title: `Retire ${broken.length} key${broken.length > 1 ? "s" : ""} using disallowed algorithms`,
        why: "DES/3DES, RSA below 2048 bits, SHA-1, MD5 and sub-224-bit curves are disallowed for protection. Data protected by them should be treated as exposed.",
        fix: "Create replacement keys (AES-256-GCM, RSA-3072+, ECDSA P-384 or ML-DSA), re-encrypt/re-sign, then deactivate and destroy the old keys.",
        frameworks: ["NIST SP 800-131A r3", "PCI DSS 4.0 §3.6.1", "CNSA 2.0"],
        affected: broken.length, evidence: sample(broken.map((k) => `${k.name} (${k.algorithm})`)),
        action: { tab: "keys", label: "Open Key Management" },
      });
    }
    const legacy = keys.filter((k) => algoStrength(k.algorithm) === "legacy");
    if (legacy.length) {
      recs.push({
        id: "algo-legacy", severity: "medium", category: "Algorithms",
        title: `Plan replacement of ${legacy.length} RSA-2048 key${legacy.length > 1 ? "s" : ""}`,
        why: "112-bit security (RSA-2048) is deprecated after 2030 and disallowed after 2035 under NIST IR 8547.",
        fix: "Move signing keys to ML-DSA (or hybrid RSA-3072 + ML-DSA) and key-establishment to ML-KEM as part of the PQC migration plan.",
        frameworks: ["NIST IR 8547", "NIST SP 800-131A r3"],
        affected: legacy.length, evidence: sample(legacy.map((k) => k.name)),
        action: { tab: "crypto_agility", label: "Open Crypto Agility" },
      });
    }
    const aes128 = keys.filter((k) => algoStrength(k.algorithm) === "sub-cnsa");
    if (aes128.length) {
      recs.push({
        id: "algo-aes128", severity: "low", category: "Algorithms",
        title: `${aes128.length} AES-128 key${aes128.length > 1 ? "s" : ""} below CNSA 2.0 / quantum-safe symmetric strength`,
        why: "Grover's algorithm halves effective symmetric strength; CNSA 2.0 requires AES-256 for national-security systems.",
        fix: "Use AES-256 for new keys; rotate AES-128 keys to AES-256 at their next rotation.",
        frameworks: ["CNSA 2.0"], affected: aes128.length, evidence: sample(aes128.map((k) => k.name)),
        action: { tab: "keys", label: "Open Key Management" },
      });
    }

    const qv = keys.filter((k) => isQuantumVulnerable(k.algorithm));
    const asym = keys.filter((k) => isAsymmetric(k.algorithm));
    check("pqc-keys", "Asymmetric keys have a PQC path", "Post-quantum", true, qv.length > 0);
    if (qv.length) {
      const longLived = qv.filter((k) => { const e = ts(k.expires_at); return e === null || e > Date.UTC(2030, 0, 1); });
      recs.push({
        id: "pqc-migrate", severity: longLived.length ? "high" : "medium", category: "Post-quantum",
        title: `${qv.length} of ${asym.length} asymmetric keys are quantum-vulnerable`,
        why: `${longLived.length} of them have no expiry or live beyond 2030 — data they protect today is exposed to harvest-now-decrypt-later. RSA/ECC are deprecated in 2030 and disallowed in 2035.`,
        fix: "Run a PQC readiness scan, prioritise long-lived and key-establishment keys, and migrate to ML-KEM-768/1024 and ML-DSA-65/87 (hybrid first where interop requires).",
        frameworks: ["NIST IR 8547", "FIPS 203/204/205", "CNSA 2.0"],
        affected: qv.length, evidence: sample(longLived.map((k) => `${k.name} (${k.algorithm})`)),
        action: { tab: "crypto_agility", label: "Plan PQC migration" },
      });
    }

    const noExpiry = keys.filter((k) => !k.expires_at);
    check("cryptoperiod", "Every key has a defined cryptoperiod", "Key lifecycle", true, noExpiry.length > 0);
    if (noExpiry.length) {
      recs.push({
        id: "no-cryptoperiod", severity: noExpiry.length > keys.length / 2 ? "high" : "medium", category: "Key lifecycle",
        title: `${noExpiry.length} active key${noExpiry.length > 1 ? "s have" : " has"} no cryptoperiod`,
        why: "Keys without an expiry never force re-keying, so compromise exposure and ciphertext volume grow without bound.",
        fix: "Set an expiry/deactivation date per key type (e.g. ≤2 years for symmetric data-encryption keys) and attach a rotation policy.",
        frameworks: ["NIST SP 800-57 Pt1 §5.3", "PCI DSS 4.0 §3.6.4"],
        affected: noExpiry.length, evidence: sample(noExpiry.map((k) => k.name)),
        action: { tab: "keys", label: "Set cryptoperiods" },
      });
    }

    const expiredActive = keys.filter((k) => { const e = ts(k.expires_at); return e !== null && e < now; });
    if (expiredActive.length) {
      recs.push({
        id: "expired-active", severity: "high", category: "Key lifecycle",
        title: `${expiredActive.length} key${expiredActive.length > 1 ? "s are" : " is"} past expiry but still active`,
        why: "A key past its cryptoperiod must not be used to protect new data.",
        fix: "Rotate to a new version, then move the old key to deactivated (decrypt/verify-only).",
        frameworks: ["NIST SP 800-57 Pt1 §5.3", "PCI DSS 4.0 §3.6.4"],
        affected: expiredActive.length, evidence: sample(expiredActive.map((k) => k.name)),
        action: { tab: "keys", label: "Rotate keys" },
      });
    }

    const stale = keys.filter((k) => {
      const t = ts(k.updated_at) ?? ts(k.created_at);
      return !isAsymmetric(k.algorithm) && (k.current_version ?? 1) <= 1 && t !== null && now - t > 365 * DAY;
    });
    if (stale.length) {
      recs.push({
        id: "never-rotated", severity: "medium", category: "Key lifecycle",
        title: `${stale.length} symmetric key${stale.length > 1 ? "s" : ""} never rotated in over a year`,
        why: "Long-lived single-version keys increase the blast radius of any compromise.",
        fix: "Rotate now and cover them with an automatic rotation policy.",
        frameworks: ["NIST SP 800-57 Pt1", "PCI DSS 4.0 §3.7.4"],
        affected: stale.length, evidence: sample(stale.map((k) => k.name)),
        action: { tab: "rotation", label: "Open Rotation & Scheduling" },
      });
    }

    const exportable = keys.filter((k) => k.export_allowed);
    check("non-exportable", "Keys are non-exportable by default", "Access control", true, exportable.length > 0);
    if (exportable.length) {
      recs.push({
        id: "exportable", severity: exportable.length > 10 ? "medium" : "low", category: "Access control",
        title: `${exportable.length} key${exportable.length > 1 ? "s allow" : " allows"} export`,
        why: "Exportable key material can leave the cryptographic boundary; enterprise KMS keys should be non-exportable unless a documented use case needs it.",
        fix: "Disable export on keys that do not need it; require wrapped export under dual control for the rest.",
        frameworks: ["PCI DSS 4.0 §3.6.1", "FIPS 140-3"],
        affected: exportable.length, evidence: sample(exportable.map((k) => k.name)),
        action: { tab: "keys", label: "Review export policy" },
      });
    }

    const unowned = keys.filter((k) => !(k.labels && (k.labels.owner || k.labels.app || k.labels.application || k.labels.team)));
    check("inventory", "Key inventory has owners", "Key lifecycle", true, unowned.length > 0);
    if (unowned.length) {
      recs.push({
        id: "unowned", severity: "low", category: "Key lifecycle",
        title: `${unowned.length} key${unowned.length > 1 ? "s have" : " has"} no owner label`,
        why: "A crypto inventory must record who owns each key and what it protects, so rotation and incident response can be routed.",
        fix: "Add owner / application labels (or enforce them in key templates).",
        frameworks: ["PCI DSS 4.0 §12.3.3", "DORA Art. 9"],
        affected: unowned.length, evidence: sample(unowned.map((k) => k.name)),
        action: { tab: "keys", label: "Label keys" },
      });
    }
  } else {
    ["algo-broken:No broken algorithms in use:Algorithms", "pqc-keys:Asymmetric keys have a PQC path:Post-quantum", "cryptoperiod:Every key has a defined cryptoperiod:Key lifecycle", "non-exportable:Keys are non-exportable by default:Access control", "inventory:Key inventory has owners:Key lifecycle"]
      .forEach((x) => { const [id = "", label = "", cat = ""] = x.split(":"); check(id, label, cat as RecCategory, false, false); });
  }

  // ── Rotation policy ──
  if (s.rotationPolicies) {
    const active = s.rotationPolicies.filter((p) => p.enabled && p.target_type === "key");
    check("rotation-policy", "Automatic key rotation is configured", "Key lifecycle", true, active.length === 0);
    if (!active.length) {
      recs.push({
        id: "no-rotation-policy", severity: "high", category: "Key lifecycle",
        title: "No automatic key rotation policy is enabled",
        why: "Rotation that depends on people remembering is the most common cause of expired cryptoperiods in audits.",
        fix: "Create a rotation policy per key class (tag selector) with auto-rotate and a notification lead time.",
        frameworks: ["NIST SP 800-57 Pt1", "PCI DSS 4.0 §3.6.4"], affected: 0, evidence: [],
        action: { tab: "rotation", label: "Create rotation policy" },
      });
    }
  } else check("rotation-policy", "Automatic key rotation is configured", "Key lifecycle", false, false);

  // ── Access control ──
  if (s.keyAccess) {
    const ka = s.keyAccess;
    check("deny-default", "Key access is deny-by-default", "Access control", true, !ka.deny_by_default);
    if (!ka.deny_by_default) {
      recs.push({
        id: "deny-default", severity: "high", category: "Access control",
        title: "Key access is not deny-by-default",
        why: "Without deny-by-default any authenticated principal in the tenant can use keys that lack an explicit policy.",
        fix: "Enable deny-by-default and grant access per key, group or interface (least privilege / zero trust).",
        frameworks: ["NIST SP 800-207", "PCI DSS 4.0 §7.2", "DORA Art. 9"], affected: 0, evidence: [],
        action: { tab: "keys", label: "Open access settings" },
      });
    }
    check("dual-control", "Policy changes need approval (dual control)", "Access control", true, !ka.require_approval_for_policy_change);
    if (!ka.require_approval_for_policy_change) {
      recs.push({
        id: "dual-control", severity: "medium", category: "Access control",
        title: "Key access policy changes do not require approval",
        why: "A single administrator can silently grant themselves key usage — split knowledge and dual control are required for key management.",
        fix: "Require approval for key access policy changes and route them through a governance quorum.",
        frameworks: ["PCI DSS 4.0 §3.6.1.2", "ISO 27001 A.8.24"], affected: 0, evidence: [],
        action: { tab: "approvals", label: "Configure approvals" },
      });
    }
    check("signed-requests", "API requests are signed with replay protection", "Access control", true, !ka.enforce_signed_requests);
    if (!ka.enforce_signed_requests) {
      recs.push({
        id: "signed-requests", severity: "low", category: "Access control",
        title: "Signed requests / replay protection not enforced for key operations",
        why: "Bearer tokens alone can be replayed if intercepted; HTTP message signatures or DPoP bind requests to the client key.",
        fix: "Enforce signed requests for machine clients (HTTP Message Signatures RFC 9421 or DPoP RFC 9449).",
        frameworks: ["RFC 9421", "RFC 9449"], affected: 0, evidence: [],
        action: { tab: "keys", label: "Open access settings" },
      });
    }
    if (ka.grant_max_ttl_minutes > 24 * 60) {
      recs.push({
        id: "grant-ttl", severity: "low", category: "Access control",
        title: `Access grants can last ${Math.round(ka.grant_max_ttl_minutes / 60)} hours`,
        why: "Long-lived grants turn just-in-time access into standing privilege.",
        fix: "Cap grant TTL at 8–24 hours and use approvals for longer windows.",
        frameworks: ["NIST SP 800-207"], affected: 0, evidence: [],
        action: { tab: "keys", label: "Open access settings" },
      });
    }
  } else {
    check("deny-default", "Key access is deny-by-default", "Access control", false, false);
    check("dual-control", "Policy changes need approval (dual control)", "Access control", false, false);
    check("signed-requests", "API requests are signed with replay protection", "Access control", false, false);
  }

  if (s.governancePolicies) {
    const live = s.governancePolicies.filter((p) => String(p.status || "active").toLowerCase() !== "disabled");
    check("quorum", "Quorum approval protects destructive operations", "Access control", true, live.length === 0);
    if (!live.length) {
      recs.push({
        id: "no-quorum", severity: "high", category: "Access control",
        title: "No quorum approval policy protects destroy / export",
        why: "Key destruction and export are irreversible; M-of-N approval prevents a single compromised admin from causing data loss.",
        fix: "Create a governance policy requiring 2-of-N approvers for key destroy, export and policy changes.",
        frameworks: ["PCI DSS 4.0 §3.6.1.2", "DORA Art. 9"], affected: 0, evidence: [],
        action: { tab: "approvals", label: "Create quorum policy" },
      });
    }
  } else check("quorum", "Quorum approval protects destructive operations", "Access control", false, false);

  if (s.users) {
    const admins = s.users.filter((u) => /admin/i.test(u.role) && String(u.status).toLowerCase() === "active");
    const defaultAdmin = s.users.find((u) => u.username === "admin" && u.must_change_password && String(u.status).toLowerCase() === "active");
    check("admin-count", "Administrator count is minimal", "Access control", true, admins.length > 5 || !!defaultAdmin);
    if (defaultAdmin) {
      recs.push({
        id: "default-admin", severity: "critical", category: "Access control",
        title: "Bootstrap admin account still has its initial password",
        why: "The seeded admin/changeit credential is publicly documented.",
        fix: "Sign in as admin to force the password change, or disable the account after creating named administrators with MFA.",
        frameworks: ["PCI DSS 4.0 §2.2.2", "CIS Controls 5.2"], affected: 1, evidence: ["admin"],
        action: { tab: "admin", label: "Open user management" },
      });
    }
    if (admins.length > 5) {
      recs.push({
        id: "too-many-admins", severity: "medium", category: "Access control",
        title: `${admins.length} active administrators`,
        why: "Every administrator can change key policy; a large admin set weakens separation of duties.",
        fix: "Reduce to named break-glass + a small operator group; move others to key-custodian or read-only roles.",
        frameworks: ["PCI DSS 4.0 §7.2.2", "ISO 27001 A.5.15"], affected: admins.length, evidence: sample(admins.map((u) => u.username)),
        action: { tab: "admin", label: "Review roles" },
      });
    }
  } else check("admin-count", "Administrator count is minimal", "Access control", false, false);

  // ── Certificates ──
  if (s.certs) {
    const live = s.certs.filter((c) => !/revoked|deleted/i.test(c.status));
    const expired = live.filter((c) => { const e = ts(c.not_after); return e !== null && e < now; });
    const soon = live.filter((c) => { const e = ts(c.not_after); return e !== null && e >= now && e - now < 30 * DAY; });
    const urgent = soon.filter((c) => (ts(c.not_after) as number) - now < 7 * DAY);
    check("cert-expiry", "No certificates expire within 30 days", "Certificates", true, soon.length + expired.length > 0);
    if (expired.length) {
      recs.push({
        id: "cert-expired", severity: "high", category: "Certificates",
        title: `${expired.length} certificate${expired.length > 1 ? "s have" : " has"} expired`,
        why: "Expired certificates cause outages and are frequently still deployed.",
        fix: "Renew or revoke; enable automatic renewal (ACME/ARI) for the issuing profile.",
        frameworks: ["NIST SP 1800-16"], affected: expired.length, evidence: sample(expired.map((c) => c.subject_cn)),
        action: { tab: "certs", label: "Open PKI" },
      });
    }
    if (soon.length) {
      recs.push({
        id: "cert-expiring", severity: urgent.length ? "high" : "medium", category: "Certificates",
        title: `${soon.length} certificate${soon.length > 1 ? "s expire" : " expires"} within 30 days`,
        why: `${urgent.length} expire within 7 days.`,
        fix: "Renew now and move these endpoints to automated renewal (ACME with ARI) so expiry stops being a manual task.",
        frameworks: ["NIST SP 1800-16"], affected: soon.length, evidence: sample(soon.map((c) => c.subject_cn)),
        action: { tab: "certs", label: "Renew certificates" },
      });
    }
    const weak = live.filter((c) => algoStrength(c.algorithm) === "broken");
    if (weak.length) {
      recs.push({
        id: "cert-weak", severity: "high", category: "Certificates",
        title: `${weak.length} certificate${weak.length > 1 ? "s use" : " uses"} a disallowed algorithm`,
        why: "SHA-1 signatures and sub-2048-bit RSA are rejected by modern clients and disallowed by NIST.",
        fix: "Re-issue with RSA-3072+/ECDSA P-384 (or ML-DSA for internal PKI).",
        frameworks: ["NIST SP 800-131A r3", "CA/B Forum BR"], affected: weak.length, evidence: sample(weak.map((c) => c.subject_cn)),
        action: { tab: "certs", label: "Re-issue certificates" },
      });
    }
    const longLeaf = live.filter((c) => {
      const cls = `${c.cert_class || ""} ${c.cert_type || ""}`.toLowerCase();
      if (/ca|root|intermediate/.test(cls) && !/leaf|server|tls|client/.test(cls)) return false;
      const a = ts(c.not_before), b = ts(c.not_after);
      return a !== null && b !== null && b - a > 200 * DAY && /tls|server|web/.test(cls);
    });
    if (longLeaf.length) {
      recs.push({
        id: "cert-lifetime", severity: "low", category: "Certificates",
        title: `${longLeaf.length} TLS certificate${longLeaf.length > 1 ? "s exceed" : " exceeds"} the 200-day public maximum`,
        why: "CA/B Forum ballot SC-081 caps public TLS lifetimes at 200 days (Mar 2026), 100 days (Mar 2027) and 47 days (Mar 2029). Internal PKI should follow to keep automation exercised.",
        fix: "Shorten profile validity and automate renewal.",
        frameworks: ["CA/B Forum SC-081"], affected: longLeaf.length, evidence: sample(longLeaf.map((c) => c.subject_cn)),
        action: { tab: "certs", label: "Edit profiles" },
      });
    }
  } else check("cert-expiry", "No certificates expire within 30 days", "Certificates", false, false);

  // ── Resilience ──
  if (s.backups) {
    const completed = s.backups.filter((b) => b.status === "completed");
    const lastOk = completed.map((b) => ts(b.completed_at || b.created_at || "") || 0).sort((a, b) => b - a)[0];
    const failed = !lastOk || now - lastOk > 7 * DAY;
    check("backup", "An encrypted backup was completed in the last 7 days", "Resilience", true, failed);
    if (failed) {
      recs.push({
        id: lastOk ? "backup-stale" : "no-backup",
        severity: lastOk ? "high" : "critical",
        category: "Resilience",
        title: lastOk ? `Last encrypted backup was ${Math.floor((now - lastOk) / DAY)} days ago` : "No encrypted backup has been taken",
        why: "Losing the key store means losing every piece of data it protects — crypto-shredding by accident.",
        fix: "System Administration > Backups: create a backup, keep the artifact and the key package in separate places, and test a restore.",
        frameworks: ["DORA Art. 12", "NIST SP 800-57 Pt2", "ISO 27001 A.8.13"], affected: 0, evidence: [],
        action: { tab: "admin", label: "Open System Administration" },
      });
    }
  } else check("backup", "An encrypted backup was completed in the last 7 days", "Resilience", false, false);

  if (s.cluster && (s.cluster.total_nodes ?? 0) > 0) {
    const total = s.cluster.total_nodes || 0;
    const down = (s.cluster.down_nodes || 0) + (s.cluster.degraded_nodes || 0);
    check("ha", "Key service is highly available", "Resilience", true, total < 2 || down > 0);
    if (total < 2) {
      recs.push({
        id: "single-node", severity: "medium", category: "Resilience",
        title: "KMS runs as a single node",
        why: "Every application that decrypts through the KMS stops when this node stops.",
        fix: "Add at least one replica node (ideally in a second site), and prove recovery by verifying a backup (System Administration > Backups > Verify Backup).",
        frameworks: ["DORA Art. 11", "ISO 22301"], affected: 1, evidence: [],
        action: { tab: "cluster", label: "Open Cluster" },
      });
    } else if (down > 0) {
      recs.push({
        id: "nodes-down", severity: "high", category: "Resilience",
        title: `${down} of ${total} cluster nodes are degraded or down`,
        why: "Reduced redundancy — another failure may cause an outage.",
        fix: "Check node health and replication lag in Cluster.",
        frameworks: ["DORA Art. 11"], affected: down, evidence: [],
        action: { tab: "cluster", label: "Open Cluster" },
      });
    }
  } else check("ha", "Key service is highly available", "Resilience", false, false);

  // ── Posture / PQC scan / FIPS ──
  if (s.postureFindings) {
    const open = s.postureFindings.filter((f) => !/resolved|closed|accepted|suppressed/i.test(f.status));
    const crit = open.filter((f) => /critical|high/i.test(f.severity));
    check("posture", "No open critical/high posture findings", "Posture", true, crit.length > 0);
    if (crit.length) {
      recs.push({
        id: "posture-open", severity: "high", category: "Posture",
        title: `${crit.length} open critical/high posture finding${crit.length > 1 ? "s" : ""}`,
        why: "Detected drift or risky behaviour that has not been triaged.",
        fix: "Triage in Posture; apply the recommended remediation or accept with justification.",
        frameworks: ["DORA Art. 10"], affected: crit.length, evidence: [],
        action: { tab: "posture", label: "Triage findings" },
      });
    }
  } else check("posture", "No open critical/high posture findings", "Posture", false, false);

  if (s.pqc !== undefined) {
    const scanned = !!s.pqc && s.pqc.total_assets > 0;
    check("pqc-scan", "PQC readiness has been assessed", "Post-quantum", true, !scanned || (s.pqc?.readiness_score ?? 0) < 50);
    if (!scanned) {
      recs.push({
        id: "pqc-scan", severity: "medium", category: "Post-quantum",
        title: "No post-quantum readiness scan on record",
        why: "A cryptographic inventory (CBOM) is the first step every PQC mandate requires.",
        fix: "Run a PQC readiness scan and export the CBOM.",
        frameworks: ["NIST IR 8547", "OMB M-23-02", "CNSA 2.0"], affected: 0, evidence: [],
        action: { tab: "sbom", label: "Open SBOM / CBOM" },
      });
    }
  } else check("pqc-scan", "PQC readiness has been assessed", "Post-quantum", false, false);

  if (s.fipsEnabled !== undefined) {
    check("fips", "FIPS 140-3 strict mode", "Algorithms", true, !s.fipsEnabled);
    if (!s.fipsEnabled) {
      recs.push({
        id: "fips-off", severity: "low", category: "Algorithms",
        title: "FIPS strict mode is off",
        why: "Regulated workloads (FedRAMP, PCI, many banking regulators) expect only FIPS 140-3 approved algorithms and modes.",
        fix: "Enable FIPS strict mode in Administration if this tenant serves regulated workloads.",
        frameworks: ["FIPS 140-3", "FedRAMP SC-13"], affected: 0, evidence: [],
        action: { tab: "admin", label: "Open Administration" },
      });
    }
  }

  recs.sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity) || b.affected - a.affected);
  return { recommendations: recs, checks };
}

export function postureScore(recs: Recommendation[], checks: ControlCheck[]): { score: number; grade: string; assessed: number } {
  const assessed = checks.filter((c) => c.status !== "unknown").length;
  if (!assessed) return { score: 0, grade: "–", assessed };
  const penalty = recs.reduce((sum, r) => sum + SEV_WEIGHT[r.severity], 0);
  const score = Math.max(0, Math.min(100, Math.round(100 - penalty)));
  const grade = score >= 90 ? "A" : score >= 80 ? "B" : score >= 65 ? "C" : score >= 50 ? "D" : "F";
  return { score, grade, assessed };
}
