import type { AuthSession } from "./auth";
import { serviceRequest } from "./serviceApi";

export type CertCA = {
  id: string;
  tenant_id: string;
  name: string;
  parent_ca_id?: string;
  ca_level: string;
  algorithm: string;
  ca_type: string;
  key_backend: string;
  key_ref?: string;
  cert_pem: string;
  subject?: string;
  status: string;
  ots_current?: number;
  ots_max?: number;
  ots_alert_threshold?: number;
  created_at?: string;
  updated_at?: string;
};

export type CertificateItem = {
  id: string;
  tenant_id: string;
  ca_id: string;
  serial_number: string;
  subject_cn: string;
  sans?: string[];
  cert_type: string;
  algorithm: string;
  profile_id?: string;
  protocol?: string;
  cert_class: string;
  cert_pem: string;
  status: string;
  not_before?: string;
  not_after?: string;
  revoked_at?: string;
  revocation_reason?: string;
  created_at?: string;
  updated_at?: string;
  key_ref?: string;
};

export type CertificateProfile = {
  id: string;
  tenant_id: string;
  name: string;
  cert_type: string;
  algorithm: string;
  cert_class: string;
  profile_json: string;
  is_default: boolean;
  created_at?: string;
};

export type InventoryCertificateItem = {
  cert_id: string;
  ca_id: string;
  cert_type: string;
  cert_class: string;
  status: string;
  not_after: string;
  profile_id?: string;
};

export type ProtocolConfig = {
  tenant_id: string;
  protocol: "acme" | "est" | "scep" | "cmpv2" | "runtime-mtls";
  enabled: boolean;
  config_json: string;
  updated_by?: string;
  updated_at?: string;
};

export type ProtocolOptionSchema = {
  key: string;
  type: string;
  required: boolean;
  default_value: unknown;
  allowed?: string[];
  description: string;
};

export type ProtocolImplementationSchema = {
  engine: string;
  language: string;
  oss_only: boolean;
  sdks?: string[];
  hardening?: string[];
  notes?: string;
};

export type CertExpiryAlertPolicy = {
  tenant_id: string;
  days_before: number;
  include_external: boolean;
  updated_by?: string;
  updated_at?: string;
};

export type CertSecurityStatus = {
  storage_mode: string;
  root_key_mode: string;
  ready: boolean;
  state: string;
  key_version?: string;
  sealed_path?: string;
  use_tpm_seal?: boolean;
  mlock_status?: string;
  last_error?: string;
};

export type ProtocolSchema = {
  protocol: "acme" | "est" | "scep" | "cmpv2" | "runtime-mtls";
  title: string;
  rfc: string;
  description: string;
  defaults: Record<string, unknown>;
  options?: ProtocolOptionSchema[];
  implementation?: ProtocolImplementationSchema;
};

type CAsResponse = { items: CertCA[] };
type CertsResponse = { items: CertificateItem[] };
type ProfilesResponse = { items: CertificateProfile[] };
type InventoryResponse = { items: InventoryCertificateItem[] };
type ProtocolsResponse = { items: ProtocolConfig[] };
type ProtocolSchemasResponse = { items: ProtocolSchema[] };
type AlertPolicyResponse = { policy: CertExpiryAlertPolicy };
type CertSecurityStatusResponse = { status: CertSecurityStatus };
type CAResponse = { ca: CertCA };
type CertResponse = { certificate: CertificateItem; private_key_pem?: string };
type ConfigResponse = { config: ProtocolConfig };
type StatusResponse = { status: string };
type CRLResponse = { crl_pem: string; generated_at: string };
type OCSPResponse = { status: string; reason?: string; produced_at?: string };
type DownloadResponse = { content: string; content_type: string };
type AcmeNewAccountResponse = { account_id: string; status: string };
type AcmeNewOrderResponse = {
  order_id: string;
  challenge_id: string;
  status: string;
  finalize_url?: string;
  challenge_url?: string;
  authorizations?: Array<{
    identifier: { type: string; value: string };
    status: string;
    challenges: Array<{ type: string; url: string; status: string }>;
  }>;
};
type AcmeChallengeInfoResponse = {
  challenge: {
    type: string;
    url: string;
    token: string;
    instructions: string;
    status: string;
  };
};
type ESTCSRAttrsResponse = {
  csrattrs: {
    algorithms: string[];
    key_lengths: number[];
    challenge_format: string;
    profile_ids: string[];
  };
};
type CMPv2ConfirmResponse = {
  confirmation: {
    transaction_id: string;
    status: string;
    cert_id: string;
    message: string;
  };
};

export type CreateCAInput = {
  name: string;
  parent_ca_id?: string;
  ca_level: "root" | "intermediate";
  algorithm: string;
  ca_type?: string;
  key_backend: "software" | "keycore" | "hsm";
  key_ref?: string;
  subject: string;
  validity_days?: number;
  ots_max?: number;
  ots_alert_threshold?: number;
};

export type IssueCertificateInput = {
  ca_id: string;
  profile_id?: string;
  cert_type?: string;
  algorithm?: string;
  cert_class?: string;
  subject_cn: string;
  sans?: string[];
  csr_pem?: string;
  server_keygen?: boolean;
  validity_days?: number;
  not_after?: string;
  protocol?: string;
  metadata_json?: string;
};

export type DownloadCertificateInput = {
  asset?: "certificate" | "chain" | "ca" | "public-key" | "pkcs11";
  format?: "pem" | "der" | "pkcs12" | "pfx" | "pkcs8";
  include_chain?: boolean;
  password?: string;
};

export type DownloadCertificateOutput = {
  content: string;
  contentType: string;
};

export type UploadThirdPartyCertificateInput = {
  purpose: string;
  certificate_pem: string;
  private_key_pem?: string;
  ca_bundle_pem?: string;
  set_active?: boolean;
  enable_ocsp_stapling?: boolean;
  auto_renew_acme?: boolean;
  updated_by?: string;
};

export type UpdateProtocolConfigInput = {
  enabled: boolean;
  config_json?: string;
  updated_by?: string;
};

export type AcmeOrderInput = {
  ca_id: string;
  account_id: string;
  subject_cn: string;
  sans?: string[];
  challenge_type?: string;
  external_account_id?: string;
  external_hmac?: string;
};

export type ESTServerKeygenInput = {
	ca_id: string;
	profile_id?: string;
	subject_cn: string;
	sans?: string[];
	auth_method?: string;
	auth_token?: string;
};

export type IssueInternalMTLSInput = {
	ca_id?: string;
	algorithm?: string;
	cert_class?: string;
	protocol?: string;
	validity_days?: number;
};

export type SCEPEnrollInput = {
  ca_id: string;
  csr_pem?: string;
  transaction_id?: string;
  message_type?: string;
  challenge_password?: string;
  cert_id?: string;
};

export type CMPv2Input = {
  ca_id: string;
  message_type: "ir" | "cr" | "kur" | "rr";
  csr_pem?: string;
  cert_id?: string;
  payload_json?: string;
  transaction_id?: string;
  protected?: boolean;
  protection_alg?: string;
};

function tenantQuery(session: AuthSession): string {
  return `tenant_id=${encodeURIComponent(session.tenantId)}`;
}

export async function listCAs(session: AuthSession): Promise<CertCA[]> {
  const out = await serviceRequest<CAsResponse>(session, "certs", `/certs/ca?${tenantQuery(session)}`);
  return Array.isArray(out?.items) ? out.items : [];
}

export async function createCA(session: AuthSession, input: CreateCAInput): Promise<CertCA> {
  const out = await serviceRequest<CAResponse>(session, "certs", "/certs/ca", {
    method: "POST",
    body: JSON.stringify({
      tenant_id: session.tenantId,
      ...input
    })
  });
  return out.ca;
}

export async function deleteCA(session: AuthSession, caId: string, force = false): Promise<void> {
  const q = new URLSearchParams();
  q.set("tenant_id", session.tenantId);
  if (force) {
    q.set("force", "true");
  }
  await serviceRequest<StatusResponse>(
    session,
    "certs",
    `/certs/ca/${encodeURIComponent(String(caId || "").trim())}?${q.toString()}`,
    {
      method: "DELETE"
    }
  );
}

export async function listCertificates(
  session: AuthSession,
  options?: { status?: string; cert_class?: string; limit?: number; offset?: number }
): Promise<CertificateItem[]> {
  const q = new URLSearchParams();
  q.set("tenant_id", session.tenantId);
  q.set("limit", String(Math.max(1, Math.min(500, Math.trunc(Number(options?.limit || 200))))));
  q.set("offset", String(Math.max(0, Math.trunc(Number(options?.offset || 0)))));
  if (String(options?.status || "").trim()) {
    q.set("status", String(options?.status || "").trim());
  }
  if (String(options?.cert_class || "").trim()) {
    q.set("cert_class", String(options?.cert_class || "").trim());
  }
  const out = await serviceRequest<CertsResponse>(session, "certs", `/certs?${q.toString()}`);
  return Array.isArray(out?.items) ? out.items : [];
}

export async function issueCertificate(
  session: AuthSession,
  input: IssueCertificateInput
): Promise<{ certificate: CertificateItem; privateKeyPEM?: string }> {
  const out = await serviceRequest<CertResponse>(session, "certs", "/certs", {
    method: "POST",
    body: JSON.stringify({
      tenant_id: session.tenantId,
      ...input
    })
  });
  return {
    certificate: out.certificate,
    privateKeyPEM: out.private_key_pem || ""
  };
}

export async function signCertificateCSR(
  session: AuthSession,
  input: Omit<IssueCertificateInput, "subject_cn"> & { csr_pem: string; subject_cn?: string }
): Promise<CertificateItem> {
  const out = await serviceRequest<CertResponse>(session, "certs", "/certs/sign-csr", {
    method: "POST",
    body: JSON.stringify({
      tenant_id: session.tenantId,
      ...input,
      server_keygen: false
    })
  });
  return out.certificate;
}

export async function renewCertificate(
  session: AuthSession,
  certId: string,
  validityDays?: number
): Promise<CertificateItem> {
  const out = await serviceRequest<CertResponse>(
    session,
    "certs",
    `/certs/${encodeURIComponent(String(certId || "").trim())}/renew?${tenantQuery(session)}`,
    {
      method: "POST",
      body: JSON.stringify({
        validity_days: Number.isFinite(Number(validityDays)) ? Number(validityDays) : 0
      })
    }
  );
  return out.certificate;
}

export async function revokeCertificate(
  session: AuthSession,
  certId: string,
  reason = "unspecified"
): Promise<void> {
  await serviceRequest<StatusResponse>(
    session,
    "certs",
    `/certs/${encodeURIComponent(String(certId || "").trim())}/revoke?${tenantQuery(session)}`,
    {
      method: "POST",
      body: JSON.stringify({
        reason: String(reason || "").trim() || "unspecified"
      })
    }
  );
}

export async function deleteCertificate(session: AuthSession, certId: string): Promise<void> {
  await serviceRequest<StatusResponse>(
    session,
    "certs",
    `/certs/${encodeURIComponent(String(certId || "").trim())}?${tenantQuery(session)}`,
    {
      method: "DELETE"
    }
  );
}

export async function downloadCertificateAsset(
  session: AuthSession,
  certId: string,
  input?: DownloadCertificateInput
): Promise<DownloadCertificateOutput> {
  const q = new URLSearchParams();
  q.set("tenant_id", session.tenantId);
  if (String(input?.asset || "").trim()) {
    q.set("asset", String(input?.asset || "").trim());
  }
  if (String(input?.format || "").trim()) {
    q.set("format", String(input?.format || "").trim());
  }
  if (typeof input?.include_chain === "boolean") {
    q.set("include_chain", String(Boolean(input?.include_chain)));
  }
  if (String(input?.password || "").trim()) {
    q.set("password", String(input?.password || ""));
  }
  const out = await serviceRequest<DownloadResponse>(
    session,
    "certs",
    `/certs/download/${encodeURIComponent(String(certId || "").trim())}?${q.toString()}`
  );
  return {
    content: String(out?.content || ""),
    contentType: String(out?.content_type || "application/octet-stream")
  };
}

export async function getCRL(session: AuthSession, caId: string): Promise<CRLResponse> {
  return serviceRequest<CRLResponse>(
    session,
    "certs",
    `/certs/crl?${tenantQuery(session)}&ca_id=${encodeURIComponent(String(caId || "").trim())}`
  );
}

export async function getOCSP(
  session: AuthSession,
  input: { cert_id?: string; serial_number?: string }
): Promise<OCSPResponse> {
  const q = new URLSearchParams();
  q.set("tenant_id", session.tenantId);
  if (String(input?.cert_id || "").trim()) {
    q.set("cert_id", String(input?.cert_id || "").trim());
  }
  if (String(input?.serial_number || "").trim()) {
    q.set("serial_number", String(input?.serial_number || "").trim());
  }
  return serviceRequest<OCSPResponse>(session, "certs", `/certs/ocsp?${q.toString()}`);
}

export async function listProfiles(session: AuthSession): Promise<CertificateProfile[]> {
  const out = await serviceRequest<ProfilesResponse>(session, "certs", `/certs/profiles?${tenantQuery(session)}`);
  return Array.isArray(out?.items) ? out.items : [];
}

export async function listInventory(session: AuthSession): Promise<InventoryCertificateItem[]> {
  const out = await serviceRequest<InventoryResponse>(session, "certs", `/certs/inventory?${tenantQuery(session)}`);
  return Array.isArray(out?.items) ? out.items : [];
}

export async function getCertSecurityStatus(session: AuthSession): Promise<CertSecurityStatus> {
  const out = await serviceRequest<CertSecurityStatusResponse>(
    session,
    "certs",
    `/certs/security/status?${tenantQuery(session)}`
  );
  return out?.status || {
    storage_mode: "unknown",
    root_key_mode: "unknown",
    ready: false,
    state: "unknown"
  };
}

export async function getCertExpiryAlertPolicy(session: AuthSession): Promise<CertExpiryAlertPolicy> {
  const out = await serviceRequest<AlertPolicyResponse>(session, "certs", `/certs/alert-policy?${tenantQuery(session)}`);
  return out.policy;
}

export async function updateCertExpiryAlertPolicy(
  session: AuthSession,
  input: { days_before: number; include_external: boolean; updated_by?: string }
): Promise<CertExpiryAlertPolicy> {
  const out = await serviceRequest<AlertPolicyResponse>(session, "certs", `/certs/alert-policy?${tenantQuery(session)}`, {
    method: "PUT",
    body: JSON.stringify({
      days_before: Math.max(1, Math.min(3650, Math.trunc(Number(input.days_before || 30)))),
      include_external: Boolean(input.include_external),
      updated_by: String(input.updated_by || session.username || "dashboard").trim() || "dashboard"
    })
  });
  return out.policy;
}

export async function uploadThirdPartyCertificate(
  session: AuthSession,
  input: UploadThirdPartyCertificateInput
): Promise<CertificateItem> {
  const out = await serviceRequest<CertResponse>(session, "certs", "/certs/upload-3p", {
    method: "POST",
    body: JSON.stringify({
      tenant_id: session.tenantId,
      purpose: input.purpose,
      certificate_pem: input.certificate_pem,
      private_key_pem: input.private_key_pem || "",
      ca_bundle_pem: input.ca_bundle_pem || "",
      set_active: Boolean(input.set_active),
      enable_ocsp_stapling: Boolean(input.enable_ocsp_stapling),
      auto_renew_acme: Boolean(input.auto_renew_acme),
      updated_by: input.updated_by || session.username || "dashboard"
    })
  });
  return out.certificate;
}

export async function listProtocolConfigs(session: AuthSession): Promise<ProtocolConfig[]> {
  const out = await serviceRequest<ProtocolsResponse>(session, "certs", `/certs/protocols?${tenantQuery(session)}`);
  return Array.isArray(out?.items) ? out.items : [];
}

export async function listProtocolSchemas(session: AuthSession): Promise<ProtocolSchema[]> {
  const out = await serviceRequest<ProtocolSchemasResponse>(
    session,
    "certs",
    `/certs/protocols/schema?${tenantQuery(session)}`
  );
  return Array.isArray(out?.items) ? out.items : [];
}

export async function updateProtocolConfig(
  session: AuthSession,
  protocol: "acme" | "est" | "scep" | "cmpv2" | "runtime-mtls",
  input: UpdateProtocolConfigInput
): Promise<ProtocolConfig> {
  const out = await serviceRequest<ConfigResponse>(
    session,
    "certs",
    `/certs/protocols/${encodeURIComponent(protocol)}?${tenantQuery(session)}`,
    {
      method: "PUT",
      body: JSON.stringify({
        enabled: Boolean(input.enabled),
        config_json: String(input.config_json || "{}"),
        updated_by: input.updated_by || session.username || "dashboard"
      })
    }
  );
  return out.config;
}

export async function acmeNewAccount(session: AuthSession, email: string): Promise<AcmeNewAccountResponse> {
  return serviceRequest<AcmeNewAccountResponse>(session, "certs", "/acme/new-account", {
    method: "POST",
    body: JSON.stringify({
      tenant_id: session.tenantId,
      email
    })
  });
}

export async function acmeNewOrder(session: AuthSession, input: AcmeOrderInput): Promise<AcmeNewOrderResponse> {
  return serviceRequest<AcmeNewOrderResponse>(session, "certs", "/acme/new-order", {
    method: "POST",
    body: JSON.stringify({
      tenant_id: session.tenantId,
      ca_id: input.ca_id,
      account_id: input.account_id,
      subject_cn: input.subject_cn,
      sans: Array.isArray(input.sans) ? input.sans : [],
      challenge_type: String(input.challenge_type || "").trim(),
      external_account_id: String(input.external_account_id || "").trim(),
      external_hmac: String(input.external_hmac || "").trim()
    })
  });
}

export async function acmeChallengeComplete(
  session: AuthSession,
  challengeId: string,
  orderId: string
): Promise<void> {
  await serviceRequest(session, "certs", `/acme/challenge/${encodeURIComponent(challengeId)}`, {
    method: "POST",
    body: JSON.stringify({
      tenant_id: session.tenantId,
      order_id: orderId,
      success: true
    })
  });
}

export async function acmeFinalize(session: AuthSession, orderId: string, csrPem = ""): Promise<CertificateItem> {
  const out = await serviceRequest<CertResponse>(
    session,
    "certs",
    `/acme/finalize/${encodeURIComponent(orderId)}`,
    {
      method: "POST",
      body: JSON.stringify({
        tenant_id: session.tenantId,
        csr_pem: csrPem
      })
    }
  );
  return out.certificate;
}

export async function estServerKeygen(session: AuthSession, input: ESTServerKeygenInput): Promise<CertificateItem> {
  const out = await serviceRequest<CertResponse>(session, "certs", "/est/.well-known/est/serverkeygen", {
    method: "POST",
    body: JSON.stringify({
      tenant_id: session.tenantId,
      ca_id: input.ca_id,
      profile_id: input.profile_id || "",
      subject_cn: input.subject_cn,
      sans: Array.isArray(input.sans) ? input.sans : [],
      auth_method: String(input.auth_method || "").trim(),
      auth_token: String(input.auth_token || "").trim()
    })
  });
  return out.certificate;
}

export async function scepEnroll(session: AuthSession, input: SCEPEnrollInput): Promise<CertificateItem> {
  const out = await serviceRequest<CertResponse>(
    session,
    "certs",
    "/scep/pkiclient.exe?operation=pkioperation",
    {
      method: "POST",
      body: JSON.stringify({
        tenant_id: session.tenantId,
        ca_id: input.ca_id,
        csr_pem: input.csr_pem || "",
        transaction_id: input.transaction_id || "",
        message_type: input.message_type || "",
        challenge_password: input.challenge_password || "",
        cert_id: input.cert_id || ""
      })
    }
  );
  return out.certificate;
}

export async function cmpv2Request(session: AuthSession, input: CMPv2Input): Promise<CertificateItem> {
  const out = await serviceRequest<CertResponse>(session, "certs", "/cmpv2", {
    method: "POST",
    body: JSON.stringify({
      tenant_id: session.tenantId,
      ca_id: input.ca_id,
      message_type: input.message_type,
      csr_pem: input.csr_pem || "",
      cert_id: input.cert_id || "",
      payload_json: input.payload_json || "",
      transaction_id: input.transaction_id || "",
      protected: Boolean(input.protected),
      protection_alg: input.protection_alg || ""
    })
  });
  return out.certificate;
}

export async function issueInternalMTLS(
	session: AuthSession,
	serviceName: string,
	input?: IssueInternalMTLSInput
): Promise<{ certificate: CertificateItem; privateKeyPEM?: string }> {
	const service = String(serviceName || "").trim().toLowerCase();
	if (!service) {
		throw new Error("service name is required");
	}
	const out = await serviceRequest<CertResponse>(
		session,
		"certs",
		`/certs/internal/mtls/${encodeURIComponent(service)}?${tenantQuery(session)}`,
		{
			method: "POST",
			body: JSON.stringify({
				tenant_id: session.tenantId,
				ca_id: String(input?.ca_id || "").trim(),
				algorithm: String(input?.algorithm || "").trim(),
				cert_class: String(input?.cert_class || "").trim(),
				protocol: String(input?.protocol || "").trim(),
				validity_days: Number.isFinite(Number(input?.validity_days))
					? Math.max(1, Math.min(3650, Math.trunc(Number(input?.validity_days || 365))))
					: 365
			})
		}
	);
	return {
		certificate: out.certificate,
		privateKeyPEM: out.private_key_pem || ""
	};
}

// ── ACME challenge info (GET) ──────────────────────────────────────
export async function acmeChallengeInfo(
  session: AuthSession,
  challengeId: string,
  orderId: string
): Promise<AcmeChallengeInfoResponse["challenge"]> {
  const out = await serviceRequest<AcmeChallengeInfoResponse>(
    session,
    "certs",
    `/acme/challenge/${encodeURIComponent(challengeId)}?${tenantQuery(session)}&order_id=${encodeURIComponent(orderId)}`,
    { method: "GET" }
  );
  return out.challenge;
}

// ── EST CSR Attributes (RFC 7030 §4.5) ────────────────────────────
export async function estCSRAttributes(session: AuthSession): Promise<ESTCSRAttrsResponse["csrattrs"]> {
  const out = await serviceRequest<ESTCSRAttrsResponse>(
    session,
    "certs",
    `/est/.well-known/est/csrattrs?${tenantQuery(session)}`
  );
  return out.csrattrs;
}

// ── EST SimpleEnroll (JSON path) ──────────────────────────────────
export async function estSimpleEnroll(
  session: AuthSession,
  input: { ca_id: string; csr_pem: string; profile_id?: string; auth_method?: string; auth_token?: string }
): Promise<CertificateItem> {
  const out = await serviceRequest<CertResponse>(
    session,
    "certs",
    "/est/.well-known/est/simpleenroll",
    {
      method: "POST",
      body: JSON.stringify({
        tenant_id: session.tenantId,
        ca_id: input.ca_id,
        csr_pem: input.csr_pem || "",
        profile_id: input.profile_id || "",
        auth_method: input.auth_method || "",
        auth_token: input.auth_token || ""
      })
    }
  );
  return out.certificate;
}

// ── SCEP GetCert ──────────────────────────────────────────────────
export async function scepGetCert(
  session: AuthSession,
  input: { serial_number?: string; cert_id?: string }
): Promise<CertificateItem> {
  const q = new URLSearchParams();
  q.set("tenant_id", session.tenantId);
  q.set("operation", "getcert");
  q.set("format", "json");
  if (input.serial_number) q.set("serial_number", input.serial_number);
  if (input.cert_id) q.set("cert_id", input.cert_id);
  const out = await serviceRequest<CertResponse>(
    session,
    "certs",
    `/scep/pkiclient.exe?${q.toString()}`
  );
  return out.certificate;
}

// ── SCEP GetCACaps ────────────────────────────────────────────────
export async function scepGetCACaps(session: AuthSession): Promise<string> {
  const q = new URLSearchParams();
  q.set("tenant_id", session.tenantId);
  q.set("operation", "getcacaps");
  const out = await serviceRequest<{ capabilities?: string }>(
    session,
    "certs",
    `/scep/pkiclient.exe?${q.toString()}`
  );
  // The response might come as plain text; serviceRequest handles JSON
  return String((out as any) || "");
}

// ── CMPv2 PKI Confirm ─────────────────────────────────────────────
export async function cmpv2Confirm(
  session: AuthSession,
  transactionId: string,
  certId: string
): Promise<CMPv2ConfirmResponse["confirmation"]> {
  const out = await serviceRequest<CMPv2ConfirmResponse>(
    session,
    "certs",
    "/cmpv2/confirm",
    {
      method: "POST",
      body: JSON.stringify({
        tenant_id: session.tenantId,
        transaction_id: transactionId,
        cert_id: certId
      })
    }
  );
  return out.confirmation;
}

// ── Certificate Transparency (Merkle) ─────────────────────────────

export type CertMerkleEpoch = {
  id: string;
  tenant_id: string;
  epoch_number: number;
  leaf_count: number;
  tree_root: string;
  created_at?: string;
};

export type CertMerkleProofSibling = {
  hash: string;
  position: "left" | "right";
};

export type CertMerkleProofResponse = {
  cert_id: string;
  serial_number: string;
  subject_cn: string;
  epoch_id: string;
  leaf_hash: string;
  leaf_index: number;
  siblings: CertMerkleProofSibling[];
  root: string;
};

export type CertMerkleVerifyResult = {
  valid: boolean;
  root: string;
  request_id: string;
};

export async function listCertMerkleEpochs(
  session: AuthSession,
  limit = 50
): Promise<CertMerkleEpoch[]> {
  const qs = new URLSearchParams();
  qs.set("tenant_id", session.tenantId);
  if (limit > 0) qs.set("limit", String(limit));
  const out = await serviceRequest<{ items: CertMerkleEpoch[] }>(
    session, "certs", `/certs/merkle/epochs?${qs.toString()}`
  );
  return Array.isArray(out?.items) ? out.items : [];
}

export async function getCertMerkleEpoch(
  session: AuthSession,
  epochId: string
): Promise<CertMerkleEpoch> {
  const out = await serviceRequest<{ epoch: CertMerkleEpoch }>(
    session, "certs", `/certs/merkle/epochs/${encodeURIComponent(epochId)}?tenant_id=${encodeURIComponent(session.tenantId)}`
  );
  return out.epoch;
}

export async function buildCertMerkleEpoch(
  session: AuthSession,
  maxLeaves = 500
): Promise<{ epoch?: CertMerkleEpoch; leaves?: number; status?: string }> {
  const out = await serviceRequest<{ epoch?: CertMerkleEpoch; leaves?: number; status?: string }>(
    session, "certs", `/certs/merkle/build?tenant_id=${encodeURIComponent(session.tenantId)}&max_leaves=${maxLeaves}`,
    { method: "POST" }
  );
  return out;
}

export async function getCertMerkleProof(
  session: AuthSession,
  certId: string
): Promise<CertMerkleProofResponse> {
  const out = await serviceRequest<{ proof: CertMerkleProofResponse }>(
    session, "certs", `/certs/merkle/proof/${encodeURIComponent(certId)}?tenant_id=${encodeURIComponent(session.tenantId)}`
  );
  return out.proof;
}

export async function verifyCertMerkleProof(
  session: AuthSession,
  proof: { leaf_hash: string; leaf_index: number; siblings: CertMerkleProofSibling[]; root: string }
): Promise<CertMerkleVerifyResult> {
  const out = await serviceRequest<CertMerkleVerifyResult>(
    session, "certs", `/certs/merkle/verify?tenant_id=${encodeURIComponent(session.tenantId)}`,
    { method: "POST", body: JSON.stringify(proof) }
  );
  return out;
}
