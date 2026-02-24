import type { AuthSession } from "./auth";
import { serviceRequest } from "./serviceApi";

type PaymentKey = {
  id: string;
  tenant_id: string;
  key_id: string;
  payment_type: string;
  usage_code: string;
  mode_of_use: string;
  key_version_num: string;
  exportability: string;
  tr31_header: string;
  kcv: string;
};

type PaymentKeyListResponse = { items: PaymentKey[] };
type PaymentPolicyResponse = { policy: PaymentPolicy };

export type PaymentPolicy = {
  tenant_id: string;
  allowed_tr31_versions: string[];
  require_kbpk_for_tr31: boolean;
  allow_inline_key_material: boolean;
  max_iso20022_payload_bytes: number;
  require_iso20022_lau_context: boolean;
  strict_pci_dss_4_0: boolean;
  require_key_id_for_operations: boolean;
  allow_tcp_interface: boolean;
  require_jwt_on_tcp: boolean;
  max_tcp_payload_bytes: number;
  allowed_tcp_operations: string[];
  allowed_pin_block_formats: string[];
  disable_iso0_pin_block: boolean;
  decimalization_table: string;
  block_wildcard_pan: boolean;
  updated_by?: string;
  updated_at?: string;
};

function tenantQuery(session: AuthSession): string {
  return `tenant_id=${encodeURIComponent(session.tenantId)}`;
}

export async function listPaymentKeys(session: AuthSession): Promise<PaymentKey[]> {
  const out = await serviceRequest<PaymentKeyListResponse>(
    session,
    "payment",
    `/payment/keys?${tenantQuery(session)}`
  );
  return Array.isArray(out?.items) ? out.items : [];
}

export async function getPaymentPolicy(session: AuthSession): Promise<PaymentPolicy> {
  const out = await serviceRequest<PaymentPolicyResponse>(session, "payment", `/payment/policy?${tenantQuery(session)}`);
  return (out?.policy || {}) as PaymentPolicy;
}

export async function updatePaymentPolicy(
  session: AuthSession,
  input: Partial<PaymentPolicy>
): Promise<PaymentPolicy> {
  const out = await serviceRequest<PaymentPolicyResponse>(session, "payment", `/payment/policy?${tenantQuery(session)}`, {
    method: "PUT",
    body: JSON.stringify({
      tenant_id: session.tenantId,
      ...input
    })
  });
  return (out?.policy || {}) as PaymentPolicy;
}

export async function createTR31(
  session: AuthSession,
  input: {
    key_id: string;
    tr31_version?: string;
    algorithm?: string;
    usage_code?: string;
    mode_of_use?: string;
    exportability?: string;
    kbpk_key_id?: string;
    kbpk_key_b64?: string;
    kek_key_id?: string;
    kek_key_b64?: string;
    source_format?: string;
    material_b64?: string;
  }
): Promise<any> {
  const out = await serviceRequest<{ result: any }>(session, "payment", "/payment/tr31/create", {
    method: "POST",
    body: JSON.stringify({
      tenant_id: session.tenantId,
      ...input
    })
  });
  return out?.result || {};
}

export async function translateTR31(
  session: AuthSession,
  input: {
    source_key_id?: string;
    source_block?: string;
    source_format: string;
    target_format: string;
    source_kbpk_key_id?: string;
    source_kbpk_key_b64?: string;
    target_kbpk_key_id?: string;
    target_kbpk_key_b64?: string;
    kek_key_id?: string;
    kek_key_b64?: string;
    tr31_version?: string;
    algorithm?: string;
    usage_code?: string;
    mode_of_use?: string;
    exportability?: string;
  }
): Promise<any> {
  const out = await serviceRequest<{ result: any }>(session, "payment", "/payment/tr31/translate", {
    method: "POST",
    body: JSON.stringify({
      tenant_id: session.tenantId,
      ...input
    })
  });
  return out?.result || {};
}

export async function validateTR31(
  session: AuthSession,
  keyBlock: string,
  input?: {
    kbpk_key_id?: string;
    kbpk_key_b64?: string;
    kek_key_id?: string;
    kek_key_b64?: string;
  }
): Promise<any> {
  const out = await serviceRequest<{ result: any }>(session, "payment", "/payment/tr31/validate", {
    method: "POST",
    body: JSON.stringify({
      tenant_id: session.tenantId,
      key_block: keyBlock,
      ...(input || {})
    })
  });
  return out?.result || {};
}

export async function translatePIN(
  session: AuthSession,
  input: {
    source_format: string;
    target_format: string;
    pin_block: string;
    pan?: string;
    source_zpk_key_id?: string;
    source_zpk_key_b64?: string;
    target_zpk_key_id?: string;
    target_zpk_key_b64?: string;
  }
): Promise<string> {
  const out = await serviceRequest<{ pin_block: string }>(session, "payment", "/payment/pin/translate", {
    method: "POST",
    body: JSON.stringify({
      tenant_id: session.tenantId,
      ...input
    })
  });
  return String(out?.pin_block || "");
}

export async function generatePVV(
  session: AuthSession,
  input: {
    pin: string;
    pan: string;
    pvki: string;
    pvk_key_id?: string;
    pvk_key_b64?: string;
  }
): Promise<string> {
  const out = await serviceRequest<{ pvv: string }>(session, "payment", "/payment/pin/pvv/generate", {
    method: "POST",
    body: JSON.stringify({
      tenant_id: session.tenantId,
      ...input
    })
  });
  return String(out?.pvv || "");
}

export async function verifyPVV(
  session: AuthSession,
  input: {
    pin: string;
    pan: string;
    pvki: string;
    pvv: string;
    pvk_key_id?: string;
    pvk_key_b64?: string;
  }
): Promise<boolean> {
  const out = await serviceRequest<{ verified: boolean }>(session, "payment", "/payment/pin/pvv/verify", {
    method: "POST",
    body: JSON.stringify({
      tenant_id: session.tenantId,
      ...input
    })
  });
  return Boolean(out?.verified);
}

export async function computeCVV(
  session: AuthSession,
  input: {
    pan: string;
    expiry_yymm: string;
    service_code: string;
    cvk_key_id?: string;
    cvk_key_b64?: string;
  }
): Promise<string> {
  const out = await serviceRequest<{ cvv: string }>(session, "payment", "/payment/pin/cvv/compute", {
    method: "POST",
    body: JSON.stringify({
      tenant_id: session.tenantId,
      ...input
    })
  });
  return String(out?.cvv || "");
}

export async function verifyCVV(
  session: AuthSession,
  input: {
    pan: string;
    expiry_yymm: string;
    service_code: string;
    cvv: string;
    cvk_key_id?: string;
    cvk_key_b64?: string;
  }
): Promise<boolean> {
  const out = await serviceRequest<{ verified: boolean }>(session, "payment", "/payment/pin/cvv/verify", {
    method: "POST",
    body: JSON.stringify({
      tenant_id: session.tenantId,
      ...input
    })
  });
  return Boolean(out?.verified);
}

export async function computeMAC(
  session: AuthSession,
  input: {
    type: "retail" | "iso9797" | "cmac";
    key_id?: string;
    key_b64?: string;
    data_b64: string;
    algorithm?: number;
  }
): Promise<string> {
  const endpoint =
    input.type === "cmac"
      ? "/payment/mac/cmac"
      : input.type === "iso9797"
        ? "/payment/mac/iso9797"
        : "/payment/mac/retail";
  const out = await serviceRequest<{ mac_b64: string }>(session, "payment", endpoint, {
    method: "POST",
    body: JSON.stringify({
      tenant_id: session.tenantId,
      ...input
    })
  });
  return String(out?.mac_b64 || "");
}

export async function verifyMAC(
  session: AuthSession,
  input: {
    type: "retail" | "iso9797" | "cmac";
    key_id?: string;
    key_b64?: string;
    data_b64: string;
    mac_b64: string;
    algorithm?: number;
  }
): Promise<boolean> {
  const out = await serviceRequest<{ verified: boolean }>(session, "payment", "/payment/mac/verify", {
    method: "POST",
    body: JSON.stringify({
      tenant_id: session.tenantId,
      ...input
    })
  });
  return Boolean(out?.verified);
}

export async function signISO20022(
  session: AuthSession,
  input: {
    key_id: string;
    xml: string;
  }
): Promise<any> {
  const out = await serviceRequest<{ result: any }>(session, "payment", "/payment/iso20022/sign", {
    method: "POST",
    body: JSON.stringify({
      tenant_id: session.tenantId,
      ...input
    })
  });
  return out?.result || {};
}

export async function verifyISO20022(
  session: AuthSession,
  input: {
    key_id: string;
    xml: string;
    signature_b64: string;
  }
): Promise<boolean> {
  const out = await serviceRequest<{ verified: boolean }>(session, "payment", "/payment/iso20022/verify", {
    method: "POST",
    body: JSON.stringify({
      tenant_id: session.tenantId,
      ...input
    })
  });
  return Boolean(out?.verified);
}

export async function encryptISO20022(
  session: AuthSession,
  input: {
    key_id: string;
    xml: string;
    iv?: string;
    reference_id?: string;
  }
): Promise<any> {
  const out = await serviceRequest<{ result: any }>(session, "payment", "/payment/iso20022/encrypt", {
    method: "POST",
    body: JSON.stringify({
      tenant_id: session.tenantId,
      ...input
    })
  });
  return out?.result || {};
}

export async function decryptISO20022(
  session: AuthSession,
  input: {
    key_id: string;
    ciphertext: string;
    iv?: string;
  }
): Promise<string> {
  const out = await serviceRequest<{ xml: string }>(session, "payment", "/payment/iso20022/decrypt", {
    method: "POST",
    body: JSON.stringify({
      tenant_id: session.tenantId,
      ...input
    })
  });
  return String(out?.xml || "");
}

export async function generateLAU(
  session: AuthSession,
  input: {
    key_id?: string;
    lau_key_b64?: string;
    message: string;
    context?: string;
  }
): Promise<string> {
  const out = await serviceRequest<{ lau_b64: string }>(session, "payment", "/payment/iso20022/lau/generate", {
    method: "POST",
    body: JSON.stringify({
      tenant_id: session.tenantId,
      ...input
    })
  });
  return String(out?.lau_b64 || "");
}

export async function verifyLAU(
  session: AuthSession,
  input: {
    key_id?: string;
    lau_key_b64?: string;
    message: string;
    context?: string;
    lau_b64: string;
  }
): Promise<boolean> {
  const out = await serviceRequest<{ verified: boolean }>(session, "payment", "/payment/iso20022/lau/verify", {
    method: "POST",
    body: JSON.stringify({
      tenant_id: session.tenantId,
      ...input
    })
  });
  return Boolean(out?.verified);
}
