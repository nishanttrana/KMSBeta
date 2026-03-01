export type HSMVendorID =
  | "aws"
  | "azure"
  | "thales"
  | "utimaco"
  | "entrust"
  | "securosys"
  | "generic";

export type HSMVendorProfile = {
  id: HSMVendorID;
  label: string;
  shortName: string;
  abbreviations: string[];
  defaultProviderName: string;
  defaultPINEnvVar: string;
  endpointTerm: string;
  slotTerm: string;
  partitionTerm: string;
  tokenTerm: string;
  libraryExamples: string[];
};

export const HSM_VENDOR_PROFILES: Record<HSMVendorID, HSMVendorProfile> = {
  aws: {
    id: "aws",
    label: "AWS CloudHSM",
    shortName: "CloudHSM",
    abbreviations: ["AWS", "CloudHSM", "PKCS#11"],
    defaultProviderName: "aws-cloudhsm",
    defaultPINEnvVar: "CLOUDHSM_PIN",
    endpointTerm: "Cluster Endpoint",
    slotTerm: "HSM Slot",
    partitionTerm: "Crypto User / Partition",
    tokenTerm: "Token Label",
    libraryExamples: ["libcloudhsm_pkcs11.so", "cloudhsm-pkcs11.dll"]
  },
  azure: {
    id: "azure",
    label: "Azure Managed HSM",
    shortName: "Managed HSM",
    abbreviations: ["Azure", "MHSM", "AKV"],
    defaultProviderName: "azure-managed-hsm",
    defaultPINEnvVar: "AZURE_HSM_PIN",
    endpointTerm: "Managed HSM URI",
    slotTerm: "PKCS#11 Slot (bridge)",
    partitionTerm: "Security Domain / Partition",
    tokenTerm: "Token Label",
    libraryExamples: ["azure-pkcs11-bridge.so", "azure-pkcs11-bridge.dll"]
  },
  thales: {
    id: "thales",
    label: "Thales Luna HSM",
    shortName: "Luna",
    abbreviations: ["Thales", "Luna", "PKCS#11"],
    defaultProviderName: "thales-luna",
    defaultPINEnvVar: "LUNA_PIN",
    endpointTerm: "NTLS Endpoint",
    slotTerm: "Luna Slot",
    partitionTerm: "Luna Partition",
    tokenTerm: "Token Label",
    libraryExamples: ["libCryptoki2_64.so", "cryptoki.dll"]
  },
  utimaco: {
    id: "utimaco",
    label: "Utimaco HSM",
    shortName: "CryptoServer",
    abbreviations: ["Utimaco", "CS", "PKCS#11"],
    defaultProviderName: "utimaco-hsm",
    defaultPINEnvVar: "UTIMACO_PIN",
    endpointTerm: "SecurityServer Endpoint",
    slotTerm: "Slot",
    partitionTerm: "CryptoServer Partition",
    tokenTerm: "Token Label",
    libraryExamples: ["libcs_pkcs11_R2.so", "cs_pkcs11_R2.dll"]
  },
  entrust: {
    id: "entrust",
    label: "Entrust nShield HSM",
    shortName: "nShield",
    abbreviations: ["Entrust", "nShield", "PKCS#11"],
    defaultProviderName: "entrust-nshield",
    defaultPINEnvVar: "NSHIELD_PIN",
    endpointTerm: "Connect Host / RFS Endpoint",
    slotTerm: "Slot",
    partitionTerm: "Security World / OCS",
    tokenTerm: "Token Label",
    libraryExamples: ["libcknfast.so", "cknfast.dll"]
  },
  securosys: {
    id: "securosys",
    label: "Securosys HSM",
    shortName: "Securosys",
    abbreviations: ["Securosys", "Primus", "PKCS#11"],
    defaultProviderName: "securosys-hsm",
    defaultPINEnvVar: "SECUROSYS_PIN",
    endpointTerm: "HSM Endpoint",
    slotTerm: "Slot",
    partitionTerm: "Partition",
    tokenTerm: "Token Label",
    libraryExamples: ["libprimusP11.so", "primusP11.dll"]
  },
  generic: {
    id: "generic",
    label: "Generic PKCS#11 HSM",
    shortName: "Generic",
    abbreviations: ["Generic", "PKCS#11"],
    defaultProviderName: "customer-hsm",
    defaultPINEnvVar: "HSM_PIN",
    endpointTerm: "HSM Endpoint",
    slotTerm: "Slot",
    partitionTerm: "Partition",
    tokenTerm: "Token Label",
    libraryExamples: ["libVendorPKCS11.so", "vendor-pkcs11.dll"]
  }
};

export const inferHSMVendor = (
  metadata: unknown,
  providerName: string,
  libraryPath: string
): HSMVendorID => {
  const metaVendor = String((metadata as any)?.hsm_vendor_id || "").trim().toLowerCase() as HSMVendorID;
  if (metaVendor && HSM_VENDOR_PROFILES[metaVendor]) {
    return metaVendor;
  }
  const probe = `${String(providerName || "")} ${String(libraryPath || "")}`.toLowerCase();
  if (probe.includes("cloudhsm") || probe.includes("aws")) return "aws";
  if (probe.includes("azure") || probe.includes("mhsm")) return "azure";
  if (probe.includes("thales") || probe.includes("luna") || probe.includes("cryptoki2")) return "thales";
  if (probe.includes("utimaco") || probe.includes("cs_pkcs11") || probe.includes("cryptoserver")) return "utimaco";
  if (probe.includes("entrust") || probe.includes("nshield") || probe.includes("cknfast")) return "entrust";
  if (probe.includes("securosys") || probe.includes("primus")) return "securosys";
  return "generic";
};

export const normalizeHSMVendorView = (rawView: string): HSMVendorID => {
  const raw = String(rawView || "").trim().toLowerCase();
  if (!raw) return "generic";
  const value = raw.startsWith("hsm-") ? raw.slice(4) : raw;
  if (value in HSM_VENDOR_PROFILES) {
    return value as HSMVendorID;
  }
  return "generic";
};
