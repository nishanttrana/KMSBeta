// HYOK protocols as the HYOK page shows them; the service's list is
// services/hyok ListEndpoints.

export const HYOK_PROTOCOL_LABELS: Record<string, string> = {
  dke: "Microsoft DKE",
  salesforce: "Salesforce Cache-Only",
  google: "Google Cloud EKM",
  generic: "Generic HYOK",
  servicenow: "ServiceNow HYOK",
  alibaba: "Alibaba Cloud EKM",
  azure: "Azure EKM",
  aws_xks: "AWS XKS",
  oci_ekm: "OCI External KMS"
};

export const HYOK_PROTOCOL_DETAILS: Record<string, string> = {
  dke: "Double Key Encryption for Microsoft 365 / Purview Information Protection",
  salesforce: "Shield Platform Encryption with Cache-Only Key Service",
  google: "External Key Manager for Google Cloud CMEK",
  generic: "Generic encrypt / decrypt / wrap / unwrap proxy",
  servicenow: "ServiceNow Shield Platform Encryption with Cache-Only Key Service (HYOK)",
  alibaba: "Alibaba Cloud External Key Manager for BYOK/EKM integration",
  azure: "Azure Managed HSM external key management (EKM Proxy API)",
  aws_xks: "AWS KMS external key store (XKS proxy API)",
  oci_ekm: "Oracle Cloud external key management (External KMS vendor API)"
};

export const HYOK_PROTOCOL_KEY_HINTS: Record<string, string> = {
  dke: "Requires RSA key (2048+ bits). Public key is served via DKE endpoint for Microsoft clients.",
  salesforce: "Supports AES-256 or RSA keys for wrap/unwrap operations.",
  google: "Supports AES-256 or RSA keys for wrap/unwrap operations with Google Cloud CMEK.",
  generic: "Any symmetric or asymmetric key supported by your Vecta KMS instance.",
  servicenow: "Supports AES-256 keys for wrap/unwrap operations using AES-KWP (RFC 5649).",
  alibaba: "Supports AES-256 keys for encrypt/decrypt operations using AES-256-GCM.",
  azure: "AES-256 (A256KW, A256KWP) or RSA 2048/3072/4096 (RSA-OAEP-256, RSA-OAEP), each mapped to the key name Managed HSM uses.",
  aws_xks: "AES-256 keys (AES-GCM with AAD); AWS signs every call with an XKS credential from Playbooks → Credentials.",
  oci_ekm: "AES-128, 192 or 256 keys (AES-GCM with AAD); OCI calls with an access token from your identity domain, checked against its JWKS."
};

export const HYOK_OPS_BY_PROTOCOL: Record<string, string[]> = {
  dke: ["decrypt", "publickey"],
  salesforce: ["wrap", "unwrap"],
  google: ["wrap", "unwrap"],
  generic: ["encrypt", "decrypt", "wrap", "unwrap"],
  servicenow: ["wrap", "unwrap"],
  alibaba: ["encrypt", "decrypt"],
  azure: ["wrapkey", "unwrapkey"],
  aws_xks: ["encrypt", "decrypt"],
  oci_ekm: ["encrypt", "decrypt"]
};

export const HYOK_PROTOCOL_URLS: Record<string, { path: string; methods: string; description: string }[]> = {
  dke: [
    { path: "/api/v1/keys/{keyId}", methods: "GET", description: "Microsoft-compatible public key endpoint (JWK format)" },
    { path: "/api/v1/keys/{keyId}/decrypt", methods: "POST", description: "Microsoft-compatible DKE decrypt endpoint" },
    { path: "/hyok/dke/v1/keys/{keyId}/publickey", methods: "GET", description: "Standard DKE public key endpoint" },
    { path: "/hyok/dke/v1/keys/{keyId}/decrypt", methods: "POST", description: "Standard DKE decrypt endpoint" },
  ],
  salesforce: [
    { path: "/hyok/salesforce/v1/keys/{keyId}/wrap", methods: "POST", description: "Salesforce key wrap endpoint" },
    { path: "/hyok/salesforce/v1/keys/{keyId}/unwrap", methods: "POST", description: "Salesforce key unwrap endpoint" },
  ],
  google: [
    { path: "/hyok/google/v1/keys/{keyId}/wrap", methods: "POST", description: "Google EKM key wrap endpoint" },
    { path: "/hyok/google/v1/keys/{keyId}/unwrap", methods: "POST", description: "Google EKM key unwrap endpoint" },
  ],
  generic: [
    { path: "/hyok/generic/v1/keys/{keyId}/encrypt", methods: "POST", description: "Generic encrypt endpoint" },
    { path: "/hyok/generic/v1/keys/{keyId}/decrypt", methods: "POST", description: "Generic decrypt endpoint" },
    { path: "/hyok/generic/v1/keys/{keyId}/wrap", methods: "POST", description: "Generic key wrap endpoint" },
    { path: "/hyok/generic/v1/keys/{keyId}/unwrap", methods: "POST", description: "Generic key unwrap endpoint" },
  ],
  servicenow: [
    { path: "/hyok/servicenow/v1/keys/{keyId}/wrap", methods: "POST", description: "ServiceNow key wrap endpoint" },
    { path: "/hyok/servicenow/v1/keys/{keyId}/unwrap", methods: "POST", description: "ServiceNow key unwrap endpoint" },
  ],
  alibaba: [
    { path: "/hyok/alibaba/v1/keys/{keyId}/encrypt", methods: "POST", description: "Alibaba Cloud EKM encrypt endpoint" },
    { path: "/hyok/alibaba/v1/keys/{keyId}/decrypt", methods: "POST", description: "Alibaba Cloud EKM decrypt endpoint" },
  ],
  // Its own mTLS listener (port 8443), not the HTTPS edge.
  azure: [
    { path: ":8443/{pathPrefix}/info", methods: "POST", description: "Proxy information and Managed HSM health probe" },
    { path: ":8443/{pathPrefix}/{keyName}/metadata", methods: "POST", description: "Key type, size and RSA public part" },
    { path: ":8443/{pathPrefix}/{keyName}/wrapkey", methods: "POST", description: "Wrap a data key" },
    { path: ":8443/{pathPrefix}/{keyName}/unwrapkey", methods: "POST", description: "Unwrap a data key" },
  ],
  // Through the HTTPS edge; XksProxyUriPath is /svc/hyok/xks/{pathPrefix}.
  aws_xks: [
    { path: "/svc/hyok/xks/{pathPrefix}/kms/xks/v1/health", methods: "POST", description: "Health (AWS checks it about once a minute)" },
    { path: "/svc/hyok/xks/{pathPrefix}/kms/xks/v1/keys/{externalKeyId}/metadata", methods: "POST", description: "Key spec, usage and status" },
    { path: "/svc/hyok/xks/{pathPrefix}/kms/xks/v1/keys/{externalKeyId}/encrypt", methods: "POST", description: "AES-GCM encrypt" },
    { path: "/svc/hyok/xks/{pathPrefix}/kms/xks/v1/keys/{externalKeyId}/decrypt", methods: "POST", description: "AES-GCM decrypt" },
  ],
  // Through the HTTPS edge; OCI's external key manager URL is /svc/hyok/oci/{pathPrefix}.
  oci_ekm: [
    { path: "/svc/hyok/oci/{pathPrefix}/ekm/v1/vaults/{vaultId}/metadata", methods: "GET", description: "Vault state" },
    { path: "/svc/hyok/oci/{pathPrefix}/ekm/v1/vaults/{vaultId}/keys/{externalKeyId}/metadata", methods: "GET", description: "Key shape, state and current version" },
    { path: "/svc/hyok/oci/{pathPrefix}/ekm/v1/vaults/{vaultId}/keys/{externalKeyId}/keyVersions/{version}/metadata", methods: "GET", description: "Key version state" },
    { path: "/svc/hyok/oci/{pathPrefix}/ekm/v1/vaults/{vaultId}/keys/{externalKeyId}/encrypt", methods: "POST", description: "AES-GCM encrypt" },
    { path: "/svc/hyok/oci/{pathPrefix}/ekm/v1/vaults/{vaultId}/keys/{externalKeyId}/decrypt", methods: "POST", description: "AES-GCM decrypt" },
    { path: "/svc/hyok/oci/{pathPrefix}/ekm/v1/vaults/{vaultId}/generateRandomBytes", methods: "POST", description: "16, 24 or 32 random bytes" },
  ],
};

export const HYOK_SETUP_GUIDES: Record<string, string[]> = {
  dke: [
    "1. Create an RSA key (2048+ bits) in Vecta KMS",
    "2. Enable the DKE protocol endpoint below",
    "3. Callers present a Vecta JWT or, for Office, an Entra ID token",
    "4. Set authorized tenants, valid issuers, and JWT audiences in metadata",
    "5. In Microsoft Purview, configure the DKE service URL to point to your Vecta HYOK endpoint",
    "6. Test the public key endpoint: GET /api/v1/keys/{keyId}",
  ],
  salesforce: [
    "1. Create an AES-256 or RSA key in Vecta KMS",
    "2. Enable the Salesforce Cache-Only protocol endpoint below",
    "3. Salesforce calls with a Vecta JWT",
    "4. In Salesforce Setup, configure Shield Platform Encryption to use Cache-Only Key Service",
    "5. Point the Cache-Only Key Service URL to your Vecta HYOK endpoint",
    "6. Test with the wrap/unwrap operations below",
  ],
  google: [
    "1. Create an AES-256 or RSA key in Vecta KMS",
    "2. Enable the Google EKM protocol endpoint below",
    "3. Configure auth mode and optional policy ID",
    "4. In Google Cloud Console, create an EKM connection pointing to your Vecta HYOK endpoint",
    "5. Create a Cloud KMS key ring using the external key manager",
    "6. Test with the wrap/unwrap operations below",
  ],
  generic: [
    "1. Create a key in Vecta KMS (any supported algorithm)",
    "2. Enable the Generic HYOK protocol endpoint below",
    "3. Configure auth mode and optional policy/governance requirements",
    "4. Use the endpoint URLs below to integrate with your application",
    "5. Test all operations using the Live Test Console",
  ],
  servicenow: [
    "1. Create an AES-256 key in Vecta KMS",
    "2. Enable the ServiceNow HYOK protocol endpoint below",
    "3. ServiceNow calls with a Vecta JWT",
    "4. In ServiceNow, navigate to System Security > Encryption Keys",
    "5. Configure Cache-Only Key (HYOK) to point to your Vecta HYOK endpoint",
    "6. Test with the wrap/unwrap operations below",
  ],
  alibaba: [
    "1. Create an AES-256 key in Vecta KMS",
    "2. Enable the Alibaba Cloud EKM protocol endpoint below",
    "3. Configure auth mode and optional policy ID",
    "4. In Alibaba Cloud Console, navigate to KMS > External Key Management",
    "5. Create an external key pointing to your Vecta HYOK endpoint",
    "6. Test with the encrypt/decrypt operations below",
  ],
  azure: [
    "1. Create an AES-256 or RSA key in Vecta KMS",
    "2. Configure Azure EKM: path prefix, Managed HSM's client CA and subject CN, key names",
    "3. In Managed HSM, create the EKM connection to https://<kms host>:8443/<path prefix>, trusting the CA of the KMS edge certificate (PKI tab)",
    "4. Add each key reference with its key name",
  ],
  aws_xks: [
    "1. Add an AWS XKS credential in Playbooks → Credentials (access key ID and secret)",
    "2. Create an AES-256 key in Vecta KMS",
    "3. Configure AWS XKS: path prefix, credential, external key IDs",
    "4. In AWS KMS, create an external key store with public endpoint https://<kms host>, the XksProxyUriPath shown, and the same credential",
    "5. Create KMS keys in the store, each with its external key ID",
  ],
  oci_ekm: [
    "1. In your OCI identity domain, create the confidential resource app (scope oci_ekms, primary audience = the address OCI reaches the KMS on) and a client app with client credentials",
    "2. Create an AES key in Vecta KMS",
    "3. Configure OCI External KMS: path prefix, vault ID, JWKS URL and issuer from /.well-known/idcs-configuration, audience, client ID, external key IDs",
    "4. If the domain's signing certificate is not public, add an OCI identity domain credential (resource app) in Playbooks → Credentials and pick it",
    "5. In OCI KMS, create an external vault pointing at https://<kms host>/svc/hyok/oci/<path prefix> through a private endpoint, then key references by external key ID",
  ],
};

// The protocol cards, in order.
export const HYOK_PROTOCOLS = ["dke", "salesforce", "google", "generic", "servicenow", "alibaba", "azure", "aws_xks", "oci_ekm"];
