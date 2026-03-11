export const KEY_TABLE_COLUMNS = [
  { id: "name", label: "Name" },
  { id: "algorithm", label: "Algorithm" },
  { id: "sizeCurve", label: "Size / Curve" },
  { id: "status", label: "Status" },
  { id: "destroyAt", label: "Destroy At" },
  { id: "fips", label: "FIPS" },
  { id: "kcv", label: "KCV" },
  { id: "version", label: "Version" },
  { id: "operations", label: "Operations" },
  { id: "tags", label: "Tags" },
  { id: "actions", label: "Actions" }
];

export const DEFAULT_KEY_COLUMN_VISIBILITY = {
  name: true,
  algorithm: true,
  sizeCurve: true,
  status: true,
  destroyAt: true,
  fips: true,
  kcv: true,
  version: true,
  operations: true,
  tags: true,
  actions: true
};

export const KEY_ACCESS_OPERATION_OPTIONS = [
  { id: "encrypt", label: "Encrypt" },
  { id: "decrypt", label: "Decrypt" },
  { id: "wrap", label: "Wrap" },
  { id: "unwrap", label: "Unwrap" },
  { id: "sign", label: "Sign" },
  { id: "verify", label: "Verify" },
  { id: "mac", label: "MAC" },
  { id: "derive", label: "Derive" },
  { id: "kem-encapsulate", label: "KEM Encap" },
  { id: "kem-decapsulate", label: "KEM Decap" },
  { id: "export", label: "Export" }
];
