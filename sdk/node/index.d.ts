/// <reference types="node" />

export interface ClientConfig {
  /** The KMS edge, https://<host>. */
  baseUrl: string;
  tenantId: string;
  /** The REST client's credentials, exchanged for tokens renewed automatically. */
  clientId?: string;
  apiKey?: string;
  /** A bearer token used as is, instead of clientId/apiKey. */
  token?: string;
  /** PEM of the KMS certificate's CA, when it is the KMS's own. */
  ca?: string | Buffer;
  /** Each token's lifetime, 60 to 3600 seconds (default 300). */
  tokenTtlSeconds?: number;
  timeoutMs?: number;
}

export interface Ciphertext { keyId: string; version: number; ciphertext: Buffer; iv: Buffer }
export interface Signature { keyId: string; version: number; signature: Buffer }
export interface DataKey { plaintext: Buffer; wrapped: Ciphertext }
export interface Key {
  id: string; name: string; description: string; algorithm: string; key_type: string; purpose: string;
  status: string; tags: string[]; labels: Record<string, string>; current_version: number; kcv: string; created_at: string;
}
export interface SecretValue { value: string; version: number; format: string; content_type: string }

export class APIError extends Error {
  readonly status: number;
  /** The KMS's reason, e.g. no_matching_grant, binding_policy, metadata_profile_violation. */
  readonly code: string;
  readonly requestId: string;
  readonly refused: boolean;
  readonly notFound: boolean;
}

export class Client {
  constructor(cfg: ClientConfig);
  createKey(input: { name: string; algorithm: string; purpose: string; keyType?: string; description?: string; labels?: Record<string, string>; tags?: string[] }): Promise<string>;
  getKey(id: string): Promise<Key>;
  listKeys(): AsyncGenerator<Key>;
  rotateKey(id: string, reason?: string): Promise<number>;
  encrypt(keyId: string, plaintext: Uint8Array, aad?: Uint8Array): Promise<Ciphertext>;
  decrypt(ct: Ciphertext, aad?: Uint8Array): Promise<Buffer>;
  sign(keyId: string, data: Uint8Array, algorithm?: string): Promise<Signature>;
  verify(sig: Signature, data: Uint8Array, algorithm?: string): Promise<boolean>;
  generateDataKey(keyId: string, aad?: Uint8Array): Promise<DataKey>;
  getSecretValue(id: string): Promise<SecretValue>;
  close(): void;
}
