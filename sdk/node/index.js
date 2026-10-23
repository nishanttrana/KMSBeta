// Node.js client for Vecta KMS: keys, cryptographic operations and secrets.
//
// It authenticates as a REST client (Workbench -> REST API): the client ID
// and API key, exchanged for short-lived tokens it renews itself. To use keys
// the client needs a role with key permissions and a key access assignment
// for the client (docs/CI_CD_AUTOMATION.md, "A role for a client").
//
//   import { Client } from "vecta-kms";
//   const kms = new Client({ baseUrl: "https://kms.example.com", tenantId: "acme",
//     clientId: process.env.KMS_CLIENT_ID, apiKey: process.env.KMS_API_KEY });
//   const ct = await kms.encrypt("key_123", Buffer.from("secret"));
//
// Node 18 or later, no dependencies.
import https from "node:https";

/** The KMS refused or failed a call; code is the KMS's reason, audited under requestId. */
export class APIError extends Error {
  constructor(status, code, message, requestId = "") {
    super(`${status} ${code}: ${message} (request ${requestId})`);
    this.name = "APIError";
    this.status = status;
    this.code = code;
    this.requestId = requestId;
  }
  get refused() { return this.status === 401 || this.status === 403; }
  get notFound() { return this.status === 404; }
}

const b64 = (b) => (b && b.length ? Buffer.from(b).toString("base64") : "");
const unb64 = (s) => (s ? Buffer.from(s, "base64") : Buffer.alloc(0));

export class Client {
  /**
   * @param {{baseUrl: string, tenantId: string, clientId?: string, apiKey?: string, token?: string,
   *          ca?: string|Buffer, tokenTtlSeconds?: number, timeoutMs?: number}} cfg
   */
  constructor(cfg) {
    const base = String(cfg?.baseUrl || "").replace(/\/+$/, "");
    let url;
    try { url = new URL(base); } catch { url = null; }
    if (!url || url.protocol !== "https:") throw new Error("baseUrl is https://<host>");
    if (!cfg.tenantId) throw new Error("tenantId is required");
    if (!cfg.token && !(cfg.clientId && cfg.apiKey)) throw new Error("set clientId and apiKey, or token");
    const ttl = cfg.tokenTtlSeconds ?? 300;
    if (ttl < 60 || ttl > 3600) throw new Error("tokenTtlSeconds is between 60 and 3600");
    this._base = base;
    this._tenant = cfg.tenantId;
    this._cfg = { ...cfg, tokenTtlSeconds: ttl };
    this._agent = new https.Agent({ ca: cfg.ca, minVersion: "TLSv1.3", keepAlive: true });
    this._token = cfg.token || "";
    this._expires = 0;
    this._pending = null;
  }

  /** One HTTPS request; resolves the parsed JSON body or rejects an APIError. */
  _send(method, url, body, headers) {
    return new Promise((resolve, reject) => {
      const data = body === undefined ? undefined : Buffer.from(JSON.stringify(body));
      const req = https.request(url, {
        method, agent: this._agent, timeout: this._cfg.timeoutMs ?? 30000,
        headers: { ...headers, ...(data ? { "Content-Type": "application/json", "Content-Length": data.length } : {}) },
      }, (res) => {
        const chunks = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () => {
          const raw = Buffer.concat(chunks).toString();
          let parsed = {};
          try { parsed = raw ? JSON.parse(raw) : {}; } catch { parsed = {}; }
          if (res.statusCode >= 300) {
            const e = parsed.error || {};
            reject(new APIError(res.statusCode, e.code || "", e.message || raw.trim(), e.request_id || ""));
          } else {
            resolve(parsed);
          }
        });
      });
      req.on("timeout", () => req.destroy(new Error("request timed out")));
      req.on("error", reject);
      if (data) req.write(data);
      req.end();
    });
  }

  async _bearer(renew) {
    if (this._cfg.token) return this._cfg.token;
    if (!renew && this._token && this._expires - Date.now() > 30000) return this._token;
    if (!this._pending) {
      this._pending = this._send("POST", this._base + "/svc/auth/auth/client-token",
        { tenant_id: this._tenant, client_id: this._cfg.clientId, ttl_seconds: this._cfg.tokenTtlSeconds },
        { "X-API-Key": this._cfg.apiKey })
        .then((out) => {
          if (!out.access_token) throw new APIError(500, "no_token", "the KMS issued no token");
          this._token = out.access_token;
          this._expires = Date.parse(out.expires_at);
          return this._token;
        })
        .finally(() => { this._pending = null; });
    }
    return this._pending;
  }

  async _call(method, path, body, query = {}) {
    const q = new URLSearchParams({ tenant_id: this._tenant, ...query });
    const url = `${this._base}${path}?${q}`;
    for (let attempt = 0; ; attempt++) {
      const token = await this._bearer(attempt > 0);
      try {
        return await this._send(method, url, body, { Authorization: `Bearer ${token}`, "X-Tenant-ID": this._tenant });
      } catch (e) {
        if (attempt === 0 && !this._cfg.token && e instanceof APIError && e.status === 401) continue;
        throw e;
      }
    }
  }

  _key(id, op = "") { return `/svc/keycore/keys/${encodeURIComponent(id)}${op ? `/${op}` : ""}`; }

  /** Creates a key and returns its ID; the tenant's metadata profiles apply. */
  async createKey({ name, algorithm, purpose, keyType, description, labels, tags }) {
    const body = { tenant_id: this._tenant, name, algorithm, purpose };
    if (keyType) body.key_type = keyType;
    if (description) body.description = description;
    if (labels) body.labels = labels;
    if (tags) body.tags = tags;
    return (await this._call("POST", "/svc/keycore/keys", body)).key_id;
  }

  async getKey(id) { return (await this._call("GET", this._key(id))).key; }

  /** Every key the client can see, a page at a time. */
  async *listKeys() {
    let query = { limit: "200" };
    for (;;) {
      const out = await this._call("GET", "/svc/keycore/keys", undefined, query);
      for (const k of out.items || []) yield k;
      if (!out.has_more || !out.next_cursor) return;
      query = { limit: "200", after_created_at: out.next_cursor.after_created_at, after_id: out.next_cursor.after_id };
    }
  }

  /** Changes only the named metadata (name, description, purpose, owner, tags, labels). */
  async updateKey(id, fields) {
    const allowed = ["name", "description", "purpose", "owner", "tags", "labels"];
    const unknown = Object.keys(fields || {}).filter((k) => !allowed.includes(k));
    if (unknown.length) throw new Error(`updateKey takes ${allowed.join(", ")}, not ${unknown.join(", ")}`);
    return (await this._call("PATCH", this._key(id), fields)).key;
  }

  /** Stops new encryption and signing; old ciphertext still decrypts. */
  async deactivateKey(id) { await this._call("POST", this._key(id, "deactivate"), {}); }

  async getKeyAccess(id) { return (await this._call("GET", this._key(id, "access-policy"))).policy?.grants || []; }

  /** Replaces the key's grants ({subject_type: user|group|client, subject_id, operations}). */
  async setKeyAccess(id, grants) {
    const out = await this._call("PUT", this._key(id, "access-policy"), { grants: grants || [] });
    if (out.status === "pending_approval") throw new APIError(202, "pending_approval", `the change waits for approval ${out.approval_request_id || ""}`);
  }

  async rotateKey(id, reason = "") { return Number((await this._call("POST", this._key(id, "rotate"), { reason })).version); }

  async encrypt(keyId, plaintext, aad) {
    const out = await this._call("POST", this._key(keyId, "encrypt"), { tenant_id: this._tenant, plaintext: b64(plaintext), aad: b64(aad) });
    return { keyId: out.key_id, version: Number(out.version), ciphertext: unb64(out.ciphertext), iv: unb64(out.iv) };
  }

  async decrypt(ct, aad) {
    const out = await this._call("POST", this._key(ct.keyId, "decrypt"),
      { tenant_id: this._tenant, ciphertext: b64(ct.ciphertext), iv: b64(ct.iv), aad: b64(aad), version: ct.version });
    return unb64(out.plaintext);
  }

  async sign(keyId, data, algorithm = "") {
    const out = await this._call("POST", this._key(keyId, "sign"), { tenant_id: this._tenant, data: b64(data), algorithm });
    return { keyId: out.key_id, version: Number(out.version), signature: unb64(out.signature) };
  }

  async verify(sig, data, algorithm = "") {
    const out = await this._call("POST", this._key(sig.keyId, "verify"),
      { tenant_id: this._tenant, data: b64(data), signature: b64(sig.signature), algorithm, version: sig.version });
    return Boolean(out.verified);
  }

  /** A 256-bit data key: use plaintext, keep wrapped, decrypt wrapped later. */
  async generateDataKey(keyId, aad) {
    const out = await this._call("POST", this._key(keyId, "generate-data-key"), { tenant_id: this._tenant, key_bytes: 32, aad: b64(aad) });
    return {
      plaintext: unb64(out.plaintext_dek),
      wrapped: { keyId: out.key_id, version: Number(out.version), ciphertext: unb64(out.wrapped_dek), iv: unb64(out.wrapped_dek_iv) },
    };
  }

  /** value, version, format and content_type of a secret's current value. */
  async getSecretValue(id) { return this._call("GET", `/svc/secrets/secrets/${encodeURIComponent(id)}/value`); }

  /** Closes kept-alive connections. */
  close() { this._agent.destroy(); }
}
