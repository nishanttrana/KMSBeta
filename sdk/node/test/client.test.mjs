// Unit tests with a stand-in transport. The real routes, over real TLS, are
// checked by services/keycore's TestSDKsAgainstKeycore, which runs contract.mjs.
import test from "node:test";
import assert from "node:assert/strict";
import { APIError, Client } from "../index.js";

test("refuses bad config", () => {
  for (const cfg of [
    { baseUrl: "http://kms", tenantId: "t", token: "x" },
    { baseUrl: "https://kms", token: "x" },
    { baseUrl: "https://kms", tenantId: "t" },
    { baseUrl: "https://kms", tenantId: "t", token: "x", tokenTtlSeconds: 5 },
  ]) {
    assert.throws(() => new Client(cfg));
  }
});

test("exchanges the API key once, reuses the token, renews it after a 401", async () => {
  const c = new Client({ baseUrl: "https://kms.example.com", tenantId: "acme", clientId: "release", apiKey: "api-key" });
  const calls = [];
  let n = 0;
  c._send = async (method, url, body, headers) => {
    calls.push(url);
    if (url.endsWith("/svc/auth/auth/client-token")) {
      assert.equal(headers["X-API-Key"], "api-key");
      assert.deepEqual(body, { tenant_id: "acme", client_id: "release", ttl_seconds: 300 });
      n++;
      return { access_token: `tok-${n}`, expires_at: new Date(Date.now() + 300000).toISOString() };
    }
    assert.match(url, /tenant_id=acme/);
    if (headers.Authorization === "Bearer tok-1" && calls.filter((u) => u.includes("keycore")).length === 2) {
      throw new APIError(401, "unauthorized", "expired");
    }
    return { key: { id: "k1", algorithm: "AES-256" } };
  };
  assert.equal((await c.getKey("k1")).algorithm, "AES-256");
  assert.equal((await c.getKey("k1")).id, "k1");
  assert.equal(calls.filter((u) => u.endsWith("client-token")).length, 2);
  c.close();
});

test("a refusal is an APIError with the KMS's reason", async () => {
  const c = new Client({ baseUrl: "https://kms.example.com", tenantId: "acme", token: "t" });
  c._send = async () => { throw new APIError(403, "no_matching_grant", "access denied", "req_1"); };
  await assert.rejects(c.encrypt("k2", Buffer.from("x")), (e) => e instanceof APIError && e.refused && e.code === "no_matching_grant" && /req_1/.test(e.message));
  c.close();
});

test("listKeys follows the cursor; encrypt sends base64", async () => {
  const c = new Client({ baseUrl: "https://kms.example.com", tenantId: "acme", token: "t" });
  const urls = [];
  const pages = [
    { items: [{ id: "a" }, { id: "b" }], has_more: true, next_cursor: { after_created_at: "2026-10-23T00:00:00Z", after_id: "b" } },
    { items: [{ id: "c" }], has_more: false },
  ];
  c._send = async (method, url) => { urls.push(url); return pages[urls.length - 1]; };
  const ids = [];
  for await (const k of c.listKeys()) ids.push(k.id);
  assert.deepEqual(ids, ["a", "b", "c"]);
  assert.match(urls[1], /after_id=b/);

  let sent;
  c._send = async (method, url, body) => { sent = body; return { key_id: "k1", version: 3, ciphertext: "Y3Q=", iv: "aXY=" }; };
  const ct = await c.encrypt("k1", Buffer.from("hello"), Buffer.from("ctx"));
  assert.equal(sent.plaintext, "aGVsbG8=");
  assert.equal(sent.aad, "Y3R4");
  assert.equal(ct.version, 3);
  assert.equal(ct.ciphertext.toString(), "ct");
  c.close();
});
