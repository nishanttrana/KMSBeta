// Run by services/keycore's TestSDKsAgainstKeycore against keycore's real
// routes over TLS. Exits non-zero, saying what failed, if the SDK and
// keycore disagree. Not part of the package.
import assert from "node:assert/strict";
import fs from "node:fs";
import { APIError, Client } from "./index.js";

const env = process.env;
const c = new Client({ baseUrl: env.VECTA_URL, tenantId: env.VECTA_TENANT, token: env.VECTA_TOKEN, ca: fs.readFileSync(env.VECTA_CA) });
const [aes, signer, hidden] = [env.AES_KEY, env.SIGN_KEY, env.HIDDEN_KEY];

assert.equal((await c.getKey(aes)).algorithm, "AES-256", "getKey");
const ct = await c.encrypt(aes, Buffer.from("card 4111"), Buffer.from("order-7"));
assert.equal((await c.decrypt(ct, Buffer.from("order-7"))).toString(), "card 4111", "decrypt");
await assert.rejects(c.decrypt(ct, Buffer.from("order-8")), APIError, "decrypt under other additional data");
const dk = await c.generateDataKey(aes, Buffer.from("blob-1"));
assert.equal(dk.plaintext.length, 32);
assert.ok((await c.decrypt(dk.wrapped, Buffer.from("blob-1"))).equals(dk.plaintext), "data key");
const sig = await c.sign(signer, Buffer.from("release v1"));
assert.ok(await c.verify(sig, Buffer.from("release v1")), "verify");
assert.ok(!(await c.verify(sig, Buffer.from("release v2"))), "verify other data");
const seen = [];
for await (const k of c.listKeys()) seen.push(k.id);
assert.ok(seen.includes(aes) && seen.includes(signer) && !seen.includes(hidden), `listKeys ${seen}`);
await assert.rejects(c.getKey(hidden), (e) => e instanceof APIError && e.notFound, "a key not granted");
const created = await c.createKey({ name: "node-pipeline-key", algorithm: "AES-256", purpose: "encrypt", keyType: "symmetric", labels: { team: "release" } });
assert.equal(await c.rotateKey(created, "scheduled"), 2, "rotate");
const updated = await c.updateKey(created, { description: "release artifacts", labels: { team: "release", tier: "gold" } });
assert.ok(updated.description === "release artifacts" && updated.labels.tier === "gold" && updated.name === "node-pipeline-key", "updateKey");
await c.setKeyAccess(created, [{ subject_type: "client", subject_id: "release-pipeline", operations: ["encrypt"] }]);
assert.equal((await c.getKeyAccess(created))[0].subject_type, "client", "key access");
await c.deactivateKey(created);
await assert.rejects(c.encrypt(created, Buffer.from("x")), APIError, "encrypt with a deactivated key");
c.close();
console.log("node contract ok");
