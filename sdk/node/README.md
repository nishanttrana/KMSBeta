# Vecta KMS Node.js SDK

`vecta-kms`: keys, cryptographic operations and secrets over the Vecta KMS
REST API. Node 18 or later, no dependencies, ES module with TypeScript
types.

```bash
npm install ./sdk/node
```

It authenticates as a REST client (client ID and API key, Workbench → REST
API), exchanging them for short-lived tokens it renews itself. To use keys,
grant the client a role with key permissions and assign each key to the
client ([CI_CD_AUTOMATION.md](../../docs/CI_CD_AUTOMATION.md#a-role-for-a-client-13530-beta)).

```js
import fs from "node:fs";
import { APIError, Client } from "vecta-kms";

const kms = new Client({ baseUrl: "https://kms.example.com", tenantId: "acme",
  clientId: process.env.KMS_CLIENT_ID, apiKey: process.env.KMS_API_KEY,
  ca: fs.readFileSync("vecta-root-ca.pem") }); // when the KMS certificate is from its own CA

const ct = await kms.encrypt(keyId, Buffer.from("card 4111"), Buffer.from("order-7"));
const plain = await kms.decrypt(ct, Buffer.from("order-7"));
const dk = await kms.generateDataKey(keyId); // use dk.plaintext, keep dk.wrapped
const sig = await kms.sign(signingKeyId, Buffer.from("release v1"));
const ok = await kms.verify(sig, Buffer.from("release v1"));
for await (const key of kms.listKeys()) console.log(key.id, key.name);
const { value } = await kms.getSecretValue(secretId);
kms.close();
```

`createKey`, `getKey` and `rotateKey` manage keys when the client's role
allows. A refused or failed call rejects with `APIError` (`status`, `code`,
`requestId`; `refused` for 401/403, `notFound` for 404). HTTPS and TLS 1.3
only.

Tests: `node --test test/client.test.mjs`. keycore's `TestSDKsAgainstKeycore`
runs `contract.mjs` against the real routes over TLS on every CI run.
