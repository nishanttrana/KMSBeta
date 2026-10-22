import { describe, expect, it } from "vitest";
import { isSealedKeyFile, keyPackageOf, unsealKeyFile } from "../../src/lib/backupSchedules";

// A scheduled backup's key file is sealed to the administrator's RSA key
// (RSA-OAEP-SHA256, the label in oaep_label). The restore dialog opens it
// in the browser; the private key is never sent.
const enc = (o: unknown) => btoa(String.fromCharCode(...new TextEncoder().encode(JSON.stringify(o))));
const b64 = (u: ArrayBuffer | Uint8Array) => btoa(String.fromCharCode(...new Uint8Array(u)));

async function pair() {
  const kp = await crypto.subtle.generateKey({ name: "RSA-OAEP", modulusLength: 3072, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, true, ["encrypt", "decrypt"]);
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", kp.privateKey));
  return { pub: kp.publicKey, pem: `-----BEGIN PRIVATE KEY-----\n${b64(pkcs8).replace(/(.{64})/g, "$1\n")}\n-----END PRIVATE KEY-----\n` };
}

describe("unsealing a scheduled backup's key file", () => {
  it("opens with the right private key and is refused by another", async () => {
    const { pub, pem } = await pair();
    const backupKey = crypto.getRandomValues(new Uint8Array(32));
    const label = "vecta-kms backup key v1";
    const wrapped = await crypto.subtle.encrypt({ name: "RSA-OAEP", label: new TextEncoder().encode(label) }, pub, backupKey);
    const file = enc({ mode: "recipient_sealed", oaep_label: label, wrapped_key_b64: b64(wrapped), backup_id: "bkp_1" });

    expect(isSealedKeyFile(file)).toBe(true);
    const opened = await unsealKeyFile(file, pem);
    const pkg = keyPackageOf(opened)!;
    expect(pkg.backup_key_b64).toBe(b64(backupKey));
    expect(pkg.backup_id).toBe("bkp_1");
    expect(isSealedKeyFile(opened)).toBe(false);

    const other = await pair();
    await expect(unsealKeyFile(file, other.pem)).rejects.toThrow("does not open");
    await expect(unsealKeyFile(file, "-----BEGIN RSA PRIVATE KEY-----\nAA==\n-----END RSA PRIVATE KEY-----")).rejects.toThrow("PKCS#8");
    await expect(unsealKeyFile(enc({ mode: "software", backup_key_b64: "x" }), pem)).rejects.toThrow("not a sealed");
  });
});
