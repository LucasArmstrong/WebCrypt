import { WebCryptAsym } from "../src/WebCryptAsym.js";

describe("WebCryptAsym JSON Web Encryption (JWE)", () => {
  let crypt;
  let keys;

  beforeAll(async () => {
    crypt = new WebCryptAsym();
    keys = await crypt.generateKeyPair();
  });

  afterAll(() => {
    if (crypt) {
      crypt.stopAutoCleanup();
    }
  });

  test("should encrypt and decrypt a string payload", async () => {
    const payload = "Hello JWE World!";
    const jwe = await crypt.encryptJWE(payload, keys.publicKey);

    expect(typeof jwe).toBe("string");
    expect(jwe.split(".").length).toBe(5);

    const decrypted = await crypt.decryptJWE(jwe, keys.privateKey);
    expect(decrypted).toBe(payload);
  });

  test("should encrypt and decrypt a JSON object payload", async () => {
    const payload = { userId: 123, role: "admin", exp: 9999999999 };
    const jwe = await crypt.encryptJWE(payload, keys.publicKey, { kid: "key-1" });

    expect(typeof jwe).toBe("string");

    const decrypted = await crypt.decryptJWE(jwe, keys.privateKey);
    expect(decrypted).toEqual(payload);
  });

  test("should fail to decrypt if jwe is tampered with", async () => {
    const payload = "Secret Data";
    const jwe = await crypt.encryptJWE(payload, keys.publicKey);

    const parts = jwe.split(".");
    // Tamper with the ciphertext (assuming it's base64url encoded, changing a char is enough)
    parts[3] = parts[3].substring(0, parts[3].length - 1) + (parts[3].endsWith("A") ? "B" : "A");
    const tamperedJwe = parts.join(".");

    await expect(crypt.decryptJWE(tamperedJwe, keys.privateKey)).rejects.toThrow();
  });

  test("should fail to decrypt with wrong private key", async () => {
    const payload = "Secret Data";
    const jwe = await crypt.encryptJWE(payload, keys.publicKey);

    const wrongKeys = await crypt.generateKeyPair();

    await expect(crypt.decryptJWE(jwe, wrongKeys.privateKey)).rejects.toThrow();
  });
});
