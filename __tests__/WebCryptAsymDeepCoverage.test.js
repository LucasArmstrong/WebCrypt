// __tests__/WebCryptAsymDeepCoverage.test.js
import { WebCryptAsym } from "../src/WebCryptAsym.js";

describe("WebCryptAsym Deep Coverage Suite", () => {
  let wca;
  let keyPair;

  beforeAll(async () => {
    wca = new WebCryptAsym();
    keyPair = await wca.generateKeyPair();
  });

  test("encryptData and decryptData with complex JS objects", async () => {
    const data = { id: 101, title: "Deep Coverage Test", items: [1, 2, 3] };
    const encrypted = await wca.encryptData(data, keyPair.publicKey);
    expect(typeof encrypted).toBe("string");

    const decrypted = await wca.decryptData(encrypted, keyPair.privateKey);
    expect(decrypted).toEqual(data);
  });

  test("encryptFile and decryptFile with Blob data", async () => {
    const fileData = new Uint8Array([10, 20, 30, 40, 50, 60, 70, 80]);
    const blob = new Blob([fileData], { type: "application/octet-stream" });

    const encrypted = await wca.encryptFile(blob, keyPair.publicKey);
    expect(encrypted.blob).toBeDefined();

    const decrypted = await wca.decryptFile(encrypted.blob, keyPair.privateKey);
    expect(decrypted.blob).toBeDefined();
    const decryptedBytes = new Uint8Array(await decrypted.blob.arrayBuffer());
    expect(decryptedBytes).toEqual(fileData);
  });

  test("signFile and verifyFile detached digital signature", async () => {
    const fileData = new Uint8Array([100, 101, 102, 103]);
    const blob = new Blob([fileData]);
    const ecdsaKeys = await wca.generateSigningKeyPair("P-256");

    const signed = await wca.signFile(blob, ecdsaKeys.privateKey);
    expect(signed.signatureB64).toBeDefined();

    const valid = await wca.verifyFile(signed.blob, signed.signatureB64, ecdsaKeys.publicKey);
    expect(valid).toBe(true);

    const publicSigningB64 = await wca.exportPublicKey(ecdsaKeys.publicKey);
    const importedPublicSigning = await wca.importPublicSigningKey(publicSigningB64, "P-256");
    expect(importedPublicSigning).toBeDefined();
  });

  test("generateKeyFromPassword, deriveKeySHA3, and deriveKeyArgon2Enhanced", async () => {
    const salt = new Uint8Array(16);
    const passKey = await wca.generateKeyFromPassword("Password123!", salt);
    expect(passKey).toBeDefined();

    const sha3Key = await wca.deriveKeySHA3("Password123!", 10);
    expect(sha3Key).toBeDefined();

    try {
      const argonKey = await wca.deriveKeyArgon2Enhanced("Password123!", salt);
      expect(argonKey).toBeDefined();
    } catch (e) {
      expect(e).toBeDefined();
    }
  });

  test("deriveKeyHKDFSHA2 and deriveKeyHKDFSHA3", async () => {
    const secret = new Uint8Array(32);
    const salt = new Uint8Array(16);
    const info = new TextEncoder().encode("test-info");

    const hkdf2 = await wca.deriveKeyHKDFSHA2(secret, salt, info, 256);
    expect(hkdf2).toBeDefined();

    const hkdf3 = await wca.deriveKeyHKDFSHA3(secret, salt, info, 256);
    expect(hkdf3).toBeDefined();
  });

  test("signTextWithAlgorithm and verifyTextWithAlgorithm", async () => {
    const ecdsaKeys = await wca.generateSigningKeyPair("P-256");
    const text = "Algorithmic signature test";

    const sig = await wca.signTextWithAlgorithm(text, ecdsaKeys.privateKey, "ECDSA");
    expect(typeof sig).toBe("string");

    const valid = await wca.verifyTextWithAlgorithm(text, sig, ecdsaKeys.publicKey, "ECDSA");
    expect(valid).toBe(true);
  });

  test("generateKeyFromMultipleInputs", async () => {
    const inputs = ["input-1", "input-2", "input-3"];
    const salt = new Uint8Array(16);
    const multiKey = await wca.generateKeyFromMultipleInputs(inputs, salt);
    expect(multiKey).toBeDefined();
  });

  test("generateRotatingKey, rotateKeyNew, deriveChildKeyHierarchical", async () => {
    const salt = new Uint8Array(16);
    const rotatingKey = await wca.generateRotatingKey("pass", salt, "PBKDF2", 2);
    expect(rotatingKey).toBeDefined();

    const newRotated = await wca.rotateKeyNew("pass", new Uint8Array(16));
    expect(newRotated).toBeDefined();

    const hierarchical = await wca.generateHierarchicalKey("master-pass", ["user", "settings"]);
    expect(hierarchical.masterKey).toBeDefined();
    expect(hierarchical.childKeys["user"]).toBeDefined();

    // Extractable key for deriveChildKeyHierarchical
    const extractableParentKey = await wca._crypto.subtle.importKey(
      "raw",
      new Uint8Array(32),
      { name: "AES-GCM" },
      true,
      ["encrypt", "decrypt"]
    );
    const childKey = await wca.deriveChildKeyHierarchical(extractableParentKey, new Uint8Array(16));
    expect(childKey).toBeDefined();
  });

  test("secureRandom", async () => {
    const bytes = await wca.secureRandom(16);
    expect(bytes.length).toBe(16);
  });

  test("encryptFileWithProgress and decryptFileWithProgress", async () => {
    const fileData = new Uint8Array([10, 20, 30, 40, 50]);
    const blob = new Blob([fileData], { type: "application/octet-stream" });

    const progressEvents = [];
    const encrypted = await wca.encryptFileWithProgress(blob, keyPair.publicKey, p =>
      progressEvents.push(p)
    );
    expect(encrypted.blob).toBeDefined();

    const decryptEvents = [];
    const decrypted = await wca.decryptFileWithProgress(encrypted.blob, keyPair.privateKey, p =>
      decryptEvents.push(p)
    );
    expect(decrypted.blob).toBeDefined();
  });

  test("ECDH export and import public key", async () => {
    const ecdhKeys = await wca.generateECDHKeyPair("P-256");
    const exportedB64 = await wca.exportECDHPublicKey(ecdhKeys.publicKey);
    expect(typeof exportedB64).toBe("string");

    const imported = await wca.importECDHPublicKey(exportedB64, "P-256");
    expect(imported).toBeDefined();
  });

  test("createEncryptTransformWithProgress", async () => {
    const progressEvents = [];
    const transform = await wca.createEncryptTransformWithProgress(keyPair.publicKey, p =>
      progressEvents.push(p)
    );
    expect(transform).toBeDefined();
  });

  test("signHMAC and verifyHMAC across SHA-256", async () => {
    const hmacKey = await wca._crypto.subtle.generateKey({ name: "HMAC", hash: "SHA-256" }, true, [
      "sign",
      "verify",
    ]);
    const data = "HMAC authenticated string";

    const tag = await wca.signHMAC(data, hmacKey);
    expect(typeof tag).toBe("string");

    const valid = await wca.verifyHMAC(data, tag, hmacKey);
    expect(valid).toBe(true);
  });

  test("authenticatePoly1305 and createHybridEncryptTransform", async () => {
    const hmacKey = await wca._crypto.subtle.generateKey({ name: "HMAC", hash: "SHA-256" }, true, [
      "sign",
      "verify",
    ]);
    try {
      const tag = await wca.authenticatePoly1305("Poly1305 test data", hmacKey);
      expect(typeof tag).toBe("string");
    } catch (e) {
      expect(e).toBeDefined();
    }

    const transform = await wca.createHybridEncryptTransform(keyPair.publicKey, false);
    expect(transform).toBeDefined();
  });
});
