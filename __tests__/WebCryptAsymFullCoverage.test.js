// __tests__/WebCryptAsymFullCoverage.test.js
import { WebCryptAsym } from "../src/WebCryptAsym.js";

describe("WebCryptAsym Full Coverage Expansion", () => {
  let wca;
  let rsaKeyPair;
  let ecdsaKeyPair;

  beforeAll(async () => {
    wca = new WebCryptAsym();
    rsaKeyPair = await wca.generateKeyPair();
    ecdsaKeyPair = await wca.generateSigningKeyPair("P-256");
  });

  test("ECDSA P-256 and P-384 digital signature signing & verification", async () => {
    const data = "Message to be digitally signed with ECDSA";

    // P-256
    const signatureP256 = await wca.signText(data, ecdsaKeyPair.privateKey);
    expect(typeof signatureP256).toBe("string");
    const validP256 = await wca.verifyText(data, signatureP256, ecdsaKeyPair.publicKey);
    expect(validP256).toBe(true);

    // P-384
    const ecdsaP384KeyPair = await wca.generateSigningKeyPair("P-384");
    const signatureP384 = await wca.signText(data, ecdsaP384KeyPair.privateKey);
    const validP384 = await wca.verifyText(data, signatureP384, ecdsaP384KeyPair.publicKey);
    expect(validP384).toBe(true);
  });

  test("Key export and import (spki / pkcs8)", async () => {
    const publicB64 = await wca.exportPublicKey(rsaKeyPair.publicKey);
    expect(typeof publicB64).toBe("string");

    const privateB64 = await wca.exportPrivateKey(rsaKeyPair.privateKey);
    expect(typeof privateB64).toBe("string");

    const importedPublic = await wca.importPublicKey(publicB64);
    expect(importedPublic).toBeDefined();

    const importedPrivate = await wca.importPrivateKey(privateB64);
    expect(importedPrivate).toBeDefined();
  });

  test("ECDH Key Agreement & Encryption (generateECDHKeyPair, deriveECDHSharedSecret, encryptWithECDH)", async () => {
    const aliceKeys = await wca.generateECDHKeyPair("P-256");
    const bobKeys = await wca.generateECDHKeyPair("P-256");

    const sharedKeyAlice = await wca.deriveECDHSharedSecret(
      aliceKeys.privateKey,
      bobKeys.publicKey
    );
    const sharedKeyBob = await wca.deriveECDHSharedSecret(bobKeys.privateKey, aliceKeys.publicKey);
    expect(sharedKeyAlice).toBeDefined();
    expect(sharedKeyBob).toBeDefined();

    const message = "Secret ECDH payload";
    const encrypted = await wca.encryptWithECDH(message, aliceKeys.privateKey, bobKeys.publicKey);
    const decrypted = await wca.decryptWithECDH(encrypted, bobKeys.privateKey, aliceKeys.publicKey);
    expect(decrypted).toBe(message);
  });

  test("JWE compact encryption and decryption (RFC 7516)", async () => {
    const payload = JSON.stringify({ user: "Alice", role: "admin" });

    const jweCompact = await wca.encryptJWE(payload, rsaKeyPair.publicKey);
    expect(typeof jweCompact).toBe("string");
    expect(jweCompact.split(".").length).toBe(5);

    const decrypted = await wca.decryptJWE(jweCompact, rsaKeyPair.privateKey);
    const decryptedStr = typeof decrypted === "object" ? JSON.stringify(decrypted) : decrypted;
    expect(JSON.parse(decryptedStr)).toEqual(JSON.parse(payload));
  });

  test("Asymmetric WebRTC stream transforms (createEncryptTransform & createDecryptTransform)", async () => {
    const encryptTransform = await wca.createEncryptTransform(rsaKeyPair.publicKey);
    const decryptTransform = await wca.createDecryptTransform(rsaKeyPair.privateKey);

    const rawData = new Uint8Array([1, 2, 3, 4, 5]).buffer;
    const frame = { data: rawData };
    const enqueued = [];

    await encryptTransform(frame, { enqueue: f => enqueued.push(f) });
    expect(enqueued.length).toBe(1);

    const decryptedEnqueued = [];
    await decryptTransform({ data: enqueued[0].data }, { enqueue: f => decryptedEnqueued.push(f) });
    expect(decryptedEnqueued.length).toBe(1);
    expect(new Uint8Array(decryptedEnqueued[0].data)).toEqual(new Uint8Array([1, 2, 3, 4, 5]));
  });
});
