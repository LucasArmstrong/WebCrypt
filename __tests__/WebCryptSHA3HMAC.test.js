import { WebCrypt } from "../src/WebCrypt.js";

describe("WebCrypt - SHA3-HMAC", () => {
  let crypt;

  beforeEach(() => {
    crypt = new WebCrypt();
  });

  describe("generateHmacKeySHA3", () => {
    test("generates a random key without password", async () => {
      const key = await crypt.generateHmacKeySHA3();

      expect(key.type).toBeTruthy();
    });
  });

  describe("computeHmacSHA3", () => {
    test("computes HMAC-SHA3-256 of a message", async () => {
      const message = new Uint8Array([1, 2, 3, 4, 5]);

      const key = await crypt.generateHmacKeySHA3();
      const tag = await crypt.computeHmacSHA3(message, key);

      expect(typeof tag).toBe("string");
      expect(tag.length).toBeGreaterThan(0);
    });

    test("produces deterministic output", async () => {
      const message = new Uint8Array([1, 2, 3, 4, 5]);
      const key = await crypt.generateHmacKeySHA3();

      const tag1 = await crypt.computeHmacSHA3(message, key);
      const tag2 = await crypt.computeHmacSHA3(message, key);

      expect(tag1).toEqual(tag2);
    });

    test("different messages produce different tags", async () => {
      const key = await crypt.generateHmacKeySHA3();
      const message1 = new Uint8Array([1, 2, 3]);
      const message2 = new Uint8Array([4, 5, 6]);

      const tag1 = await crypt.computeHmacSHA3(message1, key);
      const tag2 = await crypt.computeHmacSHA3(message2, key);

      expect(tag1).not.toEqual(tag2);
    });

    test("different keys produce different tags", async () => {
      const message = new Uint8Array([1, 2, 3, 4, 5]);
      const key1 = await crypt.generateHmacKeySHA3();
      const key2 = await crypt.generateHmacKeySHA3();

      const tag1 = await crypt.computeHmacSHA3(message, key1);
      const tag2 = await crypt.computeHmacSHA3(message, key2);

      // Should be different with very high probability
      expect(tag1).not.toEqual(tag2);
    });
  });

  describe("verifyHmacSHA3", () => {
    test("verifies valid HMAC", async () => {
      const message = new Uint8Array([1, 2, 3, 4, 5]);
      const key = await crypt.generateHmacKeySHA3();
      const tag = await crypt.computeHmacSHA3(message, key);

      const verified = await crypt.verifyHmacSHA3(message, tag, key);

      expect(verified).toBe(true);
    });

    test("rejects invalid HMAC", async () => {
      const message = new Uint8Array([1, 2, 3, 4, 5]);
      const key = await crypt.generateHmacKeySHA3();
      const validTag = await crypt.computeHmacSHA3(message, key);

      // Tamper with the base64 tag
      const tamperedTag = validTag.slice(0, -4) + "XXXX";

      const verified = await crypt.verifyHmacSHA3(message, tamperedTag, key);

      expect(verified).toBe(false);
    });

    test("rejects HMAC from different message", async () => {
      const message1 = new Uint8Array([1, 2, 3]);
      const message2 = new Uint8Array([4, 5, 6]);
      const key = await crypt.generateHmacKeySHA3();
      const tag = await crypt.computeHmacSHA3(message1, key);

      const verified = await crypt.verifyHmacSHA3(message2, tag, key);

      expect(verified).toBe(false);
    });

    test("rejects HMAC from different key", async () => {
      const message = new Uint8Array([1, 2, 3, 4, 5]);
      const key1 = await crypt.generateHmacKeySHA3();
      const key2 = await crypt.generateHmacKeySHA3();

      const tag = await crypt.computeHmacSHA3(message, key1);

      const verified = await crypt.verifyHmacSHA3(message, tag, key2);

      expect(verified).toBe(false);
    });
  });
});
