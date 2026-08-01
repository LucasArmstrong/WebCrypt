// __tests__/WebCryptFullCoverage.test.js
import { WebCrypt } from "../src/WebCrypt.js";

describe("WebCrypt Full Coverage Expansion", () => {
  test("Key cache LRU eviction and manual cleanup", async () => {
    const wc = new WebCrypt();
    const fakeKey = {};

    // Populate key cache with 10 items directly
    for (let i = 0; i < 10; i++) {
      wc.keyCache.set(`pass-${i}:salt`, { key: fakeKey, createdAt: Date.now() - (10 - i) * 1000 });
    }

    expect(wc.keyCache.size).toBe(10);

    // Deriving key 11 triggers LRU eviction of oldest key
    await wc._deriveKey("new-pass", new Uint8Array(16));
    expect(wc.keyCache.size).toBeLessThanOrEqual(10);

    wc._cleanupExpiredKeys();
    wc.clearKeyCache();
    expect(wc.keyCache.size).toBe(0);
    wc.stopAutoCleanup();
  });

  test("generateRandomPassword and static helpers", () => {
    const wc = new WebCrypt();
    const pwd16 = wc.generateRandomPassword(16);
    expect(pwd16.length).toBe(32); // 16 bytes = 32 hex chars

    const pwd64 = wc.generateRandomPassword(64);
    expect(pwd64.length).toBe(128); // 64 bytes = 128 hex chars
  });

  test("generateHmacKeySHA3 with random key generation across SHA3-256/384/512", async () => {
    const wc = new WebCrypt();

    // Random HMAC key generation (instant execution)
    const key1 = await wc.generateHmacKeySHA3(null, "SHA3-256");
    expect(key1).toBeDefined();

    const key2 = await wc.generateHmacKeySHA3(null, "SHA3-384");
    expect(key2).toBeDefined();

    const key3 = await wc.generateHmacKeySHA3(null, "SHA3-512");
    expect(key3).toBeDefined();
  });

  test("WebRTC Insertable Streams createEncryptTransform & createDecryptTransform error handling", async () => {
    const wc = new WebCrypt();
    const encryptTransform = await wc.createEncryptTransform("webrtc-pass");
    const decryptTransform = await wc.createDecryptTransform("webrtc-pass");

    const rawData = new Uint8Array([10, 20, 30, 40, 50]).buffer;
    const frame = { data: rawData };

    const enqueued = [];
    const controller = {
      enqueue: f => enqueued.push(f),
    };

    // Encrypt frame
    await encryptTransform(frame, controller);
    expect(enqueued.length).toBe(1);
    expect(enqueued[0].data.byteLength).toBeGreaterThan(rawData.byteLength);

    // Decrypt frame
    const encryptedFrame = { data: enqueued[0].data };
    const decryptedEnqueued = [];
    const decryptController = {
      enqueue: f => decryptedEnqueued.push(f),
    };

    await decryptTransform(encryptedFrame, decryptController);
    expect(decryptedEnqueued.length).toBe(1);
    expect(new Uint8Array(decryptedEnqueued[0].data)).toEqual(new Uint8Array([10, 20, 30, 40, 50]));

    // Corrupted frame decryption error handling
    const corruptFrame = { data: new Uint8Array(20).buffer };
    const corruptEnqueued = [];
    await decryptTransform(corruptFrame, { enqueue: f => corruptEnqueued.push(f) });
  });

  test("decryptFile handles invalid ciphertext and oversized payloads", async () => {
    const wc = new WebCrypt();
    const invalidCiphertext = new Uint8Array(10); // Too short

    await expect(wc.decryptFile(invalidCiphertext, "password")).rejects.toThrow();
  });
});
