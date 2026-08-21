import { WebCrypt } from "../src/WebCrypt.js";
import { WebCryptAsym } from "../src/WebCryptAsym.js";
import { WebCryptPQC } from "../src/WebCryptPQC.js";
import TimingSafeHelper from "../src/TimingSafeHelper.js";
import { getCrypto } from "../src/_crypto.js";

describe("WebCrypt Deep Coverage Boost - 100% Target", () => {
  let wc, asym, pqc;

  beforeEach(() => {
    wc = new WebCrypt();
    asym = new WebCryptAsym();
    pqc = new WebCryptPQC();
    WebCryptPQC.enableStubTesting(true);
  });

  test("asym rotateKeyNew covers all 4 KDF methods", async () => {
    const salt = new Uint8Array(16).fill(1);
    const pass = "rotation-test-password";

    const k1 = await asym.rotateKeyNew(pass, salt, "Argon2");
    expect(k1).toBeDefined();

    const k2 = await asym.rotateKeyNew(pass, salt, "SHA3");
    expect(k2).toBeDefined();

    const k3 = await asym.rotateKeyNew(pass, salt, "HKDF");
    expect(k3).toBeDefined();

    const k4 = await asym.rotateKeyNew(pass, salt, "PBKDF2");
    expect(k4).toBeDefined();

    const kDefault = await asym.rotateKeyNew(pass, salt, "UNKNOWN_DEFAULT");
    expect(kDefault).toBeDefined();

    // Test HKDF-SHA2 with null salt
    const secretBytes = new TextEncoder().encode("hkdf-secret");
    const hkdfKey = await asym.deriveKeyHKDFSHA2(secretBytes, null);
    expect(hkdfKey).toBeDefined();
  });

  test("asym hierarchical child key derivation and secureKeyErase", async () => {
    const crypto = getCrypto();
    const rawMaster = crypto.getRandomValues(new Uint8Array(32));
    const masterKey = await crypto.subtle.importKey(
      "raw",
      rawMaster,
      { name: "AES-GCM", length: 256 },
      true,
      ["encrypt", "decrypt"]
    );

    const childSalt = new Uint8Array(16).fill(5);
    const child1 = await asym.deriveChildKeyHierarchical(masterKey, childSalt, "custom-purpose");
    expect(child1).toBeDefined();

    const keyToErase = new Uint8Array([1, 2, 3, 4]);
    asym.secureKeyErase(keyToErase);
    expect(keyToErase[0]).toBe(0);
    expect(keyToErase[3]).toBe(0);
  });

  test("asym encryptData and decryptData roundtrip with complex object", async () => {
    const keyPair = await asym.generateKeyPair(2048);
    const payload = {
      user: "agent-x",
      privileges: ["root", "sec"],
      nested: { timestamp: Date.now(), flags: [true, false] },
    };

    const ciphertext = await asym.encryptData(payload, keyPair.publicKey);
    expect(typeof ciphertext).toBe("string");

    const decrypted = await asym.decryptData(ciphertext, keyPair.privateKey);
    expect(decrypted).toEqual(payload);
  });

  test("asym file streaming with progress callbacks", async () => {
    const keyPair = await asym.generateKeyPair(2048);
    const data = new Uint8Array(20 * 1024).fill(42);
    const file = new File([data], "test-doc.bin", { type: "application/octet-stream" });

    let encProgressCalled = false;
    let decProgressCalled = false;

    const { blob } = await asym.encryptFileWithProgress(file, keyPair.publicKey, progress => {
      encProgressCalled = true;
      expect(progress).toBeDefined();
    });

    const { blob: decryptedBlob } = await asym.decryptFileWithProgress(
      blob,
      keyPair.privateKey,
      progress => {
        decProgressCalled = true;
        expect(progress).toBeDefined();
      }
    );

    expect(encProgressCalled).toBe(true);
    expect(decProgressCalled).toBe(true);
    expect(decryptedBlob.size).toBe(20 * 1024);
  });

  test("symmetric file streaming with parallel chunks and corrupted data checks", async () => {
    const data = new Uint8Array(30 * 1024).fill(99);
    const file = new File([data], "sym-doc.bin", { type: "application/octet-stream" });

    const { blob } = await wc.encryptFile(file, "stream-pass", { parallelChunks: 2 });
    const { blob: decryptedBlob } = await wc.decryptFile(blob, "stream-pass", {
      parallelChunks: 2,
    });

    expect(decryptedBlob.size).toBe(30 * 1024);

    // Corrupted / too short blob
    const shortBlob = new Blob([new Uint8Array(5)]);
    await expect(wc.decryptFile(shortBlob, "stream-pass")).rejects.toThrow("Decryption failed");
  });

  test("generateHmacKey with customSalt and no password branches", async () => {
    const customSalt = new Uint8Array(16).fill(3);
    const keyWithSalt = await wc.generateHmacKey("my-pass", "SHA-256", customSalt);
    expect(keyWithSalt).toBeDefined();

    const randomKey = await wc.generateHmacKey();
    expect(randomKey).toBeDefined();
  });

  test("pqc Kyber512, Kyber1024 and Dilithium2, Dilithium5 level roundtrips", async () => {
    // Kyber512
    const k512Keys = await pqc.generateKyberKeyPair("Kyber512");
    const enc512 = await pqc.kyberEncapsulate(k512Keys.publicKey, "Kyber512");
    const dec512Secret = await pqc.kyberDecapsulate(
      enc512.ciphertext,
      k512Keys.privateKey,
      "Kyber512"
    );
    expect(new Uint8Array(dec512Secret)).toEqual(new Uint8Array(enc512.sharedSecret));

    // Kyber1024
    const k1024Keys = await pqc.generateKyberKeyPair("Kyber1024");
    const enc1024 = await pqc.kyberEncapsulate(k1024Keys.publicKey, "Kyber1024");
    const dec1024Secret = await pqc.kyberDecapsulate(
      enc1024.ciphertext,
      k1024Keys.privateKey,
      "Kyber1024"
    );
    expect(new Uint8Array(dec1024Secret)).toEqual(new Uint8Array(enc1024.sharedSecret));

    // Dilithium2
    const d2Keys = await pqc.generateDilithiumKeyPair("Dilithium2");
    const sig2 = await pqc.dilithiumSign("D2 message", d2Keys.privateKey, "Dilithium2");
    const valid2 = await pqc.dilithiumVerify("D2 message", sig2, d2Keys.publicKey, "Dilithium2");
    expect(valid2).toBe(true);

    // Dilithium5
    const d5Keys = await pqc.generateDilithiumKeyPair("Dilithium5");
    const sig5 = await pqc.dilithiumSign("D5 message", d5Keys.privateKey, "Dilithium5");
    const valid5 = await pqc.dilithiumVerify("D5 message", sig5, d5Keys.publicKey, "Dilithium5");
    expect(valid5).toBe(true);
  });

  test("TimingSafeHelper compare edge cases", async () => {
    const a = new Uint8Array([1, 2, 3]);
    const b = new Uint8Array([1, 2, 4]);
    const c = new Uint8Array([1, 2]);

    expect(await TimingSafeHelper.constantTimeCompareBuffers(a, a)).toBe(true);
    expect(await TimingSafeHelper.constantTimeCompareBuffers(a, b)).toBe(false);
    expect(await TimingSafeHelper.constantTimeCompareBuffers(a, c)).toBe(false);
  });
});
