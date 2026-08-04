// __tests__/CoverageBoost.test.js
import { WebCrypt } from "../src/WebCrypt.js";
import { WebCryptAsym } from "../src/WebCryptAsym.js";
import { WebCryptPQC } from "../src/WebCryptPQC.js";

describe("WebCrypt Additional Coverage Boost", () => {
  test("WebCrypt static properties access and transforms", async () => {
    expect(WebCrypt.ALGORITHM).toBe("AES-GCM");
    expect(WebCrypt.KEY_LENGTH).toBe(256);
    expect(WebCrypt.IV_LENGTH).toBe(12);
    expect(WebCrypt.SALT_LENGTH).toBe(16);
    expect(WebCrypt.PBKDF2_ITERATIONS).toBe(600_000);
    expect(WebCrypt.HASH_ALGORITHM).toBe("SHA-256");
    expect(WebCrypt.CHUNK_SIZE).toBe(8 * 1024 * 1024);

    const wc = new WebCrypt();
    const encTransform = await wc.createEncryptTransform("webrtcPass");
    const decTransform = await wc.createDecryptTransform("webrtcPass");
    expect(typeof encTransform).toBe("function");
    expect(typeof decTransform).toBe("function");

    const encCalls = [];
    const mockFrame = { data: new ArrayBuffer(16) };
    const mockController = { enqueue: val => encCalls.push(val) };

    await encTransform(mockFrame, mockController);
    expect(encCalls.length).toBe(1);

    const encryptedFrame = encCalls[0];
    const decCalls = [];
    const mockDecController = { enqueue: val => decCalls.push(val) };
    await decTransform(encryptedFrame, mockDecController);
    expect(decCalls.length).toBe(1);
  });

  test("WebCrypt HMAC generation without password", async () => {
    const wc = new WebCrypt();
    const randomHmacKey = await wc.generateHmacKey();
    expect(randomHmacKey).toBeDefined();

    const tag = await wc.computeHmac("data to sign", randomHmacKey);
    const valid = await wc.verifyHmac("data to sign", tag, randomHmacKey);
    expect(valid).toBe(true);
  });

  test("WebCrypt SHA3 HMAC KDF with custom salts and iterations", async () => {
    const wc = new WebCrypt();
    const key1 = await wc.generateHmacKeySHA3("pass1", "SHA3-256", "string-salt", 2);
    expect(key1).toBeDefined();

    const key2 = await wc.generateHmacKeySHA3("pass1", "SHA3-256", new Uint8Array(16), 2);
    expect(key2).toBeDefined();

    const key3 = await wc.generateHmacKey("pass1", "SHA-256", "string-salt");
    expect(key3).toBeDefined();
  });

  test("WebCrypt decryptData syntax error branch", async () => {
    const wc = new WebCrypt();
    const b64 = await wc.encryptText("non-json plain string text", "password123");
    await expect(wc.decryptData(b64, "password123")).rejects.toThrow(
      /Failed to parse decrypted data as JSON/
    );
  });

  test("WebCrypt parallelChunks streaming file encryption and decryption", async () => {
    const wc = new WebCrypt();
    const testData = new Uint8Array(20 * 1024); // 20KB payload
    for (let i = 0; i < testData.length; i++) {
      testData[i] = i % 256;
    }
    const blob = new Blob([testData], { type: "application/octet-stream" });

    const encrypted = await wc.encryptFile(blob, "streamPass", { parallelChunks: 2 });
    expect(encrypted.blob).toBeDefined();

    const decrypted = await wc.decryptFile(encrypted.blob, "streamPass", { parallelChunks: 2 });
    expect(decrypted.blob).toBeDefined();
    const decryptedBytes = new Uint8Array(await decrypted.blob.arrayBuffer());
    expect(decryptedBytes.length).toBe(testData.length);
    expect(decryptedBytes[0]).toBe(testData[0]);
  });

  test("WebCryptAsym deriveChildKeyHierarchical", async () => {
    const wca = new WebCryptAsym();
    const masterKey = await wca._crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, [
      "encrypt",
      "decrypt",
    ]);
    const childSalt = new Uint8Array(16);
    const childKey = await wca.deriveChildKeyHierarchical(masterKey, childSalt, "test-purpose");
    expect(childKey).toBeDefined();
  });

  test("WebCryptAsym decryptWithECDH invalid data branch", async () => {
    const wca = new WebCryptAsym();
    const ecdhPair = await wca.generateECDHKeyPair();
    const shortB64 = wca._arrayBufferToBase64(new Uint8Array(4));

    await expect(
      wca.decryptWithECDH(shortB64, ecdhPair.privateKey, ecdhPair.publicKey)
    ).rejects.toThrow("Invalid encrypted data");
  });

  test("WebCryptAsym Argon2 fallback paths", async () => {
    const wca = new WebCryptAsym();
    const salt = new Uint8Array(16);
    const k1 = await wca.deriveKeyArgon2("secret", salt);
    expect(k1).toBeDefined();

    await expect(wca.deriveKeyArgon2Enhanced("secret", salt)).rejects.toThrow();
  });

  test("WebCryptAsym JWE error branches and plain string payload", async () => {
    const wca = new WebCryptAsym();
    const rsaKeys = await wca.generateKeyPair(2048);

    await expect(wca.decryptJWE(123, rsaKeys.privateKey)).rejects.toThrow(
      "Invalid JWE token format"
    );
    await expect(wca.decryptJWE("a.b.c", rsaKeys.privateKey)).rejects.toThrow(
      "Invalid JWE token structure"
    );
    await expect(wca.decryptJWE("invalidHeader.b.c.d.e", rsaKeys.privateKey)).rejects.toThrow(
      /Failed to parse JWE header/
    );

    const badAlgHeader = wca._arrayBufferToBase64Url(
      new TextEncoder().encode(JSON.stringify({ alg: "HS256", enc: "A256GCM" })).buffer
    );
    await expect(wca.decryptJWE(`${badAlgHeader}.b.c.d.e`, rsaKeys.privateKey)).rejects.toThrow(
      /Unsupported JWE algorithm/
    );

    const badEncHeader = wca._arrayBufferToBase64Url(
      new TextEncoder().encode(JSON.stringify({ alg: "RSA-OAEP", enc: "A128GCM" })).buffer
    );
    await expect(wca.decryptJWE(`${badEncHeader}.b.c.d.e`, rsaKeys.privateKey)).rejects.toThrow(
      "Unsupported JWE encryption: A128GCM"
    );

    // Test JWE with non-JSON string payload
    const jweString = await wca.encryptJWE("plain text non-json string", rsaKeys.publicKey);
    const recoveredString = await wca.decryptJWE(jweString, rsaKeys.privateKey);
    expect(recoveredString).toBe("plain text non-json string");
  });

  test("WebCryptPQC unpadded base64 and hybrid fallback paths", async () => {
    const pqc = new WebCryptPQC();
    WebCryptPQC.enableStubTesting(true);

    const unpaddedB64 = "YWJj"; // "abc"
    const buf = pqc._base64ToArrayBuffer(unpaddedB64);
    expect(buf.byteLength).toBe(3);

    const hash384 = await pqc._sha3Hash(new Uint8Array([1, 2, 3]), 384);
    expect(hash384.byteLength).toBe(48);

    const hash512 = await pqc._sha3Hash(new Uint8Array([1, 2, 3]), 512);
    expect(hash512.byteLength).toBe(64);

    const rsaKeys = await pqc._crypto.subtle.generateKey(
      {
        name: "RSA-OAEP",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256",
      },
      true,
      ["encrypt", "decrypt"]
    );
    const kyberKeys = await pqc.generateKyberKeyPair("Kyber768");
    const { kyberCiphertext, rsaWrappedSharedSecret } = await pqc.hybridEncapsulate(
      rsaKeys.publicKey,
      kyberKeys.publicKey,
      "Kyber768"
    );

    const corruptedRsaSecret = new Uint8Array(rsaWrappedSharedSecret);
    corruptedRsaSecret[0] ^= 0xff;

    const hybridResult = await pqc.hybridDecapsulate(
      kyberCiphertext,
      corruptedRsaSecret,
      rsaKeys.privateKey,
      kyberKeys.privateKey,
      "Kyber768"
    );
    expect(hybridResult).toBeDefined();
    expect(hybridResult.byteLength).toBe(32);
  });

  test("WebCrypt Native SHA3 digest mock coverage", async () => {
    const pqc = new WebCryptPQC();
    const originalDigest = pqc._crypto.subtle.digest.bind(pqc._crypto.subtle);
    try {
      pqc._crypto.subtle.digest = async (alg, data) => {
        if (typeof alg === "string" && alg.startsWith("SHA3-")) {
          const size = alg === "SHA3-512" ? 64 : alg === "SHA3-384" ? 48 : 32;
          return new ArrayBuffer(size);
        }
        return originalDigest(alg, data);
      };

      const hash = await pqc._sha3Hash(new Uint8Array([1, 2, 3]), 256);
      expect(hash.byteLength).toBe(32);

      const wca = new WebCryptAsym();
      const masterKey = await wca._crypto.subtle.generateKey(
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"]
      );
      const childKey = await wca.deriveChildKeyHierarchical(
        masterKey,
        new Uint8Array(16),
        "native-sha3"
      );
      expect(childKey).toBeDefined();
    } finally {
      pqc._crypto.subtle.digest = originalDigest;
    }
  });
});
