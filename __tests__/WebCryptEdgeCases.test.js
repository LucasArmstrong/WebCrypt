// __tests__/WebCryptEdgeCases.test.js
import { WebCrypt } from "../src/WebCrypt.js";
import { WebCryptAsym } from "../src/WebCryptAsym.js";
import { WebCryptPQC } from "../src/WebCryptPQC.js";

describe("WebCrypt Additional Edge Cases & Security Checks", () => {
  test("WebCryptPQC stub mode blocking and toggling", () => {
    // Default state: stub testing is blocked
    WebCryptPQC.enableStubTesting(false);
    expect(WebCryptPQC.isStub()).toBe(true);

    const pqc = new WebCryptPQC();
    expect(() => pqc._checkStubMode()).toThrow("WebCryptPQC is a placeholder stub");

    // Enable stub testing mode
    WebCryptPQC.enableStubTesting(true);
    expect(WebCryptPQC.isStub()).toBe(false);
    expect(() => pqc._checkStubMode()).not.toThrow();
  });

  test("WebCryptAsym.decryptFile throws on corrupted or truncated files", async () => {
    const wca = new WebCryptAsym();
    const rsaKeys = await wca.generateKeyPair(2048);

    // Too small blob (less than header min length)
    const tinyBlob = new Blob([new Uint8Array(10)]);
    await expect(wca.decryptFile(tinyBlob, rsaKeys.privateKey)).rejects.toThrow(
      "Decryption failed"
    );

    // Corrupted encKeyLen length header
    const badHeaderBlob = new Blob([new Uint8Array([255, 255, 255, 255, 1, 2, 3, 4, 5])]);
    await expect(wca.decryptFile(badHeaderBlob, rsaKeys.privateKey)).rejects.toThrow(
      "Decryption failed"
    );
  });

  test("WebCrypt.decryptFile throws when file exceeds MAX_ENCRYPTED_DATA_SIZE limit", async () => {
    const wc = new WebCrypt();
    const mockFile = { size: WebCrypt.MAX_ENCRYPTED_DATA_SIZE + 100 };
    await expect(wc.decryptFile(mockFile, "password")).rejects.toThrow(
      "File too large for decryption"
    );
  });

  test("WebCrypt _arrayBufferToBase64 and _base64ToArrayBuffer handles 64KB multi-chunk payloads", () => {
    const wc = new WebCrypt();
    // 65536 bytes (spans across two 32KB chunks)
    const largeBytes = new Uint8Array(65536);
    for (let i = 0; i < largeBytes.length; i++) {
      largeBytes[i] = i % 256;
    }

    const b64 = wc._arrayBufferToBase64(largeBytes.buffer);
    expect(typeof b64).toBe("string");

    const recoveredBuffer = wc._base64ToArrayBuffer(b64);
    const recoveredBytes = new Uint8Array(recoveredBuffer);
    expect(recoveredBytes.length).toBe(65536);
    expect(recoveredBytes[0]).toBe(0);
    expect(recoveredBytes[255]).toBe(255);
    expect(recoveredBytes[65535]).toBe(255);
  });
});
