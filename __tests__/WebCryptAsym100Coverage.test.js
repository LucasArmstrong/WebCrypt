// __tests__/WebCryptAsym100Coverage.test.js
import { WebCryptAsym } from "../src/WebCryptAsym.js";

describe("WebCryptAsym 100% Coverage Expansion", () => {
  let wca;
  let rsaKeyPair;

  beforeAll(async () => {
    wca = new WebCryptAsym();
    rsaKeyPair = await wca.generateKeyPair();
  });

  test("decryptJWE error handling traps across all validation branches", async () => {
    // 1. Invalid input type
    await expect(wca.decryptJWE(12345, rsaKeyPair.privateKey)).rejects.toThrow(
      "Invalid JWE token format"
    );

    // 2. Invalid number of parts
    await expect(wca.decryptJWE("part1.part2.part3", rsaKeyPair.privateKey)).rejects.toThrow(
      "Invalid JWE token structure"
    );

    // 3. Invalid header JSON
    await expect(
      wca.decryptJWE("!!!invalid-header!!!.part2.part3.part4.part5", rsaKeyPair.privateKey)
    ).rejects.toThrow("Failed to parse JWE header");

    // 4. Unsupported algorithm in header
    const badAlgHeader = wca._arrayBufferToBase64Url(
      new TextEncoder().encode(JSON.stringify({ alg: "INVALID", enc: "A256GCM" })).buffer
    );
    await expect(
      wca.decryptJWE(`${badAlgHeader}.part2.part3.part4.part5`, rsaKeyPair.privateKey)
    ).rejects.toThrow("Unsupported JWE algorithm");

    // 5. Unsupported encryption in header
    const badEncHeader = wca._arrayBufferToBase64Url(
      new TextEncoder().encode(JSON.stringify({ alg: "RSA-OAEP", enc: "INVALID" })).buffer
    );
    await expect(
      wca.decryptJWE(`${badEncHeader}.part2.part3.part4.part5`, rsaKeyPair.privateKey)
    ).rejects.toThrow("Unsupported JWE encryption");

    // 6. Failed CEK decryption
    const validHeader = wca._arrayBufferToBase64Url(
      new TextEncoder().encode(JSON.stringify({ alg: "RSA-OAEP", enc: "A256GCM" })).buffer
    );
    const badCek = wca._arrayBufferToBase64Url(new Uint8Array(16).buffer);
    await expect(
      wca.decryptJWE(`${validHeader}.${badCek}.part3.part4.part5`, rsaKeyPair.privateKey)
    ).rejects.toThrow("Failed to decrypt Content Encryption Key");
  });

  test("encryptText and decryptText invalid input error handling", async () => {
    await expect(wca.decryptText(null, rsaKeyPair.privateKey)).rejects.toThrow();
    await expect(wca.decryptText("invalid-b64-rsa", rsaKeyPair.privateKey)).rejects.toThrow();
  });

  test("encryptFile and decryptFile invalid input error handling", async () => {
    await expect(wca.encryptFile(null, rsaKeyPair.publicKey)).rejects.toThrow();
    await expect(wca.decryptFile(null, rsaKeyPair.privateKey)).rejects.toThrow();

    const corruptBlob = new Blob([new Uint8Array(10)]);
    await expect(wca.decryptFile(corruptBlob, rsaKeyPair.privateKey)).rejects.toThrow();
  });
});
