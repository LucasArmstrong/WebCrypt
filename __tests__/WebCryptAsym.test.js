// __tests__/WebCryptAsym.test.js
import { WebCryptAsym } from "../src/WebCryptAsym";
import { jest } from "@jest/globals";

describe("WebCryptAsym", () => {
  let crypt;
  let keyPair;
  let publicKeyB64;
  let privateKeyB64;

  beforeAll(async () => {
    crypt = new WebCryptAsym();
    keyPair = await crypt.generateKeyPair();
    publicKeyB64 = await crypt.exportPublicKey(keyPair.publicKey);
    privateKeyB64 = await crypt.exportPrivateKey(keyPair.privateKey);
  });

  describe("Key Management", () => {
    test("should generate a valid RSA key pair", () => {
      expect(keyPair).toHaveProperty("publicKey");
      expect(keyPair).toHaveProperty("privateKey");
    });

    test("should export and import public key correctly", async () => {
      const importedPublic = await crypt.importPublicKey(publicKeyB64);
      expect(importedPublic).toBeDefined();
      expect(importedPublic.type).toBe("public");
    });

    test("should export and import private key correctly", async () => {
      const importedPrivate = await crypt.importPrivateKey(privateKeyB64);
      expect(importedPrivate).toBeDefined();
      expect(importedPrivate.type).toBe("private");
    });
  });

  describe("Text Encryption/Decryption", () => {
    const plainText = "Hello, this is a secret message! 🚀";

    test("should encrypt and decrypt text correctly", async () => {
      const encrypted = await crypt.encryptText(plainText, keyPair.publicKey);
      expect(encrypted).toBeTruthy();
      expect(typeof encrypted).toBe("string");

      const decrypted = await crypt.decryptText(encrypted, keyPair.privateKey);
      expect(decrypted).toBe(plainText);
    });

    test("should work with imported keys", async () => {
      const pubKey = await crypt.importPublicKey(publicKeyB64);
      const privKey = await crypt.importPrivateKey(privateKeyB64);

      const encrypted = await crypt.encryptText(plainText, pubKey);
      const decrypted = await crypt.decryptText(encrypted, privKey);
      expect(decrypted).toBe(plainText);
    });

    test("should fail decryption with wrong private key", async () => {
      const wrongKeyPair = await crypt.generateKeyPair();
      const encrypted = await crypt.encryptText(plainText, keyPair.publicKey);

      await expect(crypt.decryptText(encrypted, wrongKeyPair.privateKey)).rejects.toThrow();
    });
  });

  describe("File Encryption/Decryption", () => {
    const fileContent = "This is a test file content with some data to encrypt.";
    let testBlob;

    beforeEach(() => {
      testBlob = new Blob([fileContent], { type: "text/plain" });
      testBlob.name = "test.txt";
    });

    test("should encrypt and decrypt file blob", async () => {
      const { blob: encryptedBlob, filename: encFilename } = await crypt.encryptFile(
        testBlob,
        keyPair.publicKey
      );
      expect(encFilename).toMatch(/\.asym-encrypted$/);
      expect(encryptedBlob.size).toBeGreaterThan(fileContent.length);

      const { blob: decryptedBlob, filename: decFilename } = await crypt.decryptFile(
        encryptedBlob,
        keyPair.privateKey
      );
      expect(decFilename).toBe("test.txt");

      const decryptedText = await decryptedBlob.text();
      expect(decryptedText).toBe(fileContent);
    });

    test("should preserve filename on decryption", async () => {
      testBlob.name = "my-document.pdf";
      const { blob: encBlob } = await crypt.encryptFile(testBlob, keyPair.publicKey);
      const { filename } = await crypt.decryptFile(encBlob, keyPair.privateKey);
      expect(filename).toBe("my-document.pdf");
    });
  });

  describe("WebRTC Insertable Streams Transforms", () => {
    let encryptTransform;
    let decryptTransform;

    beforeAll(async () => {
      encryptTransform = await crypt.createEncryptTransform(keyPair.publicKey);
      decryptTransform = await crypt.createDecryptTransform(keyPair.privateKey);
    });

    test("should encrypt and decrypt WebRTC frames (first frame with header)", async () => {
      const originalData = new TextEncoder().encode("WebRTC frame data").buffer;
      const frame = { data: originalData };

      const encryptedFrames = [];
      const encryptController = {
        enqueue: f => encryptedFrames.push(f),
      };

      await encryptTransform(frame, encryptController);
      expect(encryptedFrames.length).toBe(1);
      const encryptedFrame = encryptedFrames[0];

      // Now decrypt
      const decryptedFrames = [];
      const decryptController = {
        enqueue: f => decryptedFrames.push(f),
      };

      await decryptTransform(encryptedFrame, decryptController);
      expect(decryptedFrames.length).toBe(1);

      const decryptedData = decryptedFrames[0].data;
      const decryptedText = new TextDecoder().decode(decryptedData);
      expect(decryptedText).toBe("WebRTC frame data");
    });

    test("should handle multiple frames correctly", async () => {
      const messages = ["Frame 1", "Frame 2", "Important data", "Final frame"];

      const encryptController = { enqueue: jest.fn() };
      const decryptController = { enqueue: jest.fn() };

      const encrypt = await crypt.createEncryptTransform(keyPair.publicKey);
      const decrypt = await crypt.createDecryptTransform(keyPair.privateKey);

      const encryptedFrames = [];

      // Encrypt all frames
      for (const msg of messages) {
        const frame = { data: new TextEncoder().encode(msg).buffer };
        await encrypt(frame, {
          enqueue: f => encryptedFrames.push(f),
        });
      }

      // Decrypt all frames
      const decryptedMessages = [];
      for (const encFrame of encryptedFrames) {
        const decFrame = { ...encFrame }; // clone
        await decrypt(decFrame, {
          enqueue: f => decryptedMessages.push(new TextDecoder().decode(f.data)),
        });
      }

      expect(decryptedMessages).toEqual(messages);
    });
  });

  describe("Error Handling", () => {
    test("should throw on invalid encrypted text", async () => {
      await expect(crypt.decryptText("invalidbase64", keyPair.privateKey)).rejects.toThrow();
    });

    test("should throw on truncated file", async () => {
      const smallBlob = new Blob([new Uint8Array(10)]);
      await expect(crypt.decryptFile(smallBlob, keyPair.privateKey)).rejects.toThrow(
        "Invalid file"
      );
    });
  });
});
