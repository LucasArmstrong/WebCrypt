// __tests__/WebCryptAsym.test.js
import { WebCryptAsym } from "../src/WebCryptAsym";

describe("WebCryptAsym", () => {
  let crypt;
  let rsaKeyPair;
  let rsaPublicKeyB64;
  let rsaPrivateKeyB64;

  // ECDSA signing keys
  let signingKeyPair;
  let signingPublicKeyB64;

  beforeAll(async () => {
    crypt = new WebCryptAsym();

    // Generate RSA key pair for hybrid encryption
    rsaKeyPair = await crypt.generateKeyPair();
    rsaPublicKeyB64 = await crypt.exportPublicKey(rsaKeyPair.publicKey);
    rsaPrivateKeyB64 = await crypt.exportPrivateKey(rsaKeyPair.privateKey);

    // Generate ECDSA signing key pair (P-256 default)
    signingKeyPair = await crypt.generateSigningKeyPair();
    signingPublicKeyB64 = signingKeyPair.publicKeyB64;
  });

  describe("RSA Key Management", () => {
    test("should generate a valid RSA key pair", () => {
      expect(rsaKeyPair).toHaveProperty("publicKey");
      expect(rsaKeyPair).toHaveProperty("privateKey");
    });

    test("should export and import public key correctly", async () => {
      const importedPublic = await crypt.importPublicKey(rsaPublicKeyB64);
      expect(importedPublic).toBeDefined();
      expect(importedPublic.type).toBe("public");
      expect(importedPublic.algorithm.name).toBe("RSA-OAEP");
    });

    test("should export and import private key correctly", async () => {
      const importedPrivate = await crypt.importPrivateKey(rsaPrivateKeyB64);
      expect(importedPrivate).toBeDefined();
      expect(importedPrivate.type).toBe("private");
      expect(importedPrivate.algorithm.name).toBe("RSA-OAEP");
    });
  });

  describe("ECDSA Signing Key Management", () => {
    test("should generate a valid ECDSA signing key pair", () => {
      expect(signingKeyPair).toHaveProperty("publicKey");
      expect(signingKeyPair).toHaveProperty("privateKey");
      expect(signingKeyPair.publicKeyB64).toBeTruthy();
      expect(typeof signingKeyPair.publicKeyB64).toBe("string");
    });

    test("should generate P-384 key pair when requested", async () => {
      const p384Pair = await crypt.generateSigningKeyPair("P-384");
      expect(p384Pair.publicKey.algorithm.namedCurve).toBe("P-384");
    });

    test("should throw on unsupported curve", async () => {
      await expect(crypt.generateSigningKeyPair("P-521")).rejects.toThrow("Unsupported curve");
    });

    test("should import public signing key correctly", async () => {
      const importedPublic = await crypt.importPublicSigningKey(signingPublicKeyB64);
      expect(importedPublic).toBeDefined();
      expect(importedPublic.type).toBe("public");
      expect(importedPublic.algorithm.name).toBe("ECDSA");
      expect(importedPublic.algorithm.namedCurve).toBe("P-256");
    });
  });

  describe("Text Encryption/Decryption (Hybrid RSA + AES)", () => {
    const plainText = "Hello, this is a secret message! 🚀";

    test("should encrypt and decrypt text correctly", async () => {
      const encrypted = await crypt.encryptText(plainText, rsaKeyPair.publicKey);
      expect(encrypted).toBeTruthy();
      expect(typeof encrypted).toBe("string");

      const decrypted = await crypt.decryptText(encrypted, rsaKeyPair.privateKey);
      expect(decrypted).toBe(plainText);
    });

    test("should work with imported RSA keys", async () => {
      const pubKey = await crypt.importPublicKey(rsaPublicKeyB64);
      const privKey = await crypt.importPrivateKey(rsaPrivateKeyB64);

      const encrypted = await crypt.encryptText(plainText, pubKey);
      const decrypted = await crypt.decryptText(encrypted, privKey);
      expect(decrypted).toBe(plainText);
    });

    test("should fail decryption with wrong private key", async () => {
      const wrongKeyPair = await crypt.generateKeyPair();
      const encrypted = await crypt.encryptText(plainText, rsaKeyPair.publicKey);

      await expect(crypt.decryptText(encrypted, wrongKeyPair.privateKey)).rejects.toThrow();
    });
  });

  describe("File Encryption/Decryption (Streaming Hybrid)", () => {
    const fileContent = "This is a test file content with some data to encrypt.";
    let testBlob;

    beforeEach(() => {
      testBlob = new Blob([fileContent], { type: "text/plain" });
      testBlob.name = "test.txt";
    });

    test("should encrypt and decrypt file blob", async () => {
      const { blob: encryptedBlob, filename: encFilename } = await crypt.encryptFile(
        testBlob,
        rsaKeyPair.publicKey
      );
      expect(encFilename).toMatch(/\.asym-encrypted$/);
      expect(encryptedBlob.size).toBeGreaterThan(fileContent.length);

      const { blob: decryptedBlob, filename: decFilename } = await crypt.decryptFile(
        encryptedBlob,
        rsaKeyPair.privateKey
      );
      expect(decFilename).toBe("test.txt");

      const decryptedText = await decryptedBlob.text();
      expect(decryptedText).toBe(fileContent);
    });

    test("should preserve filename on decryption", async () => {
      testBlob.name = "my-document.pdf";
      const { blob: encBlob } = await crypt.encryptFile(testBlob, rsaKeyPair.publicKey);
      const { filename } = await crypt.decryptFile(encBlob, rsaKeyPair.privateKey);
      expect(filename).toBe("my-document.pdf");
    });
  });

  describe("Digital Signatures (ECDSA)", () => {
    const message = "This message will be signed for authenticity.";

    test("should sign and verify text correctly", async () => {
      const signatureB64 = await crypt.signText(message, signingKeyPair.privateKey);
      expect(signatureB64).toBeTruthy();
      expect(typeof signatureB64).toBe("string");

      const isValid = await crypt.verifyText(message, signatureB64, signingKeyPair.publicKey);
      expect(isValid).toBe(true);
    });

    test("should verify with imported public signing key", async () => {
      const signatureB64 = await crypt.signText(message, signingKeyPair.privateKey);

      const importedPublic = await crypt.importPublicSigningKey(signingPublicKeyB64);
      const isValid = await crypt.verifyText(message, signatureB64, importedPublic);
      expect(isValid).toBe(true);
    });

    test("should reject tampered message", async () => {
      const signatureB64 = await crypt.signText(message, signingKeyPair.privateKey);
      const tampered = message + " (tampered)";

      const isValid = await crypt.verifyText(tampered, signatureB64, signingKeyPair.publicKey);
      expect(isValid).toBe(false);
    });

    test("should reject wrong signature", async () => {
      const wrongPair = await crypt.generateSigningKeyPair();
      const wrongSignature = await crypt.signText(message, wrongPair.privateKey);

      const isValid = await crypt.verifyText(message, wrongSignature, signingKeyPair.publicKey);
      expect(isValid).toBe(false);
    });

    describe("File Signing", () => {
      let testFile;

      beforeEach(() => {
        testFile = new Blob(["Important signed document content"], { type: "application/pdf" });
        testFile.name = "contract.pdf";
      });

      test("should sign and verify file (detached signature)", async () => {
        const { signatureB64 } = await crypt.signFile(testFile, signingKeyPair.privateKey);
        expect(signatureB64).toBeTruthy();

        const isValid = await crypt.verifyFile(testFile, signatureB64, signingKeyPair.publicKey);
        expect(isValid).toBe(true);
      });

      test("should reject tampered file", async () => {
        const { signatureB64 } = await crypt.signFile(testFile, signingKeyPair.privateKey);

        // Tamper by creating a new blob with different content
        const tamperedFile = new Blob(["Important signed document content - modified"], {
          type: "application/pdf",
        });

        const isValid = await crypt.verifyFile(
          tamperedFile,
          signatureB64,
          signingKeyPair.publicKey
        );
        expect(isValid).toBe(false);
      });
    });
  });

  describe("WebRTC Insertable Streams Transforms", () => {
    let encryptTransform;
    let decryptTransform;

    beforeAll(async () => {
      encryptTransform = await crypt.createEncryptTransform(rsaKeyPair.publicKey);
      decryptTransform = await crypt.createDecryptTransform(rsaKeyPair.privateKey);
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

      const encrypt = await crypt.createEncryptTransform(rsaKeyPair.publicKey);
      const decrypt = await crypt.createDecryptTransform(rsaKeyPair.privateKey);

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
        const decFrame = { ...encFrame }; // shallow clone
        await decrypt(decFrame, {
          enqueue: f => decryptedMessages.push(new TextDecoder().decode(f.data)),
        });
      }

      expect(decryptedMessages).toEqual(messages);
    });
  });

  describe("Error Handling", () => {
    test("should throw on invalid encrypted text", async () => {
      await expect(crypt.decryptText("invalidbase64", rsaKeyPair.privateKey)).rejects.toThrow();
    });

    test("should throw on truncated file", async () => {
      const smallBlob = new Blob([new Uint8Array(10)]);
      await expect(crypt.decryptFile(smallBlob, rsaKeyPair.privateKey)).rejects.toThrow(
        "Invalid file"
      );
    });
  });
});
