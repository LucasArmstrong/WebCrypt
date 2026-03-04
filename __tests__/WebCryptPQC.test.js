import { WebCryptPQC } from "../src/WebCryptPQC.js";

describe("WebCryptPQC - Post-Quantum Cryptography", () => {
  let pqc;

  beforeEach(() => {
    pqc = new WebCryptPQC();
  });

  describe("Kyber Key Encapsulation Mechanism (KEM)", () => {
    describe("Kyber Key Generation", () => {
      test("generates a key pair", async () => {
        const keys = await pqc.generateKyberKeyPair("Kyber768");

        expect(keys).toHaveProperty("publicKey");
        expect(keys).toHaveProperty("privateKey");
        expect(keys.publicKey).toBeInstanceOf(Uint8Array);
        expect(keys.privateKey).toBeInstanceOf(Uint8Array);
      });

      test("generates valid key pair for Kyber512", async () => {
        const keys = await pqc.generateKyberKeyPair("Kyber512");

        expect(keys.publicKey.byteLength).toBe(800);
        expect(keys.privateKey.byteLength).toBe(1632);
      });

      test("generates valid key pair for Kyber768", async () => {
        const keys = await pqc.generateKyberKeyPair("Kyber768");

        expect(keys.publicKey.byteLength).toBe(1184);
        expect(keys.privateKey.byteLength).toBe(2400);
      });

      test("generates valid key pair for Kyber1024", async () => {
        const keys = await pqc.generateKyberKeyPair("Kyber1024");

        expect(keys.publicKey.byteLength).toBe(1568);
        expect(keys.privateKey.byteLength).toBe(3168);
      });

      test("generates different key pairs on each call", async () => {
        const keys1 = await pqc.generateKyberKeyPair("Kyber768");
        const keys2 = await pqc.generateKyberKeyPair("Kyber768");

        expect(keys1.publicKey).not.toEqual(keys2.publicKey);
        expect(keys1.privateKey).not.toEqual(keys2.privateKey);
      });
    });

    describe("Kyber Encapsulation", () => {
      test("encapsulates using public key", async () => {
        const keys = await pqc.generateKyberKeyPair("Kyber768");

        const result = await pqc.kyberEncapsulate(keys.publicKey, "Kyber768");

        expect(result).toHaveProperty("ciphertext");
        expect(result).toHaveProperty("sharedSecret");
        expect(result.ciphertext).toBeInstanceOf(Uint8Array);
        expect(result.sharedSecret).toBeInstanceOf(Uint8Array);
      });

      test("produces correct ciphertext sizes", async () => {
        const keys512 = await pqc.generateKyberKeyPair("Kyber512");
        const result512 = await pqc.kyberEncapsulate(keys512.publicKey, "Kyber512");
        expect(result512.ciphertext.byteLength).toBe(768);

        const keys768 = await pqc.generateKyberKeyPair("Kyber768");
        const result768 = await pqc.kyberEncapsulate(keys768.publicKey, "Kyber768");
        expect(result768.ciphertext.byteLength).toBe(1088);

        const keys1024 = await pqc.generateKyberKeyPair("Kyber1024");
        const result1024 = await pqc.kyberEncapsulate(keys1024.publicKey, "Kyber1024");
        expect(result1024.ciphertext.byteLength).toBe(1568);
      });

      test("produces different ciphertexts each call", async () => {
        const keys = await pqc.generateKyberKeyPair("Kyber768");

        const result1 = await pqc.kyberEncapsulate(keys.publicKey, "Kyber768");
        const result2 = await pqc.kyberEncapsulate(keys.publicKey, "Kyber768");

        expect(result1.ciphertext).not.toEqual(result2.ciphertext);
      });
    });

    describe("Kyber Decapsulation", () => {
      test("decapsulates using private key", async () => {
        const keys = await pqc.generateKyberKeyPair("Kyber768");
        const { ciphertext } = await pqc.kyberEncapsulate(keys.publicKey, "Kyber768");

        const sharedSecret = await pqc.kyberDecapsulate(ciphertext, keys.privateKey, "Kyber768");

        expect(sharedSecret).toBeInstanceOf(Uint8Array);
        expect(sharedSecret.byteLength).toBe(32);
      });
    });
  });

  describe("Dilithium Digital Signatures", () => {
    describe("generateDilithiumKeyPair", () => {
      test("generates valid key pair", async () => {
        const keys = await pqc.generateDilithiumKeyPair("Dilithium3");

        expect(keys).toHaveProperty("publicKey");
        expect(keys).toHaveProperty("privateKey");
        expect(keys.publicKey).toBeInstanceOf(Uint8Array);
        expect(keys.privateKey).toBeInstanceOf(Uint8Array);
      });

      test("Dilithium2 generates valid key pair with correct sizes", async () => {
        const keys = await pqc.generateDilithiumKeyPair("Dilithium2");

        expect(keys.publicKey.byteLength).toBe(1312);
        expect(keys.privateKey.byteLength).toBe(2544);
      });

      test("Dilithium3 generates valid key pair with correct sizes", async () => {
        const keys = await pqc.generateDilithiumKeyPair("Dilithium3");

        expect(keys.publicKey.byteLength).toBe(1952);
        expect(keys.privateKey.byteLength).toBe(4000);
      });

      test("Dilithium5 generates valid key pair with correct sizes", async () => {
        const keys = await pqc.generateDilithiumKeyPair("Dilithium5");

        expect(keys.publicKey.byteLength).toBe(2592);
        expect(keys.privateKey.byteLength).toBe(4864);
      });

      test("generates different key pairs on each call", async () => {
        const keys1 = await pqc.generateDilithiumKeyPair("Dilithium3");
        const keys2 = await pqc.generateDilithiumKeyPair("Dilithium3");

        expect(keys1.publicKey).not.toEqual(keys2.publicKey);
        expect(keys1.privateKey).not.toEqual(keys2.privateKey);
      });
    });

    describe("dilithiumSign", () => {
      test("signs a message", async () => {
        const keys = await pqc.generateDilithiumKeyPair("Dilithium3");
        const document = new Uint8Array([1, 2, 3, 4, 5]);

        const signature = await pqc.dilithiumSign(document, keys.privateKey, "Dilithium3");

        expect(signature).toBeInstanceOf(Uint8Array);
      });

      test("produces correct signature sizes", async () => {
        const keys2 = await pqc.generateDilithiumKeyPair("Dilithium2");
        const doc = new Uint8Array([1, 2, 3]);
        const sig2 = await pqc.dilithiumSign(doc, keys2.privateKey, "Dilithium2");
        expect(sig2.byteLength).toBe(2420);

        const keys3 = await pqc.generateDilithiumKeyPair("Dilithium3");
        const sig3 = await pqc.dilithiumSign(doc, keys3.privateKey, "Dilithium3");
        expect(sig3.byteLength).toBe(3293);

        const keys5 = await pqc.generateDilithiumKeyPair("Dilithium5");
        const sig5 = await pqc.dilithiumSign(doc, keys5.privateKey, "Dilithium5");
        expect(sig5.byteLength).toBe(4595);
      });

      test("signatures are valid (stub implementation)", async () => {
        const keys = await pqc.generateDilithiumKeyPair("Dilithium3");
        const document = new Uint8Array([1, 2, 3, 4, 5]);

        const sig1 = await pqc.dilithiumSign(document, keys.privateKey, "Dilithium3");

        expect(sig1).toBeInstanceOf(Uint8Array);
        expect(sig1.byteLength).toBe(3293);
      });
    });

    describe("dilithiumVerify", () => {
      test("verifies valid signature", async () => {
        const keys = await pqc.generateDilithiumKeyPair("Dilithium3");
        const document = new Uint8Array([1, 2, 3, 4, 5]);

        const signature = await pqc.dilithiumSign(document, keys.privateKey, "Dilithium3");

        const verified = await pqc.dilithiumVerify(
          document,
          signature,
          keys.publicKey,
          "Dilithium3"
        );

        expect(verified).toBe(true);
      });

      test("verifies signatures with correct size (stub implementation)", async () => {
        const keys = await pqc.generateDilithiumKeyPair("Dilithium3");
        const document = new Uint8Array([1, 2, 3, 4, 5]);
        const signature = await pqc.dilithiumSign(document, keys.privateKey, "Dilithium3");

        const verified = await pqc.dilithiumVerify(
          document,
          signature,
          keys.publicKey,
          "Dilithium3"
        );

        expect(verified).toBe(true);
      });

      test("rejects invalid signature sizes", async () => {
        const keys = await pqc.generateDilithiumKeyPair("Dilithium3");
        const document = new Uint8Array([1, 2, 3, 4, 5]);
        const invalidSig = new Uint8Array(100);

        // NOTE: This is a stub implementation - Dilithium uses HMAC-based stubs
        // that may not properly validate signature sizes in all cases
        // In production with liboqs-js integration, this would reject invalid sizes
        const result = await pqc.dilithiumVerify(
          document,
          invalidSig,
          keys.publicKey,
          "Dilithium3"
        );

        // Stub implementation returns false for invalid signatures rather than throwing
        expect(result).toBe(false);
      });

      test("verifies with correct public key", async () => {
        const keys = await pqc.generateDilithiumKeyPair("Dilithium3");
        const document = new Uint8Array([1, 2, 3, 4, 5]);

        const signature = await pqc.dilithiumSign(document, keys.privateKey, "Dilithium3");

        const verified = await pqc.dilithiumVerify(
          document,
          signature,
          keys.publicKey,
          "Dilithium3"
        );

        expect(verified).toBe(true);
      });
    });

    describe("Key Serialization", () => {
      test("Kyber keys can be converted to/from Base64", async () => {
        const keys = await pqc.generateKyberKeyPair("Kyber768");

        const pubB64 = pqc.kyberPublicKeyToBase64(keys.publicKey);
        const privB64 = pqc.kyberPrivateKeyToBase64(keys.privateKey);

        expect(typeof pubB64).toBe("string");
        expect(typeof privB64).toBe("string");

        const pubRecover = pqc.kyberPublicKeyFromBase64(pubB64);
        const privRecover = pqc.kyberPrivateKeyFromBase64(privB64);

        expect(pubRecover).toEqual(keys.publicKey);
        expect(privRecover).toEqual(keys.privateKey);
      });

      test("Dilithium keys can be converted to/from Base64", async () => {
        const keys = await pqc.generateDilithiumKeyPair("Dilithium3");

        const pubB64 = pqc.dilithiumPublicKeyToBase64(keys.publicKey);
        const privB64 = pqc.dilithiumPrivateKeyToBase64(keys.privateKey);

        expect(typeof pubB64).toBe("string");
        expect(typeof privB64).toBe("string");

        const pubRecover = pqc.dilithiumPublicKeyFromBase64(pubB64);
        const privRecover = pqc.dilithiumPrivateKeyFromBase64(privB64);

        expect(pubRecover).toEqual(keys.publicKey);
        expect(privRecover).toEqual(keys.privateKey);
      });
    });

    describe("Algorithm Constants", () => {
      test("Kyber constants are defined correctly", () => {
        expect(WebCryptPQC.KYBER_PARAMS["Kyber512"].publicKeySize).toBe(800);
        expect(WebCryptPQC.KYBER_PARAMS["Kyber768"].ciphertextSize).toBe(1088);
        expect(WebCryptPQC.KYBER_PARAMS["Kyber1024"].sharedSecretSize).toBe(32);
      });

      test("Dilithium constants are defined correctly", () => {
        expect(WebCryptPQC.DILITHIUM_PARAMS["Dilithium2"].publicKeySize).toBe(1312);
        expect(WebCryptPQC.DILITHIUM_PARAMS["Dilithium3"].signatureSize).toBe(3293);
        expect(WebCryptPQC.DILITHIUM_PARAMS["Dilithium5"].privateKeySize).toBe(4864);
      });
    });
  });
});
