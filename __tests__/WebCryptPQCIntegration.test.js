import { WebCryptPQC } from "../src/WebCryptPQC.js";
import { WebCryptAsym } from "../src/WebCryptAsym.js";
import { WebCrypt } from "../src/WebCrypt.js";

describe("WebCryptPQC - Integration Tests", () => {
  let pqc;
  let asym;
  let crypt;

  beforeEach(() => {
    pqc = new WebCryptPQC();
    asym = new WebCryptAsym();
    crypt = new WebCrypt();
  });

  test("Hybrid key exchange between two parties", async () => {
    // Alice generates hybrid keys
    const aliceRsa = await asym.generateKeyPair();
    const aliceKyber = await pqc.generateKyberKeyPair("Kyber768");

    // Bob generates hybrid keys
    const bobRsa = await asym.generateKeyPair();
    const bobKyber = await pqc.generateKyberKeyPair("Kyber768");

    // Alice → Bob: hybrid encapsulate
    const aliceToBob = await pqc.hybridEncapsulate(
      bobRsa.publicKey,
      bobKyber.publicKey,
      "Kyber768"
    );

    // Bob decrypts
    const bobReceived = await pqc.hybridDecapsulate(
      aliceToBob.kyberCiphertext,
      aliceToBob.rsaWrappedSharedSecret,
      bobRsa.privateKey,
      bobKyber.privateKey,
      "Kyber768"
    );

    expect(bobReceived).toBeInstanceOf(Uint8Array);
    expect(bobReceived.byteLength).toBe(32);
  });

  test("Secure document signing and verification", async () => {
    const author = await pqc.generateDilithiumKeyPair("Dilithium3");
    const document = new Uint8Array([72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100]); // "Hello World"

    // Author signs
    const signature = await pqc.dilithiumSign(document, author.privateKey, "Dilithium3");

    // Reader verifies
    const verified = await pqc.dilithiumVerify(document, signature, author.publicKey, "Dilithium3");

    expect(verified).toBe(true);
  });

  test("Key derivation from password with lower iterations", async () => {
    const userPassword = "secure-password";

    // Derive key with low iterations to avoid timeout
    const baseKey = await asym.deriveKeySHA3(userPassword, 10, "SHA3-256");
    expect(baseKey).toBeInstanceOf(CryptoKey);

    // Expand into additional key material
    const masterSecret = crypto.getRandomValues(new Uint8Array(32));
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const derivedKey = await asym.deriveKeyHKDFSHA3(masterSecret, salt);

    expect(derivedKey).toBeInstanceOf(CryptoKey);
  });

  test("Authenticated encryption with HMAC", async () => {
    const sharedPassword = "shared-key";

    // Derive keys (using fast iterations)
    const aesKey = await asym.deriveKeySHA3(sharedPassword + ":enc", 10, "SHA3-256");
    const hmacKey = await crypt.generateHmacKeySHA3();

    // Encrypt
    const plaintext = new Uint8Array([1, 2, 3, 4, 5]);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, aesKey, plaintext);

    // Compute HMAC
    const ciphertextBytes = new Uint8Array(ciphertext);
    const tag = await crypt.computeHmacSHA3(ciphertextBytes, hmacKey);

    // Verify HMAC
    const authValid = await crypt.verifyHmacSHA3(ciphertextBytes, tag, hmacKey);

    expect(authValid).toBe(true);

    // Decrypt
    const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, aesKey, ciphertext);

    expect(new Uint8Array(decrypted)).toEqual(plaintext);
  });

  test("All three Kyber security levels work end-to-end", async () => {
    for (const level of ["Kyber512", "Kyber768", "Kyber1024"]) {
      const rsa = await asym.generateKeyPair();
      const kyber = await pqc.generateKyberKeyPair(level);

      const encapsulated = await pqc.hybridEncapsulate(rsa.publicKey, kyber.publicKey, level);

      const decapsulated = await pqc.hybridDecapsulate(
        encapsulated.kyberCiphertext,
        encapsulated.rsaWrappedSharedSecret,
        rsa.privateKey,
        kyber.privateKey,
        level
      );

      expect(decapsulated.byteLength).toBe(32);
    }
  });

  test("All three Dilithium security levels work end-to-end", async () => {
    const document = new Uint8Array([1, 2, 3, 4, 5]);

    for (const level of ["Dilithium2", "Dilithium3", "Dilithium5"]) {
      const keys = await pqc.generateDilithiumKeyPair(level);
      const signature = await pqc.dilithiumSign(document, keys.privateKey, level);
      const verified = await pqc.dilithiumVerify(document, signature, keys.publicKey, level);

      expect(verified).toBe(true);
    }
  });
});
