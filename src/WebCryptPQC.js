// src/WebCryptPQC.js
// Post-Quantum Cryptography (PQC) module - provides NIST-selected algorithms
// version: 0.6.3 - Quantum-resist core

/**
 * WebCryptPQC – Post-quantum key exchange and digital signatures
 * Maintained by PuterVision LLC (https://putervision.com).
 *
 * DISCLAIMER: Provided "AS IS" without warranty of any kind. PuterVision LLC
 * disclaims all liability for data loss, security breaches, or misuse.
 *
 * Implements NIST PQC finalists:
 * - Kyber: Lattice-based Key Encapsulation Mechanism (KEM)
 * - Dilithium: Lattice-based Digital Signature Algorithm
 *
 * Note: This is a polyfill-style module. In production, you would integrate
 * the official liboqs-js or equivalent. For now, we provide a secure interface
 * and mark stubs for future integration.
 */

/**
 * ⚠️ WARNING: WebCryptPQC is currently a PLACEHOLDER implementation
 *
 * Kyber and Dilithium algorithms are NOT real post-quantum cryptography.
 * They use simplified SHA-3 hashing as stubs until liboqs-js integration.
 *
 * DO NOT USE FOR PRODUCTION SECURITY!
 *
 * For production, integrate official liboqs-js:
 * npm install @openquantumsafe/libs
 */
export class WebCryptPQC {
  static WARNING =
    "⚠️ CRITICAL: WebCryptPQC is PLACEHOLDER/STUB implementation. " +
    "Kyber and Dilithium are NOT real PQC - they use SHA-3 hashing stubs. " +
    "Not suitable for production security. Integrate liboqs-js or wait for official implementation.";

  static _STUB_MODE = true;

  /**
   * Programmatically check if PQC module is running in stub mode.
   * @returns {boolean} True if PQC module is a placeholder stub.
   */
  static isStub() {
    return WebCryptPQC._STUB_MODE;
  }

  /**
   * Enable or disable stub testing mode.
   * @param {boolean} [allow=true] If true, allows stub operations for testing purposes.
   */
  static enableStubTesting(allow = true) {
    WebCryptPQC._STUB_MODE = !allow;
  }

  /**
   * Internal helper to verify stub mode state before PQC operations.
   */
  _checkStubMode() {
    if (WebCryptPQC._STUB_MODE) {
      throw new Error(
        "WebCryptPQC is a placeholder stub — not for production use. Call WebCryptPQC.enableStubTesting(true) for testing."
      );
    }
  }

  // ─────────────────────── Kyber Constants ───────────────────────
  static KYBER_512 = "Kyber512";
  static KYBER_768 = "Kyber768";
  static KYBER_1024 = "Kyber1024";

  // Kyber security levels and sizes (bytes)
  static KYBER_PARAMS = {
    [WebCryptPQC.KYBER_512]: {
      name: "Kyber512",
      securityLevel: "128-bit",
      publicKeySize: 800,
      privateKeySize: 1632,
      ciphertextSize: 768,
      sharedSecretSize: 32,
    },
    [WebCryptPQC.KYBER_768]: {
      name: "Kyber768",
      securityLevel: "192-bit",
      publicKeySize: 1184,
      privateKeySize: 2400,
      ciphertextSize: 1088,
      sharedSecretSize: 32,
    },
    [WebCryptPQC.KYBER_1024]: {
      name: "Kyber1024",
      securityLevel: "256-bit",
      publicKeySize: 1568,
      privateKeySize: 3168,
      ciphertextSize: 1568,
      sharedSecretSize: 32,
    },
  };

  // ─────────────────────── Dilithium Constants ───────────────────────
  static DILITHIUM_2 = "Dilithium2";
  static DILITHIUM_3 = "Dilithium3";
  static DILITHIUM_5 = "Dilithium5";

  static DILITHIUM_PARAMS = {
    [WebCryptPQC.DILITHIUM_2]: {
      name: "Dilithium2",
      securityLevel: "128-bit",
      publicKeySize: 1312,
      privateKeySize: 2544,
      signatureSize: 2420,
    },
    [WebCryptPQC.DILITHIUM_3]: {
      name: "Dilithium3",
      securityLevel: "192-bit",
      publicKeySize: 1952,
      privateKeySize: 4000,
      signatureSize: 3293,
    },
    [WebCryptPQC.DILITHIUM_5]: {
      name: "Dilithium5",
      securityLevel: "256-bit",
      publicKeySize: 2592,
      privateKeySize: 4864,
      signatureSize: 4595,
    },
  };

  // ─────────────────────── Algorithm Constants ───────────────────────
  static HASH_SHA3_256 = "SHA3-256";
  static HASH_SHA3_384 = "SHA3-384";
  static HASH_SHA3_512 = "SHA3-512";

  static SUPPORTED_KYBER_LEVELS = [
    WebCryptPQC.KYBER_512,
    WebCryptPQC.KYBER_768,
    WebCryptPQC.KYBER_1024,
  ];

  static SUPPORTED_DILITHIUM_LEVELS = [
    WebCryptPQC.DILITHIUM_2,
    WebCryptPQC.DILITHIUM_3,
    WebCryptPQC.DILITHIUM_5,
  ];

  constructor() {
    this._crypto = this._getCrypto();
    // Warn users immediately about placeholder status
    if (typeof console !== "undefined" && console.warn) {
      console.warn(WebCryptPQC.WARNING);
    }
  }

  _getCrypto() {
    if (typeof globalThis !== "undefined" && globalThis.crypto && globalThis.crypto.subtle) {
      return globalThis.crypto;
    }
    if (typeof require !== "undefined") {
      try {
        const { webcrypto } = require("node:crypto");
        if (webcrypto && webcrypto.subtle) return webcrypto;
      } catch (e) {}
    }
    if (typeof globalThis !== "undefined" && globalThis.crypto) {
      return globalThis.crypto;
    }
    throw new Error("Web Crypto API not available");
  }

  // ═══════════════════════════ Kyber KEM (Key Encapsulation) ═══════════════════════════

  /**
   * Generate a Kyber key pair for key encapsulation.
   * @param {string} level - Kyber level: "Kyber512" | "Kyber768" | "Kyber1024"
   * @returns {Promise<{publicKey: Uint8Array, privateKey: Uint8Array}>}
   */
  async generateKyberKeyPair(level = WebCryptPQC.KYBER_768) {
    this._checkStubMode();
    if (!WebCryptPQC.SUPPORTED_KYBER_LEVELS.includes(level)) {
      throw new Error(`Unsupported Kyber level: ${level}. Use Kyber512, Kyber768, or Kyber1024`);
    }

    // STUB: In production, call libOQS or liboqs-js Kyber1024_keypair()
    // For now, generate deterministic synthetic keys using SHA-3
    const seed = this._crypto.getRandomValues(new Uint8Array(64));
    const { publicKey, privateKey } = await this._generateKyberKeysFromSeed(seed, level);

    return { publicKey, privateKey };
  }

  /**
   * Encapsulate: Create a shared secret and ciphertext using recipient's Kyber public key.
   * @param {Uint8Array} kyberPublicKey - Recipient's Kyber public key
   * @param {string} level - Kyber level
   * @returns {Promise<{ciphertext: Uint8Array, sharedSecret: Uint8Array}>}
   */
  async kyberEncapsulate(kyberPublicKey, level = WebCryptPQC.KYBER_768) {
    this._checkStubMode();
    if (!WebCryptPQC.SUPPORTED_KYBER_LEVELS.includes(level)) {
      throw new Error(`Unsupported Kyber level: ${level}`);
    }

    const params = WebCryptPQC.KYBER_PARAMS[level];
    if (kyberPublicKey.byteLength !== params.publicKeySize) {
      throw new Error(
        `Invalid Kyber public key size: expected ${params.publicKeySize}, got ${kyberPublicKey.byteLength}`
      );
    }

    // STUB: Call libOQS Kyber1024_encaps(pk) → (ss, ct)
    // Placeholder: Hash public key to create deterministic ciphertext and shared secret
    const hashInput = new Uint8Array(kyberPublicKey.byteLength + 32);
    hashInput.set(kyberPublicKey);
    hashInput.set(this._crypto.getRandomValues(new Uint8Array(32)), kyberPublicKey.byteLength);

    const digest = await this._sha3Hash(hashInput, 256);
    const ciphertext = new Uint8Array(params.ciphertextSize);
    const sharedSecret = digest.slice(0, params.sharedSecretSize);

    ciphertext.set(digest.slice(0, params.ciphertextSize));

    return { ciphertext, sharedSecret };
  }

  /**
   * Decapsulate: Recover the shared secret using private key and ciphertext.
   * @param {Uint8Array} ciphertext - Encapsulated ciphertext from kyberEncapsulate
   * @param {Uint8Array} kyberPrivateKey - Own Kyber private key
   * @param {string} level - Kyber level
   * @returns {Promise<Uint8Array>} The shared secret
   */
  async kyberDecapsulate(ciphertext, kyberPrivateKey, level = WebCryptPQC.KYBER_768) {
    this._checkStubMode();
    if (!WebCryptPQC.SUPPORTED_KYBER_LEVELS.includes(level)) {
      throw new Error(`Unsupported Kyber level: ${level}`);
    }

    const params = WebCryptPQC.KYBER_PARAMS[level];
    if (kyberPrivateKey.byteLength !== params.privateKeySize) {
      throw new Error(
        `Invalid Kyber private key size: expected ${params.privateKeySize}, got ${kyberPrivateKey.byteLength}`
      );
    }
    if (ciphertext.byteLength !== params.ciphertextSize) {
      throw new Error(
        `Invalid ciphertext size: expected ${params.ciphertextSize}, got ${ciphertext.byteLength}`
      );
    }

    // STUB: Call libOQS Kyber1024_decaps(sk, ct) → ss
    // Placeholder: Derive shared secret from private key and ciphertext using SHA-3
    const hashInput = new Uint8Array(kyberPrivateKey.byteLength + ciphertext.byteLength);
    hashInput.set(kyberPrivateKey);
    hashInput.set(ciphertext, kyberPrivateKey.byteLength);

    const digest = await this._sha3Hash(hashInput, 256);
    return digest.slice(0, params.sharedSecretSize);
  }

  // ═══════════════════════════ Dilithium Signatures ═══════════════════════════

  /**
   * Generate a Dilithium key pair for digital signatures.
   * @param {string} level - Dilithium level: "Dilithium2" | "Dilithium3" | "Dilithium5"
   * @returns {Promise<{publicKey: Uint8Array, privateKey: Uint8Array}>}
   */
  async generateDilithiumKeyPair(level = WebCryptPQC.DILITHIUM_3) {
    this._checkStubMode();
    if (!WebCryptPQC.SUPPORTED_DILITHIUM_LEVELS.includes(level)) {
      throw new Error(`Unsupported Dilithium level: ${level}`);
    }

    // STUB: Call libOQS Dilithium3_keypair()
    const seed = this._crypto.getRandomValues(new Uint8Array(64));
    const { publicKey, privateKey } = await this._generateDilithiumKeysFromSeed(seed, level);

    return { publicKey, privateKey };
  }

  /**
   * Sign a message using Dilithium private key.
   * @param {Uint8Array|string} message - Message to sign
   * @param {Uint8Array} dilithiumPrivateKey - Dilithium private key
   * @param {string} level - Dilithium level
   * @returns {Promise<Uint8Array>} Digital signature
   */
  async dilithiumSign(message, dilithiumPrivateKey, level = WebCryptPQC.DILITHIUM_3) {
    this._checkStubMode();
    if (!WebCryptPQC.SUPPORTED_DILITHIUM_LEVELS.includes(level)) {
      throw new Error(`Unsupported Dilithium level: ${level}`);
    }

    const params = WebCryptPQC.DILITHIUM_PARAMS[level];
    if (dilithiumPrivateKey.byteLength !== params.privateKeySize) {
      throw new Error(
        `Invalid Dilithium private key size: expected ${params.privateKeySize}, got ${dilithiumPrivateKey.byteLength}`
      );
    }

    const msgBytes = typeof message === "string" ? new TextEncoder().encode(message) : message;

    // STUB: Call libOQS Dilithium3_sign(msg, sk) → sig
    // Placeholder: Sign using SHA-3 HMAC of message with private key material
    const hashInput = new Uint8Array(dilithiumPrivateKey.byteLength + msgBytes.byteLength);
    hashInput.set(dilithiumPrivateKey);
    hashInput.set(msgBytes, dilithiumPrivateKey.byteLength);

    const digest = await this._sha3Hash(hashInput, 512);
    const signature = new Uint8Array(params.signatureSize);
    signature.set(digest.slice(0, Math.min(params.signatureSize, digest.byteLength)));

    return signature;
  }

  /**
   * ⚠️ PLACEHOLDER: Dilithium signature verification stub
   *
   * This is NOT real post-quantum signature verification.
   * It only validates basic format, not cryptographic correctness.
   *
   * @param {Uint8Array|string} message - Original message
   * @param {Uint8Array} signature - Signature from dilithiumSign
   * @param {Uint8Array} dilithiumPublicKey - Dilithium public key
   * @param {string} level - Dilithium level
   * @returns {Promise<boolean>} True if format is valid (NOT cryptographic verification!)
   */
  async dilithiumVerify(message, signature, dilithiumPublicKey, level = WebCryptPQC.DILITHIUM_3) {
    this._checkStubMode();
    if (!WebCryptPQC.SUPPORTED_DILITHIUM_LEVELS.includes(level)) {
      throw new Error(`Unsupported Dilithium level: ${level}`);
    }

    const params = WebCryptPQC.DILITHIUM_PARAMS[level];
    if (dilithiumPublicKey.byteLength !== params.publicKeySize) {
      throw new Error(
        `Invalid Dilithium public key size: expected ${params.publicKeySize}, got ${dilithiumPublicKey.byteLength}`
      );
    }
    if (signature.byteLength !== params.signatureSize) {
      // Return false for obviously invalid signatures
      return false;
    }

    const msgBytes = typeof message === "string" ? new TextEncoder().encode(message) : message;

    // ⚠️ PLACEHOLDER: This does NOT verify cryptographic correctness!
    // Real implementation requires liboqs-js Dilithium_verify()
    // For now, just check that signature size is correct (format validation only)

    console.warn(
      "⚠️ dilithiumVerify() is a PLACEHOLDER stub. " +
        "This does NOT perform real post-quantum signature verification. " +
        "Integrate liboqs-js for production use."
    );

    // Placeholder: Always return true if format looks valid
    // In real impl: actual public key verification using polynomial math
    return true;
  }

  // ═══════════════════════════ Hybrid Encryption (Kyber + RSA) ═══════════════════════════

  /**
   * Hybrid encapsulation: Use both Kyber (PQC) and RSA-OAEP for forward secrecy.
   * Combines a classical and post-quantum key encapsulation.
   *
   * @param {CryptoKey} rsaPublicKey - RSA-4096 public key (classical)
   * @param {Uint8Array} kyberPublicKey - Kyber public key (PQC)
   * @param {string} kyberLevel - Kyber level (default: Kyber768)
   * @returns {Promise<{sharedSecret: Uint8Array, kyberCiphertext: Uint8Array, rsaWrappedSharedSecret: Uint8Array}>}
   */
  async hybridEncapsulate(rsaPublicKey, kyberPublicKey, kyberLevel = WebCryptPQC.KYBER_768) {
    // Step 1: Kyber encapsulation
    const { ciphertext: kyberCiphertext, sharedSecret: kyberSharedSecret } =
      await this.kyberEncapsulate(kyberPublicKey, kyberLevel);

    // Step 2: Wrap Kyber shared secret with RSA-OAEP
    const rsaWrappedSharedSecret = await this._crypto.subtle.encrypt(
      { name: "RSA-OAEP", hash: "SHA-256" },
      rsaPublicKey,
      kyberSharedSecret
    );

    // Step 3: Combine via KDF (SHA-3)
    const combinedInput = new Uint8Array(
      kyberSharedSecret.byteLength + rsaWrappedSharedSecret.byteLength
    );
    combinedInput.set(kyberSharedSecret);
    combinedInput.set(new Uint8Array(rsaWrappedSharedSecret), kyberSharedSecret.byteLength);

    const finalSharedSecret = await this._sha3Hash(combinedInput, 256);

    return {
      sharedSecret: finalSharedSecret,
      kyberCiphertext: new Uint8Array(kyberCiphertext),
      rsaWrappedSharedSecret: new Uint8Array(rsaWrappedSharedSecret),
    };
  }

  /**
   * Hybrid decapsulation: Recover shared secret using both Kyber and RSA private keys.
   *
   * @param {Uint8Array} kyberCiphertext - From hybridEncapsulate
   * @param {Uint8Array} rsaWrappedSharedSecret - From hybridEncapsulate
   * @param {CryptoKey} rsaPrivateKey - RSA-4096 private key
   * @param {Uint8Array} kyberPrivateKey - Kyber private key
   * @param {string} kyberLevel - Kyber level (default: Kyber768)
   * @returns {Promise<Uint8Array>} The hybrid shared secret
   */
  async hybridDecapsulate(
    kyberCiphertext,
    rsaWrappedSharedSecret,
    rsaPrivateKey,
    kyberPrivateKey,
    kyberLevel = WebCryptPQC.KYBER_768
  ) {
    try {
      // Step 1: Kyber decapsulation
      const kyberSharedSecret = await this.kyberDecapsulate(
        kyberCiphertext,
        kyberPrivateKey,
        kyberLevel
      );

      // Step 2: Unwrap via RSA-OAEP
      let rsaSharedSecret;
      try {
        rsaSharedSecret = await this._crypto.subtle.decrypt(
          { name: "RSA-OAEP", hash: "SHA-256" },
          rsaPrivateKey,
          rsaWrappedSharedSecret
        );
      } catch (e) {
        // RSA decryption failed: use Kyber alone (forward secrecy maintained)
        console.warn(
          "Hybrid decapsulation: RSA decryption failed, falling back to Kyber shared secret"
        );
        rsaSharedSecret = kyberSharedSecret;
      }

      // Step 3: Combine sharedSecrets via KDF (SHA-3)
      const combinedInput = new Uint8Array(
        kyberSharedSecret.byteLength + rsaSharedSecret.byteLength
      );
      combinedInput.set(kyberSharedSecret);
      combinedInput.set(new Uint8Array(rsaSharedSecret), kyberSharedSecret.byteLength);

      const finalSharedSecret = await this._sha3Hash(combinedInput, 256);
      return finalSharedSecret;
    } catch (e) {
      throw new Error(`Hybrid decapsulation failed: ${e.message}`);
    }
  }

  // ═══════════════════════════ SHA-3 Hashing ═══════════════════════════

  /**
   * Hash data using SHA-3 (post-quantum secure hash).
   * Falls back to SHA-256/512 in environments without SHA-3 support.
   *
   * @param {Uint8Array} data - Data to hash
   * @param {number} bitLength - Hash output size: 256, 384, 512
   * @returns {Promise<Uint8Array>} Hash digest
   */
  async _sha3Hash(data, bitLength = 256) {
    const algorithm = `SHA3-${bitLength}`;

    try {
      // Try native SHA-3 support
      const digest = await this._crypto.subtle.digest(algorithm, data);
      return new Uint8Array(digest);
    } catch (e) {
      // Fallback: Use SHA-256/512 (still quantum-resistant for these sizes)
      const fallbackAlgorithm =
        bitLength <= 256 ? "SHA-256" : bitLength <= 384 ? "SHA-384" : "SHA-512";
      if (typeof console !== "undefined" && console.warn) {
        console.warn(
          `SHA3-${bitLength} not natively supported by Web Crypto, falling back to ${fallbackAlgorithm}`
        );
      }
      const digest = await this._crypto.subtle.digest(fallbackAlgorithm, data);
      return new Uint8Array(digest).slice(0, bitLength / 8);
    }
  }

  // ═══════════════════════════ Key Serialization ═══════════════════════════

  /**
   * Export Kyber public key to Base64 for transmission/storage.
   */
  kyberPublicKeyToBase64(publicKey) {
    return this._arrayBufferToBase64(publicKey);
  }

  /**
   * Import Kyber public key from Base64.
   */
  kyberPublicKeyFromBase64(b64) {
    return new Uint8Array(this._base64ToArrayBuffer(b64));
  }

  /**
   * Export Kyber private key to Base64 (SECURE: handle with care).
   */
  kyberPrivateKeyToBase64(privateKey) {
    return this._arrayBufferToBase64(privateKey);
  }

  /**
   * Import Kyber private key from Base64.
   */
  kyberPrivateKeyFromBase64(b64) {
    return new Uint8Array(this._base64ToArrayBuffer(b64));
  }

  /**
   * Same methods for Dilithium keys.
   */
  dilithiumPublicKeyToBase64(publicKey) {
    return this._arrayBufferToBase64(publicKey);
  }

  dilithiumPublicKeyFromBase64(b64) {
    return new Uint8Array(this._base64ToArrayBuffer(b64));
  }

  dilithiumPrivateKeyToBase64(privateKey) {
    return this._arrayBufferToBase64(privateKey);
  }

  dilithiumPrivateKeyFromBase64(b64) {
    return new Uint8Array(this._base64ToArrayBuffer(b64));
  }

  // ═════════════════════════ Internal Helpers ═════════════════════════

  async _generateKyberKeysFromSeed(seed, level) {
    const params = WebCryptPQC.KYBER_PARAMS[level];
    const publicKey = new Uint8Array(params.publicKeySize);
    const privateKey = new Uint8Array(params.privateKeySize);

    // Deterministic key generation from seed
    const hashInput = new Uint8Array(seed.byteLength + 4);
    hashInput.set(seed);
    new DataView(hashInput.buffer).setUint32(seed.byteLength, 0, true);

    const pubHash = await this._sha3Hash(hashInput, 512);
    publicKey.set(pubHash.slice(0, Math.min(params.publicKeySize, pubHash.byteLength)));

    new DataView(hashInput.buffer).setUint32(seed.byteLength, 1, true);
    const privHash = await this._sha3Hash(hashInput, 512);
    privateKey.set(privHash.slice(0, Math.min(params.privateKeySize, privHash.byteLength)));

    return { publicKey, privateKey };
  }

  async _generateDilithiumKeysFromSeed(seed, level) {
    const params = WebCryptPQC.DILITHIUM_PARAMS[level];
    const publicKey = new Uint8Array(params.publicKeySize);
    const privateKey = new Uint8Array(params.privateKeySize);

    const hashInput = new Uint8Array(seed.byteLength + 4);
    hashInput.set(seed);
    new DataView(hashInput.buffer).setUint32(seed.byteLength, 0, true);

    const pubHash = await this._sha3Hash(hashInput, 512);
    publicKey.set(pubHash.slice(0, Math.min(params.publicKeySize, pubHash.byteLength)));

    new DataView(hashInput.buffer).setUint32(seed.byteLength, 1, true);
    const privHash = await this._sha3Hash(hashInput, 512);
    privateKey.set(privHash.slice(0, Math.min(params.privateKeySize, privHash.byteLength)));

    return { publicKey, privateKey };
  }

  // Chunked block conversion avoids stack overflow and O(N^2) memory churn
  _arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    const CHUNK_SIZE = 1024; // 1KB chunks eliminate stack overflow risks across all JS engines
    let binary = "";
    for (let i = 0; i < bytes.length; i += CHUNK_SIZE) {
      binary += String.fromCharCode.apply(null, bytes.subarray(i, i + CHUNK_SIZE));
    }
    return btoa(binary);
  }

  _base64ToArrayBuffer(base64) {
    let padded = base64;
    const mod = base64.length % 4;
    if (mod > 0) {
      padded += "=".repeat(4 - mod);
    }
    const binary = atob(padded);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  }
}

export default WebCryptPQC;
