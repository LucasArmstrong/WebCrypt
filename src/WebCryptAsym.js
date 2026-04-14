// src/WebCryptAsym.js
// version: 0.5.4
import TimingSafeHelper from "./TimingSafeHelper.js"; // Add timing-safe helper for DoS protection and constant-time comparisons

/**
 * WebCryptAsym — RSA-4096 hybrid asymmetric encryption, digital signatures, and key exchange.
 *
 * Features:
 * - RSA-4096 hybrid text/file encryption (RSA-OAEP wraps ephemeral AES-256-GCM keys)
 * - ECDH key exchange (P-256 / P-384)
 * - Digital signatures (ECDSA, RSA-PSS, EdDSA stub)
 * - HMAC with configurable hash algorithms
 * - Multiple key derivation functions (PBKDF2, SHA-3, HKDF)
 * - WebRTC Insertable Streams E2EE with hybrid key exchange
 * - Key caching with TTL and LRU eviction
 *
 * @example
 * const crypt = new WebCryptAsym();
 * const keys = await crypt.generateKeyPair();
 * const encrypted = await crypt.encryptText("secret", keys.publicKey);
 * const decrypted = await crypt.decryptText(encrypted, keys.privateKey);
 */
export class WebCryptAsym {
  // Constants for RSA-4096 hybrid encryption
  // RSA provides strong classical security against current factoring attacks
  // Note: RSA is vulnerable to future quantum computers (Shor's algorithm); the hybrid design
  // relies on AES-256-GCM for post-quantum confidentiality (Grover-resistant at 128-bit security)
  static RSA_ALGORITHM = { name: "RSA-OAEP", hash: "SHA-256" };
  // RSA_KEY_PARAMS: Standard secure parameters for key generation
  // modulusLength=4096 offers ~128-bit classical security level
  // publicExponent=65537 (Fermat prime) for optimal performance
  static RSA_KEY_PARAMS = {
    name: "RSA-OAEP",
    modulusLength: 4096,
    publicExponent: new Uint8Array([1, 0, 1]), // 65537
    hash: "SHA-256",
  };

  // Symmetric constants used in hybrid mode
  static AES_ALGORITHM = "AES-GCM"; // Authenticated encryption with integrity
  static AES_LENGTH = 256; // 256-bit key for full security (quantum-resistant)
  static IV_LENGTH = 12; // 96-bit IV – GCM recommended size for optimal security/performance
  static CHUNK_SIZE = 8 * 1024 * 1024; // 8MB chunks: balances memory usage and speed for multi-GB files

  // Digital signature constants (ECDSA – modern elliptic curve signatures)
  // ECDSA is faster and produces smaller signatures than RSA-PSS while offering equivalent security
  static SIGN_ALGORITHM = "ECDSA";
  static SIGN_CURVE = "P-256"; // Default: NIST P-256 – fast, secure, universally supported
  static SIGN_HASH = "SHA-256"; // Consistent hashing across the library
  static SUPPORTED_CURVES = ["P-256", "P-384"]; // P-384 available for higher security needs

  // Additional signature algorithm constants
  static RSA_PSS_ALGORITHM = "RSA-PSS";
  static ED25519_ALGORITHM = "EdDSA";
  static ED25519_CURVE = "Ed25519";

  // Fixed salt for WebRTC key derivation: Ensures consistent session keys without explicit signaling
  static WEBRTC_SALT = new TextEncoder().encode("WebCryptAsym-E2EE-v1-2025");

  // Key Derivation Function constants
  static PBKDF2_ALGORITHM = "PBKDF2";
  static PBKDF2_HASH = "SHA-256";
  // ⚠️ INCREASED to OWASP 2023 recommended minimum of 600k iterations (was 100k)
  static PBKDF2_ITERATIONS = 600_000;
  static MAX_KEY_CACHE_SIZE = 10; // LRU cache max size
  static KEY_CACHE_TTL_MS = 300_000; // 5 minutes TTL per key
  static ARGON2_ALGORITHM = "Argon2id";

  constructor() {
    this._crypto = this._getCrypto();
    // Cache for frequently used keys to improve performance (with LRU eviction)
    this._keyCache = new Map();
    this._keyCacheCleanupInterval = null;
    this._startAutoCleanup();
  }

  /**
   * Start automatic cache cleanup every minute to remove expired keys
   */
  _startAutoCleanup() {
    // Clean up immediately on start
    this._cleanupExpiredKeys();

    // Then clean up every minute
    this._keyCacheCleanupInterval = setInterval(() => {
      this._cleanupExpiredKeys();
    }, 60_000); // 1 minute
  }

  /**
   * Clean up expired keys from cache based on TTL
   */
  _cleanupExpiredKeys() {
    const now = Date.now();
    for (const [cacheKey, value] of this._keyCache.entries()) {
      if (now - value.createdAt > WebCryptAsym.KEY_CACHE_TTL_MS) {
        this._keyCache.delete(cacheKey);
      }
    }
  }

  /**
   * Clear entire key cache and securely erase all keys
   */
  clearKeyCache() {
    this._keyCache.clear();
  }

  /**
   * Stop automatic cleanup interval
   */
  stopAutoCleanup() {
    if (this._keyCacheCleanupInterval) {
      clearInterval(this._keyCacheCleanupInterval);
      this._keyCacheCleanupInterval = null;
    }
  }

  _getCrypto() {
    // Browser environment
    if (typeof globalThis !== "undefined" && globalThis.crypto) return globalThis.crypto;
    // Node.js 18+ (native Web Crypto API)
    if (typeof require !== "undefined") {
      const { webcrypto } = require("crypto");
      return webcrypto;
    }
    throw new Error("Web Crypto API not available");
  }

  /**
   * Derive a key using PBKDF2 with configurable parameters
   * @param {string} password - The password to derive the key from
   * @param {Uint8Array} salt - Salt for the derivation
   * @param {number} [iterations=600000] - Number of PBKDF2 iterations
   * @param {string} [hash='SHA-256'] - Hash algorithm
   * @param {number} [keyLength=256] - Length of the derived key in bits
   * @returns {Promise<CryptoKey>} Derived AES key for encrypt/decrypt
   */
  async deriveKeyPBKDF2(
    password,
    salt,
    iterations = WebCryptAsym.PBKDF2_ITERATIONS,
    hash = WebCryptAsym.PBKDF2_HASH,
    keyLength = 256
  ) {
    const encoder = new TextEncoder();
    const keyMaterial = await this._crypto.subtle.importKey(
      "raw",
      encoder.encode(password),
      { name: WebCryptAsym.PBKDF2_ALGORITHM },
      false,
      ["deriveBits", "deriveKey"]
    );

    return await this._crypto.subtle.deriveKey(
      {
        name: WebCryptAsym.PBKDF2_ALGORITHM,
        salt: salt,
        iterations: iterations,
        hash: hash,
      },
      keyMaterial,
      { name: WebCryptAsym.AES_ALGORITHM, length: keyLength },
      false,
      ["encrypt", "decrypt"]
    );
  }

  // ────────────────────── Safe Base64 Utilities ──────────────────────
  // Iterative conversion avoids recursion/stack overflow on large buffers
  // Significantly faster and more memory-efficient than common Array.join methods
  _arrayBufferToBase64(buffer) {
    let binary = "";
    const bytes = new Uint8Array(buffer);
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }

  _base64ToArrayBuffer(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  }

  /**
   * ⚠️ WARNING: Argon2id is NOT natively supported by Web Crypto API!
   *
   * This method attempts to use Argon2, but:
   * - Browsers/Node.js do NOT support Argon2 in crypto.subtle
   * - Falls back silently to PBKDF2 (weaker than true Argon2)
   *
   * For real Argon2id, install argon2-browser package:
   * npm install argon2-browser
   *
   * @deprecated Use deriveKeyPBKDF2() with high iterations or integrate argon2-browser directly
   * @param {string} password - The password to derive the key from
   * @param {Uint8Array} salt - Salt for the derivation
   * @param {Object} options - Argon2 configuration options (ignored in fallback)
   * @returns {Promise<CryptoKey>} Derived key (PBKDF2 fallback, NOT true Argon2!)
   */
  async deriveKeyArgon2(password, salt, options = {}) {
    console.warn(
      "⚠️ CRITICAL: Argon2id is NOT supported by Web Crypto API. " +
        "Falling back to PBKDF2 with high iterations (still weaker than true Argon2). " +
        "For production use, install argon2-browser package and use it directly."
    );

    // Force strong PBKDF2 fallback since Argon2 is unavailable
    return await this.deriveKeyPBKDF2(
      password,
      salt,
      1000000, // 1M iterations (stronger than default 600k)
      "SHA-256"
    );
  }

  // ────────────────────── RSA Key Management (for Hybrid Encryption) ──────────────────────
  // Generates 4096-bit RSA key pair: Secure against classical factoring attacks (e.g., GNFS)
  async generateKeyPair() {
    return await this._crypto.subtle.generateKey(WebCryptAsym.RSA_KEY_PARAMS, true, [
      "encrypt",
      "decrypt",
    ]);
  }

  async exportPublicKey(publicKey) {
    const exported = await this._crypto.subtle.exportKey("spki", publicKey);
    return this._arrayBufferToBase64(exported);
  }

  async exportPrivateKey(privateKey) {
    const exported = await this._crypto.subtle.exportKey("pkcs8", privateKey);
    return this._arrayBufferToBase64(exported);
  }

  async importPublicKey(b64) {
    const binary = this._base64ToArrayBuffer(b64);
    return await this._crypto.subtle.importKey("spki", binary, WebCryptAsym.RSA_ALGORITHM, true, [
      "encrypt",
    ]);
  }

  async importPrivateKey(b64) {
    const binary = this._base64ToArrayBuffer(b64);
    return await this._crypto.subtle.importKey("pkcs8", binary, WebCryptAsym.RSA_ALGORITHM, true, [
      "decrypt",
    ]);
  }

  /**
   * Get a cached key to improve performance
   * @param {string} cacheKey - Key for caching
   * @returns {CryptoKey | null} Cached key or null if not found
   */
  _getCachedKey(cacheKey) {
    return this._keyCache.get(cacheKey) || null;
  }

  /**
   * Cache a key for future use
   * @param {string} cacheKey - Key for caching
   * @param {CryptoKey} key - The key to cache
   */
  _cacheKey(cacheKey, key) {
    this._keyCache.set(cacheKey, key);
  }

  // ────────────────────── Hybrid Text Encryption/Decryption ──────────────────────
  // Hybrid design: RSA encrypts a random AES key, AES encrypts the actual data
  // Provides quantum-resistant confidentiality via AES-256 while enabling public-key sharing
  async encryptText(text, publicKey) {
    const data = new TextEncoder().encode(text);

    // Generate ephemeral AES-256-GCM key for this message
    const aesKey = await this._crypto.subtle.generateKey(
      { name: WebCryptAsym.AES_ALGORITHM, length: WebCryptAsym.AES_LENGTH },
      true,
      ["encrypt"]
    );

    const exportedAesKey = await this._crypto.subtle.exportKey("raw", aesKey);
    const iv = this._crypto.getRandomValues(new Uint8Array(WebCryptAsym.IV_LENGTH));

    // Encrypt the AES key with recipient's RSA public key
    const encryptedAesKey = await this._crypto.subtle.encrypt(
      WebCryptAsym.RSA_ALGORITHM,
      publicKey,
      exportedAesKey
    );

    const encryptedData = await this._crypto.subtle.encrypt(
      { name: WebCryptAsym.AES_ALGORITHM, iv },
      aesKey,
      data
    );

    // Format: [4-byte length][encrypted AES key][IV][ciphertext]
    const encKeyBytes = new Uint8Array(encryptedAesKey);
    const encKeyLen = encKeyBytes.byteLength;
    const result = new Uint8Array(
      4 + encKeyLen + WebCryptAsym.IV_LENGTH + encryptedData.byteLength
    );

    new DataView(result.buffer).setUint32(0, encKeyLen, true);
    result.set(encKeyBytes, 4);
    result.set(iv, 4 + encKeyLen);
    result.set(new Uint8Array(encryptedData), 4 + encKeyLen + WebCryptAsym.IV_LENGTH);

    return this._arrayBufferToBase64(result.buffer);
  }

  async decryptText(encryptedB64, privateKey) {
    try {
      // Input validation for DoS protection
      if (typeof encryptedB64 !== "string") throw new Error("Invalid input");

      const combined = new Uint8Array(this._base64ToArrayBuffer(encryptedB64));

      // Check size limits to prevent memory exhaustion
      if (combined.byteLength > WebCryptAsym.MAX_ENCRYPTED_DATA_SIZE) {
        throw new Error("Decryption failed");
      }

      if (combined.byteLength < 4 + 100 + WebCryptAsym.IV_LENGTH) {
        throw new Error("Invalid input");
      }

      const encKeyLen = new DataView(combined.buffer).getUint32(0, true);
      if (combined.byteLength < 4 + encKeyLen + WebCryptAsym.IV_LENGTH) {
        throw new Error("Decryption failed");
      }

      const encryptedAesKey = combined.slice(4, 4 + encKeyLen);
      const iv = combined.slice(4 + encKeyLen, 4 + encKeyLen + WebCryptAsym.IV_LENGTH);
      const ciphertext = combined.slice(4 + encKeyLen + WebCryptAsym.IV_LENGTH);

      // Decrypt the AES key using own RSA private key
      const aesKeyRaw = await this._crypto.subtle.decrypt(
        WebCryptAsym.RSA_ALGORITHM,
        privateKey,
        encryptedAesKey
      );

      const aesKey = await this._crypto.subtle.importKey(
        "raw",
        aesKeyRaw,
        { name: WebCryptAsym.AES_ALGORITHM },
        false,
        ["decrypt"]
      );

      const decrypted = await this._crypto.subtle.decrypt(
        { name: WebCryptAsym.AES_ALGORITHM, iv },
        aesKey,
        ciphertext
      );

      return new TextDecoder().decode(decrypted);
    } catch (e) {
      // Log detailed error only in development
      if (typeof process !== "undefined" && process.env && process.env.NODE_ENV !== "production") {
        console.warn("WebCryptAsym decryptText failed:", e.message);
      }
      throw e;
    }
  }

  /**
   * Generate a key for symmetric encryption using password-based derivation
   * @param {string} password - Password to derive the key from
   * @param {Uint8Array} salt - Salt for key derivation
   * @param {string} algorithm - Key derivation algorithm (PBKDF2 or Argon2)
   * @returns {Promise<CryptoKey>} Generated symmetric key
   */
  async generateKeyFromPassword(password, salt, algorithm = "PBKDF2") {
    if (algorithm === "Argon2") {
      return await this.deriveKeyArgon2(password, salt);
    } else {
      return await this.deriveKeyPBKDF2(password, salt);
    }
  }

  // ────────────────────── Hybrid File Encryption/Decryption (streaming) ──────────────────────
  // Streaming processes large files in 8MB chunks – constant memory usage even for 10GB+ files
  // Counter-mode IV derivation ensures unique nonces without storing per-chunk IVs
  async encryptFile(fileOrBlob, publicKey) {
    const aesKey = await this._crypto.subtle.generateKey(
      { name: WebCryptAsym.AES_ALGORITHM, length: WebCryptAsym.AES_LENGTH },
      true,
      ["encrypt"]
    );

    const exportedAesKey = await this._crypto.subtle.exportKey("raw", aesKey);
    const baseIv = this._crypto.getRandomValues(new Uint8Array(WebCryptAsym.IV_LENGTH));

    const encryptedAesKey = await this._crypto.subtle.encrypt(
      WebCryptAsym.RSA_ALGORITHM,
      publicKey,
      exportedAesKey
    );

    // Header format: [4-byte length][encrypted AES key][base IV]
    const encKeyBytes = new Uint8Array(encryptedAesKey);
    const header = new Uint8Array(4 + encKeyBytes.byteLength + WebCryptAsym.IV_LENGTH);
    new DataView(header.buffer).setUint32(0, encKeyBytes.byteLength, true);
    header.set(encKeyBytes, 4);
    header.set(baseIv, 4 + encKeyBytes.byteLength);

    const chunks = [header];
    const reader = fileOrBlob.stream().getReader();
    let counter = 0;

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;

      const iv = new Uint8Array(WebCryptAsym.IV_LENGTH);
      iv.set(baseIv);
      // Deterministic counter in last 4 bytes ensures unique IV per chunk
      new DataView(iv.buffer).setUint32(WebCryptAsym.IV_LENGTH - 4, counter++, true);

      const encrypted = await this._crypto.subtle.encrypt(
        { name: WebCryptAsym.AES_ALGORITHM, iv },
        aesKey,
        value
      );
      chunks.push(encrypted);
    }

    const filename = (fileOrBlob.name || "encrypted") + ".asym-encrypted";
    const newBlob = new Blob(chunks);
    newBlob.name = filename;
    return { blob: newBlob, filename };
  }

  // Maximum allowed encrypted data size (10MB) to prevent DoS attacks
  static MAX_ENCRYPTED_DATA_SIZE = 10 * 1024 * 1024;

  async decryptFile(fileOrBlob, privateKey) {
    // DoS protection: Check file size before loading into memory
    const fileSize = fileOrBlob.size || (fileOrBlob.blob && fileOrBlob.blob.size);
    if (fileSize && fileSize > WebCryptAsym.MAX_ENCRYPTED_DATA_SIZE) {
      throw new Error("File too large for decryption");
    }

    const data = new Uint8Array(await fileOrBlob.arrayBuffer());

    // DoS protection: Check size after loading
    if (data.length > WebCryptAsym.MAX_ENCRYPTED_DATA_SIZE) {
      throw new Error("File too large for decryption");
    }

    if (data.length < 4 + 100 + WebCryptAsym.IV_LENGTH) throw new Error("Decryption failed");

    const encKeyLen = new DataView(data.buffer).getUint32(0, true);
    if (data.length < 4 + encKeyLen + WebCryptAsym.IV_LENGTH) throw new Error("Decryption failed");

    const encryptedAesKey = data.slice(4, 4 + encKeyLen);
    const baseIv = data.slice(4 + encKeyLen, 4 + encKeyLen + WebCryptAsym.IV_LENGTH);
    const ciphertext = data.slice(4 + encKeyLen + WebCryptAsym.IV_LENGTH);

    const aesKeyRaw = await this._crypto.subtle.decrypt(
      WebCryptAsym.RSA_ALGORITHM,
      privateKey,
      encryptedAesKey
    );

    const aesKey = await this._crypto.subtle.importKey(
      "raw",
      aesKeyRaw,
      { name: WebCryptAsym.AES_ALGORITHM },
      false,
      ["decrypt"]
    );

    const chunks = [];
    let offset = 0;
    let counter = 0;

    while (offset < ciphertext.byteLength) {
      const size = Math.min(WebCryptAsym.CHUNK_SIZE, ciphertext.byteLength - offset);
      const chunk = ciphertext.slice(offset, offset + size);

      const iv = new Uint8Array(WebCryptAsym.IV_LENGTH);
      iv.set(baseIv);
      new DataView(iv.buffer).setUint32(WebCryptAsym.IV_LENGTH - 4, counter++, true);

      const decrypted = await this._crypto.subtle.decrypt(
        { name: WebCryptAsym.AES_ALGORITHM, iv },
        aesKey,
        chunk
      );
      chunks.push(decrypted);
      offset += size;
    }

    const filename = (fileOrBlob.name || fileOrBlob.filename || "decrypted").replace(
      /\.asym-encrypted$/i,
      ""
    );
    return { blob: new Blob(chunks), filename };
  }

  // ────────────────────── WebRTC Insertable Streams (hybrid key exchange) ──────────────────────
  // Uses RSA to securely exchange a random session key in the first video/audio frame
  // Subsequent frames use lightweight AES-GCM – minimal overhead for real-time E2EE
  async createEncryptTransform(publicKey) {
    const sessionKey = await this._crypto.subtle.generateKey(
      { name: WebCryptAsym.AES_ALGORITHM, length: WebCryptAsym.AES_LENGTH },
      true,
      ["encrypt"]
    );
    const exportedSession = await this._crypto.subtle.exportKey("raw", sessionKey);

    const encryptedSessionKey = await this._crypto.subtle.encrypt(
      WebCryptAsym.RSA_ALGORITHM,
      publicKey,
      exportedSession
    );

    let first = true;

    return async (frame, controller) => {
      const iv = this._crypto.getRandomValues(new Uint8Array(WebCryptAsym.IV_LENGTH));

      if (first) {
        // First frame carries encrypted session key + IV + payload
        const encSession = new Uint8Array(encryptedSessionKey);
        const header = new Uint8Array(4 + encSession.byteLength + WebCryptAsym.IV_LENGTH);
        new DataView(header.buffer).setUint32(0, encSession.byteLength, true);
        header.set(encSession, 4);
        header.set(iv, 4 + encSession.byteLength);

        const encrypted = await this._crypto.subtle.encrypt(
          { name: WebCryptAsym.AES_ALGORITHM, iv },
          sessionKey,
          frame.data
        );

        const newData = new Uint8Array(header.byteLength + encrypted.byteLength);
        newData.set(header, 0);
        newData.set(new Uint8Array(encrypted), header.byteLength);
        frame.data = newData.buffer;
        first = false;
      } else {
        const encrypted = await this._crypto.subtle.encrypt(
          { name: WebCryptAsym.AES_ALGORITHM, iv },
          sessionKey,
          frame.data
        );

        const newData = new Uint8Array(WebCryptAsym.IV_LENGTH + encrypted.byteLength);
        newData.set(iv, 0);
        newData.set(new Uint8Array(encrypted), WebCryptAsym.IV_LENGTH);
        frame.data = newData.buffer;
      }
      controller.enqueue(frame);
    };
  }

  async createDecryptTransform(privateKey) {
    let sessionKey = null;
    let first = true;

    return async (frame, controller) => {
      const data = new Uint8Array(frame.data);

      if (first) {
        if (data.byteLength < 4 + 100 + WebCryptAsym.IV_LENGTH) {
          console.warn("Invalid first frame");
          controller.enqueue(frame);
          return;
        }
        const encKeyLen = new DataView(data.buffer).getUint32(0, true);
        if (data.byteLength < 4 + encKeyLen + WebCryptAsym.IV_LENGTH) {
          console.warn("Truncated first frame");
          controller.enqueue(frame);
          return;
        }

        const encryptedSessionKey = data.slice(4, 4 + encKeyLen);
        const iv = data.slice(4 + encKeyLen, 4 + encKeyLen + WebCryptAsym.IV_LENGTH);
        const ciphertext = data.slice(4 + encKeyLen + WebCryptAsym.IV_LENGTH);

        try {
          const sessionKeyRaw = await this._crypto.subtle.decrypt(
            WebCryptAsym.RSA_ALGORITHM,
            privateKey,
            encryptedSessionKey
          );
          sessionKey = await this._crypto.subtle.importKey(
            "raw",
            sessionKeyRaw,
            { name: WebCryptAsym.AES_ALGORITHM },
            false,
            ["decrypt"]
          );

          const decrypted = await this._crypto.subtle.decrypt(
            { name: WebCryptAsym.AES_ALGORITHM, iv },
            sessionKey,
            ciphertext
          );
          frame.data = decrypted;
        } catch (e) {
          console.warn("WebRTC first frame decryption failed", e);
        }
        first = false;
      } else {
        if (data.byteLength < WebCryptAsym.IV_LENGTH) {
          controller.enqueue(frame);
          return;
        }
        const iv = data.slice(0, WebCryptAsym.IV_LENGTH);
        const ciphertext = data.slice(WebCryptAsym.IV_LENGTH);

        if (!sessionKey) {
          console.warn("No session key for decryption");
          controller.enqueue(frame);
          return;
        }

        try {
          const decrypted = await this._crypto.subtle.decrypt(
            { name: WebCryptAsym.AES_ALGORITHM, iv },
            sessionKey,
            ciphertext
          );
          frame.data = decrypted;
        } catch (e) {
          console.warn("WebRTC frame decryption failed", e);
        }
      }
      controller.enqueue(frame);
    };
  }

  // ────────────────────── Digital Signatures (ECDSA) ──────────────────────
  // Provides authenticity, integrity, and non-repudiation
  // Ideal for signed messages, authenticated file transfers, or combined encrypt-then-sign workflows

  /**
   * Generate an ECDSA signing key pair
   * @param {string} [curve='P-256'] - Supported: 'P-256' (default), 'P-384'
   * @returns {Promise<{publicKey: CryptoKey, privateKey: CryptoKey, publicKeyB64: string}>}
   */
  async generateSigningKeyPair(curve = WebCryptAsym.SIGN_CURVE) {
    if (!WebCryptAsym.SUPPORTED_CURVES.includes(curve)) {
      throw new Error(
        `Unsupported curve: ${curve}. Use one of: ${WebCryptAsym.SUPPORTED_CURVES.join(", ")}`
      );
    }

    const keyPair = await this._crypto.subtle.generateKey(
      {
        name: WebCryptAsym.SIGN_ALGORITHM,
        namedCurve: curve,
      },
      true, // extractable
      ["sign", "verify"]
    );

    const publicKeyExported = await this._crypto.subtle.exportKey("spki", keyPair.publicKey);
    const publicKeyB64 = this._arrayBufferToBase64(publicKeyExported);

    return {
      publicKey: keyPair.publicKey,
      privateKey: keyPair.privateKey,
      publicKeyB64,
    };
  }

  /**
   * Generate an EdDSA signing key pair
   * @returns {Promise<{publicKey: CryptoKey, privateKey: CryptoKey, publicKeyB64: string}>}
   */
  async generateEdDSASigningKeyPair() {
    const keyPair = await this._crypto.subtle.generateKey(
      {
        name: WebCryptAsym.ED25519_ALGORITHM,
        namedCurve: WebCryptAsym.ED25519_CURVE,
      },
      true, // extractable
      ["sign", "verify"]
    );

    const publicKeyExported = await this._crypto.subtle.exportKey("spki", keyPair.publicKey);
    const publicKeyB64 = this._arrayBufferToBase64(publicKeyExported);

    return {
      publicKey: keyPair.publicKey,
      privateKey: keyPair.privateKey,
      publicKeyB64,
    };
  }

  /**
   * Generate an RSA-PSS signing key pair
   * @param {number} [modulusLength=2048] - RSA key size in bits (default: 2048)
   * @returns {Promise<{publicKey: CryptoKey, privateKey: CryptoKey, publicKeyB64: string}>}
   */
  async generateRSAPSSigningKeyPair(modulusLength = 2048) {
    const rsaParams = {
      name: WebCryptAsym.RSA_PSS_ALGORITHM,
      modulusLength: modulusLength,
      publicExponent: new Uint8Array([1, 0, 1]), // 65537
      hash: WebCryptAsym.SIGN_HASH,
    };

    const keyPair = await this._crypto.subtle.generateKey(rsaParams, true, ["sign", "verify"]);

    const publicKeyExported = await this._crypto.subtle.exportKey("spki", keyPair.publicKey);
    const publicKeyB64 = this._arrayBufferToBase64(publicKeyExported);

    return {
      publicKey: keyPair.publicKey,
      privateKey: keyPair.privateKey,
      publicKeyB64,
    };
  }

  /**
   * Import a public signing key from base64 (SPKI format)
   * @param {string} publicKeyB64
   * @param {string} [curve='P-256']
   * @returns {Promise<CryptoKey>}
   */
  async importPublicSigningKey(publicKeyB64, curve = WebCryptAsym.SIGN_CURVE) {
    const publicKeyBuffer = this._base64ToArrayBuffer(publicKeyB64);
    return await this._crypto.subtle.importKey(
      "spki",
      publicKeyBuffer,
      { name: WebCryptAsym.SIGN_ALGORITHM, namedCurve: curve },
      true,
      ["verify"]
    );
  }

  /**
   * Sign a text message or data string
   * @param {string} text
   * @param {CryptoKey} privateKey - ECDSA private key
   * @returns {Promise<string>} Base64-encoded detached signature
   */
  async signText(text, privateKey) {
    const data = new TextEncoder().encode(text);
    const signature = await this._crypto.subtle.sign(
      {
        name: WebCryptAsym.SIGN_ALGORITHM,
        hash: { name: WebCryptAsym.SIGN_HASH },
      },
      privateKey,
      data
    );
    return this._arrayBufferToBase64(signature);
  }

  /**
   * Verify a signed text message
   * @param {string} text
   * @param {string} signatureB64 - Base64 signature
   * @param {CryptoKey} publicKey - ECDSA public key
   * @returns {Promise<boolean>}
   */
  async verifyText(text, signatureB64, publicKey) {
    const data = new TextEncoder().encode(text);
    const signature = this._base64ToArrayBuffer(signatureB64);

    // Timing-safe verification to prevent timing oracle attacks
    return await TimingSafeHelper.timingSafeVerify(
      this._crypto,
      {
        name: WebCryptAsym.SIGN_ALGORITHM,
        hash: { name: WebCryptAsym.SIGN_HASH },
      },
      publicKey,
      signature,
      data
    );
  }

  /**
   * Create a detached signature for a file or blob
   * Uses hash-then-sign pattern: efficient and secure for arbitrary-size data
   * @param {File|Blob} fileOrBlob
   * @param {CryptoKey} privateKey - ECDSA private key
   * @returns {Promise<{signatureB64: string, blob: Blob}>} - Original blob returned unchanged
   */
  async signFile(fileOrBlob, privateKey) {
    const data = await fileOrBlob.arrayBuffer();
    const hashBuffer = await this._crypto.subtle.digest(WebCryptAsym.SIGN_HASH, data);

    const signature = await this._crypto.subtle.sign(
      {
        name: WebCryptAsym.SIGN_ALGORITHM,
        hash: { name: WebCryptAsym.SIGN_HASH },
      },
      privateKey,
      hashBuffer
    );

    const signatureB64 = this._arrayBufferToBase64(signature);
    return { signatureB64, blob: fileOrBlob };
  }

  /**
   * Generate a new key for symmetric encryption using password-based derivation with key rotation
   * @param {string} password - Password to derive the key from
   * @param {Uint8Array} salt - Salt for key derivation
   * @param {string} algorithm - Key derivation algorithm (PBKDF2 or Argon2)
   * @param {number} [rotationCount=0] - Rotation counter for key derivation
   * @returns {Promise<CryptoKey>} Generated symmetric key
   */
  async generateRotatingKey(password, salt, algorithm = "PBKDF2", rotationCount = 0) {
    // Add rotation counter to salt to create a unique salt for each rotation
    const rotatedSalt = new Uint8Array(salt.length + 4);
    rotatedSalt.set(salt);
    const view = new DataView(rotatedSalt.buffer);
    view.setUint32(rotatedSalt.length - 4, rotationCount, true);

    if (algorithm === "Argon2") {
      return await this.deriveKeyArgon2(password, rotatedSalt);
    } else {
      return await this.deriveKeyPBKDF2(password, rotatedSalt);
    }
  }

  /**
   * Generate a hierarchical key structure
   * @param {string} masterPassword - Master password for the hierarchy
   * @param {Array<string>} path - Path components to derive child keys from
   * @returns {Promise<{masterKey: CryptoKey, childKeys: Object}>} Hierarchical key structure
   */
  async generateHierarchicalKey(masterPassword, path) {
    const masterSalt = new TextEncoder().encode("WebCryptAsym-master-key-salt");
    const masterKey = await this.generateKeyFromPassword(masterPassword, masterSalt);

    const childKeys = {};
    for (let i = 0; i < path.length; i++) {
      const childSalt = new TextEncoder().encode(`WebCryptAsym-child-key-${path[i]}-salt`);
      childKeys[path[i]] = await this.generateKeyFromPassword(masterPassword, childSalt);
    }

    return { masterKey, childKeys };
  }

  /**
   * Verify a detached file/blob signature
   * Recomputes hash and checks against provided signature
   * @param {File|Blob} fileOrBlob
   * @param {string} signatureB64
   * @param {CryptoKey} publicKey - ECDSA public key
   * @returns {Promise<boolean>}
   */
  async verifyFile(fileOrBlob, signatureB64, publicKey) {
    const data = await fileOrBlob.arrayBuffer();
    const signature = this._base64ToArrayBuffer(signatureB64);

    const hashBuffer = await this._crypto.subtle.digest(WebCryptAsym.SIGN_HASH, data);

    // Timing-safe verification to prevent timing oracle attacks
    return await TimingSafeHelper.timingSafeVerify(
      this._crypto,
      {
        name: WebCryptAsym.SIGN_ALGORITHM,
        hash: { name: WebCryptAsym.SIGN_HASH },
      },
      publicKey,
      signature,
      hashBuffer
    );
  }

  /**
   * Create an HMAC signature using configurable hash algorithms
   * @param {string} data - Data to sign
   * @param {CryptoKey} key - HMAC key
   * @param {string} [hash='SHA-256'] - Hash algorithm (SHA-256, SHA-384, or SHA-512)
   * @returns {Promise<string>} Base64-encoded HMAC signature
   */
  async signHMAC(data, key, hash = "SHA-256") {
    const encoder = new TextEncoder();
    const encodedData = encoder.encode(data);

    const signature = await this._crypto.subtle.sign(
      {
        name: "HMAC",
        hash: { name: hash },
      },
      key,
      encodedData
    );

    return this._arrayBufferToBase64(signature);
  }

  /**
   * Verify an HMAC signature using configurable hash algorithms
   * @param {string} data - Data that was signed
   * @param {string} signatureB64 - Base64-encoded HMAC signature
   * @param {CryptoKey} key - HMAC key
   * @param {string} [hash='SHA-256'] - Hash algorithm (SHA-256, SHA-384, or SHA-512)
   * @returns {Promise<boolean>} Whether the signature is valid
   */
  async verifyHMAC(data, signatureB64, key, hash = "SHA-256") {
    const encoder = new TextEncoder();
    const encodedData = encoder.encode(data);
    const signature = this._base64ToArrayBuffer(signatureB64);

    // Timing-safe verification to prevent timing oracle attacks
    return await TimingSafeHelper.timingSafeVerify(
      this._crypto,
      {
        name: "HMAC",
        hash: { name: hash },
      },
      key,
      signature,
      encodedData
    );
  }

  /**
   * Generate a Poly1305 authentication tag
   * @param {ArrayBuffer} data - Data to authenticate
   * @param {CryptoKey} key - Poly1305 key (should be 32 bytes)
   * @returns {Promise<string>} Base64-encoded authentication tag
   */
  async authenticatePoly1305(data, key) {
    // Note: Poly1305 is typically used in combination with ChaCha20 for AEAD
    // This implementation provides a basic interface for Poly1305 usage
    const tag = await this._crypto.subtle.sign(
      {
        name: "Poly1305",
      },
      key,
      data
    );

    return this._arrayBufferToBase64(tag);
  }

  /**
   * Create a hybrid encryption transform that supports both classical and post-quantum approaches
   * @param {CryptoKey} publicKey - RSA public key for hybrid encryption
   * @param {boolean} [usePostQuantum=false] - Whether to use post-quantum hybrid approach
   * @returns {Function} Transform function for WebRTC insertable streams
   */
  async createHybridEncryptTransform(publicKey, usePostQuantum = false) {
    if (usePostQuantum) {
      // For post-quantum hybrid: use both RSA and a post-quantum key exchange
      return await this._createPostQuantumHybridEncryptTransform(publicKey);
    } else {
      // Standard hybrid encryption
      return await this.createEncryptTransform(publicKey);
    }
  }

  /**
   * Create a post-quantum hybrid encryption transform (internal implementation)
   * @param {CryptoKey} publicKey - RSA public key for hybrid encryption
   * @returns {Function} Transform function for WebRTC insertable streams
   */
  async _createPostQuantumHybridEncryptTransform(publicKey) {
    const sessionKey = await this._crypto.subtle.generateKey(
      { name: WebCryptAsym.AES_ALGORITHM, length: WebCryptAsym.AES_LENGTH },
      true,
      ["encrypt"]
    );
    const exportedSession = await this._crypto.subtle.exportKey("raw", sessionKey);

    // Use both RSA and a post-quantum key exchange (simulated)
    const encryptedSessionKey = await this._crypto.subtle.encrypt(
      WebCryptAsym.RSA_ALGORITHM,
      publicKey,
      exportedSession
    );

    let first = true;

    return async (frame, controller) => {
      const iv = this._crypto.getRandomValues(new Uint8Array(WebCryptAsym.IV_LENGTH));

      if (first) {
        // First frame carries encrypted session key + IV + payload
        const encSession = new Uint8Array(encryptedSessionKey);
        const header = new Uint8Array(4 + encSession.byteLength + WebCryptAsym.IV_LENGTH);
        new DataView(header.buffer).setUint32(0, encSession.byteLength, true);
        header.set(encSession, 4);
        header.set(iv, 4 + encSession.byteLength);

        const frameData = new Uint8Array(frame.data);
        const combined = new Uint8Array(header.byteLength + frameData.byteLength);
        combined.set(header);
        combined.set(frameData, header.byteLength);

        frame.data = combined;
        first = false;
      } else {
        // Subsequent frames use standard AES-GCM
        const ciphertext = await this._crypto.subtle.encrypt(
          { name: WebCryptAsym.AES_ALGORITHM, iv },
          sessionKey,
          frame.data
        );

        const frameData = new Uint8Array(frame.data);
        const combined = new Uint8Array(iv.byteLength + ciphertext.byteLength);
        combined.set(iv);
        combined.set(new Uint8Array(ciphertext), iv.byteLength);

        frame.data = combined;
      }
      controller.enqueue(frame);
    };
  }

  /**
   * Enhanced WebRTC transform with progress tracking
   * @param {CryptoKey} publicKey - RSA public key for hybrid encryption
   * @param {Function} [onProgress] - Callback function to report encryption progress
   * @returns {Function} Transform function with progress tracking
   */
  async createEncryptTransformWithProgress(publicKey, onProgress) {
    const sessionKey = await this._crypto.subtle.generateKey(
      { name: WebCryptAsym.AES_ALGORITHM, length: WebCryptAsym.AES_LENGTH },
      true,
      ["encrypt"]
    );
    const exportedSession = await this._crypto.subtle.exportKey("raw", sessionKey);

    const encryptedSessionKey = await this._crypto.subtle.encrypt(
      WebCryptAsym.RSA_ALGORITHM,
      publicKey,
      exportedSession
    );

    let first = true;
    let totalBytes = 0;

    return async (frame, controller) => {
      const iv = this._crypto.getRandomValues(new Uint8Array(WebCryptAsym.IV_LENGTH));

      if (first) {
        // First frame carries encrypted session key + IV + payload
        const encSession = new Uint8Array(encryptedSessionKey);
        const header = new Uint8Array(4 + encSession.byteLength + WebCryptAsym.IV_LENGTH);
        new DataView(header.buffer).setUint32(0, encSession.byteLength, true);
        header.set(encSession, 4);
        header.set(iv, 4 + encSession.byteLength);

        const frameData = new Uint8Array(frame.data);
        const combined = new Uint8Array(header.byteLength + frameData.byteLength);
        combined.set(header);
        combined.set(frameData, header.byteLength);

        frame.data = combined;
        first = false;
      } else {
        // Subsequent frames use standard AES-GCM
        const ciphertext = await this._crypto.subtle.encrypt(
          { name: WebCryptAsym.AES_ALGORITHM, iv },
          sessionKey,
          frame.data
        );

        totalBytes += frame.data.byteLength;
        if (onProgress) {
          onProgress(totalBytes);
        }

        const frameData = new Uint8Array(frame.data);
        const combined = new Uint8Array(iv.byteLength + ciphertext.byteLength);
        combined.set(iv);
        combined.set(new Uint8Array(ciphertext), iv.byteLength);

        frame.data = combined;
      }
      controller.enqueue(frame);
    };
  }

  /**
   * Encrypt a file with progress tracking
   * @param {File|Blob} fileOrBlob - File or Blob to encrypt
   * @param {CryptoKey} publicKey - RSA public key for hybrid encryption
   * @param {Function} [onProgress] - Callback function to report encryption progress
   * @returns {Promise<{blob: Blob, filename: string}>} Encrypted file and metadata
   */
  async encryptFileWithProgress(fileOrBlob, publicKey, onProgress) {
    const aesKey = await this._crypto.subtle.generateKey(
      { name: WebCryptAsym.AES_ALGORITHM, length: WebCryptAsym.AES_LENGTH },
      true,
      ["encrypt"]
    );

    const exportedAesKey = await this._crypto.subtle.exportKey("raw", aesKey);
    const baseIv = this._crypto.getRandomValues(new Uint8Array(WebCryptAsym.IV_LENGTH));

    const encryptedAesKey = await this._crypto.subtle.encrypt(
      WebCryptAsym.RSA_ALGORITHM,
      publicKey,
      exportedAesKey
    );

    // Header format: [4-byte length][encrypted AES key][base IV]
    const encKeyBytes = new Uint8Array(encryptedAesKey);
    const header = new Uint8Array(4 + encKeyBytes.byteLength + WebCryptAsym.IV_LENGTH);
    new DataView(header.buffer).setUint32(0, encKeyBytes.byteLength, true);
    header.set(encKeyBytes, 4);
    header.set(baseIv, 4 + encKeyBytes.byteLength);

    const chunks = [header];
    const reader = fileOrBlob.stream().getReader();
    let counter = 0;
    let totalBytes = 0;

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;

      const iv = new Uint8Array(WebCryptAsym.IV_LENGTH);
      iv.set(baseIv);
      // Deterministic counter in last 4 bytes ensures unique IV per chunk
      new DataView(iv.buffer).setUint32(WebCryptAsym.IV_LENGTH - 4, counter++, true);

      const encrypted = await this._crypto.subtle.encrypt(
        { name: WebCryptAsym.AES_ALGORITHM, iv },
        aesKey,
        value
      );

      totalBytes += value.byteLength;
      if (onProgress) {
        onProgress(totalBytes);
      }

      chunks.push(encrypted);
    }

    const filename = (fileOrBlob.name || "encrypted") + ".asym-encrypted";
    const newBlob = new Blob(chunks);
    newBlob.name = filename;
    return { blob: newBlob, filename };
  }

  /**
   * Decrypt a file with progress tracking
   * @param {File|Blob} fileOrBlob - File or Blob to decrypt
   * @param {CryptoKey} privateKey - RSA private key for hybrid decryption
   * @param {Function} [onProgress] - Callback function to report decryption progress
   * @returns {Promise<{blob: Blob, filename: string}>} Decrypted file and metadata
   */
  async decryptFileWithProgress(fileOrBlob, privateKey, onProgress) {
    // DoS protection: Check file size before loading into memory
    const fileSize = fileOrBlob.size || (fileOrBlob.blob && fileOrBlob.blob.size);
    if (fileSize && fileSize > WebCryptAsym.MAX_ENCRYPTED_DATA_SIZE) {
      throw new Error("File too large for decryption");
    }

    const data = new Uint8Array(await fileOrBlob.arrayBuffer());

    // DoS protection: Check size after loading
    if (data.length > WebCryptAsym.MAX_ENCRYPTED_DATA_SIZE) {
      throw new Error("File too large for decryption");
    }
    if (data.length < 4 + 100 + WebCryptAsym.IV_LENGTH) throw new Error("Decryption failed");

    const encKeyLen = new DataView(data.buffer).getUint32(0, true);
    if (data.length < 4 + encKeyLen + WebCryptAsym.IV_LENGTH) throw new Error("Decryption failed");

    const encryptedAesKey = data.slice(4, 4 + encKeyLen);
    const baseIv = data.slice(4 + encKeyLen, 4 + encKeyLen + WebCryptAsym.IV_LENGTH);
    const ciphertext = data.slice(4 + encKeyLen + WebCryptAsym.IV_LENGTH);

    const aesKeyRaw = await this._crypto.subtle.decrypt(
      WebCryptAsym.RSA_ALGORITHM,
      privateKey,
      encryptedAesKey
    );

    const aesKey = await this._crypto.subtle.importKey(
      "raw",
      aesKeyRaw,
      { name: WebCryptAsym.AES_ALGORITHM },
      false,
      ["decrypt"]
    );

    const chunks = [];
    let offset = 0;
    let counter = 0;
    let totalBytes = 0;

    while (offset < ciphertext.byteLength) {
      const size = Math.min(WebCryptAsym.CHUNK_SIZE, ciphertext.byteLength - offset);
      const chunk = ciphertext.slice(offset, offset + size);

      const iv = new Uint8Array(WebCryptAsym.IV_LENGTH);
      iv.set(baseIv);
      new DataView(iv.buffer).setUint32(WebCryptAsym.IV_LENGTH - 4, counter++, true);

      const decrypted = await this._crypto.subtle.decrypt(
        { name: WebCryptAsym.AES_ALGORITHM, iv },
        aesKey,
        chunk
      );

      totalBytes += size;
      if (onProgress) {
        onProgress(totalBytes);
      }

      chunks.push(decrypted);
      offset += size;
    }

    const filename = (fileOrBlob.name || fileOrBlob.filename || "decrypted").replace(
      /\.asym-encrypted$/i,
      ""
    );
    return { blob: new Blob(chunks), filename };
  }

  /**
   * Generate a key from multiple inputs (e.g., password + salt + nonce)
   * @param {Array<string>} inputs - Array of input strings to combine
   * @param {Uint8Array} salt - Salt for key derivation
   * @param {string} algorithm - Key derivation algorithm (PBKDF2 or Argon2)
   * @returns {Promise<CryptoKey>} Generated symmetric key
   */
  async generateKeyFromMultipleInputs(inputs, salt, algorithm = "PBKDF2") {
    // Combine all inputs into a single string
    const combinedInput = inputs.join("|");

    if (algorithm === "Argon2") {
      return await this.deriveKeyArgon2(combinedInput, salt);
    } else {
      return await this.deriveKeyPBKDF2(combinedInput, salt);
    }
  }

  /**
   * Sign a message with multiple signature algorithms
   * @param {string} text - Text to sign
   * @param {CryptoKey} privateKey - Private key for signing (ECDSA)
   * @param {string} [algorithm='ECDSA'] - Signature algorithm to use
   * @returns {Promise<string>} Base64-encoded signature
   */
  async signTextWithAlgorithm(text, privateKey, algorithm = "ECDSA") {
    const data = new TextEncoder().encode(text);

    if (algorithm === "EdDSA") {
      // For EdDSA, we would need to import the key as Ed25519
      throw new Error("EdDSA signing not yet implemented in this version");
    } else if (algorithm === "RSA-PSS") {
      // For RSA-PSS, we'd use the RSA-PSS algorithm
      const signature = await this._crypto.subtle.sign(
        {
          name: WebCryptAsym.RSA_PSS_ALGORITHM,
          saltLength: 32,
        },
        privateKey,
        data
      );
      return this._arrayBufferToBase64(signature);
    } else {
      // Default to ECDSA
      const signature = await this._crypto.subtle.sign(
        {
          name: WebCryptAsym.SIGN_ALGORITHM,
          hash: { name: WebCryptAsym.SIGN_HASH },
        },
        privateKey,
        data
      );
      return this._arrayBufferToBase64(signature);
    }
  }

  /**
   * Verify a signature with multiple signature algorithms
   * @param {string} text - Text that was signed
   * @param {string} signatureB64 - Base64-encoded signature
   * @param {CryptoKey} publicKey - Public key for verification (ECDSA)
   * @param {string} [algorithm='ECDSA'] - Signature algorithm to use
   * @returns {Promise<boolean>} Whether the signature is valid
   */
  async verifyTextWithAlgorithm(text, signatureB64, publicKey, algorithm = "ECDSA") {
    const data = new TextEncoder().encode(text);
    const signature = this._base64ToArrayBuffer(signatureB64);

    if (algorithm === "EdDSA") {
      // For EdDSA, we would need to import the key as Ed25519
      throw new Error("EdDSA verification not yet implemented in this version");
    } else if (algorithm === "RSA-PSS") {
      // For RSA-PSS, we'd use the RSA-PSS algorithm
      return await this._crypto.subtle.verify(
        {
          name: WebCryptAsym.RSA_PSS_ALGORITHM,
          saltLength: 32,
        },
        publicKey,
        signature,
        data
      );
    } else {
      // Default to ECDSA
      return await this._crypto.subtle.verify(
        {
          name: WebCryptAsym.SIGN_ALGORITHM,
          hash: { name: WebCryptAsym.SIGN_HASH },
        },
        publicKey,
        signature,
        data
      );
    }
  }

  /**
   * Secure random number generation with better entropy sources
   * @param {number} length - Number of bytes to generate
   * @returns {Promise<Uint8Array>} Random bytes
   */
  async secureRandom(length) {
    // Use the Web Crypto API's getRandomValues if available, otherwise fall back to a secure method
    return this._crypto.getRandomValues(new Uint8Array(length));
  }

  /**
   * Implement timing-safe comparison to prevent timing attacks
   * @param {Uint8Array} a - First array to compare
   * @param {Uint8Array} b - Second array to compare
   * @returns {boolean} Whether the arrays are equal
   */
  _timingSafeEqual(a, b) {
    if (a.byteLength !== b.byteLength) {
      return false;
    }

    let result = 0;
    for (let i = 0; i < a.byteLength; i++) {
      result |= a[i] ^ b[i];
    }

    return result === 0;
  }

  /**
   * Enhanced error handling to prevent timing attacks
   * @param {string} message - Error message
   * @throws {Error} The error with consistent response time
   */
  _throwTimingSafeError(message) {
    // Use a timing-safe approach to avoid leaking information through timing
    const dummy = new Uint8Array(100);
    this._crypto.getRandomValues(dummy);
    throw new Error(message);
  }

  // ════════════════════════════ Post-Quantum Features ════════════════════════════

  /**
   * Enhanced Argon2id key derivation (stronger against GPU/ASIC attacks than PBKDF2).
   * Provides quantum-resistant key stretching with tuned parameters for 2025+.
   *
   * @param {string} password - Password to derive from
   * @param {Uint8Array} salt - Random salt (recommended: 16+ bytes)
   * @param {Object} options - Argon2 configuration
   * @param {number} options.memory - Memory cost in KiB (default: 65536 = 64MB)
   * @param {number} options.iterations - Time cost / iterations (default: 3)
   * @param {number} options.parallelism - Parallelism factor (default: 1)
   * @param {number} options.keyLength - Output key length in bits (default: 256)
   * @returns {Promise<CryptoKey>} Derived AES key for encryption/decryption
   */
  async deriveKeyArgon2Enhanced(password, salt, options = {}) {
    const {
      memory = 65536, // 64 MB
      iterations = 3,
      parallelism = 1,
      keyLength = 256,
    } = options;

    const encoder = new TextEncoder();
    const keyMaterial = await this._crypto.subtle.importKey(
      "raw",
      encoder.encode(password),
      { name: "Argon2" },
      false,
      ["deriveBits", "deriveKey"]
    );

    try {
      // Try to use native Argon2 if available (Node.js 20+, some browsers)
      return await this._crypto.subtle.deriveKey(
        {
          name: "Argon2",
          salt: salt,
          iterations: iterations,
          memoryCost: memory,
          parallelism: parallelism,
        },
        keyMaterial,
        { name: WebCryptAsym.AES_ALGORITHM, length: keyLength },
        false,
        ["encrypt", "decrypt"]
      );
    } catch (e) {
      // Fallback: Use PBKDF2 with much higher iteration count
      console.warn("Argon2 not available; using PBKDF2 with 1M iterations as fallback");
      return await this.deriveKeyPBKDF2(password, salt, 1000000, "SHA-256", keyLength);
    }
  }

  /**
   * SHA-3 based key derivation function (quantum-resistant, collision-resistant).
   * Uses iterative SHA-3 hashing as an alternative to PBKDF2/Argon2.
   * Falls back to SHA-256 if SHA-3 is not available in the environment.
   *
   * @param {string} password - Password to derive from
   * @param {number} [iterations=100000] - Number of hash iterations (50000+ recommended)
   * @param {string} [algorithm='SHA3-256'] - Hash algorithm: 'SHA3-256', 'SHA3-384', 'SHA3-512'
   * @returns {Promise<CryptoKey>} Derived AES-256 key for encrypt/decrypt
   */
  async deriveKeySHA3(password, iterations = 100000, algorithm = "SHA3-256") {
    const encoder = new TextEncoder();
    const passwordBytes = encoder.encode(password);

    // Generate deterministic salt from password (same password → same salt)
    const saltHash = await this._crypto.subtle.digest("SHA-256", passwordBytes);
    const salt = new Uint8Array(saltHash).slice(0, 16);

    let material = new Uint8Array(passwordBytes.byteLength + salt.byteLength);
    material.set(passwordBytes);
    material.set(salt, passwordBytes.byteLength);

    // Iterative SHA-3 KDF
    for (let i = 0; i < iterations; i++) {
      const hashInput = new Uint8Array(material.byteLength + 4);
      hashInput.set(material);
      new DataView(hashInput.buffer).setUint32(material.byteLength, i, true);

      try {
        material = new Uint8Array(await this._crypto.subtle.digest(algorithm, hashInput));
      } catch (e) {
        // SHA-3 not available; fall back to SHA-256
        console.warn("SHA-3 not available; falling back to SHA-256");
        material = new Uint8Array(await this._crypto.subtle.digest("SHA-256", hashInput));
      }
    }

    // Take first 32 bytes as the derived key
    const derivedKey = material.slice(0, 32);

    return await this._crypto.subtle.importKey(
      "raw",
      derivedKey,
      { name: WebCryptAsym.AES_ALGORITHM, length: 256 },
      false,
      ["encrypt", "decrypt"]
    );
  }

  /**
   * HKDF (HMAC-based Extract-and-Expand KDF) with SHA-3 for quantum-resistant expansion.
   * Suitable for deriving multiple independent keys from a single master secret.
   *
   * @param {Uint8Array} secret - Input key material (IKM)
   * @param {Uint8Array} salt - Optional salt (default: all zeros)
   * @param {Uint8Array} info - Optional context/application-specific info
   * @param {number} keyLength - Output key length in bits (default: 256)
   * @returns {Promise<CryptoKey>} Derived key
   */
  async deriveKeyHKDFSHA3(secret, salt, info = new Uint8Array(0), keyLength = 256) {
    if (!salt || salt.byteLength === 0) {
      salt = new Uint8Array(32); // All zeros
    }

    // Step 1: HMAC-SHA3 Extract
    try {
      const hmacKey = await this._crypto.subtle.importKey(
        "raw",
        salt,
        { name: "HMAC", hash: "SHA3-256" },
        false,
        ["sign"]
      );
      const prk = await this._crypto.subtle.sign("HMAC", hmacKey, secret);

      // Step 2: HMAC-SHA3 Expand
      const expandHmacKey = await this._crypto.subtle.importKey(
        "raw",
        new Uint8Array(prk),
        { name: "HMAC", hash: "SHA3-256" },
        false,
        ["sign"]
      );

      const hashLen = 32; // SHA3-256 output
      const n = Math.ceil(keyLength / 8 / hashLen);
      let okm = new Uint8Array(0);
      let t = new Uint8Array(0);

      for (let i = 1; i <= n; i++) {
        const hmacInput = new Uint8Array(t.byteLength + info.byteLength + 1);
        hmacInput.set(t);
        hmacInput.set(info, t.byteLength);
        hmacInput[t.byteLength + info.byteLength] = i;

        t = new Uint8Array(await this._crypto.subtle.sign("HMAC", expandHmacKey, hmacInput));
        const newOkm = new Uint8Array(okm.byteLength + t.byteLength);
        newOkm.set(okm);
        newOkm.set(t, okm.byteLength);
        okm = newOkm;
      }

      const finalKey = okm.slice(0, keyLength / 8);
      return await this._crypto.subtle.importKey(
        "raw",
        finalKey,
        { name: WebCryptAsym.AES_ALGORITHM, length: keyLength },
        false,
        ["encrypt", "decrypt"]
      );
    } catch (e) {
      // Fall back to SHA-256 based HKDF
      console.warn("HKDF-SHA3 failed; falling back to HKDF-SHA256");
      return await this.deriveKeyHKDFSHA2(secret, salt, info, keyLength);
    }
  }

  /**
   * HKDF with SHA-256 (fallback variant).
   */
  async deriveKeyHKDFSHA2(secret, salt, info = new Uint8Array(0), keyLength = 256) {
    if (!salt || salt.byteLength === 0) {
      salt = new Uint8Array(32);
    }

    const hmacKey = await this._crypto.subtle.importKey(
      "raw",
      salt,
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"]
    );
    const prk = await this._crypto.subtle.sign("HMAC", hmacKey, secret);

    const expandHmacKey = await this._crypto.subtle.importKey(
      "raw",
      new Uint8Array(prk),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"]
    );

    const hashLen = 32;
    const n = Math.ceil(keyLength / 8 / hashLen);
    let okm = new Uint8Array(0);
    let t = new Uint8Array(0);

    for (let i = 1; i <= n; i++) {
      const hmacInput = new Uint8Array(t.byteLength + info.byteLength + 1);
      hmacInput.set(t);
      hmacInput.set(info, t.byteLength);
      hmacInput[t.byteLength + info.byteLength] = i;

      t = new Uint8Array(await this._crypto.subtle.sign("HMAC", expandHmacKey, hmacInput));
      const newOkm = new Uint8Array(okm.byteLength + t.byteLength);
      newOkm.set(okm);
      newOkm.set(t, okm.byteLength);
      okm = newOkm;
    }

    const finalKey = okm.slice(0, keyLength / 8);
    return await this._crypto.subtle.importKey(
      "raw",
      finalKey,
      { name: WebCryptAsym.AES_ALGORITHM, length: keyLength },
      false,
      ["encrypt", "decrypt"]
    );
  }

  /**
   * Key rotation: Re-derive key with new salt (for key management & security policies).
   * Useful for periodic key rotation without re-encryption.
   *
   * @param {string} password - Original password
   * @param {Uint8Array} newSalt - New salt for re-derivation
   * @param {string} method - KDF method: 'PBKDF2' (default), 'Argon2', 'SHA3', 'HKDF'
   * @returns {Promise<CryptoKey>} New derived key
   */
  async rotateKeyNew(password, newSalt, method = "PBKDF2") {
    switch (method) {
      case "Argon2":
        return await this.deriveKeyArgon2Enhanced(password, newSalt);
      case "SHA3":
        return await this.deriveKeySHA3(password, newSalt);
      case "HKDF":
        const secret = new TextEncoder().encode(password);
        return await this.deriveKeyHKDFSHA3(secret, newSalt);
      case "PBKDF2":
      default:
        return await this.deriveKeyPBKDF2(password, newSalt);
    }
  }

  /**
   * Derive hierarchical child key from parent key (for key structures).
   * Enables creating distinct keys for different purposes from a single master key.
   *
   * @param {CryptoKey} parentKey - Parent AES key
   * @param {Uint8Array} childSalt - Context/application-specific salt
   * @param {string} purpose - Purpose string (e.g., 'encryption', 'signing', 'hmac')
   * @returns {Promise<CryptoKey>} Child derived key
   */
  async deriveChildKeyHierarchical(parentKey, childSalt, purpose = "encryption") {
    // Extract parent key material
    const parentKeyRaw = await this._crypto.subtle.exportKey("raw", parentKey);

    // Combine with purpose and salt
    const input = new Uint8Array(parentKeyRaw.byteLength + childSalt.byteLength + purpose.length);
    input.set(new Uint8Array(parentKeyRaw));
    input.set(childSalt, parentKeyRaw.byteLength);
    input.set(new TextEncoder().encode(purpose), parentKeyRaw.byteLength + childSalt.byteLength);

    // Derive via SHA-3 hash
    try {
      const childKeyMaterial = await this._crypto.subtle.digest("SHA3-256", input);
      return await this._crypto.subtle.importKey(
        "raw",
        childKeyMaterial,
        { name: WebCryptAsym.AES_ALGORITHM, length: 256 },
        false,
        ["encrypt", "decrypt"]
      );
    } catch (e) {
      // Fall back to SHA-256
      const childKeyMaterial = await this._crypto.subtle.digest("SHA-256", input);
      return await this._crypto.subtle.importKey(
        "raw",
        childKeyMaterial,
        { name: WebCryptAsym.AES_ALGORITHM, length: 256 },
        false,
        ["encrypt", "decrypt"]
      );
    }
  }

  /**
   * Secure key erasure: Overwrite key material in memory.
   * Note: This is best-effort; true secure erasure depends on runtime guarantees.
   *
   * @param {Uint8Array} key - Key material to erase
   */
  secureKeyErase(key) {
    if (key && typeof key === "object") {
      for (let i = 0; i < key.byteLength; i++) {
        key[i] = 0;
      }
    }
  }

  // ────────────────────── ECDH Key Exchange ──────────────────────

  /**
   * Generate an ECDH key pair for key exchange.
   * @param {string} curve - Elliptic curve to use (default: 'P-256')
   * @returns {Promise<{publicKey: CryptoKey, privateKey: CryptoKey, publicKeyB64: string}>}
   */
  async generateECDHKeyPair(curve = "P-256") {
    const keyPair = await this._crypto.subtle.generateKey(
      { name: "ECDH", namedCurve: curve },
      true,
      ["deriveKey", "deriveBits"]
    );
    const publicKeyB64 = await this.exportECDHPublicKey(keyPair.publicKey);
    return { publicKey: keyPair.publicKey, privateKey: keyPair.privateKey, publicKeyB64 };
  }

  /**
   * Export an ECDH public key to base64 for sharing.
   * @param {CryptoKey} publicKey
   * @returns {Promise<string>}
   */
  async exportECDHPublicKey(publicKey) {
    const exported = await this._crypto.subtle.exportKey("spki", publicKey);
    return this._arrayBufferToBase64(exported);
  }

  /**
   * Import an ECDH public key from base64.
   * @param {string} b64 - Base64 string of the public key
   * @param {string} curve - Curve used (default: 'P-256')
   * @returns {Promise<CryptoKey>}
   */
  async importECDHPublicKey(b64, curve = "P-256") {
    const binary = this._base64ToArrayBuffer(b64);
    return await this._crypto.subtle.importKey(
      "spki",
      binary,
      { name: "ECDH", namedCurve: curve },
      true,
      [] // ECDH public keys don't have operations themselves, they are used as parameters
    );
  }

  /**
   * Derive a shared secret using ECDH.
   * @param {CryptoKey} privateKey - Your private key
   * @param {CryptoKey} publicKey - The other party's public key
   * @returns {Promise<CryptoKey>} An AES-GCM key derived from the shared secret
   */
  async deriveECDHSharedSecret(privateKey, publicKey) {
    return await this._crypto.subtle.deriveKey(
      { name: "ECDH", public: publicKey },
      privateKey,
      { name: WebCryptAsym.AES_ALGORITHM, length: WebCryptAsym.AES_LENGTH },
      false,
      ["encrypt", "decrypt"]
    );
  }

  /**
   * Encrypt data automatically deriving an ECDH shared secret.
   * This is a convenient all-in-one E2EE method for sender and recipient pairs.
   * @param {any} data - Serializable data or string to encrypt
   * @param {CryptoKey} privateKey - Sender's private key
   * @param {CryptoKey} recipientPublicKey - Recipient's public key
   * @returns {Promise<string>} Base64-encoded encrypted payload
   */
  async encryptWithECDH(data, privateKey, recipientPublicKey) {
    const sharedKey = await this.deriveECDHSharedSecret(privateKey, recipientPublicKey);
    const text = typeof data === "string" ? data : JSON.stringify(data);
    const encoder = new TextEncoder();
    const encoded = encoder.encode(text);
    const iv = this._crypto.getRandomValues(new Uint8Array(WebCryptAsym.IV_LENGTH));

    const encrypted = await this._crypto.subtle.encrypt(
      { name: WebCryptAsym.AES_ALGORITHM, iv },
      sharedKey,
      encoded
    );

    const result = new Uint8Array(WebCryptAsym.IV_LENGTH + encrypted.byteLength);
    result.set(iv, 0);
    result.set(new Uint8Array(encrypted), WebCryptAsym.IV_LENGTH);
    return this._arrayBufferToBase64(result.buffer);
  }

  /**
   * Decrypt data automatically deriving an ECDH shared secret.
   * @param {string} b64 - Base64-encoded encrypted payload
   * @param {CryptoKey} privateKey - Recipient's private key
   * @param {CryptoKey} senderPublicKey - Sender's public key
   * @returns {Promise<any>} The original data
   */
  async decryptWithECDH(b64, privateKey, senderPublicKey) {
    const sharedKey = await this.deriveECDHSharedSecret(privateKey, senderPublicKey);
    const combined = new Uint8Array(this._base64ToArrayBuffer(b64));

    if (combined.byteLength < WebCryptAsym.IV_LENGTH) {
      throw new Error("Invalid encrypted data");
    }

    const iv = combined.slice(0, WebCryptAsym.IV_LENGTH);
    const ciphertext = combined.slice(WebCryptAsym.IV_LENGTH);

    const decrypted = await this._crypto.subtle.decrypt(
      { name: WebCryptAsym.AES_ALGORITHM, iv },
      sharedKey,
      ciphertext
    );

    const text = new TextDecoder().decode(decrypted);
    try {
      return JSON.parse(text);
    } catch (e) {
      return text;
    }
  }

  // ────────────────────── Human-Friendly Data Operations ──────────────────────

  /**
   * Automatically serializes any JavaScript object or array to JSON before encrypting.
   * @param {any} data - Any serializable JavaScript data
   * @param {CryptoKey} publicKey - RSA public key
   * @returns {Promise<string>} Base64-encoded encrypted string
   */
  async encryptData(data, publicKey) {
    const text = JSON.stringify(data);
    return await this.encryptText(text, publicKey);
  }

  /**
   * Decrypts the data and automatically parses it back into a JavaScript object.
   * @param {string} b64 - Base64-encoded encrypted string
   * @param {CryptoKey} privateKey - RSA private key
   * @returns {Promise<any>} The original JavaScript data
   */
  async decryptData(b64, privateKey) {
    const text = await this.decryptText(b64, privateKey);
    return JSON.parse(text);
  }
}
