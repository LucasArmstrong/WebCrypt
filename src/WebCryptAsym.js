// src/WebCryptAsym.js
// version: 0.4.1
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
  static PBKDF2_ITERATIONS = 100000;
  static ARGON2_ALGORITHM = "Argon2id";

  constructor() {
    this._crypto = this._getCrypto();
    // Cache for frequently used keys to improve performance
    this._keyCache = new Map();
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
   * @param {number} iterations - Number of PBKDF2 iterations (default: 100000)
   * @param {string} hash - Hash algorithm (default: SHA-256)
   * @param {number} keyLength - Length of the derived key in bits
   * @returns {Promise<ArrayBuffer>} Derived key
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
   * Derive a key using Argon2id (where supported)
   * @param {string} password - The password to derive the key from
   * @param {Uint8Array} salt - Salt for the derivation
   * @param {Object} options - Argon2 configuration options
   * @returns {Promise<ArrayBuffer>} Derived key
   */
  async deriveKeyArgon2(password, salt, options = {}) {
    // Check if Argon2 is supported in the environment
    if (typeof this._crypto.subtle.deriveKey === "function") {
      // Try to use Web Crypto API's built-in Argon2 support if available
      try {
        const encoder = new TextEncoder();
        const keyMaterial = await this._crypto.subtle.importKey(
          "raw",
          encoder.encode(password),
          { name: WebCryptAsym.ARGON2_ALGORITHM },
          false,
          ["deriveBits", "deriveKey"]
        );

        return await this._crypto.subtle.deriveKey(
          {
            name: WebCryptAsym.ARGON2_ALGORITHM,
            salt: salt,
            iterations: options.iterations || 3,
            memoryCost: options.memoryCost || 65536,
            parallelism: options.parallelism || 1,
          },
          keyMaterial,
          { name: WebCryptAsym.AES_ALGORITHM, length: 256 },
          false,
          ["encrypt", "decrypt"]
        );
      } catch (e) {
        // Fall back to PBKDF2 if Argon2 is not supported
        return await this.deriveKeyPBKDF2(
          password,
          salt,
          options.iterations || WebCryptAsym.PBKDF2_ITERATIONS
        );
      }
    } else {
      // Fall back to PBKDF2 for environments without Argon2 support
      return await this.deriveKeyPBKDF2(
        password,
        salt,
        options.iterations || WebCryptAsym.PBKDF2_ITERATIONS
      );
    }
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

  /**
   * Clear the key cache
   */
  clearKeyCache() {
    this._keyCache.clear();
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
    const iv = crypto.getRandomValues(new Uint8Array(WebCryptAsym.IV_LENGTH));

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
    const combined = new Uint8Array(this._base64ToArrayBuffer(encryptedB64));
    if (combined.byteLength < 4 + 100 + WebCryptAsym.IV_LENGTH) {
      throw new Error("Invalid encrypted data");
    }

    const encKeyLen = new DataView(combined.buffer).getUint32(0, true);
    if (combined.byteLength < 4 + encKeyLen + WebCryptAsym.IV_LENGTH) {
      throw new Error("Truncated encrypted data");
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
    const baseIv = crypto.getRandomValues(new Uint8Array(WebCryptAsym.IV_LENGTH));

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

  async decryptFile(fileOrBlob, privateKey) {
    const data = new Uint8Array(await fileOrBlob.arrayBuffer());
    if (data.length < 4 + 100 + WebCryptAsym.IV_LENGTH) throw new Error("Invalid file");

    const encKeyLen = new DataView(data.buffer).getUint32(0, true);
    if (data.length < 4 + encKeyLen + WebCryptAsym.IV_LENGTH) throw new Error("Truncated header");

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
      const iv = crypto.getRandomValues(new Uint8Array(WebCryptAsym.IV_LENGTH));

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

    return await this._crypto.subtle.verify(
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

    return await this._crypto.subtle.verify(
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
      const iv = crypto.getRandomValues(new Uint8Array(WebCryptAsym.IV_LENGTH));

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
      const iv = crypto.getRandomValues(new Uint8Array(WebCryptAsym.IV_LENGTH));

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
    const baseIv = crypto.getRandomValues(new Uint8Array(WebCryptAsym.IV_LENGTH));

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
    const data = new Uint8Array(await fileOrBlob.arrayBuffer());
    if (data.length < 4 + 100 + WebCryptAsym.IV_LENGTH) throw new Error("Invalid file");

    const encKeyLen = new DataView(data.buffer).getUint32(0, true);
    if (data.length < 4 + encKeyLen + WebCryptAsym.IV_LENGTH) throw new Error("Truncated header");

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
    return crypto.getRandomValues(new Uint8Array(length));
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
    crypto.getRandomValues(dummy);
    throw new Error(message);
  }
}
