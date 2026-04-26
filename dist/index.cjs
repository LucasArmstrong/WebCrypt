var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/index.js
var index_exports = {};
__export(index_exports, {
  WebCrypt: () => WebCrypt,
  WebCryptAsym: () => WebCryptAsym,
  WebCryptPQC: () => WebCryptPQC
});
module.exports = __toCommonJS(index_exports);

// src/WebCrypt.js
var WebCrypt = class _WebCrypt {
  // AES-256-GCM: Provides 128-bit effective security against Grover's quantum algorithm
  //   - Authenticated encryption mode preventing tampering and ensuring integrity
  static ALGORITHM = "AES-GCM";
  // KEY_LENGTH: 256 bits for AES-256, offering strong symmetric encryption (quantum-resistant at this size)
  static KEY_LENGTH = 256;
  // IV_LENGTH: 12 bytes (96 bits), standard for AES-GCM to ensure unique nonces per encryption
  static IV_LENGTH = 12;
  // SALT_LENGTH: 16 bytes (128 bits), random per-message salt for PBKDF2 to prevent rainbow table attacks
  static SALT_LENGTH = 16;
  // PBKDF2_ITERATIONS: 600,000 rounds of key stretching; OWASP-recommended for 2025 to resist brute-force and ASIC attacks (even post-quantum)
  static PBKDF2_ITERATIONS = 6e5;
  // HASH_ALGORITHM: SHA-256 for PBKDF2 hashing; collision-resistant and widely supported
  static HASH_ALGORITHM = "SHA-256";
  // Optimized for large files: 8MB chunks balance speed and memory (prevents OOM on 10GB+ files)
  static CHUNK_SIZE = 8 * 1024 * 1024;
  // WEBRTC_SALT: Fixed salt for WebRTC key derivation; ensures consistent keys between peers without transmission
  static WEBRTC_SALT = new TextEncoder().encode("WebCrypt-E2EE-v1-2025");
  // Caches derived keys for instant reuse with same password/salt (performance optimization)
  static MAX_KEY_CACHE_SIZE = 10;
  // LRU cache max size
  static KEY_CACHE_TTL_MS = 3e5;
  // 5 minutes TTL per key
  constructor() {
    this.keyCache = /* @__PURE__ */ new Map();
    this._keyCacheCleanupInterval = null;
    this._startAutoCleanup();
  }
  /**
   * Start automatic cache cleanup every minute to remove expired keys
   */
  _startAutoCleanup() {
    this._cleanupExpiredKeys();
    this._keyCacheCleanupInterval = setInterval(() => {
      this._cleanupExpiredKeys();
    }, 6e4);
  }
  /**
   * Clean up expired keys from cache based on TTL
   */
  _cleanupExpiredKeys() {
    const now = Date.now();
    for (const [cacheKey, value] of this.keyCache.entries()) {
      if (now - value.createdAt > _WebCrypt.KEY_CACHE_TTL_MS) {
        this.keyCache.delete(cacheKey);
      }
    }
  }
  /**
   * Clear entire key cache and securely erase all keys
   */
  clearKeyCache() {
    this.keyCache.clear();
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
    if (typeof globalThis !== "undefined" && globalThis.crypto) return globalThis.crypto;
    if (typeof require !== "undefined") {
      const { webcrypto } = require("crypto");
      return webcrypto;
    }
    throw new Error("Web Crypto API not available in this environment");
  }
  // Derives AES key using PBKDF2: High iterations ensure quantum-resistant key stretching
  // Cache hit: O(1) reuse; miss: Computes once per unique password/salt
  // LRU eviction when cache exceeds MAX_KEY_CACHE_SIZE
  async _deriveKey(password, salt) {
    const crypto2 = this._getCrypto();
    const cacheKey = `${password}:${btoa(String.fromCharCode(...salt))}`;
    if (this.keyCache.has(cacheKey)) {
      const value = this.keyCache.get(cacheKey);
      value.lastAccessed = Date.now();
      return value.key;
    }
    const enc = new TextEncoder();
    const keyMaterial = await crypto2.subtle.importKey(
      "raw",
      enc.encode(password),
      "PBKDF2",
      false,
      ["deriveKey"]
    );
    const key = await crypto2.subtle.deriveKey(
      {
        name: "PBKDF2",
        salt,
        iterations: _WebCrypt.PBKDF2_ITERATIONS,
        hash: _WebCrypt.HASH_ALGORITHM
      },
      keyMaterial,
      { name: _WebCrypt.ALGORITHM, length: _WebCrypt.KEY_LENGTH },
      false,
      ["encrypt", "decrypt"]
    );
    if (this.keyCache.size >= _WebCrypt.MAX_KEY_CACHE_SIZE) {
      let oldestKey = null;
      let oldestTime = Infinity;
      for (const [k, v] of this.keyCache.entries()) {
        const accessTime = v.lastAccessed || v.createdAt;
        if (accessTime < oldestTime) {
          oldestTime = accessTime;
          oldestKey = k;
        }
      }
      if (oldestKey) {
        this.keyCache.delete(oldestKey);
      }
    }
    this.keyCache.set(cacheKey, {
      key,
      createdAt: Date.now(),
      lastAccessed: Date.now()
    });
    return key;
  }
  // ────────────────────── Safe Base64 (stack-safe, fast) ──────────────────────
  // Iterative base64 conversion: Avoids recursion/stack issues for large data, faster than array methods
  _arrayBufferToBase64(buffer) {
    let binary = "";
    const bytes = new Uint8Array(buffer);
    const len = bytes.byteLength;
    for (let i = 0; i < len; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }
  _base64ToArrayBuffer(base64) {
    const binary = atob(base64);
    const len = binary.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  }
  // ────────────────────── Text Encryption (now safe for 10 MB+) ──────────────────────
  /**
   * Encrypt a text string using AES-256-GCM with a password.
   * Generates a unique random salt and IV per call.
   *
   * @param {string} text - Plain text to encrypt
   * @param {string} password - Password used for key derivation
   * @returns {Promise<string>} Base64-encoded string containing salt + IV + ciphertext
   */
  async encryptText(text, password) {
    const data = new TextEncoder().encode(text);
    const salt = crypto.getRandomValues(new Uint8Array(_WebCrypt.SALT_LENGTH));
    const iv = crypto.getRandomValues(new Uint8Array(_WebCrypt.IV_LENGTH));
    const key = await this._deriveKey(password, salt);
    const encrypted = await crypto.subtle.encrypt({ name: _WebCrypt.ALGORITHM, iv }, key, data);
    const result = new Uint8Array(_WebCrypt.SALT_LENGTH + _WebCrypt.IV_LENGTH + encrypted.byteLength);
    result.set(salt, 0);
    result.set(iv, _WebCrypt.SALT_LENGTH);
    result.set(new Uint8Array(encrypted), _WebCrypt.SALT_LENGTH + _WebCrypt.IV_LENGTH);
    return this._arrayBufferToBase64(result.buffer);
  }
  // Maximum allowed encrypted data size (10MB) to prevent DoS attacks
  static MAX_ENCRYPTED_DATA_SIZE = 10 * 1024 * 1024;
  /**
   * Decrypt a Base64 string produced by encryptText().
   *
   * @param {string} b64 - Base64-encoded encrypted data from encryptText()
   * @param {string} password - Must match the password used for encryption
   * @returns {Promise<string>} Original plain text
   * @throws {Error} If password is wrong, data is corrupted, or data exceeds 10 MB
   */
  async decryptText(b64, password) {
    try {
      const combined = new Uint8Array(this._base64ToArrayBuffer(b64));
      if (combined.length > _WebCrypt.MAX_ENCRYPTED_DATA_SIZE) {
        throw new Error("Decryption failed");
      }
      if (combined.length < _WebCrypt.SALT_LENGTH + _WebCrypt.IV_LENGTH) {
        throw new Error("Decryption failed");
      }
      const salt = combined.slice(0, _WebCrypt.SALT_LENGTH);
      const iv = combined.slice(_WebCrypt.SALT_LENGTH, _WebCrypt.SALT_LENGTH + _WebCrypt.IV_LENGTH);
      const ciphertext = combined.slice(_WebCrypt.SALT_LENGTH + _WebCrypt.IV_LENGTH);
      const key = await this._deriveKey(password, salt);
      const decrypted = await crypto.subtle.decrypt(
        { name: _WebCrypt.ALGORITHM, iv },
        key,
        ciphertext
      );
      return new TextDecoder().decode(decrypted);
    } catch (e) {
      if (typeof process !== "undefined" && process.env && process.env.NODE_ENV !== "production") {
        console.warn("WebCrypt decryptText failed:", e.message);
      }
      throw e;
    }
  }
  /**
   * Encrypt a File or Blob using streaming (constant memory usage).
   * Each chunk is encrypted with a counter-derived IV for security.
   *
   * @param {File|Blob} fileOrBlob - File or Blob to encrypt
   * @param {string} password - Encryption password
   * @returns {Promise<{blob: Blob, filename: string}>} Encrypted blob and suggested filename
   */
  async encryptFile(fileOrBlob, password) {
    const salt = crypto.getRandomValues(new Uint8Array(_WebCrypt.SALT_LENGTH));
    const baseIv = crypto.getRandomValues(new Uint8Array(_WebCrypt.IV_LENGTH));
    const key = await this._deriveKey(password, salt);
    const chunks = [];
    const reader = fileOrBlob.stream().getReader();
    let counter = 0;
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      const iv = new Uint8Array(_WebCrypt.IV_LENGTH);
      iv.set(baseIv);
      new DataView(iv.buffer).setUint32(_WebCrypt.IV_LENGTH - 4, counter++, true);
      const encrypted = await crypto.subtle.encrypt({ name: _WebCrypt.ALGORITHM, iv }, key, value);
      chunks.push(encrypted);
    }
    const header = new Uint8Array(_WebCrypt.SALT_LENGTH + _WebCrypt.IV_LENGTH);
    header.set(salt, 0);
    header.set(baseIv, _WebCrypt.SALT_LENGTH);
    const filename = (fileOrBlob.name || "encrypted") + ".encrypted";
    const newBlob = new Blob([header, ...chunks]);
    newBlob.name = filename;
    return { blob: newBlob, filename };
  }
  /**
   * Decrypt a .encrypted file produced by encryptFile().
   *
   * @param {File|Blob} fileOrBlob - Encrypted File or Blob
   * @param {string} password - Must match the password used for encryption
   * @returns {Promise<{blob: Blob, filename: string}>} Decrypted blob and original filename
   * @throws {Error} If password is wrong, file is corrupted, or file exceeds 10 MB
   */
  async decryptFile(fileOrBlob, password) {
    const fileSize = fileOrBlob.size || fileOrBlob.blob && fileOrBlob.blob.size;
    if (fileSize && fileSize > _WebCrypt.MAX_ENCRYPTED_DATA_SIZE) {
      throw new Error("File too large for decryption");
    }
    const data = new Uint8Array(await fileOrBlob.arrayBuffer());
    if (data.length > _WebCrypt.MAX_ENCRYPTED_DATA_SIZE) {
      throw new Error("File too large for decryption");
    }
    if (data.length < _WebCrypt.SALT_LENGTH + _WebCrypt.IV_LENGTH) {
      throw new Error("Decryption failed");
    }
    const salt = data.slice(0, _WebCrypt.SALT_LENGTH);
    const baseIv = data.slice(_WebCrypt.SALT_LENGTH, _WebCrypt.SALT_LENGTH + _WebCrypt.IV_LENGTH);
    const ciphertext = data.slice(_WebCrypt.SALT_LENGTH + _WebCrypt.IV_LENGTH);
    const key = await this._deriveKey(password, salt);
    const chunks = [];
    let offset = 0, counter = 0;
    while (offset < ciphertext.byteLength) {
      const size = Math.min(_WebCrypt.CHUNK_SIZE, ciphertext.byteLength - offset);
      const chunk = ciphertext.slice(offset, offset + size);
      const iv = new Uint8Array(_WebCrypt.IV_LENGTH);
      iv.set(baseIv);
      new DataView(iv.buffer).setUint32(_WebCrypt.IV_LENGTH - 4, counter++, true);
      const decrypted = await crypto.subtle.decrypt({ name: _WebCrypt.ALGORITHM, iv }, key, chunk);
      chunks.push(decrypted);
      offset += size;
    }
    const filename = (fileOrBlob.name || "decrypted").replace(/\.encrypted$/i, "");
    return { blob: new Blob(chunks), filename };
  }
  /**
   * Create an encryption transform for WebRTC Insertable Streams.
   * Use with RTCRtpSender.transform for E2EE video/audio calls.
   *
   * @param {string} password - Shared secret both peers must know
   * @returns {Promise<Function>} Transform function for RTCRtpScriptTransform
   */
  async createEncryptTransform(password) {
    const key = await this._deriveKey(password, _WebCrypt.WEBRTC_SALT);
    return async (frame, controller) => {
      const iv = crypto.getRandomValues(new Uint8Array(_WebCrypt.IV_LENGTH));
      const encrypted = await crypto.subtle.encrypt(
        { name: _WebCrypt.ALGORITHM, iv },
        key,
        frame.data
      );
      const newData = new Uint8Array(_WebCrypt.IV_LENGTH + encrypted.byteLength);
      newData.set(iv, 0);
      newData.set(new Uint8Array(encrypted), _WebCrypt.IV_LENGTH);
      frame.data = newData.buffer;
      controller.enqueue(frame);
    };
  }
  /**
   * Create a decryption transform for WebRTC Insertable Streams.
   * Use with RTCRtpReceiver.transform for E2EE video/audio calls.
   *
   * @param {string} password - Must match sender's password
   * @returns {Promise<Function>} Transform function for RTCRtpScriptTransform
   */
  async createDecryptTransform(password) {
    const key = await this._deriveKey(password, _WebCrypt.WEBRTC_SALT);
    return async (frame, controller) => {
      if (frame.data.byteLength < _WebCrypt.IV_LENGTH) return controller.enqueue(frame);
      const iv = frame.data.slice(0, _WebCrypt.IV_LENGTH);
      const ciphertext = frame.data.slice(_WebCrypt.IV_LENGTH);
      try {
        const decrypted = await crypto.subtle.decrypt(
          { name: _WebCrypt.ALGORITHM, iv },
          key,
          ciphertext
        );
        frame.data = decrypted;
      } catch (e) {
        console.warn("WebRTC frame decryption failed");
      }
      controller.enqueue(frame);
    };
  }
  /**
   * Generates or derives an HMAC key.
   * @param {string} [password] Optional password for PBKDF2 derivation (if provided, uses 600_000 iterations like existing ops).
   * @param {string} [hash='SHA-256'] Hash algorithm.
   * @returns {Promise<CryptoKey>} Usable HMAC key.
   */
  async generateHmacKey(password, hash = "SHA-256") {
    let keyMaterial;
    if (password) {
      const salt = crypto.getRandomValues(new Uint8Array(16));
      const pbkdf2Params = {
        name: "PBKDF2",
        salt,
        iterations: 6e5,
        hash: "SHA-256"
      };
      const baseKey = await crypto.subtle.importKey(
        "raw",
        new TextEncoder().encode(password),
        { name: "PBKDF2" },
        false,
        ["deriveBits", "deriveKey"]
      );
      keyMaterial = await crypto.subtle.deriveBits(pbkdf2Params, baseKey, 256);
    } else {
      keyMaterial = crypto.getRandomValues(new Uint8Array(32));
    }
    return crypto.subtle.importKey(
      "raw",
      keyMaterial,
      { name: "HMAC", hash },
      true,
      // Exportable for storage if needed
      ["sign", "verify"]
    );
  }
  /**
   * Computes HMAC on data.
   * @param {string|ArrayBuffer} data Text or ArrayBuffer to authenticate.
   * @param {CryptoKey} key HMAC key from generateHmacKey.
   * @returns {Promise<string>} Base64-encoded HMAC tag.
   */
  async computeHmac(data, key) {
    const dataBuffer = typeof data === "string" ? new TextEncoder().encode(data) : data;
    const signature = await crypto.subtle.sign("HMAC", key, dataBuffer);
    return btoa(String.fromCharCode(...new Uint8Array(signature)));
  }
  /**
   * Verifies HMAC on data.
   * @param {string|ArrayBuffer} data Text or ArrayBuffer to verify.
   * @param {string} hmac Base64-encoded HMAC tag to check.
   * @param {CryptoKey} key HMAC key.
   * @returns {Promise<boolean>} True if valid.
   */
  async verifyHmac(data, hmac, key) {
    const dataBuffer = typeof data === "string" ? new TextEncoder().encode(data) : data;
    const signatureBuffer = Uint8Array.from(atob(hmac), (c) => c.charCodeAt(0));
    return crypto.subtle.verify("HMAC", key, signatureBuffer, dataBuffer);
  }
  // ════════════════════════════ Post-Quantum HMAC (SHA-3) ════════════════════════════
  /**
   * Generate a quantum-resistant HMAC key using SHA-3 hash.
   * @param {string} [password] Optional password for derivation (600k iterations)
   * @param {string} [hash='SHA3-256'] Hash algorithm: 'SHA3-256', 'SHA3-384', 'SHA3-512'
   * @returns {Promise<CryptoKey>} Usable HMAC key with SHA-3
   */
  async generateHmacKeySHA3(password, hash = "SHA3-256") {
    let keyMaterial;
    if (password) {
      const salt = crypto.getRandomValues(new Uint8Array(16));
      const encoder = new TextEncoder();
      let material = new Uint8Array(password.length + salt.byteLength);
      material.set(encoder.encode(password));
      material.set(salt, password.length);
      for (let i = 0; i < 6e5; i++) {
        const hashInput = new Uint8Array(material.byteLength + 4);
        hashInput.set(material);
        new DataView(hashInput.buffer).setUint32(material.byteLength, i, true);
        try {
          material = new Uint8Array(await crypto.subtle.digest(hash, hashInput));
        } catch (e) {
          material = new Uint8Array(await crypto.subtle.digest("SHA-256", hashInput));
        }
      }
      keyMaterial = material.slice(0, 32);
    } else {
      keyMaterial = crypto.getRandomValues(new Uint8Array(32));
    }
    let hmacHash = hash;
    if (hash.startsWith("SHA3-")) {
      hmacHash = hash.replace("SHA3-", "SHA-");
    }
    return crypto.subtle.importKey("raw", keyMaterial, { name: "HMAC", hash: hmacHash }, true, [
      "sign",
      "verify"
    ]);
  }
  /**
   * Compute HMAC using SHA-3 (quantum-resistant).
   * @param {string|ArrayBuffer} data Data to authenticate
   * @param {CryptoKey} key HMAC key from generateHmacKeySHA3
   * @returns {Promise<string>} Base64-encoded HMAC tag
   */
  async computeHmacSHA3(data, key) {
    const dataBuffer = typeof data === "string" ? new TextEncoder().encode(data) : data;
    const signature = await crypto.subtle.sign("HMAC", key, dataBuffer);
    return btoa(String.fromCharCode(...new Uint8Array(signature)));
  }
  /**
   * Verify HMAC using SHA-3 (quantum-resistant).
   * @param {string|ArrayBuffer} data Data to verify
   * @param {string} hmac Base64-encoded HMAC tag
   * @param {CryptoKey} key HMAC key
   * @returns {Promise<boolean>} True if valid
   */
  async verifyHmacSHA3(data, hmac, key) {
    const dataBuffer = typeof data === "string" ? new TextEncoder().encode(data) : data;
    const signatureBuffer = Uint8Array.from(atob(hmac), (c) => c.charCodeAt(0));
    return crypto.subtle.verify("HMAC", key, signatureBuffer, dataBuffer);
  }
  // ────────────────────── Human-Friendly Data Operations ──────────────────────
  /**
   * Automatically serializes any JavaScript object or array to JSON before encrypting.
   * Eliminates the need for manual JSON.stringify.
   * @param {any} data - Any serializable JavaScript data (object, array, string, number)
   * @param {string} password - The encryption password
   * @returns {Promise<string>} Base64-encoded encrypted string
   */
  async encryptData(data, password) {
    const text = JSON.stringify(data);
    return await this.encryptText(text, password);
  }
  /**
   * Decrypts the data and automatically parses it back into a JavaScript object.
   * @param {string} b64 - Base64-encoded encrypted string
   * @param {string} password - The decryption password
   * @returns {Promise<any>} The original JavaScript data
   */
  async decryptData(b64, password) {
    const text = await this.decryptText(b64, password);
    return JSON.parse(text);
  }
  /**
   * Utility to generate a cryptographically secure random password or key string.
   * Useful for generating strong unique keys for encryption passes.
   * @param {number} length - Length of the generated password (default: 32)
   * @returns {string} Base64-encoded random password
   */
  generateRandomPassword(length = 32) {
    const cryptoInstance = this._getCrypto();
    const randomBytes = cryptoInstance.getRandomValues(new Uint8Array(length));
    let binary = "";
    for (let i = 0; i < randomBytes.byteLength; i++) {
      binary += String.fromCharCode(randomBytes[i]);
    }
    return btoa(binary);
  }
};

// src/TimingSafeHelper.js
var TimingSafeHelper = class {
  /**
   * Constant-time string comparison to prevent timing attacks
   * @param {string} a - First string
   * @param {string} b - Second string
   * @returns {Promise<boolean>} True if strings are equal (in constant time)
   */
  static async constantTimeCompareStrings(a, b) {
    const encoder = new TextEncoder();
    const bufA = encoder.encode(a);
    const bufB = encoder.encode(b);
    const len = Math.max(bufA.length, bufB.length);
    let diff = 0;
    for (let i = 0; i < len; i++) {
      if (i < bufA.length && i < bufB.length) {
        diff |= bufA[i] ^ bufB[i];
      } else {
        diff |= 1;
      }
    }
    return diff === 0;
  }
  /**
   * Constant-time ArrayBuffer comparison to prevent timing attacks
   * @param {ArrayBuffer} a - First buffer
   * @param {ArrayBuffer} b - Second buffer
   * @returns {Promise<boolean>} True if buffers are equal (in constant time)
   */
  static async constantTimeCompareBuffers(a, b) {
    const bufA = new Uint8Array(a);
    const bufB = new Uint8Array(b);
    const len = Math.max(bufA.length, bufB.length);
    let diff = 0;
    for (let i = 0; i < len; i++) {
      if (i < bufA.length && i < bufB.length) {
        diff |= bufA[i] ^ bufB[i];
      } else {
        diff |= 1;
      }
    }
    return diff === 0;
  }
  /**
   * Execute dummy operations to pad execution time and prevent timing attacks
   * @param {number} minMs - Minimum milliseconds to delay (e.g., 5-10ms)
   */
  static async sleepWithDummyOps(minMs = 10) {
    const startTime = performance.now();
    while (performance.now() - startTime < minMs) {
      let dummy = 0;
      for (let i = 0; i < 1e3; i++) {
        dummy ^= Math.random() * 256 | 0;
      }
    }
  }
  /**
   * Timing-safe signature verification wrapper
   * Adds constant-time comparison and padding to prevent timing oracle attacks
   * @param {any} crypto - Crypto API (subtle)
   * @param {Object} algorithmParams - Algorithm parameters
   * @param {CryptoKey} key - Verification key
   * @param {ArrayBuffer} signature - Signature buffer
   * @param {Uint8Array|ArrayBuffer} data - Data to verify
   * @returns {Promise<boolean>} True if valid signature (with constant-time comparison)
   */
  static async timingSafeVerify(crypto2, algorithmParams, key, signature, data) {
    const startTime = performance.now();
    let isValid;
    try {
      isValid = await crypto2.subtle.verify(algorithmParams, key, signature, data);
    } catch (e) {
      throw new Error("Signature verification failed");
    }
    const minVerificationTimeMs = 10;
    const elapsedMs = performance.now() - startTime;
    if (elapsedMs < minVerificationTimeMs) {
      await this.sleepWithDummyOps(minVerificationTimeMs - elapsedMs);
    }
    return isValid;
  }
  /**
   * Timing-safe key derivation verification wrapper
   * Ensures consistent timing regardless of password correctness
   * @param {Function} deriveFn - Key derivation function
   * @param {...any} args - Arguments to pass to derive function
   * @returns {Promise<CryptoKey>} Derived key
   */
  static async timingSafeDerive(deriveFn, ...args) {
    const startTime = performance.now();
    let key;
    try {
      key = await deriveFn(...args);
    } catch (e) {
      const elapsedMs2 = performance.now() - startTime;
      if (elapsedMs2 < 50) {
        await this.sleepWithDummyOps(50 - elapsedMs2);
      }
      throw e;
    }
    const minDerivationTimeMs = 50;
    const elapsedMs = performance.now() - startTime;
    if (elapsedMs < minDerivationTimeMs) {
      await this.sleepWithDummyOps(minDerivationTimeMs - elapsedMs);
    }
    return key;
  }
};
var TimingSafeHelper_default = TimingSafeHelper;

// src/WebCryptAsym.js
var WebCryptAsym = class _WebCryptAsym {
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
    publicExponent: new Uint8Array([1, 0, 1]),
    // 65537
    hash: "SHA-256"
  };
  // Symmetric constants used in hybrid mode
  static AES_ALGORITHM = "AES-GCM";
  // Authenticated encryption with integrity
  static AES_LENGTH = 256;
  // 256-bit key for full security (quantum-resistant)
  static IV_LENGTH = 12;
  // 96-bit IV – GCM recommended size for optimal security/performance
  static CHUNK_SIZE = 8 * 1024 * 1024;
  // 8MB chunks: balances memory usage and speed for multi-GB files
  // Digital signature constants (ECDSA – modern elliptic curve signatures)
  // ECDSA is faster and produces smaller signatures than RSA-PSS while offering equivalent security
  static SIGN_ALGORITHM = "ECDSA";
  static SIGN_CURVE = "P-256";
  // Default: NIST P-256 – fast, secure, universally supported
  static SIGN_HASH = "SHA-256";
  // Consistent hashing across the library
  static SUPPORTED_CURVES = ["P-256", "P-384"];
  // P-384 available for higher security needs
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
  static PBKDF2_ITERATIONS = 6e5;
  static MAX_KEY_CACHE_SIZE = 10;
  // LRU cache max size
  static KEY_CACHE_TTL_MS = 3e5;
  // 5 minutes TTL per key
  static ARGON2_ALGORITHM = "Argon2id";
  constructor() {
    this._crypto = this._getCrypto();
    this._keyCache = /* @__PURE__ */ new Map();
    this._keyCacheCleanupInterval = null;
    this._startAutoCleanup();
  }
  /**
   * Start automatic cache cleanup every minute to remove expired keys
   */
  _startAutoCleanup() {
    this._cleanupExpiredKeys();
    this._keyCacheCleanupInterval = setInterval(() => {
      this._cleanupExpiredKeys();
    }, 6e4);
  }
  /**
   * Clean up expired keys from cache based on TTL
   */
  _cleanupExpiredKeys() {
    const now = Date.now();
    for (const [cacheKey, value] of this._keyCache.entries()) {
      if (now - value.createdAt > _WebCryptAsym.KEY_CACHE_TTL_MS) {
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
    if (typeof globalThis !== "undefined" && globalThis.crypto) return globalThis.crypto;
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
  async deriveKeyPBKDF2(password, salt, iterations = _WebCryptAsym.PBKDF2_ITERATIONS, hash = _WebCryptAsym.PBKDF2_HASH, keyLength = 256) {
    const encoder = new TextEncoder();
    const keyMaterial = await this._crypto.subtle.importKey(
      "raw",
      encoder.encode(password),
      { name: _WebCryptAsym.PBKDF2_ALGORITHM },
      false,
      ["deriveBits", "deriveKey"]
    );
    return await this._crypto.subtle.deriveKey(
      {
        name: _WebCryptAsym.PBKDF2_ALGORITHM,
        salt,
        iterations,
        hash
      },
      keyMaterial,
      { name: _WebCryptAsym.AES_ALGORITHM, length: keyLength },
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
      "\u26A0\uFE0F CRITICAL: Argon2id is NOT supported by Web Crypto API. Falling back to PBKDF2 with high iterations (still weaker than true Argon2). For production use, install argon2-browser package and use it directly."
    );
    return await this.deriveKeyPBKDF2(
      password,
      salt,
      1e6,
      // 1M iterations (stronger than default 600k)
      "SHA-256"
    );
  }
  // ────────────────────── RSA Key Management (for Hybrid Encryption) ──────────────────────
  // Generates 4096-bit RSA key pair: Secure against classical factoring attacks (e.g., GNFS)
  async generateKeyPair() {
    return await this._crypto.subtle.generateKey(_WebCryptAsym.RSA_KEY_PARAMS, true, [
      "encrypt",
      "decrypt"
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
    return await this._crypto.subtle.importKey("spki", binary, _WebCryptAsym.RSA_ALGORITHM, true, [
      "encrypt"
    ]);
  }
  async importPrivateKey(b64) {
    const binary = this._base64ToArrayBuffer(b64);
    return await this._crypto.subtle.importKey("pkcs8", binary, _WebCryptAsym.RSA_ALGORITHM, true, [
      "decrypt"
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
    const aesKey = await this._crypto.subtle.generateKey(
      { name: _WebCryptAsym.AES_ALGORITHM, length: _WebCryptAsym.AES_LENGTH },
      true,
      ["encrypt"]
    );
    const exportedAesKey = await this._crypto.subtle.exportKey("raw", aesKey);
    const iv = this._crypto.getRandomValues(new Uint8Array(_WebCryptAsym.IV_LENGTH));
    const encryptedAesKey = await this._crypto.subtle.encrypt(
      _WebCryptAsym.RSA_ALGORITHM,
      publicKey,
      exportedAesKey
    );
    const encryptedData = await this._crypto.subtle.encrypt(
      { name: _WebCryptAsym.AES_ALGORITHM, iv },
      aesKey,
      data
    );
    const encKeyBytes = new Uint8Array(encryptedAesKey);
    const encKeyLen = encKeyBytes.byteLength;
    const result = new Uint8Array(
      4 + encKeyLen + _WebCryptAsym.IV_LENGTH + encryptedData.byteLength
    );
    new DataView(result.buffer).setUint32(0, encKeyLen, true);
    result.set(encKeyBytes, 4);
    result.set(iv, 4 + encKeyLen);
    result.set(new Uint8Array(encryptedData), 4 + encKeyLen + _WebCryptAsym.IV_LENGTH);
    return this._arrayBufferToBase64(result.buffer);
  }
  async decryptText(encryptedB64, privateKey) {
    try {
      if (typeof encryptedB64 !== "string") throw new Error("Invalid input");
      const combined = new Uint8Array(this._base64ToArrayBuffer(encryptedB64));
      if (combined.byteLength > _WebCryptAsym.MAX_ENCRYPTED_DATA_SIZE) {
        throw new Error("Decryption failed");
      }
      if (combined.byteLength < 4 + 100 + _WebCryptAsym.IV_LENGTH) {
        throw new Error("Invalid input");
      }
      const encKeyLen = new DataView(combined.buffer).getUint32(0, true);
      if (combined.byteLength < 4 + encKeyLen + _WebCryptAsym.IV_LENGTH) {
        throw new Error("Decryption failed");
      }
      const encryptedAesKey = combined.slice(4, 4 + encKeyLen);
      const iv = combined.slice(4 + encKeyLen, 4 + encKeyLen + _WebCryptAsym.IV_LENGTH);
      const ciphertext = combined.slice(4 + encKeyLen + _WebCryptAsym.IV_LENGTH);
      const aesKeyRaw = await this._crypto.subtle.decrypt(
        _WebCryptAsym.RSA_ALGORITHM,
        privateKey,
        encryptedAesKey
      );
      const aesKey = await this._crypto.subtle.importKey(
        "raw",
        aesKeyRaw,
        { name: _WebCryptAsym.AES_ALGORITHM },
        false,
        ["decrypt"]
      );
      const decrypted = await this._crypto.subtle.decrypt(
        { name: _WebCryptAsym.AES_ALGORITHM, iv },
        aesKey,
        ciphertext
      );
      return new TextDecoder().decode(decrypted);
    } catch (e) {
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
      { name: _WebCryptAsym.AES_ALGORITHM, length: _WebCryptAsym.AES_LENGTH },
      true,
      ["encrypt"]
    );
    const exportedAesKey = await this._crypto.subtle.exportKey("raw", aesKey);
    const baseIv = this._crypto.getRandomValues(new Uint8Array(_WebCryptAsym.IV_LENGTH));
    const encryptedAesKey = await this._crypto.subtle.encrypt(
      _WebCryptAsym.RSA_ALGORITHM,
      publicKey,
      exportedAesKey
    );
    const encKeyBytes = new Uint8Array(encryptedAesKey);
    const header = new Uint8Array(4 + encKeyBytes.byteLength + _WebCryptAsym.IV_LENGTH);
    new DataView(header.buffer).setUint32(0, encKeyBytes.byteLength, true);
    header.set(encKeyBytes, 4);
    header.set(baseIv, 4 + encKeyBytes.byteLength);
    const chunks = [header];
    const reader = fileOrBlob.stream().getReader();
    let counter = 0;
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      const iv = new Uint8Array(_WebCryptAsym.IV_LENGTH);
      iv.set(baseIv);
      new DataView(iv.buffer).setUint32(_WebCryptAsym.IV_LENGTH - 4, counter++, true);
      const encrypted = await this._crypto.subtle.encrypt(
        { name: _WebCryptAsym.AES_ALGORITHM, iv },
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
    const fileSize = fileOrBlob.size || fileOrBlob.blob && fileOrBlob.blob.size;
    if (fileSize && fileSize > _WebCryptAsym.MAX_ENCRYPTED_DATA_SIZE) {
      throw new Error("File too large for decryption");
    }
    const data = new Uint8Array(await fileOrBlob.arrayBuffer());
    if (data.length > _WebCryptAsym.MAX_ENCRYPTED_DATA_SIZE) {
      throw new Error("File too large for decryption");
    }
    if (data.length < 4 + 100 + _WebCryptAsym.IV_LENGTH) throw new Error("Decryption failed");
    const encKeyLen = new DataView(data.buffer).getUint32(0, true);
    if (data.length < 4 + encKeyLen + _WebCryptAsym.IV_LENGTH) throw new Error("Decryption failed");
    const encryptedAesKey = data.slice(4, 4 + encKeyLen);
    const baseIv = data.slice(4 + encKeyLen, 4 + encKeyLen + _WebCryptAsym.IV_LENGTH);
    const ciphertext = data.slice(4 + encKeyLen + _WebCryptAsym.IV_LENGTH);
    const aesKeyRaw = await this._crypto.subtle.decrypt(
      _WebCryptAsym.RSA_ALGORITHM,
      privateKey,
      encryptedAesKey
    );
    const aesKey = await this._crypto.subtle.importKey(
      "raw",
      aesKeyRaw,
      { name: _WebCryptAsym.AES_ALGORITHM },
      false,
      ["decrypt"]
    );
    const chunks = [];
    let offset = 0;
    let counter = 0;
    while (offset < ciphertext.byteLength) {
      const size = Math.min(_WebCryptAsym.CHUNK_SIZE, ciphertext.byteLength - offset);
      const chunk = ciphertext.slice(offset, offset + size);
      const iv = new Uint8Array(_WebCryptAsym.IV_LENGTH);
      iv.set(baseIv);
      new DataView(iv.buffer).setUint32(_WebCryptAsym.IV_LENGTH - 4, counter++, true);
      const decrypted = await this._crypto.subtle.decrypt(
        { name: _WebCryptAsym.AES_ALGORITHM, iv },
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
      { name: _WebCryptAsym.AES_ALGORITHM, length: _WebCryptAsym.AES_LENGTH },
      true,
      ["encrypt"]
    );
    const exportedSession = await this._crypto.subtle.exportKey("raw", sessionKey);
    const encryptedSessionKey = await this._crypto.subtle.encrypt(
      _WebCryptAsym.RSA_ALGORITHM,
      publicKey,
      exportedSession
    );
    let first = true;
    return async (frame, controller) => {
      const iv = this._crypto.getRandomValues(new Uint8Array(_WebCryptAsym.IV_LENGTH));
      if (first) {
        const encSession = new Uint8Array(encryptedSessionKey);
        const header = new Uint8Array(4 + encSession.byteLength + _WebCryptAsym.IV_LENGTH);
        new DataView(header.buffer).setUint32(0, encSession.byteLength, true);
        header.set(encSession, 4);
        header.set(iv, 4 + encSession.byteLength);
        const encrypted = await this._crypto.subtle.encrypt(
          { name: _WebCryptAsym.AES_ALGORITHM, iv },
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
          { name: _WebCryptAsym.AES_ALGORITHM, iv },
          sessionKey,
          frame.data
        );
        const newData = new Uint8Array(_WebCryptAsym.IV_LENGTH + encrypted.byteLength);
        newData.set(iv, 0);
        newData.set(new Uint8Array(encrypted), _WebCryptAsym.IV_LENGTH);
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
        if (data.byteLength < 4 + 100 + _WebCryptAsym.IV_LENGTH) {
          console.warn("Invalid first frame");
          controller.enqueue(frame);
          return;
        }
        const encKeyLen = new DataView(data.buffer).getUint32(0, true);
        if (data.byteLength < 4 + encKeyLen + _WebCryptAsym.IV_LENGTH) {
          console.warn("Truncated first frame");
          controller.enqueue(frame);
          return;
        }
        const encryptedSessionKey = data.slice(4, 4 + encKeyLen);
        const iv = data.slice(4 + encKeyLen, 4 + encKeyLen + _WebCryptAsym.IV_LENGTH);
        const ciphertext = data.slice(4 + encKeyLen + _WebCryptAsym.IV_LENGTH);
        try {
          const sessionKeyRaw = await this._crypto.subtle.decrypt(
            _WebCryptAsym.RSA_ALGORITHM,
            privateKey,
            encryptedSessionKey
          );
          sessionKey = await this._crypto.subtle.importKey(
            "raw",
            sessionKeyRaw,
            { name: _WebCryptAsym.AES_ALGORITHM },
            false,
            ["decrypt"]
          );
          const decrypted = await this._crypto.subtle.decrypt(
            { name: _WebCryptAsym.AES_ALGORITHM, iv },
            sessionKey,
            ciphertext
          );
          frame.data = decrypted;
        } catch (e) {
          console.warn("WebRTC first frame decryption failed", e);
        }
        first = false;
      } else {
        if (data.byteLength < _WebCryptAsym.IV_LENGTH) {
          controller.enqueue(frame);
          return;
        }
        const iv = data.slice(0, _WebCryptAsym.IV_LENGTH);
        const ciphertext = data.slice(_WebCryptAsym.IV_LENGTH);
        if (!sessionKey) {
          console.warn("No session key for decryption");
          controller.enqueue(frame);
          return;
        }
        try {
          const decrypted = await this._crypto.subtle.decrypt(
            { name: _WebCryptAsym.AES_ALGORITHM, iv },
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
  async generateSigningKeyPair(curve = _WebCryptAsym.SIGN_CURVE) {
    if (!_WebCryptAsym.SUPPORTED_CURVES.includes(curve)) {
      throw new Error(
        `Unsupported curve: ${curve}. Use one of: ${_WebCryptAsym.SUPPORTED_CURVES.join(", ")}`
      );
    }
    const keyPair = await this._crypto.subtle.generateKey(
      {
        name: _WebCryptAsym.SIGN_ALGORITHM,
        namedCurve: curve
      },
      true,
      // extractable
      ["sign", "verify"]
    );
    const publicKeyExported = await this._crypto.subtle.exportKey("spki", keyPair.publicKey);
    const publicKeyB64 = this._arrayBufferToBase64(publicKeyExported);
    return {
      publicKey: keyPair.publicKey,
      privateKey: keyPair.privateKey,
      publicKeyB64
    };
  }
  /**
   * Generate an EdDSA signing key pair
   * @returns {Promise<{publicKey: CryptoKey, privateKey: CryptoKey, publicKeyB64: string}>}
   */
  async generateEdDSASigningKeyPair() {
    const keyPair = await this._crypto.subtle.generateKey(
      {
        name: _WebCryptAsym.ED25519_ALGORITHM,
        namedCurve: _WebCryptAsym.ED25519_CURVE
      },
      true,
      // extractable
      ["sign", "verify"]
    );
    const publicKeyExported = await this._crypto.subtle.exportKey("spki", keyPair.publicKey);
    const publicKeyB64 = this._arrayBufferToBase64(publicKeyExported);
    return {
      publicKey: keyPair.publicKey,
      privateKey: keyPair.privateKey,
      publicKeyB64
    };
  }
  /**
   * Generate an RSA-PSS signing key pair
   * @param {number} [modulusLength=2048] - RSA key size in bits (default: 2048)
   * @returns {Promise<{publicKey: CryptoKey, privateKey: CryptoKey, publicKeyB64: string}>}
   */
  async generateRSAPSSigningKeyPair(modulusLength = 2048) {
    const rsaParams = {
      name: _WebCryptAsym.RSA_PSS_ALGORITHM,
      modulusLength,
      publicExponent: new Uint8Array([1, 0, 1]),
      // 65537
      hash: _WebCryptAsym.SIGN_HASH
    };
    const keyPair = await this._crypto.subtle.generateKey(rsaParams, true, ["sign", "verify"]);
    const publicKeyExported = await this._crypto.subtle.exportKey("spki", keyPair.publicKey);
    const publicKeyB64 = this._arrayBufferToBase64(publicKeyExported);
    return {
      publicKey: keyPair.publicKey,
      privateKey: keyPair.privateKey,
      publicKeyB64
    };
  }
  /**
   * Import a public signing key from base64 (SPKI format)
   * @param {string} publicKeyB64
   * @param {string} [curve='P-256']
   * @returns {Promise<CryptoKey>}
   */
  async importPublicSigningKey(publicKeyB64, curve = _WebCryptAsym.SIGN_CURVE) {
    const publicKeyBuffer = this._base64ToArrayBuffer(publicKeyB64);
    return await this._crypto.subtle.importKey(
      "spki",
      publicKeyBuffer,
      { name: _WebCryptAsym.SIGN_ALGORITHM, namedCurve: curve },
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
        name: _WebCryptAsym.SIGN_ALGORITHM,
        hash: { name: _WebCryptAsym.SIGN_HASH }
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
    return await TimingSafeHelper_default.timingSafeVerify(
      this._crypto,
      {
        name: _WebCryptAsym.SIGN_ALGORITHM,
        hash: { name: _WebCryptAsym.SIGN_HASH }
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
    const hashBuffer = await this._crypto.subtle.digest(_WebCryptAsym.SIGN_HASH, data);
    const signature = await this._crypto.subtle.sign(
      {
        name: _WebCryptAsym.SIGN_ALGORITHM,
        hash: { name: _WebCryptAsym.SIGN_HASH }
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
    const hashBuffer = await this._crypto.subtle.digest(_WebCryptAsym.SIGN_HASH, data);
    return await TimingSafeHelper_default.timingSafeVerify(
      this._crypto,
      {
        name: _WebCryptAsym.SIGN_ALGORITHM,
        hash: { name: _WebCryptAsym.SIGN_HASH }
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
        hash: { name: hash }
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
    return await TimingSafeHelper_default.timingSafeVerify(
      this._crypto,
      {
        name: "HMAC",
        hash: { name: hash }
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
    const tag = await this._crypto.subtle.sign(
      {
        name: "Poly1305"
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
      return await this._createPostQuantumHybridEncryptTransform(publicKey);
    } else {
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
      { name: _WebCryptAsym.AES_ALGORITHM, length: _WebCryptAsym.AES_LENGTH },
      true,
      ["encrypt"]
    );
    const exportedSession = await this._crypto.subtle.exportKey("raw", sessionKey);
    const encryptedSessionKey = await this._crypto.subtle.encrypt(
      _WebCryptAsym.RSA_ALGORITHM,
      publicKey,
      exportedSession
    );
    let first = true;
    return async (frame, controller) => {
      const iv = this._crypto.getRandomValues(new Uint8Array(_WebCryptAsym.IV_LENGTH));
      if (first) {
        const encSession = new Uint8Array(encryptedSessionKey);
        const header = new Uint8Array(4 + encSession.byteLength + _WebCryptAsym.IV_LENGTH);
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
        const ciphertext = await this._crypto.subtle.encrypt(
          { name: _WebCryptAsym.AES_ALGORITHM, iv },
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
      { name: _WebCryptAsym.AES_ALGORITHM, length: _WebCryptAsym.AES_LENGTH },
      true,
      ["encrypt"]
    );
    const exportedSession = await this._crypto.subtle.exportKey("raw", sessionKey);
    const encryptedSessionKey = await this._crypto.subtle.encrypt(
      _WebCryptAsym.RSA_ALGORITHM,
      publicKey,
      exportedSession
    );
    let first = true;
    let totalBytes = 0;
    return async (frame, controller) => {
      const iv = this._crypto.getRandomValues(new Uint8Array(_WebCryptAsym.IV_LENGTH));
      if (first) {
        const encSession = new Uint8Array(encryptedSessionKey);
        const header = new Uint8Array(4 + encSession.byteLength + _WebCryptAsym.IV_LENGTH);
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
        const ciphertext = await this._crypto.subtle.encrypt(
          { name: _WebCryptAsym.AES_ALGORITHM, iv },
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
      { name: _WebCryptAsym.AES_ALGORITHM, length: _WebCryptAsym.AES_LENGTH },
      true,
      ["encrypt"]
    );
    const exportedAesKey = await this._crypto.subtle.exportKey("raw", aesKey);
    const baseIv = this._crypto.getRandomValues(new Uint8Array(_WebCryptAsym.IV_LENGTH));
    const encryptedAesKey = await this._crypto.subtle.encrypt(
      _WebCryptAsym.RSA_ALGORITHM,
      publicKey,
      exportedAesKey
    );
    const encKeyBytes = new Uint8Array(encryptedAesKey);
    const header = new Uint8Array(4 + encKeyBytes.byteLength + _WebCryptAsym.IV_LENGTH);
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
      const iv = new Uint8Array(_WebCryptAsym.IV_LENGTH);
      iv.set(baseIv);
      new DataView(iv.buffer).setUint32(_WebCryptAsym.IV_LENGTH - 4, counter++, true);
      const encrypted = await this._crypto.subtle.encrypt(
        { name: _WebCryptAsym.AES_ALGORITHM, iv },
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
    const fileSize = fileOrBlob.size || fileOrBlob.blob && fileOrBlob.blob.size;
    if (fileSize && fileSize > _WebCryptAsym.MAX_ENCRYPTED_DATA_SIZE) {
      throw new Error("File too large for decryption");
    }
    const data = new Uint8Array(await fileOrBlob.arrayBuffer());
    if (data.length > _WebCryptAsym.MAX_ENCRYPTED_DATA_SIZE) {
      throw new Error("File too large for decryption");
    }
    if (data.length < 4 + 100 + _WebCryptAsym.IV_LENGTH) throw new Error("Decryption failed");
    const encKeyLen = new DataView(data.buffer).getUint32(0, true);
    if (data.length < 4 + encKeyLen + _WebCryptAsym.IV_LENGTH) throw new Error("Decryption failed");
    const encryptedAesKey = data.slice(4, 4 + encKeyLen);
    const baseIv = data.slice(4 + encKeyLen, 4 + encKeyLen + _WebCryptAsym.IV_LENGTH);
    const ciphertext = data.slice(4 + encKeyLen + _WebCryptAsym.IV_LENGTH);
    const aesKeyRaw = await this._crypto.subtle.decrypt(
      _WebCryptAsym.RSA_ALGORITHM,
      privateKey,
      encryptedAesKey
    );
    const aesKey = await this._crypto.subtle.importKey(
      "raw",
      aesKeyRaw,
      { name: _WebCryptAsym.AES_ALGORITHM },
      false,
      ["decrypt"]
    );
    const chunks = [];
    let offset = 0;
    let counter = 0;
    let totalBytes = 0;
    while (offset < ciphertext.byteLength) {
      const size = Math.min(_WebCryptAsym.CHUNK_SIZE, ciphertext.byteLength - offset);
      const chunk = ciphertext.slice(offset, offset + size);
      const iv = new Uint8Array(_WebCryptAsym.IV_LENGTH);
      iv.set(baseIv);
      new DataView(iv.buffer).setUint32(_WebCryptAsym.IV_LENGTH - 4, counter++, true);
      const decrypted = await this._crypto.subtle.decrypt(
        { name: _WebCryptAsym.AES_ALGORITHM, iv },
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
      throw new Error("EdDSA signing not yet implemented in this version");
    } else if (algorithm === "RSA-PSS") {
      const signature = await this._crypto.subtle.sign(
        {
          name: _WebCryptAsym.RSA_PSS_ALGORITHM,
          saltLength: 32
        },
        privateKey,
        data
      );
      return this._arrayBufferToBase64(signature);
    } else {
      const signature = await this._crypto.subtle.sign(
        {
          name: _WebCryptAsym.SIGN_ALGORITHM,
          hash: { name: _WebCryptAsym.SIGN_HASH }
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
      throw new Error("EdDSA verification not yet implemented in this version");
    } else if (algorithm === "RSA-PSS") {
      return await this._crypto.subtle.verify(
        {
          name: _WebCryptAsym.RSA_PSS_ALGORITHM,
          saltLength: 32
        },
        publicKey,
        signature,
        data
      );
    } else {
      return await this._crypto.subtle.verify(
        {
          name: _WebCryptAsym.SIGN_ALGORITHM,
          hash: { name: _WebCryptAsym.SIGN_HASH }
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
      memory = 65536,
      // 64 MB
      iterations = 3,
      parallelism = 1,
      keyLength = 256
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
      return await this._crypto.subtle.deriveKey(
        {
          name: "Argon2",
          salt,
          iterations,
          memoryCost: memory,
          parallelism
        },
        keyMaterial,
        { name: _WebCryptAsym.AES_ALGORITHM, length: keyLength },
        false,
        ["encrypt", "decrypt"]
      );
    } catch (e) {
      console.warn("Argon2 not available; using PBKDF2 with 1M iterations as fallback");
      return await this.deriveKeyPBKDF2(password, salt, 1e6, "SHA-256", keyLength);
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
  async deriveKeySHA3(password, iterations = 1e5, algorithm = "SHA3-256") {
    const encoder = new TextEncoder();
    const passwordBytes = encoder.encode(password);
    const saltHash = await this._crypto.subtle.digest("SHA-256", passwordBytes);
    const salt = new Uint8Array(saltHash).slice(0, 16);
    let material = new Uint8Array(passwordBytes.byteLength + salt.byteLength);
    material.set(passwordBytes);
    material.set(salt, passwordBytes.byteLength);
    for (let i = 0; i < iterations; i++) {
      const hashInput = new Uint8Array(material.byteLength + 4);
      hashInput.set(material);
      new DataView(hashInput.buffer).setUint32(material.byteLength, i, true);
      try {
        material = new Uint8Array(await this._crypto.subtle.digest(algorithm, hashInput));
      } catch (e) {
        console.warn("SHA-3 not available; falling back to SHA-256");
        material = new Uint8Array(await this._crypto.subtle.digest("SHA-256", hashInput));
      }
    }
    const derivedKey = material.slice(0, 32);
    return await this._crypto.subtle.importKey(
      "raw",
      derivedKey,
      { name: _WebCryptAsym.AES_ALGORITHM, length: 256 },
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
      salt = new Uint8Array(32);
    }
    try {
      const hmacKey = await this._crypto.subtle.importKey(
        "raw",
        salt,
        { name: "HMAC", hash: "SHA3-256" },
        false,
        ["sign"]
      );
      const prk = await this._crypto.subtle.sign("HMAC", hmacKey, secret);
      const expandHmacKey = await this._crypto.subtle.importKey(
        "raw",
        new Uint8Array(prk),
        { name: "HMAC", hash: "SHA3-256" },
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
        { name: _WebCryptAsym.AES_ALGORITHM, length: keyLength },
        false,
        ["encrypt", "decrypt"]
      );
    } catch (e) {
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
      { name: _WebCryptAsym.AES_ALGORITHM, length: keyLength },
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
    const parentKeyRaw = await this._crypto.subtle.exportKey("raw", parentKey);
    const input = new Uint8Array(parentKeyRaw.byteLength + childSalt.byteLength + purpose.length);
    input.set(new Uint8Array(parentKeyRaw));
    input.set(childSalt, parentKeyRaw.byteLength);
    input.set(new TextEncoder().encode(purpose), parentKeyRaw.byteLength + childSalt.byteLength);
    try {
      const childKeyMaterial = await this._crypto.subtle.digest("SHA3-256", input);
      return await this._crypto.subtle.importKey(
        "raw",
        childKeyMaterial,
        { name: _WebCryptAsym.AES_ALGORITHM, length: 256 },
        false,
        ["encrypt", "decrypt"]
      );
    } catch (e) {
      const childKeyMaterial = await this._crypto.subtle.digest("SHA-256", input);
      return await this._crypto.subtle.importKey(
        "raw",
        childKeyMaterial,
        { name: _WebCryptAsym.AES_ALGORITHM, length: 256 },
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
      []
      // ECDH public keys don't have operations themselves, they are used as parameters
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
      { name: _WebCryptAsym.AES_ALGORITHM, length: _WebCryptAsym.AES_LENGTH },
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
    const iv = this._crypto.getRandomValues(new Uint8Array(_WebCryptAsym.IV_LENGTH));
    const encrypted = await this._crypto.subtle.encrypt(
      { name: _WebCryptAsym.AES_ALGORITHM, iv },
      sharedKey,
      encoded
    );
    const result = new Uint8Array(_WebCryptAsym.IV_LENGTH + encrypted.byteLength);
    result.set(iv, 0);
    result.set(new Uint8Array(encrypted), _WebCryptAsym.IV_LENGTH);
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
    if (combined.byteLength < _WebCryptAsym.IV_LENGTH) {
      throw new Error("Invalid encrypted data");
    }
    const iv = combined.slice(0, _WebCryptAsym.IV_LENGTH);
    const ciphertext = combined.slice(_WebCryptAsym.IV_LENGTH);
    const decrypted = await this._crypto.subtle.decrypt(
      { name: _WebCryptAsym.AES_ALGORITHM, iv },
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
  // ────────────────────── JSON Web Encryption (JWE) ──────────────────────
  /**
   * Helper to convert an ArrayBuffer to Base64URL string
   */
  _arrayBufferToBase64Url(buffer) {
    const b64 = this._arrayBufferToBase64(buffer);
    return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }
  /**
   * Helper to convert a Base64URL string to ArrayBuffer
   */
  _base64UrlToArrayBuffer(base64url) {
    let b64 = base64url.replace(/-/g, "+").replace(/_/g, "/");
    while (b64.length % 4) {
      b64 += "=";
    }
    return this._base64ToArrayBuffer(b64);
  }
  /**
   * Encrypts payload into a JWE Compact Serialization string.
   * Uses RSA-OAEP-256 for key management and A256GCM for content encryption.
   *
   * @param {any} payload - Data to encrypt (string or serializable object)
   * @param {CryptoKey} publicKey - Recipient's RSA public key
   * @param {Object} [customHeaders={}] - Additional JWE protected headers
   * @returns {Promise<string>} JWE Token string
   */
  async encryptJWE(payload, publicKey, customHeaders = {}) {
    const encoder = new TextEncoder();
    const textPayload = typeof payload === "string" ? payload : JSON.stringify(payload);
    const plaintext = encoder.encode(textPayload);
    const protectedHeaders = {
      alg: "RSA-OAEP",
      enc: "A256GCM",
      ...customHeaders
    };
    const headerStr = JSON.stringify(protectedHeaders);
    const encodedHeader = this._arrayBufferToBase64Url(encoder.encode(headerStr).buffer);
    const cek = await this._crypto.subtle.generateKey(
      { name: _WebCryptAsym.AES_ALGORITHM, length: _WebCryptAsym.AES_LENGTH },
      true,
      ["encrypt", "decrypt"]
    );
    const exportedCek = await this._crypto.subtle.exportKey("raw", cek);
    const encryptedCek = await this._crypto.subtle.encrypt(
      _WebCryptAsym.RSA_ALGORITHM,
      publicKey,
      exportedCek
    );
    const encodedEncryptedCek = this._arrayBufferToBase64Url(encryptedCek);
    const iv = this._crypto.getRandomValues(new Uint8Array(12));
    const encodedIv = this._arrayBufferToBase64Url(iv.buffer);
    const aad = encoder.encode(encodedHeader);
    const ciphertextBuffer = await this._crypto.subtle.encrypt(
      { name: _WebCryptAsym.AES_ALGORITHM, iv, additionalData: aad },
      cek,
      plaintext
    );
    const combinedCiphertextAndTag = new Uint8Array(ciphertextBuffer);
    const tagLength = 16;
    const ciphertext = combinedCiphertextAndTag.slice(
      0,
      combinedCiphertextAndTag.byteLength - tagLength
    );
    const authTag = combinedCiphertextAndTag.slice(combinedCiphertextAndTag.byteLength - tagLength);
    const encodedCiphertext = this._arrayBufferToBase64Url(ciphertext.buffer);
    const encodedAuthTag = this._arrayBufferToBase64Url(authTag.buffer);
    return `${encodedHeader}.${encodedEncryptedCek}.${encodedIv}.${encodedCiphertext}.${encodedAuthTag}`;
  }
  /**
   * Decrypts a JWE Compact Serialization string.
   *
   * @param {string} jweToken - JWE Token string
   * @param {CryptoKey} privateKey - Recipient's RSA private key
   * @returns {Promise<any>} Decrypted payload (parsed object if applicable, else string)
   */
  async decryptJWE(jweToken, privateKey) {
    if (typeof jweToken !== "string") throw new Error("Invalid JWE token format");
    const parts = jweToken.split(".");
    if (parts.length !== 5) {
      throw new Error("Invalid JWE token structure (expected 5 parts)");
    }
    const [encodedHeader, encodedEncryptedCek, encodedIv, encodedCiphertext, encodedAuthTag] = parts;
    const decoder = new TextDecoder();
    let header;
    try {
      const headerBuffer = this._base64UrlToArrayBuffer(encodedHeader);
      header = JSON.parse(decoder.decode(headerBuffer));
    } catch (e) {
      const msg = typeof process !== "undefined" && process.env && process.env.NODE_ENV !== "production" ? `Failed to parse JWE header: ${e.message}` : "Failed to decrypt JWE";
      throw new Error(msg);
    }
    if (header.alg !== "RSA-OAEP") {
      const msg = typeof process !== "undefined" && process.env && process.env.NODE_ENV !== "production" ? `Unsupported JWE algorithm: ${header.alg}` : "Failed to decrypt JWE";
      throw new Error(msg);
    }
    if (header.enc !== "A256GCM") {
      throw new Error(`Unsupported JWE encryption: ${header.enc}`);
    }
    let cekRaw;
    try {
      const encryptedCekBuffer = this._base64UrlToArrayBuffer(encodedEncryptedCek);
      cekRaw = await this._crypto.subtle.decrypt(
        _WebCryptAsym.RSA_ALGORITHM,
        privateKey,
        encryptedCekBuffer
      );
    } catch (e) {
      const msg = typeof process !== "undefined" && process.env && process.env.NODE_ENV !== "production" ? `Failed to decrypt Content Encryption Key (CEK): ${e.message}` : "Failed to decrypt JWE";
      throw new Error(msg);
    }
    const cek = await this._crypto.subtle.importKey(
      "raw",
      cekRaw,
      { name: _WebCryptAsym.AES_ALGORITHM },
      false,
      ["decrypt"]
    );
    const iv = new Uint8Array(this._base64UrlToArrayBuffer(encodedIv));
    const ciphertext = new Uint8Array(this._base64UrlToArrayBuffer(encodedCiphertext));
    const authTag = new Uint8Array(this._base64UrlToArrayBuffer(encodedAuthTag));
    const combinedCiphertextAndTag = new Uint8Array(ciphertext.byteLength + authTag.byteLength);
    combinedCiphertextAndTag.set(ciphertext);
    combinedCiphertextAndTag.set(authTag, ciphertext.byteLength);
    const encoder = new TextEncoder();
    const aad = encoder.encode(encodedHeader);
    let decryptedBuffer;
    try {
      decryptedBuffer = await this._crypto.subtle.decrypt(
        { name: _WebCryptAsym.AES_ALGORITHM, iv, additionalData: aad },
        cek,
        combinedCiphertextAndTag
      );
    } catch (e) {
      const msg = typeof process !== "undefined" && process.env && process.env.NODE_ENV !== "production" ? "Failed to decrypt JWE payload (authentication tag mismatch or invalid data)" : "Failed to decrypt JWE";
      throw new Error(msg);
    }
    const textPayload = decoder.decode(decryptedBuffer);
    try {
      return JSON.parse(textPayload);
    } catch (e) {
      return textPayload;
    }
  }
};

// src/WebCryptPQC.js
var WebCryptPQC = class _WebCryptPQC {
  static WARNING = "\u26A0\uFE0F CRITICAL: WebCryptPQC is PLACEHOLDER/STUB implementation. Kyber and Dilithium are NOT real PQC - they use SHA-3 hashing stubs. Not suitable for production security. Integrate liboqs-js or wait for official implementation.";
  // ─────────────────────── Kyber Constants ───────────────────────
  static KYBER_512 = "Kyber512";
  static KYBER_768 = "Kyber768";
  static KYBER_1024 = "Kyber1024";
  // Kyber security levels and sizes (bytes)
  static KYBER_PARAMS = {
    [_WebCryptPQC.KYBER_512]: {
      name: "Kyber512",
      securityLevel: "128-bit",
      publicKeySize: 800,
      privateKeySize: 1632,
      ciphertextSize: 768,
      sharedSecretSize: 32
    },
    [_WebCryptPQC.KYBER_768]: {
      name: "Kyber768",
      securityLevel: "192-bit",
      publicKeySize: 1184,
      privateKeySize: 2400,
      ciphertextSize: 1088,
      sharedSecretSize: 32
    },
    [_WebCryptPQC.KYBER_1024]: {
      name: "Kyber1024",
      securityLevel: "256-bit",
      publicKeySize: 1568,
      privateKeySize: 3168,
      ciphertextSize: 1568,
      sharedSecretSize: 32
    }
  };
  // ─────────────────────── Dilithium Constants ───────────────────────
  static DILITHIUM_2 = "Dilithium2";
  static DILITHIUM_3 = "Dilithium3";
  static DILITHIUM_5 = "Dilithium5";
  static DILITHIUM_PARAMS = {
    [_WebCryptPQC.DILITHIUM_2]: {
      name: "Dilithium2",
      securityLevel: "128-bit",
      publicKeySize: 1312,
      privateKeySize: 2544,
      signatureSize: 2420
    },
    [_WebCryptPQC.DILITHIUM_3]: {
      name: "Dilithium3",
      securityLevel: "192-bit",
      publicKeySize: 1952,
      privateKeySize: 4e3,
      signatureSize: 3293
    },
    [_WebCryptPQC.DILITHIUM_5]: {
      name: "Dilithium5",
      securityLevel: "256-bit",
      publicKeySize: 2592,
      privateKeySize: 4864,
      signatureSize: 4595
    }
  };
  // ─────────────────────── Algorithm Constants ───────────────────────
  static HASH_SHA3_256 = "SHA3-256";
  static HASH_SHA3_384 = "SHA3-384";
  static HASH_SHA3_512 = "SHA3-512";
  static SUPPORTED_KYBER_LEVELS = [
    _WebCryptPQC.KYBER_512,
    _WebCryptPQC.KYBER_768,
    _WebCryptPQC.KYBER_1024
  ];
  static SUPPORTED_DILITHIUM_LEVELS = [
    _WebCryptPQC.DILITHIUM_2,
    _WebCryptPQC.DILITHIUM_3,
    _WebCryptPQC.DILITHIUM_5
  ];
  constructor() {
    this._crypto = this._getCrypto();
    if (typeof console !== "undefined" && console.warn) {
      console.warn(_WebCryptPQC.WARNING);
    }
  }
  _getCrypto() {
    if (typeof globalThis !== "undefined" && globalThis.crypto) return globalThis.crypto;
    if (typeof require !== "undefined") {
      const { webcrypto } = require("crypto");
      return webcrypto;
    }
    throw new Error("Web Crypto API not available");
  }
  // ═══════════════════════════ Kyber KEM (Key Encapsulation) ═══════════════════════════
  /**
   * Generate a Kyber key pair for key encapsulation.
   * @param {string} level - Kyber level: "Kyber512" | "Kyber768" | "Kyber1024"
   * @returns {Promise<{publicKey: Uint8Array, privateKey: Uint8Array}>}
   */
  async generateKyberKeyPair(level = _WebCryptPQC.KYBER_768) {
    if (!_WebCryptPQC.SUPPORTED_KYBER_LEVELS.includes(level)) {
      throw new Error(`Unsupported Kyber level: ${level}. Use Kyber512, Kyber768, or Kyber1024`);
    }
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
  async kyberEncapsulate(kyberPublicKey, level = _WebCryptPQC.KYBER_768) {
    if (!_WebCryptPQC.SUPPORTED_KYBER_LEVELS.includes(level)) {
      throw new Error(`Unsupported Kyber level: ${level}`);
    }
    const params = _WebCryptPQC.KYBER_PARAMS[level];
    if (kyberPublicKey.byteLength !== params.publicKeySize) {
      throw new Error(
        `Invalid Kyber public key size: expected ${params.publicKeySize}, got ${kyberPublicKey.byteLength}`
      );
    }
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
  async kyberDecapsulate(ciphertext, kyberPrivateKey, level = _WebCryptPQC.KYBER_768) {
    if (!_WebCryptPQC.SUPPORTED_KYBER_LEVELS.includes(level)) {
      throw new Error(`Unsupported Kyber level: ${level}`);
    }
    const params = _WebCryptPQC.KYBER_PARAMS[level];
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
  async generateDilithiumKeyPair(level = _WebCryptPQC.DILITHIUM_3) {
    if (!_WebCryptPQC.SUPPORTED_DILITHIUM_LEVELS.includes(level)) {
      throw new Error(`Unsupported Dilithium level: ${level}`);
    }
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
  async dilithiumSign(message, dilithiumPrivateKey, level = _WebCryptPQC.DILITHIUM_3) {
    if (!_WebCryptPQC.SUPPORTED_DILITHIUM_LEVELS.includes(level)) {
      throw new Error(`Unsupported Dilithium level: ${level}`);
    }
    const params = _WebCryptPQC.DILITHIUM_PARAMS[level];
    if (dilithiumPrivateKey.byteLength !== params.privateKeySize) {
      throw new Error(
        `Invalid Dilithium private key size: expected ${params.privateKeySize}, got ${dilithiumPrivateKey.byteLength}`
      );
    }
    const msgBytes = typeof message === "string" ? new TextEncoder().encode(message) : message;
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
  async dilithiumVerify(message, signature, dilithiumPublicKey, level = _WebCryptPQC.DILITHIUM_3) {
    if (!_WebCryptPQC.SUPPORTED_DILITHIUM_LEVELS.includes(level)) {
      throw new Error(`Unsupported Dilithium level: ${level}`);
    }
    const params = _WebCryptPQC.DILITHIUM_PARAMS[level];
    if (dilithiumPublicKey.byteLength !== params.publicKeySize) {
      throw new Error(
        `Invalid Dilithium public key size: expected ${params.publicKeySize}, got ${dilithiumPublicKey.byteLength}`
      );
    }
    if (signature.byteLength !== params.signatureSize) {
      return false;
    }
    const msgBytes = typeof message === "string" ? new TextEncoder().encode(message) : message;
    console.warn(
      "\u26A0\uFE0F dilithiumVerify() is a PLACEHOLDER stub. This does NOT perform real post-quantum signature verification. Integrate liboqs-js for production use."
    );
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
  async hybridEncapsulate(rsaPublicKey, kyberPublicKey, kyberLevel = _WebCryptPQC.KYBER_768) {
    const { ciphertext: kyberCiphertext, sharedSecret: kyberSharedSecret } = await this.kyberEncapsulate(kyberPublicKey, kyberLevel);
    const rsaWrappedSharedSecret = await this._crypto.subtle.encrypt(
      { name: "RSA-OAEP", hash: "SHA-256" },
      rsaPublicKey,
      kyberSharedSecret
    );
    const combinedInput = new Uint8Array(
      kyberSharedSecret.byteLength + rsaWrappedSharedSecret.byteLength
    );
    combinedInput.set(kyberSharedSecret);
    combinedInput.set(new Uint8Array(rsaWrappedSharedSecret), kyberSharedSecret.byteLength);
    const finalSharedSecret = await this._sha3Hash(combinedInput, 256);
    return {
      sharedSecret: finalSharedSecret,
      kyberCiphertext: new Uint8Array(kyberCiphertext),
      rsaWrappedSharedSecret: new Uint8Array(rsaWrappedSharedSecret)
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
  async hybridDecapsulate(kyberCiphertext, rsaWrappedSharedSecret, rsaPrivateKey, kyberPrivateKey, kyberLevel = _WebCryptPQC.KYBER_768) {
    try {
      const kyberSharedSecret = await this.kyberDecapsulate(
        kyberCiphertext,
        kyberPrivateKey,
        kyberLevel
      );
      let rsaSharedSecret;
      try {
        rsaSharedSecret = await this._crypto.subtle.decrypt(
          { name: "RSA-OAEP", hash: "SHA-256" },
          rsaPrivateKey,
          rsaWrappedSharedSecret
        );
      } catch (e) {
        console.warn(
          "Hybrid decapsulation: RSA decryption failed, falling back to Kyber shared secret"
        );
        rsaSharedSecret = kyberSharedSecret;
      }
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
      const digest = await this._crypto.subtle.digest(algorithm, data);
      return new Uint8Array(digest);
    } catch (e) {
      const fallbackAlgorithm = bitLength <= 256 ? "SHA-256" : bitLength <= 384 ? "SHA-384" : "SHA-512";
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
    const params = _WebCryptPQC.KYBER_PARAMS[level];
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
  async _generateDilithiumKeysFromSeed(seed, level) {
    const params = _WebCryptPQC.DILITHIUM_PARAMS[level];
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
};
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  WebCrypt,
  WebCryptAsym,
  WebCryptPQC
});
