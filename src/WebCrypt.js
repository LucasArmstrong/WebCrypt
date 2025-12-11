// src/WebCrypt.js
export class WebCrypt {
  static ALGORITHM = "AES-GCM";
  static KEY_LENGTH = 256;
  static IV_LENGTH = 12;
  static SALT_LENGTH = 16;
  static PBKDF2_ITERATIONS = 600_000;
  static HASH_ALGORITHM = "SHA-256";
  static CHUNK_SIZE = 8 * 1024 * 1024;
  static WEBRTC_SALT = new TextEncoder().encode("WebCrypt-E2EE-v1-2025");

  constructor() {
    this.keyCache = new Map();
  }

  _getCrypto() {
    // Browser (Chrome, Firefox, Safari, Edge)
    if (typeof globalThis !== "undefined" && globalThis.crypto) return globalThis.crypto;
    // Node.js 18+ has native Web Crypto
    if (typeof require !== "undefined") {
      const { webcrypto } = require("crypto");
      return webcrypto;
    }
    throw new Error("Web Crypto API not available in this environment");
  }

  async _deriveKey(password, salt) {
    const crypto = this._getCrypto();
    const cacheKey = `${password}:${btoa(String.fromCharCode(...salt))}`;
    if (this.keyCache.has(cacheKey)) return this.keyCache.get(cacheKey);

    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
      "raw",
      enc.encode(password),
      "PBKDF2",
      false,
      ["deriveKey"]
    );

    const key = await crypto.subtle.deriveKey(
      {
        name: "PBKDF2",
        salt,
        iterations: WebCrypt.PBKDF2_ITERATIONS,
        hash: WebCrypt.HASH_ALGORITHM,
      },
      keyMaterial,
      { name: WebCrypt.ALGORITHM, length: WebCrypt.KEY_LENGTH },
      false,
      ["encrypt", "decrypt"]
    );

    this.keyCache.set(cacheKey, key);
    return key;
  }

  // ────────────────────── Safe Base64 (stack-safe, fast) ──────────────────────
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
  async encryptText(text, password) {
    const data = new TextEncoder().encode(text);
    const salt = crypto.getRandomValues(new Uint8Array(WebCrypt.SALT_LENGTH));
    const iv = crypto.getRandomValues(new Uint8Array(WebCrypt.IV_LENGTH));
    const key = await this._deriveKey(password, salt);

    const encrypted = await crypto.subtle.encrypt({ name: WebCrypt.ALGORITHM, iv }, key, data);

    const result = new Uint8Array(WebCrypt.SALT_LENGTH + WebCrypt.IV_LENGTH + encrypted.byteLength);
    result.set(salt, 0);
    result.set(iv, WebCrypt.SALT_LENGTH);
    result.set(new Uint8Array(encrypted), WebCrypt.SALT_LENGTH + WebCrypt.IV_LENGTH);

    return this._arrayBufferToBase64(result.buffer);
  }

  async decryptText(b64, password) {
    const combined = new Uint8Array(this._base64ToArrayBuffer(b64));
    if (combined.length < WebCrypt.SALT_LENGTH + WebCrypt.IV_LENGTH) {
      throw new Error("Invalid encrypted data");
    }

    const salt = combined.slice(0, WebCrypt.SALT_LENGTH);
    const iv = combined.slice(WebCrypt.SALT_LENGTH, WebCrypt.SALT_LENGTH + WebCrypt.IV_LENGTH);
    const ciphertext = combined.slice(WebCrypt.SALT_LENGTH + WebCrypt.IV_LENGTH);

    const key = await this._deriveKey(password, salt);
    const decrypted = await crypto.subtle.decrypt(
      { name: WebCrypt.ALGORITHM, iv },
      key,
      ciphertext
    );
    return new TextDecoder().decode(decrypted);
  }

  // File (streaming)
  async encryptFile(fileOrBlob, password) {
    const salt = crypto.getRandomValues(new Uint8Array(WebCrypt.SALT_LENGTH));
    const baseIv = crypto.getRandomValues(new Uint8Array(WebCrypt.IV_LENGTH));
    const key = await this._deriveKey(password, salt);

    const chunks = [];
    const reader = fileOrBlob.stream().getReader();
    let counter = 0;

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;

      const iv = new Uint8Array(WebCrypt.IV_LENGTH);
      iv.set(baseIv);
      new DataView(iv.buffer).setUint32(WebCrypt.IV_LENGTH - 4, counter++, true);

      const encrypted = await crypto.subtle.encrypt({ name: WebCrypt.ALGORITHM, iv }, key, value);
      chunks.push(encrypted);
    }

    const header = new Uint8Array(WebCrypt.SALT_LENGTH + WebCrypt.IV_LENGTH);
    header.set(salt, 0);
    header.set(baseIv, WebCrypt.SALT_LENGTH);

    const filename = (fileOrBlob.name || "encrypted") + ".encrypted";
    return { blob: new Blob([header, ...chunks]), filename };
  }

  async decryptFile(fileOrBlob, password) {
    const data = new Uint8Array(await fileOrBlob.arrayBuffer());
    if (data.length < WebCrypt.SALT_LENGTH + WebCrypt.IV_LENGTH) throw new Error("Invalid file");

    const salt = data.slice(0, WebCrypt.SALT_LENGTH);
    const baseIv = data.slice(WebCrypt.SALT_LENGTH, WebCrypt.SALT_LENGTH + WebCrypt.IV_LENGTH);
    const ciphertext = data.slice(WebCrypt.SALT_LENGTH + WebCrypt.IV_LENGTH);

    const key = await this._deriveKey(password, salt);
    const chunks = [];
    let offset = 0,
      counter = 0;

    while (offset < ciphertext.byteLength) {
      const size = Math.min(WebCrypt.CHUNK_SIZE, ciphertext.byteLength - offset);
      const chunk = ciphertext.slice(offset, offset + size);

      const iv = new Uint8Array(WebCrypt.IV_LENGTH);
      iv.set(baseIv);
      new DataView(iv.buffer).setUint32(WebCrypt.IV_LENGTH - 4, counter++, true);

      const decrypted = await crypto.subtle.decrypt({ name: WebCrypt.ALGORITHM, iv }, key, chunk);
      chunks.push(decrypted);
      offset += size;
    }

    const filename = (fileOrBlob.name || "decrypted").replace(/\.encrypted$/i, "");
    return { blob: new Blob(chunks), filename };
  }

  // WebRTC Insertable Streams
  async createEncryptTransform(password) {
    const key = await this._deriveKey(password, WebCrypt.WEBRTC_SALT);
    return async (frame, controller) => {
      const iv = crypto.getRandomValues(new Uint8Array(WebCrypt.IV_LENGTH));
      const encrypted = await crypto.subtle.encrypt(
        { name: WebCrypt.ALGORITHM, iv },
        key,
        frame.data
      );
      const newData = new Uint8Array(WebCrypt.IV_LENGTH + encrypted.byteLength);
      newData.set(iv, 0);
      newData.set(new Uint8Array(encrypted), WebCrypt.IV_LENGTH);
      frame.data = newData.buffer;
      controller.enqueue(frame);
    };
  }

  async createDecryptTransform(password) {
    const key = await this._deriveKey(password, WebCrypt.WEBRTC_SALT);
    return async (frame, controller) => {
      if (frame.data.byteLength < WebCrypt.IV_LENGTH) return controller.enqueue(frame);
      const iv = frame.data.slice(0, WebCrypt.IV_LENGTH);
      const ciphertext = frame.data.slice(WebCrypt.IV_LENGTH);
      try {
        const decrypted = await crypto.subtle.decrypt(
          { name: WebCrypt.ALGORITHM, iv },
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
}
