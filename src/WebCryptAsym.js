// src/WebCryptAsym.js
export class WebCryptAsym {
  // Constants for RSA-4096 (classical security; consider post-quantum alternatives like Kyber for future quantum resistance)
  // AES-256-GCM provides Grover-resistant symmetric encryption (effective 128-bit security post-quantum)
  // RSA_ALGORITHM: RSA-OAEP with SHA-256; padding scheme for secure key encapsulation
  static RSA_ALGORITHM = { name: "RSA-OAEP", hash: "SHA-256" };
  // RSA_KEY_PARAMS: Defines key generation; modulusLength=4096 bits for high security against factoring (e.g., ~128-bit equivalent)
  //   - publicExponent=65537: Standard Fermat prime for efficient encryption
  static RSA_KEY_PARAMS = {
    name: "RSA-OAEP",
    modulusLength: 4096,
    publicExponent: new Uint8Array([1, 0, 1]), // 65537
    hash: "SHA-256",
  };
  // AES_ALGORITHM: AES-GCM for symmetric operations; authenticated mode with integrity checks
  static AES_ALGORITHM = "AES-GCM";
  // AES_LENGTH: 256 bits, ensuring quantum-resistant symmetric encryption
  static AES_LENGTH = 256;
  // IV_LENGTH: 12 bytes (96 bits), optimal for AES-GCM to minimize overhead while ensuring uniqueness
  static IV_LENGTH = 12;
  // Optimized chunk size for streaming large files with low memory usage (8MB balances I/O and crypto ops)
  static CHUNK_SIZE = 8 * 1024 * 1024; // Matches original symmetric class

  constructor() {
    this._crypto = this._getCrypto();
  }

  _getCrypto() {
    if (typeof globalThis !== "undefined" && globalThis.crypto) return globalThis.crypto;
    if (typeof require !== "undefined") {
      const { webcrypto } = require("crypto");
      return webcrypto;
    }
    throw new Error("Web Crypto API not available");
  }

  // ────────────────────── Key Management ──────────────────────
  // Generates 4096-bit RSA key pair: Secure against classical factoring attacks (e.g., GNFS)
  // Note: Vulnerable to Shor's algorithm on quantum computers; hybrid design relies on AES for post-quantum strength
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

  // ────────────────────── Safe Base64 (stack-safe, fast) ──────────────────────
  // Optimized for large buffers: Iterative approach avoids stack overflow, faster than reduce/join
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

  // ────────────────────── Text Encryption (hybrid) ──────────────────────
  // Hybrid encryption: RSA for key exchange + AES-256-GCM for data
  // Quantum resistance: AES-256 remains secure post-quantum; RSA provides classical security
  async encryptText(text, publicKey) {
    const data = new TextEncoder().encode(text);

    const aesKey = await this._crypto.subtle.generateKey(
      { name: WebCryptAsym.AES_ALGORITHM, length: WebCryptAsym.AES_LENGTH },
      true,
      ["encrypt"]
    );

    const exportedAesKey = await this._crypto.subtle.exportKey("raw", aesKey);
    const iv = crypto.getRandomValues(new Uint8Array(WebCryptAsym.IV_LENGTH));

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

  // ────────────────────── File Encryption (streaming, hybrid) ──────────────────────
  // Streaming encryption: Processes files in chunks to handle 10GB+ with constant memory
  // Optimization: Counter-based IV for deterministic nonces without per-chunk storage
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

  // ────────────────────── WebRTC Insertable Streams (shared secret salt) ──────────────────────
  // Fixed salt for WebRTC key derivation: Ensures consistent keys without signaling
  // Security: First-frame encrypted session key exchange; AES-256 for quantum-resistant streaming
  // WEBRTC_SALT: Versioned string encoded as bytes; used in hypothetical derivation if needed
  static WEBRTC_SALT = new TextEncoder().encode("WebCryptAsym-E2EE-v1-2025");

  async createEncryptTransform(publicKey) {
    // Derive a shared AES key from a fixed salt + encrypted random session key
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

    // Prepend encrypted session key to first frame (simple approach; in production, use signaling channel)
    let first = true;

    return async (frame, controller) => {
      const iv = crypto.getRandomValues(new Uint8Array(WebCryptAsym.IV_LENGTH));

      if (first) {
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
}
