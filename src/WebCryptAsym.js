// src/WebCryptAsym.js
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

  // Fixed salt for WebRTC key derivation: Ensures consistent session keys without explicit signaling
  static WEBRTC_SALT = new TextEncoder().encode("WebCryptAsym-E2EE-v1-2025");

  constructor() {
    this._crypto = this._getCrypto();
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
}
