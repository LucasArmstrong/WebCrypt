// src/WebCrypt.d.ts

/**
 * WebCrypt – Zero-dependency quantum-resistant AES-256-GCM encryption
 *
 * Supports:
 * - Text encryption/decryption
 * - Large file encryption/decryption (streaming)
 * - WebRTC Insertable Streams E2EE (video + audio)
 * - HMAC for message authentication
 *
 * Works in Browser, Node.js 18+, Deno, Cloudflare Workers
 */
declare class WebCrypt {
  /**
   * Encrypts a string and returns Base64-encoded ciphertext
   * @param text Plain text to encrypt
   * @param password Password (or shared secret)
   * @returns Base64 string (salt + iv + ciphertext)
   */
  encryptText(text: string, password: string): Promise<string>;

  /**
   * Decrypts a Base64 string produced by encryptText()
   * @param base64 Encrypted data from encryptText()
   * @param password Must match encryption password
   * @returns Original plain text
   * @throws If password is wrong or data is corrupted
   */
  decryptText(base64: string, password: string): Promise<string>;

  /**
   * Encrypts a File or Blob using streaming (low memory, handles huge files)
   * @param file File or Blob to encrypt
   * @param password Encryption password
   * @returns Object with encrypted Blob and suggested filename
   */
  encryptFile(
    file: File | Blob,
    password: string
  ): Promise<{
    blob: Blob;
    filename: string;
  }>;

  /**
   * Decrypts a .encrypted file produced by encryptFile()
   * @param file Encrypted File or Blob
   * @param password Must match encryption password
   * @returns Object with decrypted Blob and original filename
   * @throws If password is wrong or file is corrupted
   */
  decryptFile(
    file: File | Blob,
    password: string
  ): Promise<{
    blob: Blob;
    filename: string;
  }>;

  /**
   * Creates an encryption transform for WebRTC Insertable Streams
   * Use with RTCRtpSender.transform
   * @param password Shared secret both peers must know
   */
  createEncryptTransform(
    password: string
  ): Promise<
    (
      frame: RTCEncodedVideoFrame | RTCEncodedAudioFrame,
      controller: TransformStreamDefaultController
    ) => Promise<void>
  >;

  /**
   * Creates a decryption transform for WebRTC Insertable Streams
   * Use with RTCRtpReceiver.transform
   * @param password Must match sender's password
   */
  createDecryptTransform(
    password: string
  ): Promise<
    (
      frame: RTCEncodedVideoFrame | RTCEncodedAudioFrame,
      controller: TransformStreamDefaultController
    ) => Promise<void>
  >;

  /**
   * Generates or derives an HMAC key.
   * @param password Optional password for PBKDF2 derivation (if provided, uses 600_000 iterations).
   * @param hash Hash algorithm (default: 'SHA-256').
   * @returns Usable HMAC key.
   */
  generateHmacKey(password?: string, hash?: "SHA-256" | "SHA-384" | "SHA-512"): Promise<CryptoKey>;

  /**
   * Computes HMAC on data.
   * @param data Text or ArrayBuffer to authenticate.
   * @param key HMAC key from generateHmacKey.
   * @returns Base64-encoded HMAC tag.
   */
  computeHmac(data: string | ArrayBuffer, key: CryptoKey): Promise<string>;

  /**
   * Verifies HMAC on data.
   * @param data Text or ArrayBuffer to verify.
   * @param hmac Base64-encoded HMAC tag to check.
   * @param key HMAC key.
   * @returns True if valid.
   */
  verifyHmac(data: string | ArrayBuffer, hmac: string, key: CryptoKey): Promise<boolean>;

  /**
   * Generate a quantum-resistant HMAC key using SHA-3 hash.
   * @param password Optional password for derivation (600k iterations)
   * @param hash Hash algorithm: 'SHA3-256' | 'SHA3-384' | 'SHA3-512' (default: SHA3-256)
   * @returns Usable HMAC key with SHA-3
   */
  generateHmacKeySHA3(
    password?: string,
    hash?: "SHA3-256" | "SHA3-384" | "SHA3-512"
  ): Promise<CryptoKey>;

  /**
   * Compute HMAC using SHA-3 (quantum-resistant).
   * @param data Data to authenticate
   * @param key HMAC key from generateHmacKeySHA3
   * @returns Base64-encoded HMAC tag
   */
  computeHmacSHA3(data: string | ArrayBuffer, key: CryptoKey): Promise<string>;

  /**
   * Verify HMAC using SHA-3 (quantum-resistant).
   * @param data Data to verify
   * @param hmac Base64-encoded HMAC tag
   * @param key HMAC key
   * @returns True if valid
   */
  verifyHmacSHA3(data: string | ArrayBuffer, hmac: string, key: CryptoKey): Promise<boolean>;

  /**
   * Automatically serializes any JavaScript object or array to JSON before encrypting.
   */
  encryptData(data: any, password: string): Promise<string>;

  /**
   * Decrypts the data and automatically parses it back into a JavaScript object.
   */
  decryptData(base64: string, password: string): Promise<any>;

  /**
   * Utility to generate a cryptographically secure random password or key string.
   */
  generateRandomPassword(length?: number): string;

  /**
   * Clear entire key cache.
   */
  clearKeyCache(): void;

  /**
   * Stop automatic cache cleanup interval.
   */
  stopAutoCleanup(): void;
}

/**
 * Default export and named export
 */
export { WebCrypt };
export default WebCrypt;
