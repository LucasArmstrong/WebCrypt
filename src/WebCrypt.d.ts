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
}

/**
 * Default export and named export
 */
export { WebCrypt };
export default WebCrypt;
