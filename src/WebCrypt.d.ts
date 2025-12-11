// src/WebCrypt.d.ts

/**
 * WebCrypt – Zero-dependency quantum-resistant AES-256-GCM encryption
 *
 * Supports:
 * - Text encryption/decryption
 * - Large file encryption/decryption (streaming)
 * - WebRTC Insertable Streams E2EE (video + audio)
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
}

/**
 * Default export and named export
 */
export { WebCrypt };
export default WebCrypt;
