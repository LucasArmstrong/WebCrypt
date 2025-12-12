// WebCryptAsym.d.ts

/**
 * Asymmetric encryption utility using RSA-OAEP + AES-GCM hybrid encryption.
 * Supports text, file (streaming), and WebRTC insertable streams.
 */
declare class WebCryptAsym {
  /**
   * RSA-OAEP algorithm parameters
   */
  static readonly RSA_ALGORITHM: AlgorithmIdentifier;

  /**
   * Parameters for RSA key generation (4096-bit, SHA-256)
   */
  static readonly RSA_KEY_PARAMS: RsaHashedKeyGenParams;

  /**
   * AES-GCM algorithm name
   */
  static readonly AES_ALGORITHM: "AES-GCM";

  /**
   * AES key length (256 bits)
   */
  static readonly AES_LENGTH: 256;

  /**
   * IV length for AES-GCM (12 bytes recommended)
   */
  static readonly IV_LENGTH: 12;

  /**
   * Chunk size for file streaming (8 MB)
   */
  static readonly CHUNK_SIZE: number;

  /**
   * Fixed salt-like identifier for WebRTC transforms
   */
  static readonly WEBRTC_SALT: Uint8Array;

  constructor();

  /**
   * Generate a new RSA-4096 key pair
   */
  generateKeyPair(): Promise<CryptoKeyPair>;

  /**
   * Export public key to Base64-encoded SPKI format
   */
  exportPublicKey(publicKey: CryptoKey): Promise<string>;

  /**
   * Export private key to Base64-encoded PKCS8 format
   */
  exportPrivateKey(privateKey: CryptoKey): Promise<string>;

  /**
   * Import public key from Base64 SPKI string
   */
  importPublicKey(b64: string): Promise<CryptoKey>;

  /**
   * Import private key from Base64 PKCS8 string
   */
  importPrivateKey(b64: string): Promise<CryptoKey>;

  /**
   * Encrypt text using recipient's public key (hybrid: RSA-wrapped AES-GCM)
   * @returns Base64-encoded encrypted data
   */
  encryptText(text: string, publicKey: CryptoKey): Promise<string>;

  /**
   * Decrypt text using own private key
   */
  decryptText(encryptedB64: string, privateKey: CryptoKey): Promise<string>;

  /**
   * Encrypt a file/blob using recipient's public key (streaming)
   * @returns Object with encrypted Blob and suggested filename
   */
  encryptFile(
    fileOrBlob: Blob | File,
    publicKey: CryptoKey
  ): Promise<{ blob: Blob; filename: string }>;

  /**
   * Decrypt an asymmetrically encrypted file/blob
   * @returns Object with decrypted Blob and original filename
   */
  decryptFile(
    fileOrBlob: Blob | File,
    privateKey: CryptoKey
  ): Promise<{ blob: Blob; filename: string }>;

  /**
   * Create an encryption transform function for WebRTC insertable streams
   * Sends encrypted session key in the first frame.
   */
  createEncryptTransform(
    publicKey: CryptoKey
  ): Promise<
    (
      frame: RTCEncodedVideoFrame | RTCEncodedAudioFrame,
      controller: TransformStreamDefaultController
    ) => Promise<void>
  >;

  /**
   * Create a decryption transform function for WebRTC insertable streams
   * Extracts session key from first frame and decrypts subsequent frames.
   */
  createDecryptTransform(
    privateKey: CryptoKey
  ): Promise<
    (
      frame: RTCEncodedVideoFrame | RTCEncodedAudioFrame,
      controller: TransformStreamDefaultController
    ) => Promise<void>
  >;
}

export { WebCryptAsym };
export default WebCryptAsym;
