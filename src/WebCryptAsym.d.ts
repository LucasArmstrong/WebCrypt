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

  /**
   * PBKDF2 algorithm name
   */
  static readonly PBKDF2_ALGORITHM: "PBKDF2";

  /**
   * Default PBKDF2 hash algorithm
   */
  static readonly PBKDF2_HASH: "SHA-256";

  /**
   * Default number of PBKDF2 iterations
   */
  static readonly PBKDF2_ITERATIONS: number;

  /**
   * Argon2 algorithm name
   */
  static readonly ARGON2_ALGORITHM: "Argon2id";

  /**
   * RSA-PSS algorithm name
   */
  static readonly RSA_PSS_ALGORITHM: "RSA-PSS";

  /**
   * EdDSA algorithm name
   */
  static readonly ED25519_ALGORITHM: "EdDSA";

  /**
   * Ed25519 curve name
   */
  static readonly ED25519_CURVE: "Ed25519";

  constructor();

  /**
   * Generate a new RSA-4096 key pair
   */
  generateKeyPair(): Promise<CryptoKeyPair>;

  /**
   * Generate an ECDSA signing key pair
   * @param curve - Supported curves: 'P-256' (default), 'P-384'
   */
  generateSigningKeyPair(curve?: string): Promise<{
    publicKey: CryptoKey;
    privateKey: CryptoKey;
    publicKeyB64: string;
  }>;

  /**
   * Generate an EdDSA signing key pair
   */
  generateEdDSASigningKeyPair(): Promise<{
    publicKey: CryptoKey;
    privateKey: CryptoKey;
    publicKeyB64: string;
  }>;

  /**
   * Generate an RSA-PSS signing key pair
   * @param modulusLength - RSA key size in bits (default: 2048)
   */
  generateRSAPSSigningKeyPair(modulusLength?: number): Promise<{
    publicKey: CryptoKey;
    privateKey: CryptoKey;
    publicKeyB64: string;
  }>;

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

  /**
   * Create a hybrid encryption transform that supports both classical and post-quantum approaches
   * @param publicKey - RSA public key for hybrid encryption
   * @param usePostQuantum - Whether to use post-quantum hybrid approach
   */
  createHybridEncryptTransform(
    publicKey: CryptoKey,
    usePostQuantum?: boolean
  ): Promise<
    (
      frame: RTCEncodedVideoFrame | RTCEncodedAudioFrame,
      controller: TransformStreamDefaultController
    ) => Promise<void>
  >;

  /**
   * Enhanced WebRTC transform with progress tracking
   * @param publicKey - RSA public key for hybrid encryption
   * @param onProgress - Callback function to report encryption progress
   */
  createEncryptTransformWithProgress(
    publicKey: CryptoKey,
    onProgress?: (bytesProcessed: number) => void
  ): Promise<
    (
      frame: RTCEncodedVideoFrame | RTCEncodedAudioFrame,
      controller: TransformStreamDefaultController
    ) => Promise<void>
  >;

  /**
   * Encrypt a file with progress tracking
   * @param fileOrBlob - File or Blob to encrypt
   * @param publicKey - RSA public key for hybrid encryption
   * @param onProgress - Callback function to report encryption progress
   */
  encryptFileWithProgress(
    fileOrBlob: Blob | File,
    publicKey: CryptoKey,
    onProgress?: (bytesProcessed: number) => void
  ): Promise<{ blob: Blob; filename: string }>;

  /**
   * Decrypt a file with progress tracking
   * @param fileOrBlob - File or Blob to decrypt
   * @param privateKey - RSA private key for hybrid decryption
   * @param onProgress - Callback function to report decryption progress
   */
  decryptFileWithProgress(
    fileOrBlob: Blob | File,
    privateKey: CryptoKey,
    onProgress?: (bytesProcessed: number) => void
  ): Promise<{ blob: Blob; filename: string }>;

  /**
   * Derive a key using PBKDF2 with configurable parameters
   * @param password - The password to derive the key from
   * @param salt - Salt for the derivation
   * @param iterations - Number of PBKDF2 iterations (default: 100000)
   * @param hash - Hash algorithm (default: SHA-256)
   * @param keyLength - Length of the derived key in bits
   */
  deriveKeyPBKDF2(
    password: string,
    salt: Uint8Array,
    iterations?: number,
    hash?: string,
    keyLength?: number
  ): Promise<CryptoKey>;

  /**
   * Derive a key using Argon2id (where supported)
   * @param password - The password to derive the key from
   * @param salt - Salt for the derivation
   * @param options - Argon2 configuration options
   */
  deriveKeyArgon2(
    password: string,
    salt: Uint8Array,
    options?: {
      iterations?: number;
      memoryCost?: number;
      parallelism?: number;
    }
  ): Promise<CryptoKey>;

  /**
   * Generate a key for symmetric encryption using password-based derivation
   * @param password - Password to derive the key from
   * @param salt - Salt for key derivation
   * @param algorithm - Key derivation algorithm (PBKDF2 or Argon2)
   */
  generateKeyFromPassword(
    password: string,
    salt: Uint8Array,
    algorithm?: "PBKDF2" | "Argon2"
  ): Promise<CryptoKey>;

  /**
   * Generate a new key for symmetric encryption using password-based derivation with key rotation
   * @param password - Password to derive the key from
   * @param salt - Salt for key derivation
   * @param algorithm - Key derivation algorithm (PBKDF2 or Argon2)
   * @param rotationCount - Rotation counter for key derivation
   */
  generateRotatingKey(
    password: string,
    salt: Uint8Array,
    algorithm?: "PBKDF2" | "Argon2",
    rotationCount?: number
  ): Promise<CryptoKey>;

  /**
   * Generate a hierarchical key structure
   * @param masterPassword - Master password for the hierarchy
   * @param path - Path components to derive child keys from
   */
  generateHierarchicalKey(
    masterPassword: string,
    path: string[]
  ): Promise<{
    masterKey: CryptoKey;
    childKeys: { [key: string]: CryptoKey };
  }>;

  /**
   * Generate a key from multiple inputs (e.g., password + salt + nonce)
   * @param inputs - Array of input strings to combine
   * @param salt - Salt for key derivation
   * @param algorithm - Key derivation algorithm (PBKDF2 or Argon2)
   */
  generateKeyFromMultipleInputs(
    inputs: string[],
    salt: Uint8Array,
    algorithm?: "PBKDF2" | "Argon2"
  ): Promise<CryptoKey>;

  /**
   * Sign a text message or data string with configurable algorithms
   * @param text - Text to sign
   * @param privateKey - Private key for signing (ECDSA)
   * @param algorithm - Signature algorithm to use (ECDSA, EdDSA, RSA-PSS)
   */
  signTextWithAlgorithm(
    text: string,
    privateKey: CryptoKey,
    algorithm?: "ECDSA" | "EdDSA" | "RSA-PSS"
  ): Promise<string>;

  /**
   * Verify a signed text message with configurable algorithms
   * @param text - Text that was signed
   * @param signatureB64 - Base64-encoded signature
   * @param publicKey - Public key for verification (ECDSA)
   * @param algorithm - Signature algorithm to use (ECDSA, EdDSA, RSA-PSS)
   */
  verifyTextWithAlgorithm(
    text: string,
    signatureB64: string,
    publicKey: CryptoKey,
    algorithm?: "ECDSA" | "EdDSA" | "RSA-PSS"
  ): Promise<boolean>;

  /**
   * Create an HMAC signature using configurable hash algorithms
   * @param data - Data to sign
   * @param key - HMAC key
   * @param hash - Hash algorithm (SHA-256, SHA-384, or SHA-512)
   */
  signHMAC(data: string, key: CryptoKey, hash?: "SHA-256" | "SHA-384" | "SHA-512"): Promise<string>;

  /**
   * Verify an HMAC signature using configurable hash algorithms
   * @param data - Data that was signed
   * @param signatureB64 - Base64-encoded HMAC signature
   * @param key - HMAC key
   * @param hash - Hash algorithm (SHA-256, SHA-384, or SHA-512)
   */
  verifyHMAC(
    data: string,
    signatureB64: string,
    key: CryptoKey,
    hash?: "SHA-256" | "SHA-384" | "SHA-512"
  ): Promise<boolean>;

  /**
   * Generate a Poly1305 authentication tag
   * @param data - Data to authenticate
   * @param key - Poly1305 key (should be 32 bytes)
   */
  authenticatePoly1305(data: ArrayBuffer, key: CryptoKey): Promise<string>;

  /**
   * Secure random number generation with better entropy sources
   * @param length - Number of bytes to generate
   */
  secureRandom(length: number): Promise<Uint8Array>;

  /**
   * Clear the internal key cache
   */
  clearKeyCache(): void;
}

export { WebCryptAsym };
export default WebCryptAsym;
