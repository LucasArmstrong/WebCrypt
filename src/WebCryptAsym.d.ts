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
    publicKey: CryptoKey,
    options?: { parallelChunks?: number }
  ): Promise<{ blob: Blob; filename: string }>;

  /**
   * Decrypt an asymmetrically encrypted file/blob
   * @returns Object with decrypted Blob and original filename
   */
  decryptFile(
    fileOrBlob: Blob | File,
    privateKey: CryptoKey,
    options?: { parallelChunks?: number }
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
   * @param iterations - Number of PBKDF2 iterations (default: 600000)
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
   * @deprecated Poly1305 is not supported by standard Web Crypto API. Use signHMAC() instead.
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

  /**
   * Stop automatic cache cleanup interval
   */
  stopAutoCleanup(): void;

  // ═══════════════════════════ Post-Quantum Key Derivation ═══════════════════════════

  /**
   * Enhanced Argon2id KDF (quantum-resistant, GPU/ASIC resistant).
   * Stronger than PBKDF2 for high-entropy passwords.
   *
   * @param password - Password to derive from
   * @param salt - Random salt (16+ bytes recommended)
   * @param options - Configuration object
   * @param options.memory - Memory cost in KiB (default: 65536 = 64MB)
   * @param options.iterations - Time cost (default: 3)
   * @param options.parallelism - Parallelism factor (default: 1)
   * @param options.keyLength - Output key length in bits (default: 256)
   * @returns Derived AES key
   */
  deriveKeyArgon2Enhanced(
    password: string,
    salt: Uint8Array,
    options?: {
      memory?: number;
      iterations?: number;
      parallelism?: number;
      keyLength?: number;
    }
  ): Promise<CryptoKey>;

  /**
   * SHA-3 based KDF (post-quantum collision-resistant).
   * Alternative to PBKDF2/Argon2 using quantum-resistant SHA-3 hash.
   *
   * @param password - Password to derive from
   * @param salt - Random salt
   * @param iterations - KDF iterations (default: 50000)
   * @param hash - Hash algorithm: 'SHA3-256' | 'SHA3-384' | 'SHA3-512'
   * @param keyLength - Output key length in bits (default: 256)
   * @returns Derived AES key
   */
  deriveKeySHA3(
    password: string,
    iterations?: number,
    algorithm?: "SHA3-256" | "SHA3-384" | "SHA3-512"
  ): Promise<CryptoKey>;

  /**
   * HKDF with SHA-3 (quantum-resistant key expansion).
   * Suitable for deriving multiple independent keys from a master secret.
   *
   * @param secret - Input key material (IKM)
   * @param salt - Optional salt (default: all zeros)
   * @param info - Optional context/application-specific info
   * @param keyLength - Output key length in bits (default: 256)
   * @returns Derived AES key
   */
  deriveKeyHKDFSHA3(
    secret: Uint8Array,
    salt?: Uint8Array,
    info?: Uint8Array,
    keyLength?: number
  ): Promise<CryptoKey>;

  /**
   * HKDF with SHA-256 (fallback variant).
   */
  deriveKeyHKDFSHA2(
    secret: Uint8Array,
    salt?: Uint8Array,
    info?: Uint8Array,
    keyLength?: number
  ): Promise<CryptoKey>;

  /**
   * Key rotation: Derive new key with fresh salt.
   * Enables periodic key rotation without data re-encryption (in some schemes).
   *
   * @param password - Original password
   * @param newSalt - New salt for re-derivation
   * @param method - KDF method: 'PBKDF2' | 'Argon2' | 'SHA3' | 'HKDF'
   * @returns New derived key
   */
  rotateKeyNew(
    password: string,
    newSalt: Uint8Array,
    method?: "PBKDF2" | "Argon2" | "SHA3" | "HKDF"
  ): Promise<CryptoKey>;

  /**
   * Hierarchical key derivation: Create distinct keys for different purposes.
   * Enables key structures where child keys are derived from a parent key.
   *
   * @param parentKey - Parent AES key
   * @param childSalt - Context/application-specific salt
   * @param purpose - Purpose string (e.g., 'encryption', 'signing', 'hmac')
   * @returns Child derived key
   */
  deriveChildKeyHierarchical(
    parentKey: CryptoKey,
    childSalt: Uint8Array,
    purpose?: string
  ): Promise<CryptoKey>;

  /**
   * Secure key erasure: Overwrite sensitive key material in memory.
   * Best-effort; true secure erasure depends on runtime guarantees.
   *
   * @param key - Key material to erase
   */
  secureKeyErase(key: Uint8Array): void;

  // ────────────────────── ECDH Key Exchange ──────────────────────

  /**
   * Generate an ECDH key pair for key exchange.
   * @param curve - Elliptic curve to use (default: 'P-256')
   */
  generateECDHKeyPair(curve?: string): Promise<{
    publicKey: CryptoKey;
    privateKey: CryptoKey;
    publicKeyB64: string;
  }>;

  /**
   * Export an ECDH public key to base64 for sharing.
   */
  exportECDHPublicKey(publicKey: CryptoKey): Promise<string>;

  /**
   * Import an ECDH public key from base64.
   * @param b64 - Base64 string of the public key
   * @param curve - Curve used (default: 'P-256')
   */
  importECDHPublicKey(b64: string, curve?: string): Promise<CryptoKey>;

  /**
   * Derive a shared secret using ECDH.
   * @param privateKey - Your private key
   * @param publicKey - The other party's public key
   */
  deriveECDHSharedSecret(privateKey: CryptoKey, publicKey: CryptoKey): Promise<CryptoKey>;

  /**
   * Encrypt data automatically deriving an ECDH shared secret.
   * @param data - Serializable data or string to encrypt
   * @param privateKey - Sender's private key
   * @param recipientPublicKey - Recipient's public key
   */
  encryptWithECDH(data: any, privateKey: CryptoKey, recipientPublicKey: CryptoKey): Promise<string>;

  /**
   * Decrypt data automatically deriving an ECDH shared secret.
   * @param b64 - Base64-encoded encrypted payload
   * @param privateKey - Recipient's private key
   * @param senderPublicKey - Sender's public key
   */
  decryptWithECDH(b64: string, privateKey: CryptoKey, senderPublicKey: CryptoKey): Promise<any>;

  /**
   * Automatically serializes any JavaScript object or array to JSON before encrypting.
   */
  encryptData(data: any, publicKey: CryptoKey): Promise<string>;

  /**
   * Decrypts the data and automatically parses it back into a JavaScript object.
   */
  decryptData(b64: string, privateKey: CryptoKey): Promise<any>;

  /**
   * Import a public signing key from base64 (SPKI format)
   * @param publicKeyB64 - Base64 encoded SPKI public key
   * @param curve - Elliptic curve ('P-256' default, 'P-384')
   */
  importPublicSigningKey(publicKeyB64: string, curve?: string): Promise<CryptoKey>;

  /**
   * Sign a text message or data string with ECDSA
   * @param text - Text to sign
   * @param privateKey - ECDSA private key
   * @returns Base64-encoded detached signature
   */
  signText(text: string, privateKey: CryptoKey): Promise<string>;

  /**
   * Verify a signed text message with ECDSA
   * @param text - Text that was signed
   * @param signatureB64 - Base64 signature
   * @param publicKey - ECDSA public key
   */
  verifyText(text: string, signatureB64: string, publicKey: CryptoKey): Promise<boolean>;

  /**
   * Create a detached signature for a file or blob
   * @param fileOrBlob - File or Blob object to sign
   * @param privateKey - ECDSA private key
   */
  signFile(fileOrBlob: any, privateKey: CryptoKey): Promise<{ signatureB64: string; blob: any }>;

  /**
   * Verify a detached signature for a file or blob
   * @param fileOrBlob - File or Blob object that was signed
   * @param signatureB64 - Base64 signature
   * @param publicKey - ECDSA public key
   */
  verifyFile(fileOrBlob: any, signatureB64: string, publicKey: CryptoKey): Promise<boolean>;

  // ────────────────────── JSON Web Encryption (JWE) ──────────────────────

  /**
   * Encrypts payload into a JWE Compact Serialization string.
   * Uses RSA-OAEP-256 for key management and A256GCM for content encryption.
   *
   * @param payload - Data to encrypt (string or serializable object)
   * @param publicKey - Recipient's RSA public key
   * @param customHeaders - Additional JWE protected headers
   * @returns JWE Token string
   */
  encryptJWE(payload: any, publicKey: CryptoKey, customHeaders?: object): Promise<string>;

  /**
   * Decrypts a JWE Compact Serialization string.
   *
   * @param jweToken - JWE Token string
   * @param privateKey - Recipient's RSA private key
   * @returns Decrypted payload (parsed object if applicable, else string)
   */
  decryptJWE(jweToken: string, privateKey: CryptoKey): Promise<any>;
}

export { WebCryptAsym };
export default WebCryptAsym;
