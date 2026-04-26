// src/WebCryptPQC.d.ts
// Post-Quantum Cryptography type definitions

/**
 * WebCryptPQC – Post-quantum key exchange and digital signatures
 *
 * Implements NIST PQC finalists:
 * - Kyber: Lattice-based Key Encapsulation Mechanism (KEM)
 * - Dilithium: Lattice-based Digital Signature Algorithm
 */
declare class WebCryptPQC {
  /**
   * Kyber security levels
   */
  static readonly KYBER_512: "Kyber512";
  static readonly KYBER_768: "Kyber768";
  static readonly KYBER_1024: "Kyber1024";

  /**
   * Kyber parameters including key and ciphertext sizes
   */
  static readonly KYBER_PARAMS: {
    [key: string]: {
      name: string;
      securityLevel: string;
      publicKeySize: number;
      privateKeySize: number;
      ciphertextSize: number;
      sharedSecretSize: number;
    };
  };

  /**
   * Dilithium security levels
   */
  static readonly DILITHIUM_2: "Dilithium2";
  static readonly DILITHIUM_3: "Dilithium3";
  static readonly DILITHIUM_5: "Dilithium5";

  /**
   * Dilithium parameters including key and signature sizes
   */
  static readonly DILITHIUM_PARAMS: {
    [key: string]: {
      name: string;
      securityLevel: string;
      publicKeySize: number;
      privateKeySize: number;
      signatureSize: number;
    };
  };

  /**
   * SHA-3 hash algorithms
   */
  static readonly HASH_SHA3_256: "SHA3-256";
  static readonly HASH_SHA3_384: "SHA3-384";
  static readonly HASH_SHA3_512: "SHA3-512";

  /**
   * Supported Kyber levels
   */
  static readonly SUPPORTED_KYBER_LEVELS: string[];

  /**
   * Supported Dilithium levels
   */
  static readonly SUPPORTED_DILITHIUM_LEVELS: string[];

  constructor();

  // ─────────────────────── Kyber KEM ───────────────────────

  /**
   * Generate a Kyber key pair for key encapsulation.
   * @param level - Kyber level: "Kyber512" | "Kyber768" | "Kyber1024" (default: Kyber768)
   */
  generateKyberKeyPair(level?: string): Promise<{
    publicKey: Uint8Array;
    privateKey: Uint8Array;
  }>;

  /**
   * Encapsulate: Create a shared secret and ciphertext using recipient's Kyber public key.
   * @param kyberPublicKey - Recipient's Kyber public key
   * @param level - Kyber level (default: Kyber768)
   * @returns Ciphertext and derived shared secret
   */
  kyberEncapsulate(
    kyberPublicKey: Uint8Array,
    level?: string
  ): Promise<{
    ciphertext: Uint8Array;
    sharedSecret: Uint8Array;
  }>;

  /**
   * Decapsulate: Recover the shared secret using private key and ciphertext.
   * @param ciphertext - Encapsulated ciphertext from kyberEncapsulate
   * @param kyberPrivateKey - Own Kyber private key
   * @param level - Kyber level (default: Kyber768)
   * @returns The shared secret
   */
  kyberDecapsulate(
    ciphertext: Uint8Array,
    kyberPrivateKey: Uint8Array,
    level?: string
  ): Promise<Uint8Array>;

  // ─────────────────────── Dilithium Signatures ───────────────────────

  /**
   * Generate a Dilithium key pair for digital signatures.
   * @param level - Dilithium level: "Dilithium2" | "Dilithium3" | "Dilithium5" (default: Dilithium3)
   */
  generateDilithiumKeyPair(level?: string): Promise<{
    publicKey: Uint8Array;
    privateKey: Uint8Array;
  }>;

  /**
   * Sign a message using Dilithium private key.
   * @param message - Message to sign (string or Uint8Array)
   * @param dilithiumPrivateKey - Dilithium private key
   * @param level - Dilithium level (default: Dilithium3)
   * @returns Digital signature
   */
  dilithiumSign(
    message: string | Uint8Array,
    dilithiumPrivateKey: Uint8Array,
    level?: string
  ): Promise<Uint8Array>;

  /**
   * Verify a Dilithium signature.
   * @param message - Original message (string or Uint8Array)
   * @param signature - Signature from dilithiumSign
   * @param dilithiumPublicKey - Dilithium public key
   * @param level - Dilithium level (default: Dilithium3)
   * @returns True if valid
   */
  dilithiumVerify(
    message: string | Uint8Array,
    signature: Uint8Array,
    dilithiumPublicKey: Uint8Array,
    level?: string
  ): Promise<boolean>;

  // ─────────────────────── Hybrid Encryption ───────────────────────

  /**
   * Hybrid encapsulation: Use both Kyber (PQC) and RSA-OAEP.
   * Combines classical and post-quantum key encapsulation for maximum security.
   *
   * @param rsaPublicKey - RSA-4096 public key (classical)
   * @param kyberPublicKey - Kyber public key (post-quantum)
   * @param kyberLevel - Kyber level (default: Kyber768)
   * @returns Shared secret and ciphertexts for both KEM schemes
   */
  hybridEncapsulate(
    rsaPublicKey: CryptoKey,
    kyberPublicKey: Uint8Array,
    kyberLevel?: string
  ): Promise<{
    sharedSecret: Uint8Array;
    kyberCiphertext: Uint8Array;
    rsaWrappedSharedSecret: Uint8Array;
  }>;

  /**
   * Hybrid decapsulation: Recover shared secret using both Kyber and RSA private keys.
   * Falls back to Kyber alone if RSA decryption fails (provides forward secrecy).
   *
   * @param kyberCiphertext - From hybridEncapsulate
   * @param rsaWrappedSharedSecret - From hybridEncapsulate
   * @param rsaPrivateKey - RSA-4096 private key
   * @param kyberPrivateKey - Kyber private key
   * @param kyberLevel - Kyber level (default: Kyber768)
   * @returns The hybrid shared secret
   */
  hybridDecapsulate(
    kyberCiphertext: Uint8Array,
    rsaWrappedSharedSecret: Uint8Array,
    rsaPrivateKey: CryptoKey,
    kyberPrivateKey: Uint8Array,
    kyberLevel?: string
  ): Promise<Uint8Array>;

  // ─────────────────────── Key Serialization ───────────────────────

  kyberPublicKeyToBase64(publicKey: Uint8Array): string;
  kyberPublicKeyFromBase64(b64: string): Uint8Array;
  kyberPrivateKeyToBase64(privateKey: Uint8Array): string;
  kyberPrivateKeyFromBase64(b64: string): Uint8Array;

  dilithiumPublicKeyToBase64(publicKey: Uint8Array): string;
  dilithiumPublicKeyFromBase64(b64: string): Uint8Array;
  dilithiumPrivateKeyToBase64(privateKey: Uint8Array): string;
  dilithiumPrivateKeyFromBase64(b64: string): Uint8Array;
}

export { WebCryptPQC, WebCryptPQC as default };
