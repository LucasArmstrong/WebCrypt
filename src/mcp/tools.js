// src/mcp/tools.js
// Tool schemas and metadata for WebCrypt MCP Server (PuterVision Standard)

export const WEBCRYPT_MCP_TOOLS = [
  {
    name: "encrypt_payload",
    description:
      "Encrypt text, JSON objects, or files using AES-256-GCM symmetric or RSA-4096 hybrid asymmetric encryption.",
    inputSchema: {
      type: "object",
      properties: {
        mode: {
          type: "string",
          enum: ["symmetric", "asymmetric", "data"],
          description:
            "Encryption mode: 'symmetric' (password-based AES-256-GCM), 'asymmetric' (RSA-4096 public key), or 'data' (auto-JSON AES-256-GCM)",
          default: "symmetric",
        },
        data: {
          description: "Plain text, JSON serializable object, or Base64 binary string to encrypt",
        },
        password: {
          type: "string",
          description:
            "Password for symmetric encryption (required for 'symmetric' and 'data' modes)",
        },
        public_key_jwk: {
          type: "object",
          description: "JWK-formatted RSA public key (required for 'asymmetric' mode)",
        },
      },
      required: ["mode", "data"],
    },
  },
  {
    name: "decrypt_payload",
    description: "Decrypt ciphertext produced by WebCrypt back into plaintext or JSON object.",
    inputSchema: {
      type: "object",
      properties: {
        mode: {
          type: "string",
          enum: ["symmetric", "asymmetric", "data"],
          description: "Decryption mode: 'symmetric', 'asymmetric', or 'data'",
          default: "symmetric",
        },
        ciphertext: {
          type: "string",
          description: "Base64-encoded encrypted string from encrypt_payload",
        },
        password: {
          type: "string",
          description:
            "Password used during encryption (required for 'symmetric' and 'data' modes)",
        },
        private_key_jwk: {
          type: "object",
          description: "JWK-formatted RSA private key (required for 'asymmetric' mode)",
        },
      },
      required: ["mode", "ciphertext"],
    },
  },
  {
    name: "manage_keys",
    description:
      "Generate, export, or import cryptographic keypairs (RSA-4096/2048, ECDH P-256/P-384, HMAC).",
    inputSchema: {
      type: "object",
      properties: {
        action: {
          type: "string",
          enum: ["generate", "generate_random_password"],
          description: "Action to perform",
        },
        type: {
          type: "string",
          enum: ["rsa", "ecdh", "ecdsa", "rsa-pss", "hmac"],
          description: "Key type to generate (for action: 'generate')",
        },
        modulusLength: {
          type: "number",
          enum: [2048, 4096],
          default: 4096,
          description: "RSA modulus length in bits",
        },
        namedCurve: {
          type: "string",
          enum: ["P-256", "P-384"],
          default: "P-256",
          description: "Elliptic curve for ECDH",
        },
        length: {
          type: "number",
          default: 32,
          description: "Length for random password or key in bytes",
        },
      },
      required: ["action"],
    },
  },
  {
    name: "crypto_hash",
    description:
      "Compute cryptographic hashes (SHA-256, SHA-384, SHA-512, SHA3-256, SHA3-384, SHA3-512).",
    inputSchema: {
      type: "object",
      properties: {
        algorithm: {
          type: "string",
          enum: ["SHA-256", "SHA-384", "SHA-512", "SHA3-256", "SHA3-384", "SHA3-512"],
          default: "SHA-256",
          description: "Hash algorithm",
        },
        data: {
          type: "string",
          description: "Text data to hash",
        },
        encoding: {
          type: "string",
          enum: ["hex", "base64"],
          default: "hex",
          description: "Output digest encoding",
        },
      },
      required: ["data"],
    },
  },
  {
    name: "sign_verify",
    description:
      "Create or verify digital signatures and HMAC authentication tags (ECDSA, RSA-PSS, HMAC, HMAC-SHA3).",
    inputSchema: {
      type: "object",
      properties: {
        action: {
          type: "string",
          enum: ["sign", "verify"],
          description: "Action to perform: 'sign' or 'verify'",
        },
        algorithm: {
          type: "string",
          enum: ["ECDSA", "RSA-PSS", "HMAC", "HMAC-SHA3"],
          default: "ECDSA",
          description: "Signature or MAC algorithm",
        },
        data: {
          type: "string",
          description: "Message data to sign or verify",
        },
        signature: {
          type: "string",
          description: "Base64 signature tag (required for action: 'verify')",
        },
        password: {
          type: "string",
          description: "Password for HMAC key derivation (used with HMAC algorithms)",
        },
        key_jwk: {
          type: "object",
          description: "JWK formatted key for signing (private) or verifying (public)",
        },
      },
      required: ["action", "data"],
    },
  },
  {
    name: "pqc_kem_sign",
    description:
      "Post-Quantum Cryptography operations (Kyber KEM, Dilithium signatures, and Hybrid classical+PQC KEM).",
    inputSchema: {
      type: "object",
      properties: {
        action: {
          type: "string",
          enum: [
            "generate_kyber_keypair",
            "kyber_encapsulate",
            "kyber_decapsulate",
            "hybrid_encapsulate",
            "hybrid_decapsulate",
            "generate_dilithium_keypair",
            "dilithium_sign",
            "dilithium_verify",
          ],
          description: "PQC action to perform",
        },
        level: {
          type: "string",
          enum: ["Kyber512", "Kyber768", "Kyber1024", "Dilithium2", "Dilithium3", "Dilithium5"],
          default: "Kyber768",
          description: "Security level for Kyber or Dilithium",
        },
        public_key_b64: {
          type: "string",
          description: "Base64 encoded Kyber or Dilithium public key",
        },
        private_key_b64: {
          type: "string",
          description: "Base64 encoded Kyber or Dilithium private key",
        },
        ciphertext_b64: {
          type: "string",
          description: "Base64 encoded Kyber ciphertext (for decapsulate)",
        },
        rsa_public_key_jwk: {
          type: "object",
          description: "JWK RSA public key for hybrid encapsulate",
        },
        rsa_private_key_jwk: {
          type: "object",
          description: "JWK RSA private key for hybrid decapsulate",
        },
        rsa_wrapped_secret_b64: {
          type: "string",
          description: "Base64 RSA wrapped secret for hybrid decapsulate",
        },
        data: {
          type: "string",
          description: "Text message to sign or verify with Dilithium",
        },
        signature_b64: {
          type: "string",
          description: "Base64 Dilithium signature to verify",
        },
      },
      required: ["action"],
    },
  },
];
