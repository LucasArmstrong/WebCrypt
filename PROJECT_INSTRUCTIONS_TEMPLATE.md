# Project Instructions Template

> **Note**: Running `webcrypt init` in your project root will automatically create/append these instructions to all supported IDE instruction files. This template is kept as a reference.

---

# Project Instructions

<!-- webcrypt-mcp:start -->

## Cryptographic Vault & Security (webcrypt-mcp)

This project provides native `webcrypt-mcp` tooling for zero-dependency AES-256-GCM symmetric encryption, RSA-4096 hybrid public-key encryption, digital signatures, cryptographic hashes, and post-quantum cryptography.

### 1. Mandatory Workflow & Priority

1. **Confidential Artifacts**: Whenever saving sensitive credentials, tokens, or private workflow states, encrypt them using `encrypt_payload(mode: "data", password: "...")` or `encrypt_payload(mode: "symmetric", password: "...")`.
2. **Key Management**: Use `manage_keys(action: "generate", type: "rsa" | "ecdh" | "hmac")` to generate cryptographically strong JWK-formatted keys for inter-agent communication.
3. **Integrity & Signatures**: Before completing tasks that produce verifiable evidence (such as evidence packs or release binaries), compute signatures or HMAC tags using `sign_verify(action: "sign", algorithm: "ECDSA" | "HMAC")`.
4. **Triple Memory Triad**:
   - `state-memory-mcp`: Workflow state tracking.
   - `vision-memory-mcp`: Visual state caching.
   - `webcrypt-mcp`: Local database vault encryption and evidence pack cryptographic signing.

### 2. Quick Tool Reference

- `encrypt_payload`: Encrypt plaintext, structured JSON objects, or files (`symmetric`, `asymmetric`, `data`).
- `decrypt_payload`: Decrypt ciphertext back to plaintext or structured JSON.
- `manage_keys`: Generate RSA-4096, ECDH P-256/P-384, or HMAC keys (JWK format) and secure random passwords.
- `crypto_hash`: Compute cryptographic hash digests (SHA-256, SHA-384, SHA-512, SHA-3).
- `sign_verify`: Sign or verify messages with ECDSA, RSA-PSS, or HMAC.
- `pqc_kem_sign`: Post-quantum Kyber KEM, Dilithium lattice signatures, and hybrid classical+PQC encapsulation.

<!-- webcrypt-mcp:end -->
