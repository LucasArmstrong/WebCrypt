# WebCrypt Architecture & Security Overview

WebCrypt is engineered as a zero-dependency cryptography library for modern web applications, browser extensions, Node.js servers, and WebRTC edge services.

---

## Cryptographic Design & Primitives

WebCrypt exclusively uses standard algorithms implemented directly in browser engine C++ / Rust layers via the native **W3C Web Crypto API (`globalThis.crypto.subtle`)**:

| Primitive                 | Implementation Details                            | Security Standard       |
| ------------------------- | ------------------------------------------------- | ----------------------- |
| **Symmetric Encryption**  | AES-256-GCM (256-bit key, 96-bit IV, 128-bit Tag) | NIST SP 800-38D         |
| **Asymmetric Encryption** | RSA-OAEP 4096-bit with SHA-256                    | RFC 3447 / PKCS #1 v2.2 |
| **Key Agreement**         | ECDH (P-256 / P-384)                              | NIST FIPS 186-4         |
| **Digital Signatures**    | ECDSA (P-256/P-384) & RSA-PSS 4096-bit            | FIPS 186-4 / RFC 8017   |
| **Key Derivation**        | PBKDF2 (SHA-256, 600,000 rounds) & HKDF-SHA256    | OWASP 2025+ / RFC 5869  |
| **Token Format**          | JWE Compact Serialization                         | RFC 7516                |

---

## Security Guarantees & Mitigations

### 1. Timing-Safe Constant-Time Operations

Timing oracle attacks allow eavesdroppers to infer secrets by measuring microsecond differences in comparison functions. `TimingSafeHelper` provides constant-time comparison methods:

- `constantTimeCompareStrings(strA, strB)`
- `constantTimeCompareBuffers(bufA, bufB)`
- `timingSafeVerify(...)`

### 2. Post-Quantum & Quantum Resistance Status

- **Symmetric Encryption (AES-256)**: Resists Grover's quantum search algorithm (effective quantum security: 128 bits).
- **Key Derivation (PBKDF2-SHA256, 600k rounds)**: Resists Grover quantum speedup for passphrase brute forcing.
- **NIST Post-Quantum Cryptography (PQC)**: WebCrypt includes experimental Kyber-768/1024 and Dilithium2/3/5 key exchange and signature stubs. See [docs/PQC.md](./PQC.md) for liboqs migration details.

### 3. Memory & Stream Protection

- Large file streaming (`encryptFile` / `decryptFile`) processes data in 8MB chunks, preventing V8 heap exhaustion on multi-gigabyte files.
- Base64 encoding/decoding is chunked in 32KB windows to eliminate `RangeError: Maximum call stack size exceeded` errors.
