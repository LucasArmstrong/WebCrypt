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

---

## Model Context Protocol (MCP) AI Agent Architecture

WebCrypt v1.0.0 introduces a zero-dependency **Model Context Protocol (MCP)** stdio server conforming to JSON-RPC 2.0 and specification `"2024-11-05"`.

```
┌──────────────────────────────────────────────────────────┐
│                   AI Coding Agent                        │
│     (Antigravity / Cursor / Claude / Copilot / Cline)     │
└────────┬───────────────────┬───────────────────┬─────────┘
         │                   │                   │
         ▼                   ▼                   ▼
┌──────────────────┐┌──────────────────┐┌──────────────────┐
│ state-memory-mcp ││ vision-memory-mcp││   webcrypt-mcp   │
│ (Workflow State) ││  (Visual Cache)  ││ (Cryptographic)  │
│  • Task DAG      ││  • Screenshots   ││  • AES-256-GCM   │
│  • Decisions     ││  • UI Grounding  ││  • RSA-4096      │
│  • Blockers      ││  • Transitions   ││  • Signatures    │
└──────────────────┘└──────────────────┘└──────────────────┘
```

### 1. Zero-Dependency Transport & Dispatch

- **Stdio Line Framing**: Transport processes newline-delimited JSON-RPC 2.0 messages over standard I/O with non-blocking stream buffering.
- **Lazy Module Initialization**: `WebCrypt`, `WebCryptAsym`, and `WebCryptPQC` instances are created on-demand when tools are invoked, avoiding initial process lag and console noise.
- **Error Formatting**: Implements standard JSON-RPC 2.0 error codes (`-32700` parse error, `-32601` method not found, `-32602` invalid params).

### 2. Registered Agent MCP Tools

1. `encrypt_payload`: Symmetric (AES-256-GCM) or asymmetric (RSA-4096) string, JSON data, and file encryption.
2. `decrypt_payload`: Symmetric or asymmetric decryption returning original plaintext or structured data.
3. `manage_keys`: Generates JWK-formatted RSA-4096, ECDH (P-256/P-384), HMAC keys, or high-entropy passwords.
4. `crypto_hash`: Cryptographic digest generation (SHA-256, SHA-512, SHA-3) in hex or base64.
5. `sign_verify`: ECDSA, RSA-PSS, or HMAC digital signature creation and validation.
6. `pqc_kem_sign`: Post-quantum Kyber key encapsulation and Dilithium lattice signatures.

### 3. Global Project Registry & Tooling Parity

- **Registry Path**: `~/.webcrypt/projects.json` (overridable via `process.env.WEBCRYPT_REGISTRY_PATH`).
- **CLI Commands**:
  - `webcrypt init [dir]`: Scaffolds agent skills, MCP configurations, and instruction rules.
  - `webcrypt init-global [--scan <dir>] [--clean-stale]`: Re-synchronizes all registered projects.
  - `webcrypt doctor [dir] [--json]`: Diagnoses Web Crypto capabilities, skills, and MCP config validity.
  - `webcrypt doctor-global [--json] [--clean-stale]`: Performs multi-project system health audit.
  - `webcrypt projects [--clean-stale]`: Lists registered projects and status.

For setup details across editors, see [docs/MCP_IDE_SETUP.md](./MCP_IDE_SETUP.md).
