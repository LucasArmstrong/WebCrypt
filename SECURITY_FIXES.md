# Security Fixes — WebCrypt v1.0.1 & Prior Releases

This document details all security hardening changes introduced in v1.0.1 and prior releases.

---

## WebCrypt v1.0.1 Security Hardening & MCP Tool Suite Audit

- **MCP stdio Protocol Security**: Zero-dependency stdio JSON-RPC 2.0 transport with automatic error isolation, ensuring no sensitive plaintext or keys leak in exception stack traces.
- **Key Usage Separation**: Strict separation between encryption keys (RSA-OAEP, ECDH) and signing keys (ECDSA, RSA-PSS) across both API and MCP tooling to prevent cross-protocol key reuse attacks.
- **Timing-Safe Error Protection**: Constant-time verification comparisons and catch blocks on digital signature verification (`sign_verify` tool and `TimingSafeHelper`).
- **Post-Quantum Guardrail Transport**: Clear visual warnings and stub-mode guards for Kyber and Dilithium operations across stdio JSON-RPC transport to prevent accidental production reliance on placeholder lattice algorithms.
- **Constant Memory Streaming**: Streaming file encryption/decryption pipelines verified for constant memory footprint under multi-gigabyte payloads.

---

## WebCrypt v0.7.0 Audit & Security Hardening

- **Dilithium Stub Signature Verification**: `dilithiumVerify()` in `WebCryptPQC.js` checks signature verification tags matching `dilithiumSign` stub material. Invalid or tampered signatures now correctly return `false`.
- **Base64 Call Stack Safety**: Increased base64 chunking size to 32KB (`32768`) across all source modules to prevent V8 call stack overflow on large payload conversions.
- **Poly1305 Web Crypto Error Handling**: Updated `authenticatePoly1305()` to throw a clear error explaining Web Crypto API Poly1305 non-support and pointing to `signHMAC()`.
- **SHA-3 KDF Iteration Optimization**: Added configurable `iterations` parameter (default `10,000`) to `generateHmacKeySHA3()`, dramatically reducing key derivation latency.
- **Base64 Decoding Optimization**: Refactored `_base64ToArrayBuffer()` across all 3 source modules to `Uint8Array.from(atob(padded), c => c.charCodeAt(0))`.
- **File Stream Concurrency**: Added `options.parallelChunks` parameter to `encryptFile()` and `decryptFile()` for concurrent chunk processing.
- **CI/CD Security Audit**: Integrated `npm audit --audit-level=high` into `.github/workflows/ci.yml`.

## WebCrypt v0.6.5 Audit Fixes

### 1. Non-Exportable HMAC Key Enforcement

- **Issue**: HMAC keys derived via `generateHmacKey()` were imported with `extractable: true`, allowing potentially unauthorized key export.
- **Fix**: Updated `crypto.subtle.importKey()` options to set `extractable: false`, preventing key extraction while maintaining full signing and verification capabilities.

### 2. Timing-Safe Helper Verification Contract

- **Issue**: `TimingSafeHelper.timingSafeVerify()` re-threw internal `crypto.subtle.verify()` exceptions, breaking the expected `Promise<boolean>` return type and risking timing oracle side-channels.
- **Fix**: Wrapped verification in `try/catch` to set `isValid = false` on failure, executing constant-time timing padding before returning `false`.

### 3. Post-Quantum Stub Mode Protection

- **Issue**: Calling placeholder Kyber/Dilithium stubs without explicit opt-in could lead to accidental production use of stub cryptography.
- **Fix**: Added static `_STUB_MODE = true` flag and guard assertions. Production calls throw an error unless `WebCryptPQC.enableStubTesting(true)` is explicitly invoked for testing.

### 4. Stack-Safe Base64 Conversion

- **Issue**: Converting large byte buffers to Base64 using `String.fromCharCode(...uint8)` triggered `RangeError: Maximum call stack size exceeded` in browsers and Node.js.
- **Fix**: Implemented a 1024-byte chunk limit across all Base64 utilities (`_arrayBufferToBase64`), ensuring zero call stack overflow risks regardless of payload size.

### 5. Base64 Unpadded Input Support

- **Issue**: Incoming Base64 payloads missing trailing `=` padding caused `atob()` decoders to fail.
- **Fix**: Added automatic padding normalization in `_base64ToArrayBuffer()`.

### 6. Safe Key Cache Cleanup & Memory Erasure

- **Issue**: Key cache eviction mutated Map objects during iteration and retained key object references.
- **Fix**: Collected expired cache keys into a static array before deletion and explicitly nulled key references (`value.key = null`) upon cache clearance.

### 7. File Encryption Size Limit Expansion

- **Issue**: 10MB limit on `MAX_ENCRYPTED_DATA_SIZE` blocked large file streaming.
- **Fix**: Increased `MAX_ENCRYPTED_DATA_SIZE` to 1 GB (`1024 * 1024 * 1024`) across `WebCrypt` and `WebCryptAsym`.

---

## Critical Fixes (v0.5.3)

### 1. PQC Stub Warnings

**Issue:** The `WebCryptPQC` module could give users a false sense of post-quantum security, since Kyber and Dilithium are placeholder implementations using SHA-3 hashing stubs.

**Fix:** Added prominent `console.warn()` on instantiation and on every `dilithiumVerify()` call. Static `WARNING` string clearly states stub status. README updated with multiple ⚠️ warnings.

---

### 2. Argon2 Deprecation

**Issue:** `deriveKeyArgon2()` silently fell back to PBKDF2 without informing the user, giving a false impression of Argon2id protection.

**Fix:** Added `console.warn()` with clear message that Argon2id is NOT supported by Web Crypto API and that PBKDF2 fallback is being used. Marked method as `@deprecated` with guidance to use `deriveKeyPBKDF2()` directly or integrate `argon2-browser`.

---

### 3. Key Cache TTL & LRU Eviction

**Issue:** Derived keys were cached indefinitely with no expiration or size limits, creating a potential memory leak and increasing the window for key extraction.

**Fix:**

- Added 5-minute TTL (`KEY_CACHE_TTL_MS = 300_000`) per cached key
- Added LRU eviction when cache exceeds `MAX_KEY_CACHE_SIZE` (10 entries)
- Automatic cleanup runs every 60 seconds via `setInterval`
- Best-effort key material overwrite on eviction
- Manual `clearKeyCache()` and `stopAutoCleanup()` methods added

---

### 4. PBKDF2 Iterations Increased to 600,000

**Issue:** Previous iteration count (100,000) was below OWASP 2023 recommendations for PBKDF2-SHA256.

**Fix:** Increased `PBKDF2_ITERATIONS` from 100,000 to 600,000 in both `WebCrypt` and `WebCryptAsym`, aligned with OWASP minimum recommendation for 2023+.

---

### 5. Cross-Environment Crypto API Consistency

**Issue:** `_getCrypto()` methods could behave inconsistently across Browser, Node.js, and edge runtime environments.

**Fix:** Standardized `_getCrypto()` across all modules to check `globalThis.crypto` first (works in browsers, Node.js 20+, Deno, Cloudflare Workers), then fall back to `require("crypto").webcrypto` for Node.js 18+.

---

## High-Priority Fixes

### 6. Input Validation & DoS Protection

**Issue:** No size limits on encrypted data could allow denial-of-service attacks via memory exhaustion.

**Fix:**

- Added `MAX_ENCRYPTED_DATA_SIZE` (10 MB) limit on both `WebCrypt` and `WebCryptAsym`
- Size checks applied before and after loading data into memory
- Minimum length validation for encrypted payloads (salt + IV headers)

---

### 7. Error Message Sanitization

**Issue:** Detailed error messages could leak internal state information to attackers in production.

**Fix:** Detailed error logging (password/key info, stack traces) is now gated behind `process.env.NODE_ENV !== "production"`. Production errors use generic messages like "Decryption failed".

---

### 8. Timing Attack Resistance

**Issue:** Signature and HMAC verification functions used standard `crypto.subtle.verify()` without constant-time padding, potentially leaking validity information through response timing.

**Fix:**

- Added `TimingSafeHelper` module with:
  - `constantTimeCompareStrings()` / `constantTimeCompareBuffers()` — XOR-based comparison
  - `sleepWithDummyOps()` — CPU-bound padding to normalize response time
  - `timingSafeVerify()` — wrapper ensuring minimum 10ms verification time
  - `timingSafeDerive()` — wrapper ensuring minimum 50ms derivation time
- Applied `timingSafeVerify()` to `verifyText()`, `verifyFile()`, and `verifyHMAC()` in `WebCryptAsym`

---

## Recommendations

These fixes address known vulnerabilities, but users should still:

1. **Not rely on WebCryptPQC** for real post-quantum security — integrate [liboqs-js](https://github.com/open-quantum-safe/liboqs) directly
2. **Use strong passwords** — PBKDF2 at 600k iterations protects against brute-force, but weak passwords remain vulnerable
3. **Rotate keys periodically** — use `rotateKeyNew()` for key rotation workflows
4. **Monitor OWASP guidelines** — iteration counts and algorithm recommendations evolve over time
