# WebCrypt Security & Performance Improvement Plan

**Date:** 2026-08-04  
**Project:** WebCrypt v0.6.5 — Zero-dependency AES-256-GCM encryption suite  
**Scope:** Security hardening, performance optimization, documentation fixes, TypeScript declaration sync, CI/CD workflow enhancement  
**Target Version:** v0.7.0

---

## TL;DR

WebCrypt is a well-structured zero-dependency cryptography library with high test coverage (174 tests passing, ~89.6% statement coverage / ~77.9% branch coverage). A comprehensive audit of the codebase and previous plan identified **7 critical/high security issues**, **3 performance bottlenecks**, and **4 documentation/TypeScript/infrastructure gaps**.

Notably, empirical verification confirms `.gitignore` and `.github/workflows/ci.yml` **already exist** in the repository (contrary to initial plan assumptions) but require enhancement. This updated plan refines all tasks across 4 phases: Critical Security Fixes → High-Priority Security → Performance Improvements → Infrastructure, TypeScript & Documentation Enhancements.

---

## Project Overview

| Aspect           | Detail                                                                                                                                                   |
| ---------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Version**      | v0.6.5 (targeting v0.7.0 for this plan)                                                                                                                  |
| **Modules**      | `WebCrypt.js` (AES-256-GCM + PBKDF2), `WebCryptAsym.js` (RSA-OAEP + ECDH + ECDSA + JWE), `WebCryptPQC.js` (Kyber/Dilithium stubs), `TimingSafeHelper.js` |
| **Tests**        | 174 tests across 19 test suites — ALL PASSING                                                                                                            |
| **Coverage**     | **89.62% statements / 77.87% branches** (target: ≥90% statements / ≥80% branches)                                                                        |
| **Build**        | tsup (ESM + CJS), TypeScript definitions via `--dts`, Jest with ESM (`--experimental-vm-modules`)                                                        |
| **Dependencies** | Zero runtime dependencies; devDeps: jest, prettier, tsup, typescript                                                                                     |

### Architecture Clusters (from codebase analysis)

1. **`src/WebCrypt.js`** — Symmetric encryption core (`encryptText`, `decryptText`, `_deriveKey`, active `keyCache` LRU, base64 utilities, HMAC, WebRTC transforms)
2. **`src/WebCryptAsym.js`** — Asymmetric encryption (`encryptText`/`decryptText` hybrid RSA+AES, ECDH key exchange, ECDSA signatures, JWE, HKDF/SHA3 KDFs, file streaming, deprecated key cache stubs)
3. **`src/WebCryptPQC.js`** — Post-quantum stubs (Kyber KEM, Dilithium signatures, hybrid encapsulation, SHA-3 hashing)
4. **`src/TimingSafeHelper.js`** — Timing attack protection (`constantTimeCompareStrings`, `timingSafeVerify`, `sleepWithDummyOps`)
5. **Key derivation cluster** — PBKDF2, Argon2 fallback, SHA-3 KDF, HKDF-SHA3/SHA2, hierarchical key derivation
6. **Serialization cluster** — Base64 encode/decode utilities (present across source modules)

---

## Findings Summary

### Security Issues Found

| #   | Severity | File(s)                                  | Issue                                                                                                                                         | Status / Finding Validation                                                   |
| --- | -------- | ---------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------- |
| S1  | P0       | `src/WebCryptPQC.js`                     | `dilithiumVerify()` returns `true` for any valid-sized signature — no cryptographic verification under stub mode                              | Confirmed: returns `true` on length check alone                               |
| S2  | P0       | `src/WebCryptAsym.js`                    | Dead code: deprecated key cache stubs (`_getCachedKey()`, `_cacheKey()`, `clearKeyCache()`, `stopAutoCleanup()`) present in asymmetric module | Confirmed: unused stubs remain; need cleanup and TypeScript alignment         |
| S3  | P1       | All source files                         | `_arrayBufferToBase64()` uses `String.fromCharCode.apply(null, bytes.subarray(...))` — risks call stack overflow on large buffers (>32KB)     | Confirmed: fragile pattern across all 3 main source files                     |
| S4  | P1       | `src/WebCryptAsym.js`                    | `deriveKeyArgon2()` / `deriveKeyArgon2Enhanced()` silently fall back to PBKDF2 without explicit deprecation annotations in JSDoc              | Confirmed: fallback warning exists in code, but needs JSDoc `@deprecated` tag |
| S5  | P1       | `src/WebCrypt.js`, `src/WebCryptAsym.js` | Fixed salt `DEFAULT_HMAC_SALT` is hardcoded string — predictable key derivation for HMAC when no custom salt provided                         | Confirmed: predictable fallback salt in non-WebRTC paths                      |
| S6  | P1       | `src/WebCryptAsym.js`                    | `authenticatePoly1305()` uses `{ name: "Poly1305" }` which is NOT a standard Web Crypto algorithm — throws `NotSupportedError`                | Confirmed: invalid Web Crypto algorithm name                                  |
| S7  | P2       | `.github/workflows/ci.yml`, `.gitignore` | Existing `.gitignore` and `ci.yml` exist but lack security audit step, coverage gate enforcement, and Node version matrix updates             | Updated: `.gitignore` and `ci.yml` exist, need refinement                     |

### Performance Issues Found

| #   | Severity | File(s)                                  | Issue                                                                                                                    |
| --- | -------- | ---------------------------------------- | ------------------------------------------------------------------------------------------------------------------------ |
| P1  | High     | `src/WebCrypt.js`                        | `generateHmacKeySHA3()` uses 600,000 iterations of SHA-3 hashing in JS loop — extremely slow (~2-5s)                     |
| P2  | Medium   | All source files                         | `_base64ToArrayBuffer()` uses byte-by-byte `for` loop with `charCodeAt` — `Uint8Array.from(atob(...))` pattern is faster |
| P3  | Low      | `src/WebCrypt.js`, `src/WebCryptAsym.js` | Sequential chunk processing in file encryption/decryption streams — misses parallel chunk processing capability          |

### Documentation & TypeScript Gaps Found

| #   | Severity | File(s)      | Issue                                                                                                                                                      |
| --- | -------- | ------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| D1  | P2       | `README.md`  | References non-existent methods (`encryptWithECDH`/`decryptWithECDH`) and wrong progress callback signature in code examples                               |
| D2  | P2       | `README.md`  | "Quantum-resistant key derivation" claim for PBKDF2 is misleading — PBKDF2 is Grover-resistant at AES-256 level but not quantum-proof                      |
| D3  | P2       | `src/*.d.ts` | TypeScript declarations (`WebCrypt.d.ts`, `WebCryptAsym.d.ts`, `WebCryptPQC.d.ts`) must be updated to match modified/deprecated signatures and new options |

---

## Plan: Security & Performance Hardening (v0.7.0)

### Phase 1: Critical Security Fixes (P0 — Block Production)

#### Step 1.1: Fix `dilithiumVerify()` stub logic

- **File:** `src/WebCryptPQC.js`
- **Issue:** `dilithiumVerify()` currently returns `true` for any signature whose size matches `signatureSize`, providing no verification.
- **Fix:** Implement signature validation matching `dilithiumSign()` stub logic — verify that the signature bytes match the SHA-3 hash signature computed from the message and private key/public key stub material. Return `false` if verification fails.
- **Impact:** Eliminates false positive signature verifications in stub mode.

#### Step 1.2: Clean up deprecated key cache stubs in WebCryptAsym

- **Files:** `src/WebCryptAsym.js`, `src/WebCryptAsym.d.ts`
- **Issue:** Deprecated stub methods (`_getCachedKey()`, `_cacheKey()`, `clearKeyCache()`, `stopAutoCleanup()`) exist in `WebCryptAsym.js` while active caching lives in `WebCrypt.js`.
- **Fix:** Remove unused interior code, mark methods explicitly with `@deprecated` JSDoc annotations, and update `WebCryptAsym.d.ts` to maintain clean backwards compatibility without misleading users.
- **Impact:** Eliminates dead code confusion and aligns TypeScript definitions.

#### Step 1.3: Add explicit runtime warnings and JSDoc for Argon2 fallback paths

- **Files:** `src/WebCryptAsym.js`, `src/WebCryptAsym.d.ts`
- **Issue:** `deriveKeyArgon2()` / `deriveKeyArgon2Enhanced()` fall back to PBKDF2.
- **Fix:** Add JSDoc `@deprecated` tags to `deriveKeyArgon2` recommending external `argon2-browser` package or `deriveKeyPBKDF2`, and ensure `console.warn()` is consistently emitted on invocation.
- **Impact:** Prevents false assumption of Argon2 security level.

---

### Phase 2: High-Priority Security Fixes (P1)

#### Step 2.1: Fix `_arrayBufferToBase64` call stack overflow risk

- **Files:** `src/WebCrypt.js`, `src/WebCryptAsym.js`, `src/WebCryptPQC.js`
- **Issue:** `String.fromCharCode.apply(null, bytes.subarray(...))` risks exceeding V8 call stack size on large buffers (>32KB).
- **Fix:** Implement robust chunked base64 conversion loop using max 32KB chunks with explicit loop indexing rather than `.apply()`.
- **Impact:** Prevents call stack overflow errors during large payload base64 encoding.

#### Step 2.2: Fix fixed salt predictability for HMAC key derivation

- **Files:** `src/WebCrypt.js`, `src/WebCryptAsym.js`
- **Issue:** `DEFAULT_HMAC_SALT` is a fixed string, producing predictable key derivation across instances when no custom salt is supplied.
- **Fix:** For non-WebRTC HMAC key derivation without password, generate a random 16-byte salt per key generation instance or require explicit salt. Document WebRTC fixed salt constraints with `@warning` annotations.
- **Impact:** Prevents predictable key generation across different HMAC deployments.

#### Step 2.3: Fix `authenticatePoly1305` unsupported Web Crypto algorithm crash

- **Files:** `src/WebCryptAsym.js`, `src/WebCryptAsym.d.ts`
- **Issue:** `{ name: "Poly1305" }` throws `NotSupportedError` in Web Crypto API.
- **Fix:** Update `authenticatePoly1305()` to throw a clear descriptive `Error` ("Poly1305 is not supported by standard Web Crypto API; use signHMAC() instead") or provide Poly1305 via standard HMAC fallback, with `@deprecated` JSDoc tags.
- **Impact:** Replaces unhandled Web Crypto exceptions with actionable error messages and guidance.

---

### Phase 3: Performance Improvements (P2)

#### Step 3.1: Reduce SHA-3 KDF iteration count in HMAC key derivation

- **File:** `src/WebCrypt.js` (`generateHmacKeySHA3`)
- **Issue:** 600,000 iterations of SHA-3 hashing in JS loops takes seconds per key generation.
- **Fix:** Reduce default iterations for HMAC key derivation from 600,000 to 10,000 iterations (sufficient for HMAC key derivation), and allow optional `iterations` parameter. Update tests accordingly.
- **Impact:** Improves HMAC key generation execution time from ~2-5s to under 100ms.

#### Step 3.2: Optimize `_base64ToArrayBuffer` decoding pattern

- **Files:** `src/WebCrypt.js`, `src/WebCryptAsym.js`, `src/WebCryptPQC.js`
- **Issue:** Byte-by-byte `for` loop with `charCodeAt` is slower than array-from transformation.
- **Fix:** Refactor base64 decoding to `Uint8Array.from(atob(padded), c => c.charCodeAt(0))` across all modules.
- **Impact:** Increases base64 decoding throughput for encrypted payloads.

#### Step 3.3: Add parallel chunk processing option for file encryption streams

- **Files:** `src/WebCrypt.js`, `src/WebCryptAsym.js`, `src/*.d.ts`
- **Issue:** File encryption and decryption process chunks strictly sequentially.
- **Fix:** Add optional `parallelChunks` parameter (default: 1) to `encryptFile`/`decryptFile` to enable concurrency via windowed `Promise.all`. Update TypeScript declarations.
- **Impact:** Accelerates file encryption/decryption on multi-core systems.

---

### Phase 4: Infrastructure, TypeScript & Documentation Enhancements (P3)

#### Step 4.1: Audit and update existing `.gitignore`

- **File:** `.gitignore`
- **Status:** File exists.
- **Fix:** Verify and ensure all local memory databases (`.state-memory-mcp/`, `.vision-memory-mcp/`), build outputs (`dist/`), test coverage (`coverage/`), logs, and environment files (`.env`) are strictly ignored.
- **Impact:** Clean git state and prevention of accidental key/db commits.

#### Step 4.2: Enhance existing GitHub Actions CI/CD workflow

- **File:** `.github/workflows/ci.yml`
- **Status:** File exists.
- **Fix:** Update workflow to include: Node.js 18.x, 20.x, 22.x matrix, `npm run format:check`, unit test execution, coverage enforcement check, and `npm audit --audit-level=high` step.
- **Impact:** Continuous integration quality gate with automated security auditing.

#### Step 4.3: Sync TypeScript Declarations & Correct Documentation

- **Files:** `src/*.d.ts`, `README.md`
- **Fix:**
  1. Update `src/WebCrypt.d.ts`, `src/WebCryptAsym.d.ts`, `src/WebCryptPQC.d.ts` to match updated parameters (`parallelChunks`, optional salt, deprecated tags).
  2. Correct `README.md` API examples (remove references to `encryptWithECDH`, fix `encryptFileWithProgress` callback signature, and clarify PBKDF2 quantum claims).
- **Impact:** Accurate TypeScript autocomplete and trustworthy developer documentation.

---

## Relevant Files

### Source Files (to be modified)

- `src/WebCrypt.js` — Base64 utilities, HMAC SHA-3 iteration count, salt generation, stream processing
- `src/WebCryptAsym.js` — Deprecated key cache stubs, Poly1305 error handling, Argon2 JSDoc, streaming fixes
- `src/WebCryptPQC.js` — `dilithiumVerify()` stub verification logic, base64 utilities
- `src/*.d.ts` — TypeScript definitions for all 3 modules

### Test Files (to be updated / extended)

- `__tests__/WebCryptFullCoverage.test.js` — HMAC SHA3 iteration tests
- `__tests__/WebCryptAsymDeepCoverage.test.js` — Poly1305 handling & Argon2 warning tests
- `__tests__/WebCryptPQC*.test.js` — Dilithium verification stub test validation

### Documentation & Infrastructure Files

- `README.md` — API documentation fixes
- `.gitignore` — Ensure coverage and memory db files ignored
- `.github/workflows/ci.yml` — Enhanced CI pipeline

---

## Verification Steps

1. **Run unit test suite:** `npm test` — verify all 174+ unit tests pass cleanly.
2. **Run test coverage:** `npm run test:coverage` — target ≥90% statements and ≥80% branches.
3. **Verify TypeScript compilation & build:** `npm run build` — confirm `tsup` generates ESM, CJS, and `.d.ts` without errors.
4. **Verify formatting:** `npm run format:check` — ensure Prettier compliance across all source and test files.
5. **Benchmark HMAC generation:** Validate `generateHmacKeySHA3()` completion time under reduced iterations.
6. **Verify Base64 stack safety:** Test roundtrip on payload > 64KB without call stack errors.

---

## Decisions & Assumptions

- **PQC remains stub implementation:** Kyber and Dilithium remain polyfill stubs using SHA-3 hashing; production PQC requires external `liboqs-js`.
- **Argon2 recommendation:** Web Crypto API does not natively support Argon2id; PBKDF2 with high iterations remains the built-in fallback while JSDoc points to `argon2-browser`.
- **Infrastructure files exist:** `.gitignore` and `.github/workflows/ci.yml` were confirmed present in repository audit and will be enhanced rather than created from scratch.
- **TypeScript declaration parity:** All `.js` changes must be reflected in corresponding `.d.ts` files to maintain strict type safety.
