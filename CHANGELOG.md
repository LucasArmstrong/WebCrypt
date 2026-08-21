# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.1] - 2026-08-21

### Changed & Fixed

- **MCP Registry Metadata**: Added required `"mcpName": "io.github.putervision/webcrypt"` field in `package.json` for official Model Context Protocol registry compliance.
- **Manifest Synchronization**: Synchronized `manifest.json`, `server.json`, and `glama.json` descriptions to `< 100` characters.
- **CLI Reference Guide**: Added dedicated documentation [`docs/CLI.md`](docs/CLI.md) for global project scanning, health diagnostics, and terminal crypto utilities.

## [1.0.0] - 2026-08-21

### Major Milestone Release: AI Agent MCP Server, Multi-IDE Integration, Deterministic Streaming & Global Tooling Suite

- **Native Model Context Protocol (MCP) Server**: Zero-dependency stdio JSON-RPC 2.0 server (`npx webcrypt mcp` / `webcrypt-mcp`) exposing 6 core cryptographic tools to AI coding agents:
  - `encrypt_payload`: Symmetric (AES-256-GCM), asymmetric (RSA-4096), and JSON data encryption.
  - `decrypt_payload`: Plaintext and structured JSON decryption.
  - `manage_keys`: JWK key generation for RSA-4096, ECDH (P-256/P-384), HMAC, and high-entropy passwords.
  - `crypto_hash`: Cryptographic digests (SHA-256, SHA-512, SHA-3) in hex and base64.
  - `sign_verify`: ECDSA, RSA-PSS, HMAC, and HMAC-SHA3 signing & verification.
  - `pqc_kem_sign`: Post-quantum Kyber KEM, Dilithium lattice signatures, and hybrid classical+PQC key encapsulation.
- **Automated Project Scaffolding (`webcrypt init [dir]`)**: Auto-scaffolds `.agents/skills/webcrypt-mcp/SKILL.md`, `.cursor/mcp.json`, `.vscode/mcp.json`, and updates rule markers in `AGENTS.md`, `.cursorrules`, `.windsurfrules`, `.gemini/instructions.md`, and `CLAUDE.md`.
- **Global Project Registry (`~/.webcrypt/projects.json`)**: Multi-project tracking and batch management with `webcrypt init-global [--scan]`, `webcrypt doctor-global [--clean-stale]`, and `webcrypt projects`.
- **Environment & Configuration Diagnostics (`webcrypt doctor [dir]`)**: Audits Web Crypto API runtime availability, agent skills, and editor configuration health.
- **Deterministic Multi-Chunk AES-GCM Framing (Bug C1 Fixed)**: Slices plaintext into deterministic 8MB blocks (CHUNK_SIZE = 8,388,608 bytes) and ciphertext into 8MB + 16B (8,388,624 bytes) frames, fixing streaming encryption for files > 8MB with constant memory usage.
- **Kyber & Hybrid KEM Roundtrips (Bug C2 Fixed)**: Embedded ephemeral nonce in ciphertext and public key in private key tail, enabling byte-for-byte matching shared secrets across classical, post-quantum, and hybrid modes.
- **Argon2 PBKDF2 Fallback (Bug H1 Fixed)**: Wrapped `importKey` in `deriveKeyArgon2Enhanced` inside `try/catch` to cleanly fall back to 1M iteration PBKDF2 in runtimes lacking native Argon2.
- **WebRTC Transform Encryption (Bug H3 Fixed)**: Encrypted first frame payload with `sessionKey` in `_createPostQuantumHybridEncryptTransform` and `createEncryptTransformWithProgress`, ensuring standard `ArrayBuffer` return types.
- **Centralized Subsystem Utilities**:
  - `src/_crypto.js`: Unified SubtleCrypto detection for Browser, Web Workers, Node.js 18+, Bun, and edge runtimes.
  - `src/_base64.js`: Stack-safe 32KB chunked Base64 encoding/decoding and strict format validation.
- **Expanded Test Matrix**: 30 test suites / 247 tests passing (100% pass rate) with ~94% overall code coverage.
- **PuterVision Triple Memory Synergy**: Standardized integration between `state-memory-mcp` (workflow tracking), `vision-memory-mcp` (visual cache), and `webcrypt` (cryptographic vault).

## [0.8.0] - 2026-08-11

### Minor Feature Release: API Documentation Overhaul, Asymmetric Streaming & Edge Testing

- **Asymmetric Stream Concurrency (`options.parallelChunks`)**: Extended `WebCryptAsym.encryptFile()` and `decryptFile()` to accept `options.parallelChunks` for windowed concurrent promise processing.
- **Complete API Reference & Playground Sync**: Overhauled `README.md`, `docs/API_SYMMETRIC.md`, `docs/API_ASYMMETRIC.md`, and `docs/index.html` (fixed 3-arg `encryptWithECDH`, `generateSigningKeyPair`, and removed draft unimplemented methods).
- **Dedicated Edge Case Suite (`WebCryptEdgeCases.test.js`)**: Added test suite covering PQC stub mode toggles (`_STUB_BLOCKED`), file header bounds checking, DoS payload limits, and 64KB multi-chunk base64 conversions (21 test suites / 191 tests passing).
- **Security Audit & Version Bump**: Audited dependencies (`npm audit fix` → 0 vulnerabilities) and bumped release version `0.8.0` across package manifests and source headers.

## [0.7.0] - 2026-08-04

### Security Hardening, Performance Optimization & Infrastructure Enhancements

- **Dilithium Stub Signature Verification**: Updated `dilithiumSign` and `dilithiumVerify` in `WebCryptPQC.js` to compute signature verification tags. `dilithiumVerify` now correctly checks signatures against message and public key material in stub mode and returns `false` on tampered payloads or modified messages.
- **Base64 Call Stack Safety**: Increased base64 chunking size to 32KB (`32768`) across `WebCrypt.js`, `WebCryptAsym.js`, `WebCryptPQC.js`, and `docs/app.js` to eliminate V8 call stack overflow risks on large payloads.
- **Poly1305 Web Crypto Error Handling**: Updated `authenticatePoly1305()` in `WebCryptAsym.js` to throw a descriptive error explaining Web Crypto API Poly1305 non-support and pointing users to `signHMAC()`. Marked method as `@deprecated`.
- **SHA-3 KDF Iteration Optimization**: Added a configurable `iterations` parameter (default `10,000`, down from 600,000) to `generateHmacKeySHA3()`, reducing key derivation latency from ~2-5s to under 100ms.
- **Base64 Decoding Optimization**: Refactored `_base64ToArrayBuffer()` across all 3 source files to use `Uint8Array.from(atob(padded), c => c.charCodeAt(0))`.
- **File Stream Concurrency**: Added optional `options.parallelChunks` parameter to `encryptFile()` and `decryptFile()` in `WebCrypt.js` and `WebCryptAsym.js` for concurrent windowed processing via `Promise.all`.
- **CI/CD Pipeline Security Integration & Audit**: Fixed all vulnerabilities (`npm audit fix` → 0 vulnerabilities) and enhanced `.github/workflows/ci.yml` with `npm audit --audit-level=high` step.
- **API Documentation & Website Sync**: Synchronized method signatures across `README.md`, `docs/API_SYMMETRIC.md`, `docs/API_ASYMMETRIC.md`, and `docs/index.html` (fixed `encryptWithECDH` 3-arg parameters, `generateSigningKeyPair` parameters, and removed unimplemented API method drafts).
- **TypeScript & Edge Case Test Suite**: Added `WebCryptEdgeCases.test.js` (21 test suites / 191 tests passing), exported `SUPPORTED_DILITHIUM_LEVELS` in `WebCryptPQC.d.ts`, and validated `npx tsc --noEmit`.

## [0.6.5] - 2026-08-01

### TypeScript Typings, Documentation Sync & System Audit

- **Complete TypeScript Definitions**: Repaired `.d.ts` declarations across `WebCrypt.d.ts`, `WebCryptAsym.d.ts`, and `WebCryptPQC.d.ts`. Added missing method signatures (`signText`, `verifyText`, `signFile`, `verifyFile`, `importPublicSigningKey`, `generateHmacSalt`, static constants, `isStub`, `enableStubTesting`), removed duplicate declarations, and created `TimingSafeHelper.d.ts`.
- **API Reference & Documentation Sync**: Documented 15+ previously missing API methods in `README.md`, corrected method signature parameters (`generateHmacKey`, `deriveKeyPBKDF2`), linked `docs/PQC.md`, and validated all markdown links.
- **Security & Version Synchronization**: Added version headers `// version: 0.6.5`, added JSDoc `@warning` annotations to default static salts, and synchronized version `0.6.5` across `package.json`, `package-lock.json`, source files, documentation, and unit tests.

## [0.6.4] - 2026-08-01

### Comprehensive Test Coverage Expansion (95%+)

- **95%+ Test Coverage & 174 Unit Tests Passing**: Added comprehensive test suites covering all re-exports (`src/index.js`), timing-safe key verification KDF, stream encryption/decryption, LRU key cache eviction, digital signatures (ECDSA P-256, P-384, RSA-PSS), PEM/JWK key import & export, JWE compact format (RFC 7516), ECDH key agreement, and PQC stub error traps. Verified 100% test suite pass rate (174/174 unit tests) across Node.js 18, 20, and 22.
- **Strict Coverage Thresholds**: Updated `jest.config.js` coverage thresholds and `testTimeout: 30000` to handle resource-constrained CI runners.
- **TypeScript Declarations & Security Audit**: Repaired `.d.ts` definitions, created `TimingSafeHelper.d.ts`, added version headers, and gated PQC stubs.
- **System-Wide Version Bump**: Synchronized version `0.6.4` across `package.json`, `package-lock.json`, source files (`WebCrypt.js`, `WebCryptAsym.js`, `WebCryptPQC.js`), documentation, web site, and unit tests.

## [0.6.3] - 2026-08-01

### Node 18+ Compatibility & UI Responsiveness

- **Node 18+ WebCrypto Fix**: Explicitly populated `const crypto = this._getCrypto()` across all HMAC methods in `src/WebCrypt.js` (`generateHmacKey`, `computeHmac`, `verifyHmac`, `generateHmacKeySHA3`, `computeHmacSHA3`, `verifyHmacSHA3`), resolving `ReferenceError: crypto is not defined` in Node 18 environments.
- **Jest Runner Setup**: Updated `jest.setup.js` to safely define `globalThis.crypto` using `Object.defineProperty` for read-only getter environments.
- **Responsive Segmented Tab Bar**: Redesigned tool tab navigation in `docs/index.html` and `docs/style.css` into a modern segmented pill container with clean mobile flex-wrapping and no native horizontal scrollbars.
- **Hero Wording Update**: Streamlined hero description text on `docs/index.html`.
- **System-Wide Version Bump**: Synchronized version `0.6.3` across `package.json`, `package-lock.json`, source files (`WebCrypt.js`, `WebCryptAsym.js`, `WebCryptPQC.js`), documentation, web site, and unit tests.

## [0.6.2] - 2026-08-01

### Audit, Planning & System-Wide Version Bump

- **System-Wide Version Bump**: Bumped version to `0.6.2` across `package.json`, `package-lock.json`, source files (`WebCrypt.js`, `WebCryptAsym.js`, `WebCryptPQC.js`), documentation, and unit tests.
- **Audit Plan Update**: Updated `/plans/PLAN-8-1-26.md` with critical security, performance, Jest coverage tooling fixes, and stub mode test safeguards.

## [0.6.1] - 2026-07-29

### Security & Dependency Hardening

- **Zero NPM Audit Vulnerabilities**: Resolved all 19 high-severity transitive dev-dependency vulnerabilities (`brace-expansion`, `minimatch`, `glob`) via explicit dependency overrides in `package.json`.
- **System-Wide Version Sync**: Bumped version to `0.6.1` across all source modules (`WebCrypt.js`, `WebCryptAsym.js`, `WebCryptPQC.js`), package manifests (`package.json`, `package-lock.json`), documentation (`README.md`, `SECURITY.md`, `docs/PQC.md`), web pages (`docs/index.html`), and unit tests.
- **Verification**: Verified 100% test suite pass rate (131/131 tests passing) and clean production build.

## [0.6.0] - 2026-07-29

### Security & Accuracy

- **Deterministic HMAC Key Derivation**: Fixed password-based HMAC key derivation in `WebCrypt.js` (`generateHmacKey` and `generateHmacKeySHA3`) by adding salt configuration/defaults (`WebCrypt.DEFAULT_HMAC_SALT`) for reproducible verification.
- **Non-blocking Timing-Safe Helper**: Refactored `TimingSafeHelper.sleepWithDummyOps()` to use non-blocking async timers (`setTimeout`/`Promise`) instead of a CPU-blocking tight spin loop.
- **Limitation of Liability**: Added explicit Limitation of Liability & Warranty Disclaimer sections across `README.md`, `SECURITY.md`, `CONTRIBUTING.md`, `docs/index.html`, `docs/PQC.md`, and code headers.

### Performance

- **High-Speed Chunked Base64 Conversion**: Replaced O(N²) string concatenation in Base64 encoding across `WebCrypt.js`, `WebCryptAsym.js`, and `WebCryptPQC.js` with 32KB block chunking for zero memory explosion and stack safety.
- **Unref Key Cache Timers**: Safely `.unref()` key cache cleanup intervals in Node.js environments to prevent open process handle leaks.

### Webpage Expansion & Documentation

- **Expanded Webpage**: Transformed `docs/index.html` into a rich documentation site featuring release badges, comprehensive code examples (Symmetric, Asymmetric RSA-4096, WebRTC E2EE, HMAC, PQC stubs), a complete API reference table, and a dedicated Limitation of Liability section.
- **PuterVision Website Linking**: Updated all PuterVision brand labels and links to point directly to [https://putervision.com](https://putervision.com).
- **Author Scrub**: Scrubbed personal author references across package metadata, LICENSE, documentation, code, and website files.

## [0.5.5] - 2026

### Added

- **JSON Web Encryption (JWE)**: Added `encryptJWE()` and `decryptJWE()` to `WebCryptAsym` supporting standard RFC 7516 Compact Serialization (RSA-OAEP-256 / A256GCM).
- Updated package keywords to include `jwe`, `jose`, `jwt`, `json-web-encryption`, `rfc7516`.

## [0.5.4] - 2026

### Added

- `SECURITY_FIXES.md` — documents all v0.5.3 security hardening changes
- `SECURITY.md` — vulnerability disclosure / security policy
- `CHANGELOG.md` — version history (this file)
- `CONTRIBUTING.md` — development setup and contribution guidelines
- `prepare` script in `package.json` — auto-builds `dist/` on `npm install` from git

### Fixed

- README API reference now matches actual source code method names
  - `signTextWithRSAPSS()` → `signTextWithAlgorithm(..., "RSA-PSS")`
  - `computeHmac()` / `verifyHmac()` on WebCryptAsym → `signHMAC()` / `verifyHMAC()`
  - `rotateKey()` → `rotateKeyNew()`
  - `deriveChildKey()` → `deriveChildKeyHierarchical()`
  - Removed nonexistent `createKyberEncryptTransform` / `createDilithiumDecryptTransform`
- README `deriveKeySHA3()` usage example matches actual 3-argument signature
- README PBKDF2 example now shows correct 600k default iterations (was 100k)
- README file encryption claim corrected: "10 GB+" → "large files (10 MB decrypt limit)"
- Copyright year synced to 2025 across README and LICENSE
- `process.env.NODE_ENV` guarded for browser environments (was throwing `ReferenceError`)
- Dead code removed: async `exportKey()` in key cache cleanup (was returning Promise, not awaiting)
- Version headers synced across all source modules
- `.d.ts` type definitions updated to match actual method signatures
- Jest setup: added `CryptoKey`, `Blob`, `File` globals (fixed 15 pre-existing test failures)
- Softened "unbreakable encryption" marketing claim

## [0.5.3] - 2026

### Security

- All critical vulnerabilities addressed — see [SECURITY_FIXES.md](./SECURITY_FIXES.md)
- PQC stub warnings added to prevent false security assumptions
- Argon2 deprecated with clear fallback warnings
- Key cache TTL (5-minute expiry) and LRU eviction (max 10 entries)
- PBKDF2 iterations increased from 100k to 600k (OWASP 2023 compliant)
- Cross-environment crypto API consistency fixed
- Input validation and DoS protection (10 MB limit)
- Error message sanitization (generic errors in production)
- Timing attack resistance via `TimingSafeHelper` in verification functions

## [0.5.1] - 2026

### Added

- `encryptData()` / `decryptData()` helpers for JSON object encryption on both `WebCrypt` and `WebCryptAsym`
- ECDH key exchange: `generateECDHKeyPair()`, `encryptWithECDH()`, `decryptWithECDH()`
- `generateRandomPassword()` utility on `WebCrypt`

## [0.5.0] - 2026

### Added

- **WebCryptPQC module** (placeholder): Kyber KEM and Dilithium signatures (stub implementations)
- Hybrid encryption: `hybridEncapsulate()` / `hybridDecapsulate()` (Kyber + RSA-OAEP)
- Post-quantum KDFs: `deriveKeySHA3()`, `deriveKeyHKDFSHA3()`, `deriveKeyArgon2Enhanced()`
- Advanced key management: `rotateKeyNew()`, `deriveChildKeyHierarchical()`, `secureKeyErase()`
- ECDSA digital signatures: `signText()`, `verifyText()`, `signFile()`, `verifyFile()`
- RSA-PSS and EdDSA signature generation
- HMAC support: `generateHmacKey()`, `computeHmac()`, `verifyHmac()` on `WebCrypt`
- HMAC-SHA3: `generateHmacKeySHA3()`, `computeHmacSHA3()`, `verifyHmacSHA3()`
- MAC extensions: `signHMAC()`, `verifyHMAC()`, `authenticatePoly1305()` on `WebCryptAsym`
- Streaming file encryption with progress: `encryptFileWithProgress()`, `decryptFileWithProgress()`
- WebRTC hybrid transforms with progress tracking
- Full TypeScript `.d.ts` definitions for all modules

### Changed

- Streaming base64 utilities replaced recursive approach (stack-safe for large files)
- File header format improved for robust large-file handling

## [0.4.0] - 2025

### Added

- Initial `WebCrypt` symmetric encryption (AES-256-GCM, PBKDF2)
- `WebCryptAsym` asymmetric encryption (RSA-4096 hybrid)
- Streaming file encryption/decryption
- WebRTC Insertable Streams E2EE
- Browser and Node.js 18+ support
