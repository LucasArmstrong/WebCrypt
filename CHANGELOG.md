# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.6.4] - 2026-08-01

### Comprehensive Test Coverage Expansion (95%+)

- **95%+ Test Coverage**: Added comprehensive test suites covering all re-exports (`src/index.js`), timing-safe key verification KDF, stream encryption/decryption, LRU key cache eviction, digital signatures (ECDSA P-256, P-384, RSA-PSS), PEM/JWK key import & export, JWE compact format (RFC 7516), ECDH key agreement, and PQC stub error traps.
- **Strict Coverage Thresholds**: Updated `jest.config.js` global coverage thresholds to `branches: 90%, functions: 95%, lines: 95%, statements: 95%`.
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
- **PuterVision LLC Website Linking**: Updated all PuterVision LLC brand labels and links to point directly to [https://putervision.com](https://putervision.com).
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
