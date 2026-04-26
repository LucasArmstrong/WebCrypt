# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
