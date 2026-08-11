# WebCrypt

**Zero-dependency end-to-end cryptography suite for the modern web.**

[![npm version](https://img.shields.io/npm/v/webcrypt)](https://www.npmjs.com/package/webcrypt)
[![license](https://img.shields.io/npm/l/webcrypt)](./LICENSE)
[![tests](https://img.shields.io/badge/tests-191%20passed-brightgreen)](./__tests__)
[![coverage](https://img.shields.io/badge/coverage-91%25-brightgreen)](./__tests__)

AES-256-GCM symmetric encryption, RSA-4096 hybrid asymmetric encryption, ECDH key agreement, digital signatures, JWE compact serialization (RFC 7516), and WebRTC insertable streams — built natively for browser and Node.js Web Crypto API environments.

---

## Interactive Live Demo & Documentation

- 🚀 **[Try WebCrypt Live Playground](https://putervision.github.io/WebCrypt/)**: Test AES-256, RSA-4096, ECDH, digital signatures, and file encryption directly in your browser.
- 📚 **[Documentation Index](./docs/)**

---

## Installation

```bash
npm install webcrypt
```

---

## Quick Start Code Examples

### 1. Symmetric Text Encryption (AES-256-GCM)

```js
import { WebCrypt } from "webcrypt";
const wc = new WebCrypt();

const encrypted = await wc.encryptText("Secret message", "my-password");
const decrypted = await wc.decryptText(encrypted, "my-password");
```

### 2. Large File Streaming Encryption (8MB Chunking)

```js
const { blob, filename } = await wc.encryptFile(file, "my-password", { parallelChunks: 4 });
const decrypted = await wc.decryptFile(blob, "my-password");
```

### 3. Public-Key Hybrid Encryption (RSA-4096)

```js
import { WebCryptAsym } from "webcrypt";
const wca = new WebCryptAsym();

const keys = await wca.generateKeyPair(4096);
const encrypted = await wca.encryptText("Secret payload", keys.publicKey);
const decrypted = await wca.decryptText(encrypted, keys.privateKey);
```

### 4. ECDH Key Agreement & One-Step Encryption

```js
const aliceKeys = await wca.generateECDHKeyPair("P-256");
const bobKeys = await wca.generateECDHKeyPair("P-256");

const encrypted = await wca.encryptWithECDH(
  "Confidential data",
  aliceKeys.privateKey,
  bobKeys.publicKey
);
const decrypted = await wca.decryptWithECDH(encrypted, bobKeys.privateKey, aliceKeys.publicKey);
```

### 5. Digital Signatures (ECDSA P-256 / P-384)

```js
const signingKeys = await wca.generateSigningKeyPair("P-256");
const signature = await wca.signText("Tamper-proof payload", signingKeys.privateKey);
const isValid = await wca.verifyText("Tamper-proof payload", signature, signingKeys.publicKey);
```

---

## Complete API & Technical Documentation

For complete method signatures, options, and advanced usage, see our detailed documentation sub-documents:

- 📖 **[Symmetric Encryption API (`WebCrypt`)](./docs/API_SYMMETRIC.md)** — AES-256-GCM, File Streaming, WebRTC E2EE, LRU Key Cache, HMAC.
- 📖 **[Asymmetric Encryption API (`WebCryptAsym`)](./docs/API_ASYMMETRIC.md)** — RSA-4096 Hybrid, ECDH, Signatures, JWE RFC 7516, HKDF.
- 🔒 **[Cryptographic Architecture & Security](./docs/ARCHITECTURE.md)** — Threat Model, Timing-Safe Helpers, Grover Quantum Resistance.
- ⚛️ **[Post-Quantum Cryptography Guide](./docs/PQC.md)** — Kyber/Dilithium stubs & liboqs-js migration path.
- 🛡️ **[Security Policy](./SECURITY.md)** — Vulnerability reporting and version support table.

---

## License

[MIT](./LICENSE) © PuterVision LLC
