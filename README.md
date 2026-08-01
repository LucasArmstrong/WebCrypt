# WebCrypt

**Zero-dependency end-to-end encryption for the modern web.**

[![npm version](https://img.shields.io/npm/v/webcrypt)](https://www.npmjs.com/package/webcrypt)
[![license](https://img.shields.io/npm/l/webcrypt)](./LICENSE)
[![tests](https://img.shields.io/badge/tests-174%20passed-brightgreen)](./__tests__)

AES-256-GCM symmetric encryption, RSA-4096 hybrid asymmetric encryption, ECDH key exchange, digital signatures, HMAC, and streaming file encryption — all powered by the native Web Crypto API with zero runtime dependencies.

---

## Quick Start

```bash
npm install webcrypt
```

**Encrypt and decrypt text:**

```js
import { WebCrypt } from "webcrypt";
const wc = new WebCrypt();

const encrypted = await wc.encryptText("Secret message", "my-password");
const decrypted = await wc.decryptText(encrypted, "my-password");
```

**Encrypt a file:**

```js
const { blob, filename } = await wc.encryptFile(file, "my-password");
```

**Public-key encryption (RSA-4096):**

```js
import { WebCryptAsym } from "webcrypt";
const wca = new WebCryptAsym();

const keys = await wca.generateKeyPair();
const encrypted = await wca.encryptText("Secret", keys.publicKey);
const decrypted = await wca.decryptText(encrypted, keys.privateKey);
```

---

## Table of Contents

- [Features](#features)
- [Modules](#modules)
- [Symmetric Encryption (WebCrypt)](#symmetric-encryption-webcrypt)
- [Asymmetric Encryption (WebCryptAsym)](#asymmetric-encryption-webcryptasym)
- [HMAC](#hmac)
- [Key Derivation](#key-derivation)
- [Post-Quantum Cryptography](#post-quantum-cryptography)
- [API Reference](#api-reference)
- [Security](#security)
- [Environment Support](#environment-support)
- [License](#license)

---

## Features

| Feature                     | Status  | Details                                                    |
| --------------------------- | ------- | ---------------------------------------------------------- |
| Text encryption             | ✅ Done | AES-256-GCM, returns base64 string                         |
| File encryption             | ✅ Done | Streaming — handles large files (1 GB size limit)          |
| WebRTC E2EE                 | ✅ Done | Insertable Streams for video + audio                       |
| Digital signatures          | ✅ Done | ECDSA, RSA-PSS                                             |
| ECDH key exchange           | ✅ Done | P-256 / P-384 Diffie-Hellman                               |
| HMAC                        | ✅ Done | SHA-256/384/512 and SHA-3                                  |
| Key derivation              | ✅ Done | PBKDF2 (600k iterations), SHA-3 KDF, HKDF                  |
| Key caching                 | ✅ Done | Safe unref'd timers & reference nulling                    |
| TypeScript                  | ✅ Done | Full `.d.ts` for all modules                               |
| Zero dependencies           | ✅ Done | Pure Web Crypto API                                        |
| JWE (JSON Web Encryption)   | ✅ Done | RFC 7516 Compact Serialization (RSA-OAEP/A256GCM)          |
| Post-quantum (Kyber/Dilith) | ⚠️ Stub | Stub mode testing guard — see [docs/PQC.md](./docs/PQC.md) |

---

## Modules

WebCrypt is split into three modules. Import only what you need:

```js
import { WebCrypt } from "webcrypt"; // Symmetric (password-based)
import { WebCryptAsym } from "webcrypt"; // Asymmetric (public/private key)
import { WebCryptPQC } from "webcrypt"; // Post-quantum (⚠️ stub)
```

| Module         | Use case                  | Encryption        | Quantum-safe?              |
| -------------- | ------------------------- | ----------------- | -------------------------- |
| `WebCrypt`     | Password-based encryption | AES-256-GCM       | ✅ Yes (Grover-resistant)  |
| `WebCryptAsym` | Public-key encryption     | RSA-4096 + AES    | ⚠️ RSA vulnerable to Shor  |
| `WebCryptPQC`  | Post-quantum (future)     | Kyber + Dilithium | ⚠️ Stub — not real PQC yet |

---

## Symmetric Encryption (WebCrypt)

Password-based AES-256-GCM encryption with PBKDF2 key derivation (600,000 iterations).

### Text

```js
import { WebCrypt } from "webcrypt";
const wc = new WebCrypt();

const encrypted = await wc.encryptText("The treasure is buried under the oak tree", "password");
const decrypted = await wc.decryptText(encrypted, "password");
```

### JSON Data

```js
const data = { message: "Hello", users: ["Alice", "Bob"] };
const encrypted = await wc.encryptData(data, "password");
const decrypted = await wc.decryptData(encrypted, "password");
// decrypted.users → ["Alice", "Bob"]
```

### Files

```js
// Encrypt
const { blob, filename } = await wc.encryptFile(file, "password");

// Decrypt
const { blob: decrypted, filename: originalName } = await wc.decryptFile(encryptedBlob, "password");
```

### WebRTC End-to-End Encryption

```js
const wc = new WebCrypt();
const PASSWORD = "shared-call-secret";

const stream = await navigator.mediaDevices.getUserMedia({ video: true, audio: true });
const pc = new RTCPeerConnection();

// Encrypt outgoing
stream.getTracks().forEach(async track => {
  const sender = pc.addTrack(track, stream);
  sender.transform = new RTCRtpScriptTransform(await wc.createEncryptTransform(PASSWORD));
});

// Decrypt incoming
pc.ontrack = async event => {
  event.receiver.transform = new RTCRtpScriptTransform(await wc.createDecryptTransform(PASSWORD));
  document.getElementById("remoteVideo").srcObject = event.streams[0];
};
```

Both peers use the same password. The SFU/server sees only encrypted data.

---

## Asymmetric Encryption (WebCryptAsym)

RSA-4096 hybrid encryption: RSA-OAEP encrypts an ephemeral AES-256-GCM session key, which encrypts the payload.

### Encrypt / Decrypt

```js
import { WebCryptAsym } from "webcrypt";
const crypt = new WebCryptAsym();

// Generate key pair
const keys = await crypt.generateKeyPair();

// Share public key
const publicKeyB64 = await crypt.exportPublicKey(keys.publicKey);

// Recipient imports and encrypts
const publicKey = await crypt.importPublicKey(publicKeyB64);
const encrypted = await crypt.encryptText("Secret message", publicKey);

// Decrypt with private key
const decrypted = await crypt.decryptText(encrypted, keys.privateKey);
```

### ECDH Key Exchange

Derive a shared secret between two parties without transmitting any secret material.

```js
// Each party generates an ECDH key pair
const alice = await crypt.generateECDHKeyPair();
const bob = await crypt.generateECDHKeyPair();

// Exchange public keys, then encrypt
const encrypted = await crypt.encryptWithECDH(
  { data: "Secret from Alice" },
  alice.privateKey,
  await crypt.importECDHPublicKey(bob.publicKeyB64)
);

// Recipient decrypts
const decrypted = await crypt.decryptWithECDH(
  encrypted,
  bob.privateKey,
  await crypt.importECDHPublicKey(alice.publicKeyB64)
);
// decrypted.data → "Secret from Alice"
```

### Digital Signatures (ECDSA)

```js
// Generate signing key pair
const { publicKey, privateKey, publicKeyB64 } = await crypt.generateSigningKeyPair("P-256");

// Sign
const signature = await crypt.signText("I approve transaction #123", privateKey);

// Verify
const valid = await crypt.verifyText("I approve transaction #123", signature, publicKey);
// valid === true

// Sign/verify files (detached signatures)
const { signatureB64 } = await crypt.signFile(file, privateKey);
const fileValid = await crypt.verifyFile(file, signatureB64, publicKey);
```

### File Encryption with Progress

```js
const { blob, filename } = await crypt.encryptFileWithProgress(file, publicKey, progress => {
  console.log(`${Math.round(progress * 100)}%`);
});
```

### JSON Web Encryption (JWE)

Create and decrypt standard JWE Compact Serialization tokens (RFC 7516) using RSA-OAEP-256 and A256GCM.

```js
import { WebCryptAsym } from "webcrypt";
const crypt = new WebCryptAsym();

// Generate or import key pair
const keys = await crypt.generateKeyPair();

// Encrypt payload into a JWE string
const payload = { userId: 123, role: "admin" };
const jweToken = await crypt.encryptJWE(payload, keys.publicKey, { kid: "my-key-id" });

// Decrypt JWE token
const decrypted = await crypt.decryptJWE(jweToken, keys.privateKey);
// decrypted.role → "admin"
```

---

## HMAC

Message authentication codes using SHA-256, SHA-384, SHA-512, or SHA-3.

```js
import { WebCrypt } from "webcrypt";
const wc = new WebCrypt();

// Generate key and compute HMAC
const key = await wc.generateHmacKey("password");
const hmac = await wc.computeHmac("Important message", key);

// Verify
const valid = await wc.verifyHmac("Important message", hmac, key); // true

// SHA-3 variant (quantum-resistant)
const sha3Key = await wc.generateHmacKeySHA3("password");
const sha3Hmac = await wc.computeHmacSHA3("Important message", sha3Key);
const sha3Valid = await wc.verifyHmacSHA3("Important message", sha3Hmac, sha3Key);
```

---

## Key Derivation

### PBKDF2 (default)

```js
const key = await crypt.deriveKeyPBKDF2("password", "salt"); // 600,000 iterations
```

### SHA-3 KDF

```js
const key = await crypt.deriveKeySHA3("password", 50000, "SHA3-256");
```

### HKDF-SHA3

```js
const masterSecret = new TextEncoder().encode("master-password");
const key = await crypt.deriveKeyHKDFSHA3(masterSecret, saltBytes, infoBytes, 256);
```

### Key rotation and hierarchical keys

```js
// Rotate with a new salt
const rotatedKey = await crypt.rotateKeyNew("password", newSaltBytes, "PBKDF2");

// Derive child keys for different purposes
const encKey = await crypt.deriveChildKeyHierarchical(parentKey, childSalt, "encryption");
const sigKey = await crypt.deriveChildKeyHierarchical(parentKey, childSalt, "signing");
```

---

## Post-Quantum Cryptography

> ⚠️ **STUB IMPLEMENTATION** — WebCryptPQC currently uses SHA-3 hashing stubs, not real lattice-based cryptography. For production PQC, integrate [liboqs-js](https://github.com/open-quantum-safe/liboqs) directly.

WebCryptPQC provides a placeholder API for **Kyber** (key encapsulation) and **Dilithium** (digital signatures) that mirrors the real API surface. Build against it today, swap in real PQC when v0.6+ ships.

```js
import { WebCryptPQC } from "webcrypt";
const pqc = new WebCryptPQC(); // ⚠️ Warns about stub status

const kyberKeys = await pqc.generateKyberKeyPair("Kyber768");
const { ciphertext, sharedSecret } = await pqc.kyberEncapsulate(kyberKeys.publicKey, "Kyber768");
const recovered = await pqc.kyberDecapsulate(ciphertext, kyberKeys.privateKey, "Kyber768");
```

**Full PQC documentation:** [docs/PQC.md](./docs/PQC.md) — includes Kyber, Dilithium, hybrid encryption, security levels, and migration path.

---

## API Reference

### WebCrypt (Symmetric)

```ts
const wc = new WebCrypt();

// Text
wc.encryptText(text: string, password: string): Promise<string>
wc.decryptText(b64: string, password: string): Promise<string>

// JSON data
wc.encryptData(data: any, password: string): Promise<string>
wc.decryptData(b64: string, password: string): Promise<any>

// Files
wc.encryptFile(file: File | Blob, password: string): Promise<{ blob: Blob, filename: string }>
wc.decryptFile(file: File | Blob, password: string): Promise<{ blob: Blob, filename: string }>

// WebRTC E2EE
wc.createEncryptTransform(password: string): Promise<TransformFunction>
wc.createDecryptTransform(password: string): Promise<TransformFunction>

// HMAC
wc.generateHmacSalt(length?: number): Uint8Array
wc.generateHmacKey(password?: string, hash?: string, salt?: Uint8Array | string): Promise<CryptoKey>
wc.computeHmac(data: string | ArrayBuffer, key: CryptoKey): Promise<string>
wc.verifyHmac(data: string | ArrayBuffer, hmac: string, key: CryptoKey): Promise<boolean>

// HMAC-SHA3
wc.generateHmacKeySHA3(password?: string, hash?: string, salt?: Uint8Array | string): Promise<CryptoKey>
wc.computeHmacSHA3(data: string | ArrayBuffer, key: CryptoKey): Promise<string>
wc.verifyHmacSHA3(data: string | ArrayBuffer, hmac: string, key: CryptoKey): Promise<boolean>

// Utilities
wc.generateRandomPassword(length?: number): string
wc.clearKeyCache(): void
wc.stopAutoCleanup(): void
```

### WebCryptAsym (Asymmetric)

```ts
const crypt = new WebCryptAsym();

// Key management
crypt.generateKeyPair(modulusLength?: number): Promise<CryptoKeyPair>
crypt.exportPublicKey(key: CryptoKey): Promise<string>
crypt.exportPrivateKey(key: CryptoKey): Promise<string>
crypt.importPublicKey(b64: string): Promise<CryptoKey>
crypt.importPrivateKey(b64: string): Promise<CryptoKey>

// Text
crypt.encryptText(text: string, publicKey: CryptoKey): Promise<string>
crypt.decryptText(b64: string, privateKey: CryptoKey): Promise<string>

// JSON data
crypt.encryptData(data: any, publicKey: CryptoKey): Promise<string>
crypt.decryptData(b64: string, privateKey: CryptoKey): Promise<any>

// Files
crypt.encryptFile(file: File | Blob, publicKey: CryptoKey): Promise<{ blob, filename }>
crypt.decryptFile(file: File | Blob, privateKey: CryptoKey): Promise<{ blob, filename }>
crypt.encryptFileWithProgress(file, publicKey, onProgress?): Promise<{ blob, filename }>
crypt.decryptFileWithProgress(file, privateKey, onProgress?): Promise<{ blob, filename }>

// ECDH key exchange
crypt.generateECDHKeyPair(curve?: string): Promise<{ publicKey, privateKey, publicKeyB64 }>
crypt.exportECDHPublicKey(key: CryptoKey): Promise<string>
crypt.importECDHPublicKey(b64: string, curve?: string): Promise<CryptoKey>
crypt.deriveECDHSharedSecret(privateKey: CryptoKey, peerPublicKey: CryptoKey): Promise<CryptoKey>
crypt.encryptWithECDH(data: any, privateKey, recipientPublicKey): Promise<string>
crypt.decryptWithECDH(b64: string, privateKey, senderPublicKey): Promise<any>

// Digital Signatures (ECDSA / RSA-PSS)
crypt.generateSigningKeyPair(curve?: string): Promise<{ publicKey, privateKey, publicKeyB64 }>
crypt.generateEdDSASigningKeyPair(): Promise<{ publicKey, privateKey, publicKeyB64 }>
crypt.generateRSAPSSigningKeyPair(modulusLength?: number): Promise<{ publicKey, privateKey, publicKeyB64 }>
crypt.importPublicSigningKey(b64: string, curve?: string): Promise<CryptoKey>
crypt.signText(text: string, privateKey: CryptoKey): Promise<string>
crypt.verifyText(text: string, sig: string, publicKey: CryptoKey): Promise<boolean>
crypt.signFile(file: File | Blob, privateKey: CryptoKey): Promise<{ signatureB64, blob }>
crypt.verifyFile(file: File | Blob, sig: string, publicKey: CryptoKey): Promise<boolean>
crypt.signTextWithAlgorithm(text, privateKey, algorithm?: 'ECDSA' | 'RSA-PSS'): Promise<string>
crypt.verifyTextWithAlgorithm(text, sig, publicKey, algorithm?: 'ECDSA' | 'RSA-PSS'): Promise<boolean>

// JWE (JSON Web Encryption)
crypt.encryptJWE(payload: any, publicKey: CryptoKey, headers?: object): Promise<string>
crypt.decryptJWE(jweToken: string, privateKey: CryptoKey): Promise<any>

// MAC & Poly1305
crypt.signHMAC(data: string, key: CryptoKey, hash?: string): Promise<string>
crypt.verifyHMAC(data: string, sig: string, key: CryptoKey, hash?: string): Promise<boolean>
crypt.authenticatePoly1305(data: string | Uint8Array, key: Uint8Array): Promise<string>

// Key derivation & rotation
crypt.deriveKeyPBKDF2(password, salt, iterations?, hash?, keyLength?): Promise<CryptoKey>
crypt.deriveKeyArgon2(password, salt, options?): Promise<CryptoKey>
crypt.deriveKeySHA3(password, iterations?, algorithm?): Promise<CryptoKey>
crypt.deriveKeyHKDFSHA2(secret, salt?, info?, keyLength?): Promise<CryptoKey>
crypt.deriveKeyHKDFSHA3(secret, salt?, info?, keyLength?): Promise<CryptoKey>
crypt.generateKeyFromPassword(password, salt, algorithm?): Promise<CryptoKey>
crypt.generateRotatingKey(password, salt, algorithm?, rotationCount?): Promise<CryptoKey>
crypt.generateHierarchicalKey(masterPassword, path: string[]): Promise<{ masterKey, childKeys }>
crypt.generateKeyFromMultipleInputs(inputs: string[], salt, algorithm?): Promise<CryptoKey>
crypt.rotateKeyNew(password, newSalt, method?): Promise<CryptoKey>
crypt.deriveChildKeyHierarchical(parentKey, childSalt, purpose?): Promise<CryptoKey>
crypt.secureRandom(length: number): Promise<Uint8Array>
crypt.secureKeyErase(key: Uint8Array): void

// WebRTC Insertable Streams
crypt.createEncryptTransform(publicKey: CryptoKey): Promise<TransformFunction>
crypt.createDecryptTransform(privateKey: CryptoKey): Promise<TransformFunction>
crypt.createHybridEncryptTransform(publicKey, kyberPublicKey, level?): Promise<TransformFunction>
crypt.createEncryptTransformWithProgress(publicKey, onProgress?): Promise<TransformFunction>
```

### WebCryptPQC (Post-Quantum)

See [docs/PQC.md](./docs/PQC.md) for the full API reference.

---

## Security

### What's quantum-safe today

| Layer                 | Algorithm   | Quantum status                                     |
| --------------------- | ----------- | -------------------------------------------------- |
| Symmetric encryption  | AES-256-GCM | ✅ Safe — 128-bit security even with Grover        |
| Key derivation        | PBKDF2 600k | ✅ Safe — no quantum speedup for password cracking |
| HMAC                  | SHA-256/3   | ✅ Safe — collision resistance holds               |
| Asymmetric encryption | RSA-4096    | ⚠️ Vulnerable to Shor's algorithm (est. 2030–2040) |
| Signatures            | ECDSA       | ⚠️ Vulnerable to Shor's algorithm                  |
| PQC (Kyber/Dilithium) | Stubs       | ❌ Not real PQC yet                                |

### Security hardening (v0.6.5)

- **PBKDF2 Iterations**: **600,000** (OWASP 2025+ compliant).
- **Non-Exportable HMAC Keys**: Generated HMAC keys pass `extractable: false` to `crypto.subtle.importKey` preventing secret key extraction while allowing full signing and verification.
- **Constant-Time Verification Contract**: `TimingSafeHelper.timingSafeVerify()` catches signature verification failures and returns `false` with padding instead of re-throwing exceptions.
- **PQC Stub Guard**: `WebCryptPQC._STUB_MODE` throws explicit errors on production calls unless `WebCryptPQC.enableStubTesting(true)` is explicitly enabled for unit testing.
- **Safe Memory Cleanup**: Map mutations are isolated prior to deletion in `clearKeyCache()` and secret `CryptoKey` references are nulled.
- **Stack-Safe Base64**: Uses 1024-byte chunking in Base64 encoding/decoding, eliminating call stack overflow risks across JS runtimes.
- **Base64 Padding Resilience**: `_base64ToArrayBuffer()` automatically normalizes unpadded Base64 strings.
- **Increased File Payload Limit**: `MAX_ENCRYPTED_DATA_SIZE` increased to **1 GB** for large file streaming.
- **Full-Entropy Random Passwords**: `generateRandomPassword()` returns full-entropy hexadecimal strings derived via `crypto.getRandomValues`.
- **SHA-3 Fallback Warning**: Explicit `console.warn` logging when SHA-3 falls back to SHA-256/384/512 in standard Web Crypto runtimes.
- **Sanitized Production Logs**: Detailed internal error logging gated behind `NODE_ENV !== "production"`.

### Known limitations

- **PQC is a stub** — Kyber/Dilithium use SHA-3 hashing, not real lattice-based crypto
- **Argon2id is not supported** by Web Crypto API — falls back to PBKDF2 with a warning
- **JavaScript cannot guarantee secure memory erasure** — key cleanup is best-effort
- **WebRTC E2EE uses a fixed salt** for key derivation from passwords

For vulnerability reporting, see [SECURITY.md](./SECURITY.md).  
For security fix details, see [SECURITY_FIXES.md](./SECURITY_FIXES.md).

---

## Environment Support

**Browser:** Chrome 80+ · Edge 80+ · Firefox 90+ · Safari 15+  
**Runtime:** Node.js 18+ · Deno · Cloudflare Workers · Electron  
**Frameworks:** React · Next.js · Vue · Angular · Svelte

```js
// ES Modules
import { WebCrypt } from "webcrypt";

// CommonJS
const { WebCrypt } = require("webcrypt");
```

---

## License

MIT License — free for personal and commercial use.  
© 2025-2026 [PuterVision LLC](https://putervision.com)

---

## Legal & Usage Disclaimers

> [!WARNING]
> **Limitation of Liability & Disclaimer of Warranty**  
> WebCrypt is maintained by [PuterVision LLC](https://putervision.com) and provided **"AS IS"**, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND NONINFRINGEMENT. IN NO EVENT SHALL PUTERVISION LLC, ITS AFFILIATES, OR CONTRIBUTORS BE LIABLE FOR ANY CLAIM, DAMAGES, OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT, OR OTHERWISE, ARISING FROM, OUT OF, OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE. USERS AND DEVELOPERS ARE SOLELY RESPONSIBLE FOR VERIFYING CRYPTOGRAPHIC PARAMETERS, CONDUCTING INDEPENDENT SECURITY AUDITS, AND DETERMINING SUITABILITY FOR PRODUCTION DEPLOYMENTS.

> [!NOTE]
> **Data Privacy & Local Execution Guarantee**  
> WebCrypt operations execute 100% locally in your browser or Node.js runtime using the native Web Crypto API. No private keys, passwords, plaintext data, or encrypted payloads are ever transmitted to external cloud servers.

> [!IMPORTANT]
> **Third-Party AI Model & API Fees Disclaimer**  
> This software is provided as free, open-source software under the MIT License. If integrated into developer AI agent frameworks (such as OpenAI, Anthropic Claude, Google Gemini, xAI Grok, or Ollama), any third-party API usage and billing fees remain the sole responsibility of the user. [PuterVision LLC](https://putervision.com) is not responsible for third-party API costs.

> [!NOTE]
> **Trademark & Open Specification Attributions**  
> Model Context Protocol (MCP) is an open specification created by Anthropic, PBC. Web Crypto API, W3C standards, and third-party IDE trademarks are property of their respective owners. [PuterVision LLC](https://putervision.com) is an independent open-source software developer.

> [!NOTE]
> **Performance & Cost Savings Estimates**  
> Encryption performance benchmarks, throughput speeds, and zero-dependency efficiency metrics reported in documentation are derived from standard browser and Node.js WebCrypto benchmarks and may vary based on hardware acceleration.
