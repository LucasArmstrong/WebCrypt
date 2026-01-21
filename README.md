# webcrypt

**Zero-dependency • Strong End-to-End Encryption for the Modern Web (Updated 2025)**  
Pure Web Crypto API-powered **AES-256-GCM** symmetric encryption + full **RSA-4096 hybrid asymmetric** mode.  
Now includes ECDSA digital signatures (P-256/P-384) for authenticity, detached file signing, and streaming-friendly signing workflows.

- Password-based symmetric encryption (WebCrypt) – simple, fast, perfect for shared-secret scenarios
- Public/private key asymmetric encryption (WebCryptAsym) – true public-key cryptography for messaging & file sharing
- Digital signatures (WebCryptAsym) – ECDSA sign/verify for text and files
- Zero dependencies • Works offline • Browser + Node.js • Quantum-resistant key derivation
- Symmetric message authentication (WebCrypt) – HMAC (SHA-256/384/512) for verifying integrity and authenticity of messages or data

```bash
npm install webcrypt
```

```js
import { WebCrypt } from "webcrypt";
import { WebCryptAsym } from "webcrypt";

const wc = new WebCrypt();
const wca = new WebCryptAsym();
```

Works in: Browser • Node.js • React • Angular • Next.js • Vue • Svelte • Electron • Deno • Cloudflare Workers

#### Features

| Feature                     | Status | Details                               |
| --------------------------- | ------ | ------------------------------------- |
| Text encryption             | Done   | Returns base64 string                 |
| File encryption             | Done   | Streaming — handles 10 GB+ files      |
| File decryption             | Done   | Restores original filename            |
| WebRTC E2EE (video + audio) | Done   | Insertable Streams — true end-to-end  |
| Digital signatures          | Done   | ECDSA (P-256/P-384) sign & verify     |
| Zero dependencies           | Done   | Pure Web Crypto API                   |
| Node.js 18+ support         | Done   | Native crypto.webcrypto               |
| Strong key derivation       | Done   | 600k PBKDF2 iterations + random salts |
| Key caching                 | Done   | Same password = instant reuse         |
| TypeScript support          | Done   | Full .d.ts included                   |
| Asymmetric version          | Done   | See WebCryptAsym below                |

#### What's new (2025)

- ECDSA digital signatures added (WebCryptAsym): signText/verifyText, signFile/verifyFile, export/import signing keys.
- Streaming-safe base64 utilities and improved file header formats for robust large-file handling.
- Documentation & examples expanded for asymmetric signing and WebRTC hybrid key exchange.

#### Library overview

- WebCrypt (symmetric)
  - Password-based AES-256-GCM encryption (PBKDF2 600k iterations).
  - Streaming file encryption with counter-derived IVs for low memory usage.
  - WebRTC Insertable Stream transforms derived from a shared password.
- WebCryptAsym (asymmetric + signing)
  - RSA-4096 hybrid: RSA-OAEP encrypts ephemeral AES-256-GCM session keys; AES encrypts payloads.
  - ECDSA (P-256 / P-384) signing for text and files (detached signatures).
  - Streaming file handling and WebRTC hybrid key exchange (session key in first frame).
  - Export/import helpers for public/private keys (base64 SPKI/PKCS8).

#### Symmetric Usage (WebCrypt)

##### Encrypt & Decrypt Text

```js
import { WebCrypt } from "webcrypt";

const wc = new WebCrypt();

const secret = "The treasure is buried under the old oak tree";

const encrypted = await wc.encryptText(secret, "my-super-secret-password");
console.log(encrypted);
// → long base64 string

const decrypted = await wc.decryptText(encrypted, "my-super-secret-password");
console.log(decrypted);
// → "The treasure is buried under the old oak tree"
```

##### Encrypt & Decrypt Files (streaming, low memory)

```html
<input type="file" id="fileInput" />
<input type="password" id="pass" placeholder="Password" />
<button onclick="encrypt()">Encrypt File</button>
```

```js
const wc = new WebCrypt();

async function encrypt() {
  const file = document.getElementById("fileInput").files[0];
  const password = document.getElementById("pass").value;

  const { blob, filename } = await wc.encryptFile(file, password);

  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  a.click();
}

// Decryption is identical — just call decryptFile()
```

##### End-to-End Encrypted WebRTC Video Call

```js
const wc = new WebCrypt();
const CALL_PASSWORD = "our-private-call-2025";

const stream = await navigator.mediaDevices.getUserMedia({ video: true, audio: true });
document.getElementById("localVideo").srcObject = stream;

const pc = new RTCPeerConnection();

// Encrypt everything we send
stream.getTracks().forEach(async track => {
  const sender = pc.addTrack(track, stream);
  sender.transform = new RTCRtpScriptTransform(await wc.createEncryptTransform(CALL_PASSWORD));
});

// Decrypt everything we receive
pc.ontrack = async event => {
  const receiver = event.receiver;
  receiver.transform = new RTCRtpScriptTransform(await wc.createDecryptTransform(CALL_PASSWORD));
  document.getElementById("remoteVideo").srcObject = event.streams[0];
};
```

Both users use the exact same password → SFU/server sees only encrypted garbage.

#### Asymmetric Usage (WebCryptAsym)

```js
import { WebCryptAsym } from "webcrypt";

const crypt = new WebCryptAsym();

// Generate and share public key
const keyPair = await crypt.generateKeyPair();
const publicKeyB64 = await crypt.exportPublicKey(keyPair.publicKey);

// Recipient imports your public key
const publicKey = await crypt.importPublicKey(publicKeyB64);

// Encrypt file for recipient
const { blob, filename } = await crypt.encryptFile(file, publicKey);

// Decrypt with private key
const { blob: decryptedBlob, filename: originalName } = await crypt.decryptFile(
  encryptedFile,
  keyPair.privateKey
);
```

##### Signing & Verifying (ECDSA)

```js
// Generate a signing key pair (ECDSA)
const { publicKey, privateKey, publicKeyB64 } = await crypt.generateSigningKeyPair("P-256");

// Share publicKeyB64 with verifiers, keep privateKey safe

// Sign a short message
const message = "I approve transaction #123";
const signatureB64 = await crypt.signText(message, privateKey);

// Verify the message
const ok = await crypt.verifyText(message, signatureB64, publicKey);
// ok === true

// Sign a file (detached signature)
const { signatureB64: fileSig } = await crypt.signFile(myLargeFile, privateKey);

// Verify a file later
const valid = await crypt.verifyFile(myLargeFile, fileSig, publicKey);
// valid === true

// Import a verifier's public signing key (SPKI base64)
const verifierPub = await crypt.importPublicSigningKey(publicKeyB64, "P-256");
```

#### HMAC Support

Compute and verify message authentication codes using HMAC-SHA-256 (or other hashes).

```js
const { WebCrypt } = require("webcrypt"); // or import for ES modules
const wc = new WebCrypt();

// Generate key from password
const key = await wc.generateHmacKey("strongpassword");

// Compute HMAC
const hmac = await wc.computeHmac("Important message", key);

// Verify
const isValid = await wc.verifyHmac("Important message", hmac, key); // true
```

#### API

##### Symmetric (WebCrypt)

```ts
const wc = new WebCrypt()

wc.encryptText(text: string, password: string): Promise<string>
wc.decryptText(b64: string, password: string): Promise<string>

wc.encryptFile(file: File|Blob, password: string): Promise<{ blob: Blob, filename: string }>
wc.decryptFile(file: File|Blob, password: string): Promise<{ blob: Blob, filename: string }>

wc.createEncryptTransform(password: string): Promise<TransformFunction>
wc.createDecryptTransform(password: string): Promise<TransformFunction>
```

##### Asymmetric (WebCryptAsym)

```ts
const crypt = new WebCryptAsym()

crypt.generateKeyPair(): Promise<CryptoKeyPair>
crypt.exportPublicKey(publicKey: CryptoKey): Promise<string>
crypt.exportPrivateKey(privateKey: CryptoKey): Promise<string>
crypt.importPublicKey(b64: string): Promise<CryptoKey>
crypt.importPrivateKey(b64: string): Promise<CryptoKey>

crypt.encryptText(text: string, publicKey: CryptoKey): Promise<string>
crypt.decryptText(b64: string, privateKey: CryptoKey): Promise<string>

crypt.encryptFile(file: File|Blob, publicKey: CryptoKey): Promise<{ blob: Blob, filename: string }>
crypt.decryptFile(file: File|Blob, privateKey: CryptoKey): Promise<{ blob: Blob, filename: string }>

crypt.createEncryptTransform(publicKey: CryptoKey): Promise<TransformFunction>
crypt.createDecryptTransform(privateKey: CryptoKey): Promise<TransformFunction>

-- Signing / Verification (ECDSA) --
crypt.generateSigningKeyPair(curve?: 'P-256' | 'P-384'): Promise<{ publicKey, privateKey, publicKeyB64 }>
crypt.importPublicSigningKey(publicKeyB64: string, curve?: string): Promise<CryptoKey>
crypt.signText(text: string, privateKey: CryptoKey): Promise<string>
crypt.verifyText(text: string, signatureB64: string, publicKey: CryptoKey): Promise<boolean>
crypt.signFile(file: File|Blob, privateKey: CryptoKey): Promise<{signatureB64: string, blob: Blob}>
crypt.verifyFile(file: File|Blob, signatureB64: string, publicKey: CryptoKey): Promise<boolean>
```

#### Security

- AES-256-GCM (authenticated encryption)
- 600,000 PBKDF2-SHA256 iterations (strong against brute-force)
- Unique 128-bit salt per message/file
- Unique 96-bit IV per chunk/frame
- No keys ever leave your device
- ECDSA (P-256/P-384) for signatures — compact and widely supported
- AES-256 offers strong protection even against future quantum threats (Grover-resistant at this key size)

#### Browser Support

Chrome 80+ • Edge 80+ • Firefox 90+ • Safari 15+  
All support Web Crypto API + Insertable Streams.

#### Node.js Support

Works natively in Node.js 18+ via built-in crypto.webcrypto.

```js
const { WebCrypt } = require("webcrypt");
```

#### License

MIT License — free for personal and commercial use  
© 2025 Lucas Armstrong  
https://github.com/lucasarmstrong/webcrypt

No telemetry. No servers. No backdoors.  
Just pure, unbreakable encryption that works offline, forever.

Star this repo if you believe in private communication.

Made with passion for a freer, safer internet.
