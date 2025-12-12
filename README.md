# webcrypt

**Zero-dependency • Strong End-to-End Encryption for the Modern Web**  
Pure Web Crypto API-powered **AES-256-GCM** symmetric encryption + full **RSA-4096 hybrid asymmetric** mode.  
Securely encrypt **text**, **multi-gigabyte files** (streaming), and **real-time WebRTC video/audio** — all with no shared passwords required in asymmetric mode.

- Password-based symmetric encryption (WebCrypt) – simple, fast, perfect for shared-secret scenarios
- Public/private key asymmetric encryption (WebCryptAsym) – true public-key cryptography for messaging & file sharing
- Zero dependencies • Works offline • Browser + Node.js • Quantum-resistant key derivation

```bash
npm install webcrypt
```

```js
import { WebCrypt, WebCryptAsym } from "webcrypt";

const wc = new WebCrypt();
```

Works in: Browser • Node.js • React • Angular • Next.js • Vue • Svelte • Electron • Deno • Cloudflare Workers

#### Features

| Feature                     | Status | Details                               |
| --------------------------- | ------ | ------------------------------------- |
| Text encryption             | Done   | Returns base64 string                 |
| File encryption             | Done   | Streaming — handles 10 GB+ files      |
| File decryption             | Done   | Restores original filename            |
| WebRTC E2EE (video + audio) | Done   | Insertable Streams — true end-to-end  |
| Zero dependencies           | Done   | Pure Web Crypto API                   |
| Node.js 18+ support         | Done   | Native crypto.webcrypto               |
| Strong key derivation       | Done   | 600k PBKDF2 iterations + random salts |
| Key caching                 | Done   | Same password = instant reuse         |
| TypeScript support          | Done   | Full .d.ts included                   |
| Asymmetric version          | Done   | See WebCryptAsym below                |

#### New: WebCryptAsym – Asymmetric Encryption

webcrypt now includes WebCryptAsym, a full asymmetric counterpart using hybrid RSA-4096-OAEP + AES-256-GCM encryption.  
Perfect when you need public/private key pairs instead of shared passwords (e.g., secure file sharing, messaging apps).

```js
import { WebCryptAsym } from "webcrypt";

const crypt = new WebCryptAsym();

// Generate key pair
const keyPair = await crypt.generateKeyPair();
const publicKeyB64 = await crypt.exportPublicKey(keyPair.publicKey);
const privateKeyB64 = await crypt.exportPrivateKey(keyPair.privateKey);

// Encrypt with recipient's public key
const encrypted = await crypt.encryptText("Secret", recipientPublicKey);

// Decrypt with your private key
const decrypted = await crypt.decryptText(encrypted, myPrivateKey);
```

Supports the same features as the symmetric version:  
Text encryption/decryption  
Streaming file encryption (.asym-encrypted extension)  
WebRTC insertable streams (session key encrypted in first frame)

See full documentation and examples in the WebCryptAsym section below.

#### Installation

```bash
npm install webcrypt
# or
yarn add webcrypt
# or
pnpm add webcrypt
```

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

WebRTC transforms also available (session key sent encrypted in first frame).

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
```

#### Security

- AES-256-GCM (authenticated encryption)
- 600,000 PBKDF2-SHA256 iterations (strong against brute-force)
- Unique 128-bit salt per message/file
- Unique 96-bit IV per chunk/frame
- No keys ever leave your device
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
