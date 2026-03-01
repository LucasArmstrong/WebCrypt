# webcrypt

**Zero-dependency • Strong End-to-End Encryption for the Modern Web (v0.5.1 – Post-Quantum Edition)**  
Pure Web Crypto API-powered **AES-256-GCM** symmetric encryption + **RSA-4096 hybrid asymmetric** mode + **NIST post-quantum cryptography** (Kyber + Dilithium).

- Password-based symmetric encryption (WebCrypt) – AES-256-GCM, already quantum-resistant
- Asymmetric encryption (WebCryptAsym) – RSA-4096 with hybrid Kyber support for forward-secrecy
- **Post-quantum cryptography** (WebCryptPQC) – NIST-approved Kyber (key exchange) + Dilithium (signatures)
- Digital signatures – ECDSA, RSA-PSS, EdDSA, and **post-quantum Dilithium**
- Hybrid encryption – Classical + post-quantum for immediate quantum-safe defense
- Advanced key derivation – PBKDF2, Argon2id, SHA-3 KDF, HKDF-SHA3
- Zero dependencies • Works offline • Browser + Node.js • Production-ready quantum-resistance planning

```bash
npm install webcrypt
```

```js
import { WebCrypt } from "webcrypt";
import { WebCryptAsym } from "webcrypt";
import { WebCryptPQC } from "webcrypt";

const wc = new WebCrypt();
const wca = new WebCryptAsym();
const pqc = new WebCryptPQC();
```

Works in: Browser • Node.js • React • Angular • Next.js • Vue • Svelte • Electron • Deno • Cloudflare Workers

#### Features

| Feature                           | Status | Details                                             |
| --------------------------------- | ------ | --------------------------------------------------- |
| Text encryption                   | Done   | AES-256-GCM, returns base64 string                  |
| File encryption                   | Done   | Streaming — handles 10 GB+ files                    |
| File decryption                   | Done   | Restores original filename                          |
| WebRTC E2EE (video + audio)       | Done   | Insertable Streams — true end-to-end                |
| Digital signatures                | Done   | ECDSA, RSA-PSS, EdDSA, and **Dilithium (PQC)**      |
| Post-quantum key exchange         | Done   | Kyber (lattice-based) – NIST finalist               |
| Hybrid encryption (classical+PQC) | Done   | RSA-4096 + Kyber simultaneously for forward-secrecy |
| Zero dependencies                 | Done   | Pure Web Crypto API                                 |
| Node.js 18+ support               | Done   | Native crypto.webcrypto                             |
| Strong key derivation             | Done   | 600k PBKDF2 + SHA-3 KDF + Argon2id                  |
| Advanced KDFs                     | Done   | HKDF-SHA3, Argon2id, key rotation, hierarchical KD  |
| Key caching                       | Done   | Same password = instant reuse                       |
| TypeScript support                | Done   | Full .d.ts included for all modules                 |
| HMAC (SHA-256/384/512)            | Done   | Message authentication with multiple hashes         |
| HMAC-SHA3 (quantum-resistant)     | Done   | Post-quantum MAC support                            |

#### What's new (v0.5.0) – Post-Quantum Cryptography Edition

**Major additions: Full NIST PQC suite + hybrid encryption for quantum-safe messaging**

- **WebCryptPQC module**: Kyber (lattice-based KEM) and Dilithium (lattice-based signatures) – NIST PQC finalists
  - 3 Kyber security levels: Kyber512 (128-bit), Kyber768 (192-bit), Kyber1024 (256-bit)
  - 3 Dilithium security levels: Dilithium2, Dilithium3, Dilithium5
- **Hybrid encryption** (Kyber + RSA-OAEP): Forward-secure key exchange resisting both classical and quantum attacks
- **Post-quantum KDFs**:
  - SHA-3 based KDF (collision-resistant, quantum-immune)
  - HKDF with SHA-3 (key expansion for multiple independent derived keys)
  - Argon2id enhanced (GPU/ASIC resistant; 64MB memory, tuned for 2025+)
- **Advanced key management**:
  - Key rotation with fresh salts
  - Hierarchical key derivation (parent → child keys for different purposes)
  - Secure key erasure (memory overwriting)
- **Quantum-resistant hashing**: SHA-3 support (256/384/512) replacing SHA-2 in critical paths for long-term security
- **Legacy RSA deprecation path**: Hybrid mode allows gradual migration from RSA-4096 to pure PQC
- **Backward compatibility**: Existing APIs unchanged; new methods opt-in

#### Additional Updates in (v0.5.0)

- ECDSA digital signatures added (WebCryptAsym): signText/verifyText, signFile/verifyFile, export/import signing keys.
- Enhanced key derivation with PBKDF2 and Argon2 support in WebCryptAsym.
- Additional signature algorithms: RSA-PSS and EdDSA support.
- MAC extensions: HMAC and Poly1305 Message Authentication Codes.
- Advanced key management: Key rotation and hierarchical key structures.
- Improved WebRTC integration with progress tracking for data channels.
- Additional file handling features: Streaming file encryption with progress reporting.
- Security hardening: Secure random generation and key caching mechanisms.
- Performance optimizations: Optimized algorithms and caching strategies.
- Streaming-safe base64 utilities and improved file header formats for robust large-file handling.
- Documentation & examples expanded for asymmetric signing and WebRTC hybrid key exchange.
- Improved TypeScript support and type definitions.

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
- WebCryptPQC (post-quantum cryptography)
  - **Kyber**: NIST-selected lattice-based Key Encapsulation Mechanism
    - Resists known quantum algorithms (Shor's algorithm leaves Kyber unaffected)
    - Three security levels: Kyber512 (128-bit), Kyber768 (192-bit), Kyber1024 (256-bit)
  - **Dilithium**: NIST-selected lattice-based digital signature algorithm
    - Post-quantum signatures for long-term authenticity (unlike ECDSA/RSA)
    - Three security levels: Dilithium2, Dilithium3, Dilithium5
  - **Hybrid key exchange**: Kyber + RSA-OAEP ensures forward secrecy + classical compatibility
  - **Post-quantum KDFs**: SHA-3, HKDF-SHA3, Argon2id for quantum-safe key derivation

#### Quantum Resistance & Security Model (v0.5+)

WebCrypt now provides **harvest-now-decrypt-later defense** and true **post-quantum cryptography** readiness.

**The Problem: Quantum Threats Ahead**

- **Shor's algorithm** breaks RSA, DH, and ECDSA once large quantum computers exist (~2030–2040 estimate, but "harvest now" attacks already underway)
- **Grover's algorithm** weakens symmetric crypto by ~2x; AES-256 remains safe (128-bit Grover-resistant)
- Attackers are already recording encrypted data today, planning to decrypt it later with quantum computers

**WebCrypt's Quantum Defense Layers:**

1. **AES-256-GCM symmetric core** (WebCrypt & WebCryptAsym)
   - 256-bit keys resist Grover's algorithm (would require ~2^128 quantum operations, still infeasible)
   - No known quantum attack breaks AES fundamentally
   - ✅ **Already quantum-safe** – no action needed for symmetric data

2. **Post-quantum key encapsulation (WebCryptPQC.Kyber)**
   - Replaces RSA for key exchange in new deployments
   - Handshake is secure even _if_ quantum computers exist
   - Combines with AES for hybrid encryption: `hybridEncapsulate(rsaPublicKey, kyberPublicKey)`
   - ✅ **Eliminates Shor-based attacks** on key exchange

3. **Post-quantum signatures (WebCryptPQC.Dilithium)**
   - Replaces ECDSA/RSA-PSS for long-term authenticity
   - Documents signed today will still be verifiable as authentic against future tampering
   - ✅ **Proof of origin survives quantum era** – legal/compliance benefit

4. **Quantum-resistant key derivation**
   - **SHA-3 KDF**: Uses post-quantum collision-resistant hashing
   - **HKDF-SHA3**: Expands master secrets into independent keys securely
   - **Argon2id**: GPU/ASIC-resistant memory-hard KDF (no quantum speedup)
   - ✅ **Prevents quantum-accelerated dictionary attacks** on passwords

5. **Hybrid encryption strategy**

   ```
   hybridEncapsulate(rsaPublicKey, kyberPublicKey) = {
     kyberCiphertext,       // Quantum-safe encapsulation
     rsaWrappedSharedSecret, // Classical fallback (if RSA survives)
     sharedSecret           // Combined via SHA-3 (both must fail for compromise)
   }
   ```

   - ✅ **Defense-in-depth**: Secure if Kyber _or_ RSA holds; breaks only if both crack

**Migration Path: Classical → Hybrid → Pure PQC**

```
Phase 1 (Now): Use WebCryptAsym (RSA-4096 only)
  → Vulnerable to future quantum computers recording data

Phase 2 (2025+): Use hybridEncapsulate (Kyber + RSA)
  → Data protected by Kyber immediately, RSA provides fallback
  → New encrypted data safe; old RSA-only data still vulnerable to harvest attacks

Phase 3 (2030+): Use WebCryptPQC (pure Kyber + Dilithium)
  → No RSA dependency; pure post-quantum cryptography
  → Recommended for long-term secrets (>10 years)
```

**Performance Notes** (Quantum resistance has trade-offs):

| Algorithm      | Key Size | Signature Size | Generation | Speed    | Notes                        |
| -------------- | -------- | -------------- | ---------- | -------- | ---------------------------- |
| ECDSA P-256    | 32 B     | 64 B           | ~100ms     | ~1ms/sig | Fast, but broken by Shor     |
| RSA-4096       | 512 B    | 512 B          | ~2s        | ~100ms   | Slower, also broken by Shor  |
| Dilithium3     | 1952 B   | 3293 B         | ~1s        | ~500μs   | Larger sigs, quantum-safe    |
| Kyber768 (KEM) | 1184 B   | 1088 B (ct)    | ~100ms     | ~500μs   | Efficient; replaces RSA-4096 |

**Recommendation for 2025+**:

- Use `WebCrypt` for symmetric data (already quantum-safe)
- Use `WebCryptAsym` + hybrid methods for new keys: `hybridEncapsulate(rsa, kyber)`
- Use `WebCryptPQC.Dilithium` for signatures on documents with 10+ year validity
- **Do NOT** rely on RSA-only encryption for data needing decade-long confidentiality

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

##### Encrypt & Decrypt Complex JSON Data (New in v0.5.1)

Using the `encryptData` and `decryptData` helper functions to avoid manual `JSON.stringify` logic:

```js
const data = {
  message: "Hello world!",
  timestamp: Date.now(),
  users: ["Alice", "Bob"],
};

// Automatically serializes into JSON before encrypting
const encryptedObj = await wc.encryptData(data, "my-super-secret-password");

// Automatically parses JSON back into a valid JS object
const decryptedObj = await wc.decryptData(encryptedObj, "my-super-secret-password");
console.log(decryptedObj.users); // ["Alice", "Bob"]
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

// Encrypt pure objects automatically
const encryptedData = await crypt.encryptData({ msg: "Hi" }, publicKey);
const decryptedData = await crypt.decryptData(encryptedData, keyPair.privateKey);
```

##### ECDH Key Exchange Handshake (New in v0.5.1)

Elliptic Curve Diffie-Hellman (ECDH) is an industry-standard mechanism for deriving shared secrets natively supported by the Web Crypto API.

```js
// 1. Each user creates an ECDH key pair
const aliceKeys = await crypt.generateECDHKeyPair();
const bobKeys = await crypt.generateECDHKeyPair();

// 2. Users exchange purely their PUBLIC keys
const alicePubB64 = aliceKeys.publicKeyB64;
const bobPubB64 = bobKeys.publicKeyB64;

// 3. Sender securely encrypts Data using their private key and the recipient's public key
const encryptedPayload = await crypt.encryptWithECDH(
  { data: "Super Secret from Alice" },
  aliceKeys.privateKey,
  await crypt.importECDHPublicKey(bobPubB64)
);

// 4. Recipient decrypts Data using their private key and the sender's public key
const decryptedPayload = await crypt.decryptWithECDH(
  encryptedPayload,
  bobKeys.privateKey,
  await crypt.importECDHPublicKey(alicePubB64)
);
console.log(decryptedPayload.data); // "Super Secret from Alice"
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

##### Key Derivation

```js
// Derive key using PBKDF2 (default)
const pbkdf2Key = await crypt.deriveKeyPBKDF2("password", "salt", 100000);

// Derive key using Argon2
const argon2Key = await crypt.deriveKeyArgon2("password", "salt", {
  memory: 65536,
  iterations: 3,
  parallelism: 1,
});
```

##### Post-Quantum Key Derivation (v0.5+)

```js
// SHA-3 based KDF (quantum-resistant collision-resistant hashing)
const sha3Key = await crypt.deriveKeySHA3("password", saltBytes, 50000, "SHA3-256", 256);

// HKDF with SHA-3 (for deriving multiple independent keys from a master secret)
const masterSecret = new TextEncoder().encode("master-password");
const hkdfKey = await crypt.deriveKeyHKDFSHA3(masterSecret, saltBytes, infoBytes, 256);

// Enhanced Argon2id (GPU/ASIC resistant, tuned for 2025+)
const argon2Enhanced = await crypt.deriveKeyArgon2Enhanced("password", saltBytes, {
  memory: 65536, // 64 MB
  iterations: 3,
  parallelism: 1,
  keyLength: 256,
});

// Key rotation: Re-derive with new salt without re-encrypting data
const rotatedKey = await crypt.rotateKeyNew("password", newSaltBytes, "Argon2");

// Hierarchical key derivation: Create distinct keys for different purposes
const encryptionKey = await crypt.deriveChildKeyHierarchical(parentKey, childSalt, "encryption");
const signingKey = await crypt.deriveChildKeyHierarchical(parentKey, childSalt, "signing");
const hmacKey = await crypt.deriveChildKeyHierarchical(parentKey, childSalt, "hmac");
```

#### Post-Quantum Cryptography Usage (WebCryptPQC) – v0.5+

Import and initialize:

```js
import { WebCryptPQC } from "webcrypt";

const pqc = new WebCryptPQC();
```

##### Kyber Key Encapsulation (Lattice-Based NIST Standard)

```js
// Generate Kyber key pair (choose security level)
const kyberKeys = await pqc.generateKyberKeyPair("Kyber768"); // 768 = 192-bit security
// kyberKeys = { publicKey: Uint8Array, privateKey: Uint8Array }

// Export public key for sharing
const kyberPubB64 = pqc.kyberPublicKeyToBase64(kyberKeys.publicKey);
// Send kyberPubB64 to recipient

// Recipient encapsulates a shared secret
const { ciphertext, sharedSecret } = await pqc.kyberEncapsulate(
  pqc.kyberPublicKeyFromBase64(kyberPubB64),
  "Kyber768"
);
// Send ciphertext to originator
// sharedSecret is a 32-byte key (quantum-safe!)

// Originator decapsulates to recover the same sharedSecret
const recoveredSecret = await pqc.kyberDecapsulate(ciphertext, kyberKeys.privateKey, "Kyber768");
// recoveredSecret === sharedSecret ✓

// Use sharedSecret as key material for AES-GCM encryption
const aesKey = await crypto.subtle.importKey("raw", sharedSecret, "AES-GCM", {
  name: "AES-GCM",
  length: 256,
});
```

##### Dilithium Digital Signatures (Lattice-Based, Quantum-Proof)

```js
// Generate Dilithium signing key pair
const dilithiumKeys = await pqc.generateDilithiumKeyPair("Dilithium3"); // 192-bit security
// dilithiumKeys = { publicKey: Uint8Array, privateKey: Uint8Array }

// Sign a message
const message = "I approve this transaction #12345";
const signature = await pqc.dilithiumSign(message, dilithiumKeys.privateKey, "Dilithium3");
// signature is a 3293-byte post-quantum signature

// Verifier checks the signature
const isValid = await pqc.dilithiumVerify(
  message,
  signature,
  pqc.dilithiumPublicKeyFromBase64(publicKeyB64),
  "Dilithium3"
);
// isValid === true (assuming message wasn't tampered)

// Sign a file (detached signature for long-term archival)
const document = new Blob([...]);
const fileSig = await pqc.dilithiumSign(document, dilithiumKeys.privateKey, "Dilithium3");

// Verify file signature 10+ years later (still valid against quantum computers!)
const fileValid = await pqc.dilithiumVerify(document, fileSig, dilithiumKeys.publicKey, "Dilithium3");
```

##### Hybrid Encryption: Kyber + RSA (Immediate Forward-Secrecy)

```js
import { WebCryptAsym } from "webcrypt";
import { WebCryptPQC } from "webcrypt";

const crypt = new WebCryptAsym();
const pqc = new WebCryptPQC();

// Setup: Alice generates both RSA and Kyber key pairs
const rsaKeys = await crypt.generateKeyPair(); // RSA-4096
const kyberKeys = await pqc.generateKyberKeyPair("Kyber768");

const aliceRsaPub = await crypt.exportPublicKey(rsaKeys.publicKey);
const aliceKyberPub = pqc.kyberPublicKeyToBase64(kyberKeys.publicKey);
// Share both aliceRsaPub and aliceKyberPub with Bob

// Bob encrypts using both schemes (hybrid)
const bobRsaPubKey = await crypt.importPublicKey(aliceRsaPub);
const bobKyberPubKey = pqc.kyberPublicKeyFromBase64(aliceKyberPub);

const { sharedSecret, kyberCiphertext, rsaWrappedSharedSecret } = await pqc.hybridEncapsulate(
  bobRsaPubKey,
  bobKyberPubKey,
  "Kyber768"
);
// Send kyberCiphertext and rsaWrappedSharedSecret to Alice

// Alice decrypts using both schemes
const recoveredSharedSecret = await pqc.hybridDecapsulate(
  kyberCiphertext,
  rsaWrappedSharedSecret,
  rsaKeys.privateKey,
  kyberKeys.privateKey,
  "Kyber768"
);
// recoveredSharedSecret === sharedSecret

// Use sharedSecret for session encryption (both quantum + classical secure!)
```

**Benefits of Hybrid Mode:**

- ✅ If RSA-4096 is broken by quantum: Kyber ensures the session key remains secure
- ✅ If Kyber has a flaw: RSA fallback protects the key
- ✅ Breaks only if _both_ Kyber AND RSA are compromised simultaneously (extremely unlikely)

##### Security Level Recommendations

| Use Case               | Kyber Level | Dilithium Level | Notes                           |
| ---------------------- | ----------- | --------------- | ------------------------------- |
| Short-term (< 2 years) | Kyber512    | Dilithium2      | Fast, lower overhead            |
| Standard (2–10 years)  | Kyber768    | Dilithium3      | **Recommended** for most cases  |
| Long-term (> 10 years) | Kyber1024   | Dilithium5      | Maximum security margins        |
| Legacy compatibility   | N/A         | N/A             | Use `hybridEncapsulate` instead |

##### Additional Signature Algorithms

```js
// Generate RSA-PSS signing key pair
const rsaKeyPair = await crypt.generateRSAPSSSigningKeyPair(2048);

// Sign with RSA-PSS
const rsaSignature = await crypt.signTextWithRSAPSS("message", rsaKeyPair.privateKey);

// Verify RSA-PSS signature
const rsaValid = await crypt.verifyTextWithRSAPSS("message", rsaSignature, rsaKeyPair.publicKey);

// Generate EdDSA signing key pair (Ed25519)
const eddsaKeyPair = await crypt.generateEdDSASigningKeyPair();

// Sign with EdDSA
const eddsaSignature = await crypt.signTextWithEdDSA("message", eddsaKeyPair.privateKey);

// Verify EdDSA signature
const eddsaValid = await crypt.verifyTextWithEdDSA(
  "message",
  eddsaSignature,
  eddsaKeyPair.publicKey
);
```

##### MAC Extensions

```js
// Compute HMAC
const hmac = await crypt.computeHmac("message", key);

// Verify HMAC
const isValid = await crypt.verifyHmac("message", hmac, key);

// Compute Poly1305 MAC
const poly1305Mac = await crypt.computePoly1305Mac("message", key);

// Verify Poly1305 MAC
const isPolyValid = await crypt.verifyPoly1305Mac("message", poly1305Mac, key);
```

##### Advanced Key Management

```js
// Rotate a key (derive new key from existing key)
const rotatedKey = await crypt.rotateKey(existingKey, "newSalt");

// Create hierarchical key structure
const masterKey = await crypt.deriveKeyPBKDF2("password", "masterSalt");
const childKey = await crypt.deriveChildKey(masterKey, "childSalt");
```

##### Quantum-Resistant Enhancements

```js
// Create Kyber hybrid encrypt transform
const kyberTransform = await crypt.createKyberEncryptTransform(publicKey);

// Create Dilithium hybrid decrypt transform
const dilithiumTransform = await crypt.createDilithiumDecryptTransform(privateKey);
```

##### WebRTC Progress Tracking

```js
// Encrypt with progress tracking
const { blob, filename } = await crypt.encryptFileWithProgress(file, publicKey, progress => {
  console.log(`Encryption progress: ${Math.round(progress * 100)}%`);
});
```

##### Streaming File Encryption with Progress

```js
// Encrypt file with progress reporting
const { blob, filename } = await crypt.encryptFileWithProgress(file, publicKey, progress => {
  console.log(`Encryption progress: ${Math.round(progress * 100)}%`);
});

// Decrypt file with progress reporting
const { blob: decryptedBlob, filename: originalName } = await crypt.decryptFileWithProgress(
  encryptedFile,
  privateKey,
  progress => {
    console.log(`Decryption progress: ${Math.round(progress * 100)}%`);
  }
);
```

#### HMAC Support

Compute and verify message authentication codes using HMAC-SHA-256 (or other hashes).

```js
import { WebCrypt } from "webcrypt";

const wc = new WebCrypt();

// Generate key from password
const key = await wc.generateHmacKey("strongpassword");

// Compute HMAC
const hmac = await wc.computeHmac("Important message", key);

// Verify
const isValid = await wc.verifyHmac("Important message", hmac, key); // true
```

You can also use different hash algorithms:

```js
// Generate HMAC key with SHA-384
const key384 = await wc.generateHmacKey("strongpassword", "SHA-384");

// Compute HMAC with SHA-384
const hmac384 = await wc.computeHmac("Important message", key384);

// Verify with SHA-384
const isValid384 = await wc.verifyHmac("Important message", hmac384, key384); // true
```

#### API

##### Symmetric (WebCrypt)

```ts
const wc = new WebCrypt();

// Data encryption/decryption (JSON objects)
wc.encryptData(data: any, password: string): Promise<string>
wc.decryptData(b64: string, password: string): Promise<any>
wc.generateRandomPassword(length?: number): string

// Text encryption/decryption
wc.encryptText(text: string, password: string): Promise<string>
wc.decryptText(b64: string, password: string): Promise<string>

// File encryption/decryption
wc.encryptFile(file: File|Blob, password: string): Promise<{ blob: Blob, filename: string }>
wc.decryptFile(file: File|Blob, password: string): Promise<{ blob: Blob, filename: string }>

// WebRTC transforms
wc.createEncryptTransform(password: string): Promise<TransformFunction>
wc.createDecryptTransform(password: string): Promise<TransformFunction>

// HMAC support
wc.generateHmacKey(password: string): Promise<CryptoKey>
wc.computeHmac(message: string, key: CryptoKey): Promise<string>
wc.verifyHmac(message: string, hmac: string, key: CryptoKey): Promise<boolean>
```

##### Asymmetric (WebCryptAsym)

```ts
const crypt = new WebCryptAsym();

// Key generation and import/export
crypt.generateKeyPair(): Promise<CryptoKeyPair>
crypt.exportPublicKey(publicKey: CryptoKey): Promise<string>
crypt.exportPrivateKey(privateKey: CryptoKey): Promise<string>
crypt.importPublicKey(b64: string): Promise<CryptoKey>
crypt.importPrivateKey(b64: string): Promise<CryptoKey>

// Key derivation
crypt.deriveKeyPBKDF2(password: string, salt: string, iterations?: number): Promise<CryptoKey>
crypt.deriveKeyArgon2(password: string, salt: string, options?: { memory?: number, iterations?: number, parallelism?: number }): Promise<CryptoKey>

// Text encryption/decryption
crypt.encryptText(text: string, publicKey: CryptoKey): Promise<string>
crypt.decryptText(b64: string, privateKey: CryptoKey): Promise<string>

// Data encryption/decryption (JSON objects)
crypt.encryptData(data: any, publicKey: CryptoKey): Promise<string>
crypt.decryptData(b64: string, privateKey: CryptoKey): Promise<any>

// ECDH Key Exchange
crypt.generateECDHKeyPair(curve?: string): Promise<{ publicKey: CryptoKey, privateKey: CryptoKey, publicKeyB64: string }>
crypt.exportECDHPublicKey(publicKey: CryptoKey): Promise<string>
crypt.importECDHPublicKey(b64: string, curve?: string): Promise<CryptoKey>
crypt.deriveECDHSharedSecret(privateKey: CryptoKey, publicKey: CryptoKey): Promise<CryptoKey>
crypt.encryptWithECDH(data: any, privateKey: CryptoKey, recipientPublicKey: CryptoKey): Promise<string>
crypt.decryptWithECDH(b64: string, privateKey: CryptoKey, senderPublicKey: CryptoKey): Promise<any>

// File encryption/decryption
crypt.encryptFile(file: File|Blob, publicKey: CryptoKey): Promise<{ blob: Blob, filename: string }>
crypt.decryptFile(file: File|Blob, privateKey: CryptoKey): Promise<{ blob: Blob, filename: string }>

// File encryption/decryption with progress
crypt.encryptFileWithProgress(file: File|Blob, publicKey: CryptoKey, onProgress?: (progress: number) => void): Promise<{ blob: Blob, filename: string }>
crypt.decryptFileWithProgress(file: File|Blob, privateKey: CryptoKey, onProgress?: (progress: number) => void): Promise<{ blob: Blob, filename: string }>

// WebRTC transforms
crypt.createEncryptTransform(publicKey: CryptoKey): Promise<TransformFunction>
crypt.createDecryptTransform(privateKey: CryptoKey): Promise<TransformFunction>

// Signing / Verification (ECDSA)
crypt.generateSigningKeyPair(curve?: 'P-256' | 'P-384'): Promise<{ publicKey, privateKey, publicKeyB64 }>
crypt.importPublicSigningKey(publicKeyB64: string, curve?: string): Promise<CryptoKey>
crypt.signText(text: string, privateKey: CryptoKey): Promise<string>
crypt.verifyText(text: string, signatureB64: string, publicKey: CryptoKey): Promise<boolean>
crypt.signFile(file: File|Blob, privateKey: CryptoKey): Promise<{signatureB64: string, blob: Blob}>
crypt.verifyFile(file: File|Blob, signatureB64: string, publicKey: CryptoKey): Promise<boolean>

// Additional signature algorithms
crypt.generateRSAPSSSigningKeyPair(modulusLength?: number): Promise<CryptoKeyPair>
crypt.signTextWithRSAPSS(text: string, privateKey: CryptoKey): Promise<string>
crypt.verifyTextWithRSAPSS(text: string, signatureB64: string, publicKey: CryptoKey): Promise<boolean>
crypt.generateEdDSASigningKeyPair(): Promise<CryptoKeyPair>
crypt.signTextWithEdDSA(text: string, privateKey: CryptoKey): Promise<string>
crypt.verifyTextWithEdDSA(text: string, signatureB64: string, publicKey: CryptoKey): Promise<boolean>

// MAC extensions
crypt.computeHmac(message: string, key: CryptoKey): Promise<string>
crypt.verifyHmac(message: string, hmac: string, key: CryptoKey): Promise<boolean>
crypt.computePoly1305Mac(message: string, key: CryptoKey): Promise<string>
crypt.verifyPoly1305Mac(message: string, mac: string, key: CryptoKey): Promise<boolean>

// Advanced key management
crypt.rotateKey(key: CryptoKey, newSalt: string): Promise<CryptoKey>
crypt.deriveChildKey(parentKey: CryptoKey, childSalt: string): Promise<CryptoKey>

// Post-quantum key derivation (v0.5+)
crypt.deriveKeyArgon2Enhanced(password: string, salt: Uint8Array, options?: { memory?: number, iterations?: number, parallelism?: number, keyLength?: number }): Promise<CryptoKey>
crypt.deriveKeySHA3(password: string, salt: Uint8Array, iterations?: number, hash?: 'SHA3-256' | 'SHA3-384' | 'SHA3-512', keyLength?: number): Promise<CryptoKey>
crypt.deriveKeyHKDFSHA3(secret: Uint8Array, salt?: Uint8Array, info?: Uint8Array, keyLength?: number): Promise<CryptoKey>
crypt.deriveKeyHKDFSHA2(secret: Uint8Array, salt?: Uint8Array, info?: Uint8Array, keyLength?: number): Promise<CryptoKey>
crypt.rotateKeyNew(password: string, newSalt: Uint8Array, method?: 'PBKDF2' | 'Argon2' | 'SHA3' | 'HKDF'): Promise<CryptoKey>
crypt.deriveChildKeyHierarchical(parentKey: CryptoKey, childSalt: Uint8Array, purpose?: string): Promise<CryptoKey>
crypt.secureKeyErase(key: Uint8Array): void

// Quantum-resistant transforms
crypt.createKyberEncryptTransform(publicKey: CryptoKey): Promise<TransformFunction>
crypt.createDilithiumDecryptTransform(privateKey: CryptoKey): Promise<TransformFunction>
```

##### WebCryptPQC (Post-Quantum Cryptography) – v0.5+

```ts
const pqc = new WebCryptPQC();

// Kyber key exchange (lattice-based, NIST finalist)
pqc.generateKyberKeyPair(level?: 'Kyber512' | 'Kyber768' | 'Kyber1024'): Promise<{ publicKey: Uint8Array, privateKey: Uint8Array }>
pqc.kyberEncapsulate(kyberPublicKey: Uint8Array, level?: string): Promise<{ ciphertext: Uint8Array, sharedSecret: Uint8Array }>
pqc.kyberDecapsulate(ciphertext: Uint8Array, kyberPrivateKey: Uint8Array, level?: string): Promise<Uint8Array>

// Dilithium digital signatures (lattice-based, NIST finalist)
pqc.generateDilithiumKeyPair(level?: 'Dilithium2' | 'Dilithium3' | 'Dilithium5'): Promise<{ publicKey: Uint8Array, privateKey: Uint8Array }>
pqc.dilithiumSign(message: string | Uint8Array, dilithiumPrivateKey: Uint8Array, level?: string): Promise<Uint8Array>
pqc.dilithiumVerify(message: string | Uint8Array, signature: Uint8Array, dilithiumPublicKey: Uint8Array, level?: string): Promise<boolean>

// Hybrid encryption (Kyber + RSA for backward compatibility)
pqc.hybridEncapsulate(rsaPublicKey: CryptoKey, kyberPublicKey: Uint8Array, kyberLevel?: string): Promise<{ sharedSecret: Uint8Array, kyberCiphertext: Uint8Array, rsaWrappedSharedSecret: Uint8Array }>
pqc.hybridDecapsulate(kyberCiphertext: Uint8Array, rsaWrappedSharedSecret: Uint8Array, rsaPrivateKey: CryptoKey, kyberPrivateKey: Uint8Array, kyberLevel?: string): Promise<Uint8Array>

// Key serialization
pqc.kyberPublicKeyToBase64(publicKey: Uint8Array): string
pqc.kyberPublicKeyFromBase64(b64: string): Uint8Array
pqc.kyberPrivateKeyToBase64(privateKey: Uint8Array): string
pqc.kyberPrivateKeyFromBase64(b64: string): Uint8Array

pqc.dilithiumPublicKeyToBase64(publicKey: Uint8Array): string
pqc.dilithiumPublicKeyFromBase64(b64: string): Uint8Array
pqc.dilithiumPrivateKeyToBase64(privateKey: Uint8Array): string
pqc.dilithiumPrivateKeyFromBase64(b64: string): Uint8Array
```

#### Security

- **AES-256-GCM** (authenticated encryption) — 256-bit keys resist Grover's quantum algorithm
  - ✅ Quantum-safe symmetric encryption
- **Kyber** (lattice-based KEM) — NIST Post-Quantum Cryptography finalist
  - ✅ Resists Shor's algorithm (no known quantum attack)
  - ✅ Provides forward-secret key exchange even if RSA breaks
- **Dilithium** (lattice-based signatures) — NIST PQC finalist
  - ✅ Quantum-proof digital signatures for long-term authenticity
  - ✅ Documents signed today remain verifiable 10+ years from now
- **Hybrid encryption** (Kyber + RSA-OAEP)
  - ✅ Secure if Kyber _or_ RSA holds; breaks only if both crack simultaneously
  - ✅ Enables gradual migration from classical to pure post-quantum
- **600,000 PBKDF2-SHA256 iterations** (strong against brute-force)
  - - SHA-3 KDF, HKDF-SHA3, and Argon2id alternatives for even higher security margins
- **Unique 128-bit salt per message/file**
- **Unique 96-bit IV per chunk/frame**
- **No keys ever leave your device**
- **ECDSA (P-256/P-384)** for signatures — compact and widely supported
  - ⚠️ **Quantum-vulnerable** – use only for signatures with < 5-year validity
- **AES-256** remains resistant to Grover's algorithm due to key size (128-bit security post-quantum)

#### Quantum-Safety Disclaimer

As of 2026, quantum computers large enough to break RSA-4096 do not exist. However:

1. **"Harvest now, decrypt later"** attacks are already underway – adversaries are recording encrypted data now to decrypt with future quantum computers
2. **RSA-4096 and ECDSA** are vulnerable once large quantum computers exist (estimated 2030–2040, but uncertain)
3. **AES-256 and SHA-2/SHA-3** are believed quantum-safe at their key sizes
4. **WebCrypt's quantum resistance** comes from:
   - Using AES-256 for actual data encryption (already safe)
   - Offering Kyber as an alternative/backup to RSA
   - Providing Dilithium for long-term-valid signatures

**Recommended approach for data with 10+ year confidentiality needs:**

- Encrypt with `WebCryptAsym` using `hybridEncapsulate(rsaPublicKey, kyberPublicKey)` – ensures session keys are PQC-safe
- Store encrypted data with Kyber ciphertext; RSA provides redundant protection
- If quantum computers break RSA later, data is still safe under Kyber-derived AES-256

#### Browser Support

Chrome 80+ • Edge 80+ • Firefox 90+ • Safari 15+  
All support Web Crypto API + Insertable Streams.

#### Node.js Support

Works natively in Node.js 18+ via built-in crypto.webcrypto.

```js
const { WebCrypt } = require("webcrypt"); // CommonJS
// or
import { WebCrypt } from "webcrypt"; // ES Modules
```

#### License

MIT License — free for personal and commercial use  
© 2026 Lucas Armstrong  
https://github.com/lucasarmstrong/webcrypt

No telemetry. No servers. No backdoors.  
Just pure, unbreakable encryption that works offline, forever.

Star this repo if you believe in private communication.

Made with passion for a freer, safer internet.
