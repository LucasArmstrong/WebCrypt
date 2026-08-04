# WebCrypt API Reference (Symmetric Encryption)

The `WebCrypt` class provides zero-dependency symmetric encryption using **AES-256-GCM**, streaming file encryption, WebRTC Insertable Streams (E2EE), LRU key caching, and HMAC helpers powered natively by the Web Crypto API.

---

## Table of Contents

- [Instantiation](#instantiation)
- [Text Encryption](#text-encryption)
- [Data Encryption](#data-encryption)
- [Streaming File Encryption](#streaming-file-encryption)
- [WebRTC Insertable Streams (E2EE)](#webrtc-insertable-streams-e2ee)
- [Key Caching & LRU Eviction](#key-caching--lru-eviction)
- [HMAC & Key Derivation Helpers](#hmac--key-derivation-helpers)
- [Static Constants](#static-constants)

---

## Instantiation

```js
import { WebCrypt } from "webcrypt";

// Default instance
const wc = new WebCrypt();

// Custom key cache max size
const wcCustom = new WebCrypt({ maxCacheSize: 50 });
```

---

## Text Encryption

### `encryptText(text, password)`

Encrypts a plaintext string into a Base64-encoded payload containing salt, IV, and AES-256-GCM ciphertext.

- **Parameters:**
  - `text` _(string)_: Plaintext string to encrypt.
  - `password` _(string)_: Secret password for key derivation.
- **Returns:** `Promise<string>` — Base64 payload.

```js
const encrypted = await wc.encryptText("Hello, WebCrypt!", "secret-password");
```

### `decryptText(b64, password)`

Decrypts a Base64 payload back into plaintext string.

- **Parameters:**
  - `b64` _(string)_: Base64-encoded encrypted payload.
  - `password` _(string)_: Decryption password.
- **Returns:** `Promise<string>` — Decrypted string.

```js
const decrypted = await wc.decryptText(encrypted, "secret-password");
```

---

## Data Encryption

### `encryptData(data, password)`

Serializes JavaScript objects or values to JSON and encrypts them.

- **Parameters:**
  - `data` _(any)_: Any JSON-serializable JavaScript object or primitive.
  - `password` _(string)_: Encryption password.
- **Returns:** `Promise<string>` — Base64 payload.

```js
const payload = { userId: 42, role: "admin", sessionToken: "abc123xyz" };
const encrypted = await wc.encryptData(payload, "secret-password");
```

### `decryptData(b64, password)`

Decrypts a Base64 payload and parses it back into a JavaScript object/value.

- **Parameters:**
  - `b64` _(string)_: Base64 encrypted string.
  - `password` _(string)_: Decryption password.
- **Returns:** `Promise<any>` — Parsed JavaScript value.

```js
const data = await wc.decryptData(encrypted, "secret-password");
console.log(data.userId); // 42
```

---

## Streaming File Encryption

### `encryptFile(fileOrBlob, password, options)`

Encrypts a `File` or `Blob` in constant-memory 8MB chunks using windowed parallel processing.

- **Parameters:**
  - `fileOrBlob` _(File|Blob)_: Target file/blob.
  - `password` _(string)_: Encryption password.
  - `options` _(Object, optional)_:
    - `parallelChunks` _(number)_: Number of parallel chunk promises (default: 4).
- **Returns:** `Promise<{ blob: Blob, filename: string }>`

```js
const { blob, filename } = await wc.encryptFile(userFile, "password", { parallelChunks: 4 });
```

### `decryptFile(fileOrBlob, password, options)`

Decrypts a WebCrypt encrypted file or blob in chunks.

- **Parameters:**
  - `fileOrBlob` _(File|Blob)_: Encrypted file/blob.
  - `password` _(string)_: Decryption password.
  - `options` _(Object, optional)_:
    - `parallelChunks` _(number)_: Parallel processing windows.
- **Returns:** `Promise<{ blob: Blob, filename: string }>`

```js
const { blob, filename } = await wc.decryptFile(encryptedBlob, "password");
```

---

## WebRTC Insertable Streams (E2EE)

### `createEncryptTransform(password)`

Creates an encryption transform function for `RTCRtpScriptTransform` / WebRTC Insertable Streams.

```js
const transform = await wc.createEncryptTransform("conference-secret");
// Pass to RTCRtpSender.transform
```

### `createDecryptTransform(password)`

Creates a decryption transform function for `RTCRtpReceiver.transform`.

```js
const transform = await wc.createDecryptTransform("conference-secret");
// Pass to RTCRtpReceiver.transform
```

---

## Key Caching & LRU Eviction

WebCrypt automatically caches derived PBKDF2 keys in memory using an **LRU (Least Recently Used)** cache to accelerate repeated encryptions while maintaining security.

```js
// Clear key cache manually
wc.clearKeyCache();

// Stop background automatic cleanup interval
wc.stopAutoCleanup();
```

---

## HMAC & Key Derivation Helpers

### `generateHmacKey(password, hash, customSalt)`

Generates or derives a non-exportable HMAC `CryptoKey`.

```js
const hmacKey = await wc.generateHmacKey("my-pass", "SHA-256");
```

### `generateHmacKeySHA3(password, hash, customSalt, iterations)`

Derives a quantum-resistant HMAC key using iterative SHA-3 hashing.

```js
const hmacKeySHA3 = await wc.generateHmacKeySHA3("my-pass", "SHA3-256", null, 10000);
```

### `computeHmac(data, key)` / `verifyHmac(data, tag, key)`

Computes and verifies HMAC authentication tags.

```js
const tag = await wc.computeHmac("message", hmacKey);
const isValid = await wc.verifyHmac("message", tag, hmacKey);
```

---

## Static Constants

- `WebCrypt.ALGORITHM`: `"AES-GCM"`
- `WebCrypt.KEY_LENGTH`: `256`
- `WebCrypt.IV_LENGTH`: `12` (96 bits)
- `WebCrypt.SALT_LENGTH`: `16` (128 bits)
- `WebCrypt.PBKDF2_ITERATIONS`: `600,000`
- `WebCrypt.CHUNK_SIZE`: `8 * 1024 * 1024` (8MB)
