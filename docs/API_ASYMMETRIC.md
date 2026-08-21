# WebCryptAsym API Reference (Asymmetric & Public-Key Cryptography)

The `WebCryptAsym` class provides zero-dependency asymmetric cryptography including **RSA-4096 Hybrid Encryption**, **ECDH Key Agreement**, **Digital Signatures (ECDSA P-256 / RSA-PSS)**, **JWE Compact Serialization (RFC 7516)**, **HKDF/PBKDF2 Key Derivation**, and **Hierarchical Key Derivation**.

---

## Table of Contents

- [Instantiation](#instantiation)
- [RSA Key Pairs & Hybrid Encryption](#rsa-key-pairs--hybrid-encryption)
- [ECDH Key Agreement](#ecdh-key-agreement)
- [Digital Signatures](#digital-signatures)
- [JWE Compact Serialization (RFC 7516)](#jwe-compact-serialization-rfc-7516)
- [Key Derivation (HKDF / PBKDF2 / SHA-3)](#key-derivation-hkdf--pbkdf2--sha-3)
- [Hierarchical Key Derivation](#hierarchical-key-derivation)
- [Key Export / Import (SPKI / PKCS#8 Base64)](#key-export--import-spki--pkcs8-base64)

---

## Instantiation

```js
import { WebCryptAsym } from "webcrypt";

const wca = new WebCryptAsym();
```

---

## RSA Key Pairs & Hybrid Encryption

### `generateKeyPair(modulusLength)`

Generates an RSA-OAEP key pair (default: 4096-bit).

- **Parameters:** `modulusLength` _(number, default: 4096)_
- **Returns:** `Promise<{ publicKey: CryptoKey, privateKey: CryptoKey }>`

```js
const keys = await wca.generateKeyPair(4096);
```

### `encryptText(text, publicKey)` / `decryptText(b64, privateKey)`

Hybrid encryption using RSA-OAEP to encrypt an ephemeral AES-256-GCM session key.

```js
const encrypted = await wca.encryptText("Confidential message", keys.publicKey);
const decrypted = await wca.decryptText(encrypted, keys.privateKey);
```

### `encryptData(data, publicKey)` / `decryptData(b64, privateKey)`

Serializes JavaScript objects to JSON and encrypts via RSA hybrid encryption.

```js
const b64 = await wca.encryptData({ secret: "data" }, keys.publicKey);
const obj = await wca.decryptData(b64, keys.privateKey);
```

---

## ECDH Key Agreement

### `generateECDHKeyPair(namedCurve)`

Generates an Elliptic Curve Diffie-Hellman key pair (P-256 or P-384).

```js
const aliceKeys = await wca.generateECDHKeyPair("P-256");
const bobKeys = await wca.generateECDHKeyPair("P-256");
```

### `deriveECDHSharedSecret(privateKey, peerPublicKey)`

Derives an AES-GCM 256-bit shared key via ECDH key agreement.

```js
const sharedKey = await wca.deriveECDHSharedSecret(aliceKeys.privateKey, bobKeys.publicKey);
```

### `encryptWithECDH(payload, senderPrivateKey, recipientPublicKey)` / `decryptWithECDH(b64, recipientPrivateKey, senderPublicKey)`

One-step ECDH public-key encryption and decryption.

```js
const encrypted = await wca.encryptWithECDH("ECDH Secret", aliceKeys.privateKey, bobKeys.publicKey);
const decrypted = await wca.decryptWithECDH(encrypted, bobKeys.privateKey, aliceKeys.publicKey);
```

---

## Digital Signatures

### `generateSigningKeyPair(curve = "P-256")`

Generates ECDSA digital signing key pair (P-256 or P-384).

```js
const ecdsaKeys = await wca.generateSigningKeyPair("P-256");
```

### `signText(text, privateKey)` / `verifyText(text, signatureB64, publicKey)`

Computes and verifies digital signatures over text messages.

```js
const sig = await wca.signText("Message", ecdsaKeys.privateKey);
const isValid = await wca.verifyText("Message", sig, ecdsaKeys.publicKey);
```

---

## JWE Compact Serialization (RFC 7516)

### `encryptJWE(payload, publicKey, customHeaders)`

Encrypts payload into a RFC 7516 compliant 5-part JWE Compact Serialization string (`header.encryptedKey.iv.ciphertext.tag`).

```js
const jweToken = await wca.encryptJWE({ user: "Alice" }, rsaKeys.publicKey);
```

### `decryptJWE(jweToken, privateKey)`

Decrypts a 5-part JWE Compact string.

```js
const payload = await wca.decryptJWE(jweToken, rsaKeys.privateKey);
```

---

## Key Derivation (HKDF / PBKDF2 / SHA-3)

### `deriveKeyHKDFSHA2(secret, salt, info, keyLength)`

Derives a key using HKDF-SHA256 (RFC 5869).

```js
const hkdfKey = await wca.deriveKeyHKDFSHA2(masterSecret, salt, "app-context", 256);
```

### `deriveKeyHKDFSHA3(secret, salt, info, keyLength)`

Derives key via HKDF with SHA-3 digest.

```js
const hkdfSha3Key = await wca.deriveKeyHKDFSHA3(masterSecret, salt, "context", 256);
```

---

## Hierarchical Key Derivation

### `deriveChildKeyHierarchical(parentKey, childSalt, purpose)`

Derives a child AES key from an existing parent AES key for context-specific operations.

```js
const childKey = await wca.deriveChildKeyHierarchical(parentKey, salt, "file-encryption");
```

---

## Key Export / Import (SPKI / PKCS#8 Base64)

### `exportPublicKey(publicKey)` / `importPublicKey(b64Key)`

Exports and imports RSA/ECDH public keys in Base64 SPKI format.

```js
const pubB64 = await wca.exportPublicKey(rsaKeys.publicKey);
const importedPub = await wca.importPublicKey(pubB64);
```

### `exportPrivateKey(privateKey)` / `importPrivateKey(b64Key)`

Exports and imports RSA/ECDH private keys in Base64 PKCS#8 format.

```js
const privB64 = await wca.exportPrivateKey(rsaKeys.privateKey);
const importedPriv = await wca.importPrivateKey(privB64);
```

---

## AI Agent MCP Tooling

WebCrypt includes native Model Context Protocol (MCP) tooling exposing asymmetric cryptography to AI agents:

- `manage_keys(action: "generate", type: "rsa" | "ecdh" | "hmac" | "password", modulusLength?: 2048 | 4096, namedCurve?: "P-256" | "P-384")`
- `encrypt_payload(mode: "asymmetric", data: string | object, public_key_jwk: object)`
- `decrypt_payload(mode: "asymmetric", ciphertext: string, private_key_jwk: object)`
- `sign_verify(action: "sign" | "verify", algorithm: "ECDSA" | "RSA-PSS", data: string, key_jwk: object, signature?: string)`
- `pqc_kem_sign(action: "hybrid_encapsulate" | "hybrid_decapsulate", rsa_public_key_jwk?: object, rsa_private_key_jwk?: object, public_key_b64?: string, private_key_b64?: string)`

For full agent setup instructions, see [docs/MCP_IDE_SETUP.md](./MCP_IDE_SETUP.md).
