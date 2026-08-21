# WebCrypt MCP Testing Patterns & Tool Execution Reference

This document provides autonomous AI coding agents with complete JSON-RPC 2.0 request/response examples and test recipes for all 6 tools provided by `webcrypt-mcp`.

---

## ⚡ Quick Test Command

Any agent can immediately verify the entire WebCrypt MCP server by running:

```bash
node .agents/skills/webcrypt-mcp/scripts/exercise_tools.js
```

---

## 🛠️ Tool-by-Tool Request & Response Schemas

### 1. `crypto_hash`

Computes cryptographic hash digests with Web Crypto API and SHA-3 fallback.

**Request:**

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "crypto_hash",
    "arguments": {
      "algorithm": "SHA-256",
      "data": "Evidence Pack Proof #1",
      "encoding": "hex"
    }
  }
}
```

**Response:**

```json
{
  "algorithm": "SHA-256",
  "encoding": "hex",
  "digest": "bcc30009961779f41c0747bbb473cdf997b2bcc44066fbea47128ecec502a4d1"
}
```

---

### 2. `manage_keys`

Generates high-entropy passwords, RSA keypairs (RSA-OAEP or RSA-PSS), ECDH key agreement pairs, ECDSA signing pairs, or HMAC keys in standard JWK format.

**Generate Password:**

```json
{
  "name": "manage_keys",
  "arguments": { "action": "generate_random_password", "length": 32 }
}
```

**Generate ECDSA Signing Keypair:**

```json
{
  "name": "manage_keys",
  "arguments": { "action": "generate", "type": "ecdsa", "namedCurve": "P-256" }
}
```

---

### 3. `encrypt_payload` & `decrypt_payload`

#### A. Symmetric Mode (AES-256-GCM + 600k PBKDF2)

- **Encrypt**: `{ "mode": "symmetric", "data": "secret text", "password": "..." }`
- **Decrypt**: `{ "mode": "symmetric", "ciphertext": "...", "password": "..." }`
- **Returns**: `{ "data": "secret text", "plaintext": "secret text", "mode": "symmetric" }`

#### B. Structured JSON Data Mode

- **Encrypt**: `{ "mode": "data", "data": { "apiKey": "sk_123", "tokens": 500 }, "password": "..." }`
- **Decrypt**: `{ "mode": "data", "ciphertext": "...", "password": "..." }`
- **Returns**: `{ "data": { "apiKey": "sk_123", "tokens": 500 }, "mode": "data" }`

#### C. Asymmetric RSA-4096 Hybrid Mode

- **Encrypt**: `{ "mode": "asymmetric", "data": "secret text", "public_key_jwk": { ... } }`
- **Decrypt**: `{ "mode": "asymmetric", "ciphertext": "...", "private_key_jwk": { ... } }`
- **Returns**: `{ "data": "secret text", "plaintext": "secret text", "mode": "asymmetric" }`

---

### 4. `sign_verify`

Computes or verifies digital signatures (HMAC, ECDSA, RSA-PSS, HMAC-SHA3).

**Sign ECDSA:**

```json
{
  "name": "sign_verify",
  "arguments": {
    "action": "sign",
    "algorithm": "ECDSA",
    "data": "Checksum statement",
    "key_jwk": { "kty": "EC", "crv": "P-256", "d": "...", "x": "...", "y": "..." }
  }
}
```

**Verify ECDSA:**

```json
{
  "name": "sign_verify",
  "arguments": {
    "action": "verify",
    "algorithm": "ECDSA",
    "data": "Checksum statement",
    "signature": "...",
    "key_jwk": { "kty": "EC", "crv": "P-256", "x": "...", "y": "..." }
  }
}
```

**Returns:** `{ "algorithm": "ECDSA", "valid": true }`

---

### 5. `pqc_kem_sign`

Post-Quantum lattice key encapsulation (Kyber512 / 768 / 1024) and signatures (Dilithium2 / 3 / 5).

- **`generate_kyber_keypair`**: `{ "level": "Kyber768" }` ➔ `{ "public_key_b64": "...", "private_key_b64": "..." }`
- **`kyber_encapsulate`**: `{ "level": "Kyber768", "public_key_b64": "..." }` ➔ `{ "ciphertext_b64": "...", "shared_secret_b64": "..." }`
- **`kyber_decapsulate`**: `{ "level": "Kyber768", "ciphertext_b64": "...", "private_key_b64": "..." }` ➔ `{ "shared_secret_b64": "..." }`
- **`generate_dilithium_keypair`**: `{ "level": "Dilithium3" }` ➔ `{ "public_key_b64": "...", "private_key_b64": "..." }`
- **`dilithium_sign`**: `{ "level": "Dilithium3", "data": "...", "private_key_b64": "..." }` ➔ `{ "signature_b64": "..." }`
- **`dilithium_verify`**: `{ "level": "Dilithium3", "data": "...", "signature_b64": "...", "public_key_b64": "..." }` ➔ `{ "valid": true }`
