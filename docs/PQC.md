# Post-Quantum Cryptography (WebCryptPQC)

> ⚠️ **PLACEHOLDER IMPLEMENTATION** — Kyber and Dilithium use SHA-3 hashing stubs, NOT real lattice-based cryptography. Do not use for production security. See [migration path](#migration-path) below.

---

## Limitation of Liability & Security Disclaimer

WebCryptPQC is maintained by [PuterVision LLC](https://putervision.com) and provided "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED.

IN NO EVENT SHALL PUTERVISION LLC, ITS AFFILIATES, OR CONTRIBUTORS BE LIABLE FOR ANY CLAIM, DAMAGES, OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT, OR OTHERWISE, ARISING FROM, OUT OF, OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

---

## Overview

WebCryptPQC provides a **framework** for post-quantum key exchange and digital signatures using NIST PQC finalists. The current implementation is a placeholder that mirrors the real API surface, allowing you to build against it today and swap in real PQC when official native Web Crypto PQC standards or `liboqs-js` integrations land.

## Kyber Key Encapsulation (KEM)

Kyber is a lattice-based Key Encapsulation Mechanism selected by NIST for post-quantum standardization.

```js
import { WebCryptPQC } from "webcrypt";

// Enable stub mode for development/testing environments
WebCryptPQC.enableStubTesting(true);

const pqc = new WebCryptPQC(); // ⚠️ Warns about stub status

// Generate Kyber key pair (choose security level)
const kyberKeys = await pqc.generateKyberKeyPair("Kyber768"); // 192-bit security
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
```

## Dilithium Digital Signatures

Dilithium is a lattice-based digital signature algorithm selected by NIST for post-quantum standardization.

```js
// Generate Dilithium signing key pair
const dilithiumKeys = await pqc.generateDilithiumKeyPair("Dilithium3"); // 192-bit security

// Sign a message
const message = "I approve this transaction #12345";
const signature = await pqc.dilithiumSign(message, dilithiumKeys.privateKey, "Dilithium3");

// Verify the signature
const isValid = await pqc.dilithiumVerify(
  message,
  signature,
  dilithiumKeys.publicKey,
  "Dilithium3"
);
```

## Hybrid Encryption (Kyber + RSA)

Combines classical RSA-4096 with post-quantum Kyber for defense-in-depth. Secure if **either** algorithm holds.

```js
import { WebCryptAsym } from "webcrypt";
import { WebCryptPQC } from "webcrypt";

const crypt = new WebCryptAsym();
const pqc = new WebCryptPQC();

// Alice generates both RSA and Kyber key pairs
const rsaKeys = await crypt.generateKeyPair(); // RSA-4096
const kyberKeys = await pqc.generateKyberKeyPair("Kyber768");

// Bob encrypts using both schemes (hybrid)
const bobRsaPubKey = await crypt.importPublicKey(await crypt.exportPublicKey(rsaKeys.publicKey));
const { sharedSecret, kyberCiphertext, rsaWrappedSharedSecret } = await pqc.hybridEncapsulate(
  bobRsaPubKey,
  kyberKeys.publicKey,
  "Kyber768"
);

// Alice decrypts using both schemes
const recoveredSharedSecret = await pqc.hybridDecapsulate(
  kyberCiphertext,
  rsaWrappedSharedSecret,
  rsaKeys.privateKey,
  kyberKeys.privateKey,
  "Kyber768"
);
// recoveredSharedSecret === sharedSecret
```

## Security Level Recommendations

| Use Case               | Kyber Level | Dilithium Level | Notes                          |
| ---------------------- | ----------- | --------------- | ------------------------------ |
| Short-term (< 2 years) | Kyber512    | Dilithium2      | Fast, lower overhead           |
| Standard (2–10 years)  | Kyber768    | Dilithium3      | **Recommended** for most cases |
| Long-term (> 10 years) | Kyber1024   | Dilithium5      | Maximum security margins       |

## Performance Characteristics

| Algorithm      | Key Size | Signature Size | Generation | Speed    | Notes                        |
| -------------- | -------- | -------------- | ---------- | -------- | ---------------------------- |
| ECDSA P-256    | 32 B     | 64 B           | ~100ms     | ~1ms/sig | Fast, but broken by Shor     |
| RSA-4096       | 512 B    | 512 B          | ~2s        | ~100ms   | Slower, also broken by Shor  |
| Dilithium3     | 1952 B   | 3293 B         | ~1s        | ~500μs   | Larger sigs, quantum-safe    |
| Kyber768 (KEM) | 1184 B   | 1088 B (ct)    | ~100ms     | ~500μs   | Efficient; replaces RSA-4096 |

## API Reference

```ts
const pqc = new WebCryptPQC();

// Kyber KEM
pqc.generateKyberKeyPair(level?: 'Kyber512' | 'Kyber768' | 'Kyber1024'): Promise<{ publicKey: Uint8Array, privateKey: Uint8Array }>
pqc.kyberEncapsulate(publicKey: Uint8Array, level?: string): Promise<{ ciphertext: Uint8Array, sharedSecret: Uint8Array }>
pqc.kyberDecapsulate(ciphertext: Uint8Array, privateKey: Uint8Array, level?: string): Promise<Uint8Array>

// Dilithium Signatures
pqc.generateDilithiumKeyPair(level?: 'Dilithium2' | 'Dilithium3' | 'Dilithium5'): Promise<{ publicKey: Uint8Array, privateKey: Uint8Array }>
pqc.dilithiumSign(message: string | Uint8Array, privateKey: Uint8Array, level?: string): Promise<Uint8Array>
pqc.dilithiumVerify(message: string | Uint8Array, signature: Uint8Array, publicKey: Uint8Array, level?: string): Promise<boolean>

// Hybrid Encryption
pqc.hybridEncapsulate(rsaPublicKey: CryptoKey, kyberPublicKey: Uint8Array, level?: string): Promise<{ sharedSecret, kyberCiphertext, rsaWrappedSharedSecret }>
pqc.hybridDecapsulate(kyberCiphertext: Uint8Array, rsaWrapped: Uint8Array, rsaPrivateKey: CryptoKey, kyberPrivateKey: Uint8Array, level?: string): Promise<Uint8Array>

// Key Serialization
pqc.kyberPublicKeyToBase64(key: Uint8Array): string
pqc.kyberPublicKeyFromBase64(b64: string): Uint8Array
pqc.kyberPrivateKeyToBase64(key: Uint8Array): string
pqc.kyberPrivateKeyFromBase64(b64: string): Uint8Array
pqc.dilithiumPublicKeyToBase64(key: Uint8Array): string
pqc.dilithiumPublicKeyFromBase64(b64: string): Uint8Array
pqc.dilithiumPrivateKeyToBase64(key: Uint8Array): string
pqc.dilithiumPrivateKeyFromBase64(b64: string): Uint8Array
```

## Migration Path

```
v0.6.x (Current): Placeholder stubs → Integrate liboqs-js manually
v0.7+ (Future):   Official liboqs-js integration → Production-ready PQC
2030+:            Pure lattice-based cryptography → Full quantum resistance
```

For production post-quantum needs today, integrate [liboqs-js](https://github.com/open-quantum-safe/liboqs) directly:

```bash
npm install @openquantumsafe/libs
```
