# Examples

Browser-based demos for WebCrypt. Open each file directly in a browser (no build step required).

| File                                 | Description                                                 |
| ------------------------------------ | ----------------------------------------------------------- |
| [symmetric.html](./symmetric.html)   | HMAC generation and verification with SHA-3                 |
| [asymmetric.html](./asymmetric.html) | RSA-4096 key generation, encrypt/decrypt, and ECDSA signing |
| [combined.html](./combined.html)     | SHA-3 key derivation + AES-GCM encryption + HMAC            |

## Running

```bash
# Serve from the project root (examples import from ../src/)
npx serve .
# Then open http://localhost:3000/examples/symmetric.html
```

Or simply open the HTML files directly in a browser that supports ES modules (Chrome 80+, Firefox 90+, Safari 15+).
