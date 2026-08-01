# Security Policy

## Supported Versions

| Version         | Supported               |
| --------------- | ----------------------- |
| 0.6.5 (Current) | ✅ Active support       |
| < 0.6.5         | ❌ Legacy / unsupported |

## Reporting a Vulnerability

If you discover a security vulnerability in WebCrypt, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

### How to Report

1. Email / Advisory: Open a private security advisory via [GitHub Security Advisories](https://github.com/putervision/webcrypt/security/advisories/new) or contact [PuterVision LLC](https://putervision.com).
2. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact assessment
   - Suggested fix (if any)

### What to Expect

- **Acknowledgment** within 48 hours
- **Assessment** within 1 week
- **Fix timeline** communicated after assessment
- **Credit** given in the release notes (unless you prefer anonymity)

## Limitation of Liability & Disclaimer of Warranty

WebCrypt is maintained by [PuterVision LLC](https://putervision.com) and provided "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND NONINFRINGEMENT.

IN NO EVENT SHALL PUTERVISION LLC, ITS AFFILIATES, OR CONTRIBUTORS BE LIABLE FOR ANY CLAIM, DAMAGES, OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT, OR OTHERWISE, ARISING FROM, OUT OF, OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

USERS AND DEVELOPERS ARE SOLELY RESPONSIBLE FOR VERIFYING CRYPTOGRAPHIC PARAMETERS, CONDUCTING INDEPENDENT SECURITY AUDITS, AND DETERMINING SUITABILITY FOR PRODUCTION DEPLOYMENTS.

## Security Considerations

### What WebCrypt Provides

- AES-256-GCM authenticated encryption (quantum-resistant symmetric)
- RSA-4096 hybrid encryption (classical asymmetric)
- ECDSA / RSA-PSS / EdDSA digital signatures
- PBKDF2 key derivation (600,000 iterations, OWASP compliant)
- Timing-attack resistant verification functions
- Input validation and DoS protection

### Known Limitations

- **WebCryptPQC is a PLACEHOLDER** — Kyber and Dilithium implementations are SHA-3 stubs, NOT real post-quantum cryptography. See [SECURITY_FIXES.md](./SECURITY_FIXES.md).
- **Argon2id is not supported** by the Web Crypto API — falls back to PBKDF2
- **JavaScript cannot guarantee secure memory erasure** — key cleanup is best-effort
- **RSA-4096 is vulnerable to future quantum computers** — use hybrid encryption for long-term secrets
- **WebRTC E2EE uses a fixed salt** for key derivation from passwords

### Recommended Practices

1. Use strong, unique passwords for symmetric encryption
2. Use `WebCryptAsym` with hybrid methods for data needing 10+ year confidentiality
3. Do not rely on `WebCryptPQC` for production post-quantum security
4. Integrate [liboqs-js](https://github.com/open-quantum-safe/liboqs) for real Kyber/Dilithium
5. Rotate keys periodically using `rotateKeyNew()`
