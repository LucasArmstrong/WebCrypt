# Contributing to WebCrypt

Thank you for your interest in contributing to WebCrypt! This document provides guidelines for contributing.

## Development Setup

```bash
# Clone the repository
git clone https://github.com/lucasarmstrong/webcrypt.git
cd webcrypt

# Install dependencies
npm install

# Run tests
npm test

# Run tests in watch mode
npm run test:watch

# Check formatting
npm run format:check

# Fix formatting
npm run format

# Build for distribution
npm run build
```

## Project Structure

```
webcrypt/
├── src/
│   ├── index.js              # Entry point (re-exports all modules)
│   ├── WebCrypt.js            # Symmetric encryption (AES-256-GCM)
│   ├── WebCrypt.d.ts          # TypeScript definitions
│   ├── WebCryptAsym.js        # Asymmetric encryption (RSA-4096 hybrid)
│   ├── WebCryptAsym.d.ts      # TypeScript definitions
│   ├── WebCryptPQC.js         # Post-quantum cryptography (placeholder)
│   ├── WebCryptPQC.d.ts       # TypeScript definitions
│   └── TimingSafeHelper.js    # Timing attack protection utilities
├── __tests__/                 # Jest test suites
├── examples/                  # HTML example files
├── SECURITY_FIXES.md          # Security hardening changelog
├── SECURITY.md                # Vulnerability reporting policy
└── CHANGELOG.md               # Version history
```

## Guidelines

### Code Style

- **Formatter:** Prettier is configured in `package.json` — run `npm run format` before committing
- **No dependencies:** WebCrypt is zero-dependency by design. Do not add runtime dependencies.
- **Comments:** Preserve existing comments. Add JSDoc for all public methods.

### Testing

- All tests use Jest with Node.js (ESM mode)
- Run the full suite: `npm test`
- Tests must pass before submitting a PR

### Pull Requests

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Make your changes
4. Run `npm test` and `npm run format:check`
5. Commit with clear, descriptive messages
6. Open a PR against `main`

### Security

- **Do NOT open public issues for security vulnerabilities** — see [SECURITY.md](./SECURITY.md)
- All crypto-related changes require careful review
- Update `.d.ts` type definitions when changing public API signatures

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
