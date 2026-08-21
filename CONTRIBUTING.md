# Contributing to WebCrypt

Thank you for your interest in contributing to WebCrypt! This document provides guidelines for contributing to WebCrypt, maintained by [PuterVision](https://putervision.com).

## Development Setup

```bash
# Clone the repository
git clone https://github.com/putervision/webcrypt.git
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
│   ├── WebCryptAsym.js        # Asymmetric encryption (RSA-4096 hybrid)
│   ├── WebCryptPQC.js         # Post-quantum cryptography (Kyber/Dilithium)
│   ├── TimingSafeHelper.js    # Timing attack protection utilities
│   ├── _base64.js             # Stack-safe Base64 encoding/decoding
│   ├── _crypto.js             # Unified SubtleCrypto resolution
│   ├── mcp/
│   │   ├── server.js          # JSON-RPC 2.0 stdio MCP server
│   │   ├── handlers.js        # Tool execution handlers
│   │   └── tools.js           # MCP tool definitions & JSON schemas
│   └── cli/
│       ├── init.js            # Project scaffolding (webcrypt init)
│       ├── doctor.js          # Health diagnostics (webcrypt doctor)
│       ├── registry.js        # Global project registry (~/.webcrypt/)
│       └── templates.js       # Skill, config, and rule templates
├── bin/
│   ├── webcrypt.js            # CLI launcher
│   └── webcrypt-mcp.js        # MCP server executable
├── dist/                      # Built ESM/CJS bundles & .d.ts declarations
├── docs/
│   ├── index.html             # Interactive playground web app
│   ├── app.js                 # Playground JavaScript
│   ├── ARCHITECTURE.md        # Architecture & MCP design docs
│   ├── MCP_IDE_SETUP.md       # Multi-IDE installation guide
│   ├── API_SYMMETRIC.md       # Symmetric API reference
│   ├── API_ASYMMETRIC.md      # Asymmetric API reference
│   └── PQC.md                 # Post-quantum API reference
├── .agents/
│   ├── AGENTS.md              # Multi-agent workspace instructions
│   └── skills/                # Agent skill definitions
├── __tests__/                 # Jest test suites (30 suites, 247 tests)
├── examples/                  # HTML example files
├── SECURITY.md                # Vulnerability reporting policy
├── SECURITY_FIXES.md          # Security hardening changelog
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

### Security & Disclaimer

- **Do NOT open public issues for security vulnerabilities** — see [SECURITY.md](./SECURITY.md)
- All crypto-related changes require careful review
- Update `.d.ts` type definitions when changing public API signatures
- Contributions are accepted subject to the [PuterVision](https://putervision.com) MIT License and Limitation of Liability disclaimer.

## License

By contributing, you agree that your contributions will be licensed under the MIT License by [PuterVision](https://putervision.com).
