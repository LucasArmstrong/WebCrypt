# WebCrypt v1.0.0

**Zero-dependency cryptographic suite & native AI Agent Tooling (MCP) for modern JavaScript.**

[![npm version](https://img.shields.io/npm/v/webcrypt.svg)](https://www.npmjs.com/package/webcrypt)
[![npm downloads](https://img.shields.io/npm/dm/webcrypt.svg)](https://www.npmjs.com/package/webcrypt)
[![Node](https://img.shields.io/badge/node-%3E%3D18.0.0-339933.svg?logo=node.js&logoColor=white)](https://nodejs.org)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.5-3178C6.svg?logo=typescript&logoColor=white)](https://www.typescriptlang.org)
[![MCP](https://img.shields.io/badge/MCP-Ready-blueviolet.svg?logo=json&logoColor=white)](https://modelcontextprotocol.io)
[![Tests](https://img.shields.io/badge/tests-247%20passed-brightgreen.svg)](./__tests__)
[![Coverage](https://img.shields.io/badge/coverage-93.8%25-success.svg)](./coverage)
[![PuterVision Triad](https://img.shields.io/badge/PuterVision-Triad%20Standard-6366f1.svg)](https://putervision.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://github.com/putervision/webcrypt/blob/main/LICENSE)

AES-256-GCM symmetric encryption, RSA-4096 hybrid asymmetric encryption, ECDH key agreement, digital signatures, JWE compact serialization (RFC 7516), post-quantum cryptography (Kyber/Dilithium), and native Model Context Protocol (MCP) tooling — built natively for browser, Node.js, edge runtimes, and autonomous AI coding agents.

---

## Interactive Live Demo & Documentation

- 🚀 **[Try WebCrypt Live Playground](https://putervision.github.io/webcrypt/)**: Test AES-256, RSA-4096, ECDH, digital signatures, and file encryption directly in your browser.
- 📖 **[Multi-IDE MCP Setup Guide](./docs/MCP_IDE_SETUP.md)**: Step-by-step installation for Google Antigravity, Cursor, Claude Desktop, VS Code, Windsurf, Cline, and Zed.
- 📚 **[Documentation Index](./docs/)**

---

## What's New in v1.0.0

- 🤖 **Native Model Context Protocol (MCP) Server**: Zero-dependency stdio server (`npx webcrypt mcp`) empowering AI agents to encrypt sensitive artifacts, generate cryptographic proofs, and protect vault data.
- ⚡ **Automated Project Scaffolding (`webcrypt init`)**: One-command initialization of agent skills, IDE MCP configs, and workspace instruction rules.
- 🌐 **Global Multi-Project Management (`webcrypt init-global` / `webcrypt doctor-global`)**: Batch re-scaffolding and health diagnostics across all projects registered in `~/.webcrypt/projects.json`.
- 📐 **Deterministic Multi-Chunk Framing**: Fixed 8MB plaintext chunking with 8MB + 16B ciphertext streaming framing for constant-memory multi-gigabyte file encryption.
- ⚛️ **Self-Consistent Post-Quantum KEM**: Kyber512/768/1024 and hybrid classical+PQC KEM round-trips.
- 🛡️ **Centralized Web Crypto Resolution**: Automatic seamless environment detection across browsers, Web Workers, Node.js 18+, Bun, and edge runtimes.
- 🌐 **PuterVision Triple Memory Synergy**: Seamless zero-friction encryption layer for `state-memory-mcp` (workflow state memory) and `vision-memory-mcp` (visual caching & grounding).

---

## Installation & Quick Setup

### 1. Install as Library

```bash
npm install webcrypt
```

### 2. Auto-Initialize Project for AI Agents & IDEs

```bash
# Global installation (recommended for CLI)
npm install -g webcrypt

# Inside any project directory
webcrypt init
```

_`webcrypt init` automatically creates `.agents/skills/webcrypt-mcp/SKILL.md`, `.cursor/mcp.json`, `.vscode/mcp.json`, and injects agent rules into `AGENTS.md`, `.cursorrules`, `.windsurfrules`, `.gemini/instructions.md`, and `CLAUDE.md`._

---

## Why Use WebCrypt MCP? (Key Benefits for AI Agents)

AI coding agents (Antigravity, Cursor, Claude, Copilot, Windsurf, Cline) routinely handle confidential materials: API keys, database connection strings, architecture plans, and private conversation logs.

**WebCrypt MCP** equips your AI agents with an autonomous, zero-dependency cryptographic vault directly in their toolbelt:

- 🔐 **Confidential Local Vaulting**: Agents encrypt API keys, credentials, and sensitive state nodes (`encrypt_payload`) before saving them to disk, preventing plaintext leaks in prompt histories and git repositories.
- 🛡️ **Cryptographic Provenance & Tamper-Proof Signing**: Agents compute SHA-256/SHA-3 hashes (`crypto_hash`) and digital signatures (`sign_verify`) on code diffs, release binaries, and test evidence packs.
- 🤝 **Secure Inter-Agent Communication**: Subagents and peer agents generate ephemeral JWK keypairs (`manage_keys`) to establish encrypted channels over shared message buses.
- 🧠 **Completes the PuterVision Triad**:
  - `state-memory-mcp`: Workflow tracking, task DAGs, decisions, and blockers.
  - `vision-memory-mcp`: Visual UI state caching, screenshot layout trees, and element grounding.
  - `webcrypt-mcp`: Vault encryption, evidence signatures, and cryptographic integrity.
- ⚡ **Zero Dependencies**: 100% native Web Crypto API execution (`globalThis.crypto.subtle`) across Node.js 18+, Bun, browsers, and edge environments—no `node-gyp` or native compilation issues.
- ⚛️ **Post-Quantum Ready**: Built-in Kyber KEM and Dilithium signatures (`pqc_kem_sign`) future-proof long-term agent artifacts against quantum attacks.

### Comparison: With vs. Without WebCrypt MCP

| Feature / Workflow         | ❌ Without WebCrypt MCP                               | ✅ With WebCrypt MCP                                    |
| :------------------------- | :---------------------------------------------------- | :------------------------------------------------------ |
| **Secret Storage**         | Plaintext in `.env`, artifacts, or prompt logs        | Authenticated AES-256-GCM encrypted vaults              |
| **Artifact Integrity**     | Unsigned files, trust-based verification              | Cryptographic ECDSA / HMAC digital signatures           |
| **Setup & Dependencies**   | Agents install heavy packages (`crypto-js`, `bcrypt`) | Zero dependencies — instant native Web Crypto execution |
| **Inter-Agent Security**   | Unencrypted subagent messages in chat history         | Ephemeral ECDH / RSA hybrid encrypted channels          |
| **Workflow State Privacy** | Raw data stored in task graphs and memory             | Encrypted state node payloads and signed proofs         |

---

## IDE & AI Agent Platform Integration

WebCrypt provides native Model Context Protocol (MCP) tooling exposing 6 core cryptographic tools to AI agents:

| MCP Tool              | Description                                                   | Example Agent Use Case                                      |
| :-------------------- | :------------------------------------------------------------ | :---------------------------------------------------------- |
| **`encrypt_payload`** | Symmetric AES-256-GCM, RSA-4096, or JSON Data mode            | Encrypt sensitive tokens, passwords, and private DAG states |
| **`decrypt_payload`** | Decrypt ciphertext back to plaintext or structured JSON       | Restore credentials or decrypted cache states               |
| **`manage_keys`**     | Generate RSA-4096, ECDH P-256/P-384, HMAC keys (JWK format)   | Create secure keypairs for agent-to-agent communication     |
| **`crypto_hash`**     | Compute SHA-256, SHA-384, SHA-512, or SHA-3 digests           | Compute content hashes and integrity tags                   |
| **`sign_verify`**     | ECDSA, RSA-PSS, HMAC, and HMAC-SHA3 signing & verification    | Cryptographically sign build artifacts and evidence packs   |
| **`pqc_kem_sign`**    | Kyber KEM, Dilithium signatures, and Hybrid classical+PQC KEM | Post-quantum key encapsulation and quantum-safe signatures  |

### MCP Configuration Snippets by IDE

#### 🔵 Google Antigravity (`~/.gemini/config/config.json`)

```json
{
  "mcpServers": {
    "webcrypt": {
      "command": "npx",
      "args": ["-y", "webcrypt", "mcp"]
    }
  }
}
```

#### 🟣 Cursor IDE (`.cursor/mcp.json`)

```json
{
  "mcpServers": {
    "webcrypt": {
      "command": "npx",
      "args": ["-y", "webcrypt", "mcp"]
    }
  }
}
```

#### 🟠 Claude Desktop (`claude_desktop_config.json`)

```json
{
  "mcpServers": {
    "webcrypt": {
      "command": "npx",
      "args": ["-y", "webcrypt", "mcp"]
    }
  }
}
```

#### 🟢 VS Code / GitHub Copilot Agent (`.vscode/mcp.json`)

```json
{
  "mcpServers": {
    "webcrypt": {
      "command": "npx",
      "args": ["-y", "webcrypt", "mcp"]
    }
  }
}
```

#### 🌊 Windsurf (`~/.codeium/windsurf/mcp_config.json`) & 🤖 Cline (`cline_mcp_settings.json`)

```json
{
  "mcpServers": {
    "webcrypt": {
      "command": "npx",
      "args": ["-y", "webcrypt", "mcp"]
    }
  }
}
```

> 📖 For full setup details, see the **[Multi-IDE MCP Setup Guide](./docs/MCP_IDE_SETUP.md)**.

---

## CLI & Global Project Management

```bash
# Verify environment and configuration health
webcrypt doctor

# Audit all registered projects across your machine
webcrypt doctor-global

# Re-initialize all projects in ~/.webcrypt/projects.json
webcrypt init-global

# Scan an entire workspace directory and auto-register all projects
webcrypt init-global --scan ~/workspaces

# List all registered projects
webcrypt projects --clean-stale

# Direct CLI text encryption / decryption
webcrypt encrypt "secret message" -p "my-password"
webcrypt decrypt "<base64>" -p "my-password"

# Direct CLI key generation
webcrypt keygen rsa
webcrypt keygen ecdh
webcrypt keygen password
```

---

## PuterVision Triple Memory Triad

WebCrypt serves as the cryptographic security pillar of the PuterVision autonomous agent ecosystem:

```
                  ┌──────────────────────────────────────────────────────────┐
                  │                 Autonomous AI Coding Agent               │
                  └─────────────┬──────────────────────────────┬─────────────┘
                                │                              │
                                ▼                              ▼
                 ┌─────────────────────────────┐ ┌───────────────────────────┐
                 │  State Memory MCP (Graph)   │ │  Vision Memory MCP (AX)   │
                 └──────────────┬──────────────┘ └─────────────┬─────────────┘
                                │                              │
                                └──────────────┬───────────────┘
                                               │ (Zero-friction Vault Protection)
                                               ▼
                                 ┌───────────────────────────┐
                                 │     WebCrypt MCP Server   │
                                 │   (Stdio JSON-RPC 2.0)    │
                                 └───────────────────────────┘
```

| Module                  | Role in Agent Ecosystem        | Primary Benefit                                                          |
| :---------------------- | :----------------------------- | :----------------------------------------------------------------------- |
| **`state-memory-mcp`**  | Workflow State Memory          | Persistent task graph, blocker tracing, and decision memory              |
| **`vision-memory-mcp`** | Visual Cache & Grounding       | Visual state caching, token savings, AX tree coordinate prediction       |
| **`webcrypt`**          | Cryptographic Vault & Security | Local database encryption, secure artifact sharing, tamper-proof signing |

---

## JavaScript / TypeScript API Quick Start

### 1. Symmetric Text & JSON Encryption (AES-256-GCM)

```js
import { WebCrypt } from "webcrypt";
const wc = new WebCrypt();

// Text encryption
const encrypted = await wc.encryptText("Secret message", "my-password");
const decrypted = await wc.decryptText(encrypted, "my-password");

// Automatic JSON object serialization
const vaultData = { apiKey: "secret_123", tokens: 5000 };
const cipherData = await wc.encryptData(vaultData, "vault-password");
const restoredData = await wc.decryptData(cipherData, "vault-password");
```

### 2. Streaming File Encryption (Constant Memory)

```js
const { blob, filename } = await wc.encryptFile(file, "my-password", { parallelChunks: 4 });
const decrypted = await wc.decryptFile(blob, "my-password");
```

### 3. Public-Key Hybrid Encryption (RSA-4096)

```js
import { WebCryptAsym } from "webcrypt";
const wca = new WebCryptAsym();

const keys = await wca.generateKeyPair(4096);
const encrypted = await wca.encryptText("Secret payload", keys.publicKey);
const decrypted = await wca.decryptText(encrypted, keys.privateKey);
```

### 4. ECDH Key Agreement & Fast Encryption

```js
const aliceKeys = await wca.generateECDHKeyPair("P-256");
const bobKeys = await wca.generateECDHKeyPair("P-256");

const encrypted = await wca.encryptWithECDH(
  "Confidential channel data",
  aliceKeys.privateKey,
  bobKeys.publicKey
);
const decrypted = await wca.decryptWithECDH(encrypted, bobKeys.privateKey, aliceKeys.publicKey);
```

### 5. Digital Signatures & HMAC

```js
// ECDSA signatures
const signingKeys = await wca.generateSigningKeyPair("P-256");
const signature = await wca.signText("Tamper-proof statement", signingKeys.privateKey);
const isValid = await wca.verifyText("Tamper-proof statement", signature, signingKeys.publicKey);

// Post-Quantum HMAC (SHA-3)
const hmacKey = await wc.generateHmacKeySHA3("shared-secret");
const tag = await wc.computeHmacSHA3("Message data", hmacKey);
const validMac = await wc.verifyHmacSHA3("Message data", tag, hmacKey);
```

---

---

## 📚 Technical Documentation Directory

Explore dedicated technical guides and deep dives in the [`docs/`](docs/) directory:

| Guide                                                                       | Description                                                                                                                |
| :-------------------------------------------------------------------------- | :------------------------------------------------------------------------------------------------------------------------- |
| ⚙️ **[Multi-IDE MCP Setup Guide](docs/MCP_IDE_SETUP.md)**                   | Step-by-step setup for Google Antigravity, Cursor, Claude Desktop, VS Code / Copilot, Windsurf, Cline, and Zed.            |
| 🔒 **[Symmetric Encryption API (`WebCrypt`)](docs/API_SYMMETRIC.md)**       | OWASP PBKDF2 (600,000 iterations), AES-256-GCM, streaming file encryption, WebRTC transform streams, and HMAC.             |
| 🔑 **[Asymmetric Encryption API (`WebCryptAsym`)](docs/API_ASYMMETRIC.md)** | RSA-4096 hybrid encryption, ECDH P-256/P-384 key agreement, JWE compact serialization (RFC 7516), and digital signatures.  |
| ⚛️ **[Post-Quantum Cryptography Guide](docs/PQC.md)**                       | Lattice-based Kyber KEM, Dilithium digital signatures, hybrid classical+PQC encapsulation, and future roadmap.             |
| 🏗️ **[Architecture & MCP Specifications](docs/ARCHITECTURE.md)**            | Zero-dependency design, JSON-RPC 2.0 stdio framing, deterministic chunking offsets, and PuterVision Triad synergy.         |
| 🤖 **[Agent Skill Definition](.agents/skills/webcrypt-mcp/SKILL.md)**       | Teaches autonomous AI coding agents how and when to invoke WebCrypt MCP tools for vaulting and verification.               |
| 📋 **[Project Instructions Template](PROJECT_INSTRUCTIONS_TEMPLATE.md)**    | Canonical instruction rule block for multi-agent workspaces (`<!-- webcrypt-mcp:start --> ... <!-- webcrypt-mcp:end -->`). |

---

## 🌐 PuterVision Triple Memory Triad

WebCrypt forms the core cryptographic and security layer of the **PuterVision Autonomous AI Agent Ecosystem**:

```
┌───────────────────────────────────────────────────────────┐
│              Autonomous AI Coding Agent                   │
│     (Antigravity / Cursor / Claude / Copilot / Cline)     │
└─────────┬───────────────────┬───────────────────┬─────────┘
          │                   │                   │
          ▼                   ▼                   ▼
┌───────────────────┐┌───────────────────┐┌───────────────────┐
│ state-memory-mcp  ││ vision-memory-mcp ││     webcrypt      │
│  (Workflow State) ││  (Visual Cache)   ││  (Security Vault) │
│  • Task Graph DAG ││  • UI Grounding   ││  • AES-256 Vault  │
│  • Decisions & SDD││  • Layout Trees   ││  • RSA/ECDH Keys  │
│  • Event Ledger   ││  • Visual History ││  • Digital Sigs   │
└───────────────────┘└───────────────────┘└───────────────────┘
```

- 📊 **[`@putervision/state-memory-mcp`](https://github.com/putervision/state-memory-mcp)**: Deterministic persistent SQLite state graph for tracking workflow state, task DAGs, decision records, and Spec-Driven Development.
- 👁️ **[`@putervision/vision-memory-mcp`](https://github.com/putervision/vision-memory-mcp)**: Multimodal visual layout caching, perceptual hashing, element grounding, and video replay analysis.
- 🔐 **[`webcrypt`](https://github.com/putervision/webcrypt)**: Zero-dependency cryptographic vault, payload encryption, key generation, digital signatures, and post-quantum security.

---

## 🧪 Testing & Verification

```bash
# Run full unit and integration test matrix (30 test suites, 247 tests)
npm test

# Run test coverage audit
npm run test:coverage
```

---

## ⚖️ License & Disclaimers

Developed and maintained by [PuterVision](https://putervision.com). Released under the [MIT License](LICENSE).

- **100% Local Execution Guarantee**: All encryption, key generation, and hash calculations occur entirely in your local runtime via standard W3C Web Crypto API (`crypto.subtle`). Zero external API calls, telemetry, or network transmissions.
- **Trademarks & Non-Affiliation**: Product names (Cursor, Claude Code, Google Antigravity, VS Code, GitHub Copilot, Windsurf, Cline, Zed) are property of their respective owners and used solely for compatibility identification.
