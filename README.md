# WebCrypt v1.0.0

**Zero-dependency Web Crypto & native AI Agent Tooling (MCP) for modern JavaScript.**

[![npm version](https://img.shields.io/npm/v/webcrypt.svg)](https://www.npmjs.com/package/webcrypt)
[![npm downloads](https://img.shields.io/npm/dm/webcrypt.svg)](https://www.npmjs.com/package/webcrypt)
[![Node](https://img.shields.io/badge/node-%3E%3D18.0.0-339933.svg?logo=node.js&logoColor=white)](https://nodejs.org)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.5-3178C6.svg?logo=typescript&logoColor=white)](https://www.typescriptlang.org)
[![MCP](https://img.shields.io/badge/MCP-Ready-blueviolet.svg?logo=json&logoColor=white)](https://modelcontextprotocol.io)
[![Tests](https://img.shields.io/badge/tests-247%20passed-brightgreen.svg)](./__tests__)
[![Coverage](https://img.shields.io/badge/coverage-93.8%25-success.svg)](./coverage)
[![PuterVision Triad](https://img.shields.io/badge/PuterVision-Triad%20Standard-6366f1.svg)](https://putervision.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

AES-256-GCM symmetric encryption, RSA-4096 hybrid public keys, ECDH key agreement, ECDSA/HMAC digital signatures, and Post-Quantum KEM (Kyber/Dilithium) — zero runtime dependencies, pure Web Crypto API.

---

## ⚡ Quickstart (15 Seconds)

### 1. Installation

```bash
# 📦 Install as project library (Node.js, TypeScript, Browser)
npm install webcrypt

# 🌐 Install globally (CLI utilities & global MCP tools)
npm install -g webcrypt
```

```javascript
import { WebCrypt, WebCryptAsym } from "webcrypt";

// 🔒 Symmetric AES-256-GCM (600k PBKDF2 iterations)
const wc = new WebCrypt();
const encrypted = await wc.encryptText("Secret payload", "password");
const decrypted = await wc.decryptText(encrypted, "password");

// 🔑 Asymmetric RSA-4096 Hybrid Encryption
const wca = new WebCryptAsym();
const keyPair = await wca.generateKeyPair(4096);
const cipher = await wca.encryptText("Secret payload", keyPair.publicKey);
const plain = await wca.decryptText(cipher, keyPair.privateKey);
```

---

### 2. Auto-Setup for AI Agents & IDEs (MCP Server)

```bash
# Initialize MCP server, agent skills, and rules across your project
npx webcrypt init  # or `webcrypt init` if installed globally
```

_Supports **Google Antigravity**, **Cursor**, **Claude Desktop**, **VS Code / Copilot**, **Windsurf**, **Cline**, and **Zed**._

---

## 🤖 Why AI Agents Need WebCrypt MCP

Equip autonomous coding agents with an authenticated cryptographic vault directly in their toolbelt:

- 🔐 **Confidential Local Vaulting (`encrypt_payload`)**: Encrypt API keys and state memory before writing to disk to prevent prompt log leaks.
- 🛡️ **Tamper-Proof Provenance (`sign_verify`)**: Cryptographically sign test evidence packs, release binaries, and code diffs with ECDSA or HMAC.
- 🤝 **Inter-Agent Key Exchange (`manage_keys`)**: Ephemeral JWK keypairs (RSA-4096, ECDH P-256/P-384) for private agent-to-agent messaging.
- ⚛️ **Post-Quantum Guardrails (`pqc_kem_sign`)**: Built-in Kyber KEM and Dilithium signatures future-proof long-term agent artifacts.
- ⚡ **Zero Dependencies**: 100% native `crypto.subtle` execution across Node.js 18+, Bun, browsers, and Edge runtimes.

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

---

## 🛠️ MCP Tools Reference (6 Core Tools)

| Tool                  | Action / Mode                            | Description                                                                  |
| :-------------------- | :--------------------------------------- | :--------------------------------------------------------------------------- |
| **`encrypt_payload`** | `symmetric` \| `asymmetric` \| `data`    | Encrypt text, JSON objects, or files with AES-256-GCM or RSA-4096.           |
| **`decrypt_payload`** | `symmetric` \| `asymmetric` \| `data`    | Decrypt ciphertext back to plaintext or structured JSON.                     |
| **`manage_keys`**     | `generate` \| `generate_random_password` | Generate JWK keypairs (RSA, ECDH, ECDSA, RSA-PSS) or high-entropy passwords. |
| **`crypto_hash`**     | `SHA-256` \| `SHA-512` \| `SHA-3`        | Compute cryptographic hash digests in hex or base64.                         |
| **`sign_verify`**     | `sign` \| `verify`                       | Sign and verify messages, release hashes, and evidence packs.                |
| **`pqc_kem_sign`**    | `kyber_*` \| `dilithium_*` \| `hybrid_*` | Post-quantum Kyber KEM encapsulation and Dilithium signatures.               |

---

## 📚 Technical Documentation Directory

Explore dedicated guides in [`docs/`](docs/) and [`examples/`](examples/):

| Guide                                                                         | Topic                                                         |
| :---------------------------------------------------------------------------- | :------------------------------------------------------------ |
| 🚀 **[Live Interactive Playground](https://putervision.github.io/webcrypt/)** | Test all crypto features in the browser demo.                 |
| 💻 **[CLI Reference Guide](docs/CLI.md)**                                     | Scaffolding, global project scanning, and terminal utilities. |
| ⚙️ **[Multi-IDE MCP Setup Guide](docs/MCP_IDE_SETUP.md)**                     | Step-by-step MCP JSON configs for all major IDEs.             |
| 🔒 **[Symmetric Encryption API (`WebCrypt`)](docs/API_SYMMETRIC.md)**         | AES-256-GCM, streaming files, WebRTC E2EE, PBKDF2.            |
| 🔑 **[Asymmetric Encryption API (`WebCryptAsym`)](docs/API_ASYMMETRIC.md)**   | RSA-4096 hybrid, ECDH key agreement, ECDSA/RSA-PSS.           |
| ⚛️ **[Post-Quantum Cryptography Guide](docs/PQC.md)**                         | Kyber KEM, Dilithium signatures, and Hybrid KEM.              |
| 🏗️ **[Architecture & MCP Specifications](docs/ARCHITECTURE.md)**              | Stdio JSON-RPC 2.0 protocol and chunk framing specs.          |
| 🤖 **[Agent Skill Definition](.agents/skills/webcrypt-mcp/SKILL.md)**         | Custom agent skill with automated test runner script.         |
| 📋 **[Project Instructions Template](PROJECT_INSTRUCTIONS_TEMPLATE.md)**      | Multi-agent rules template (`<!-- webcrypt-mcp:start -->`).   |
| 💡 **[Code Examples Directory](examples/README.md)**                          | Ready-to-run Node.js & browser recipes.                       |

---

## 🌐 PuterVision Triad Standard

- 📊 **[`@putervision/state-memory-mcp`](https://github.com/putervision/state-memory-mcp)**: Persistent SQLite graph for workflow states, task DAGs, and decision trails.
- 👁️ **[`@putervision/vision-memory-mcp`](https://github.com/putervision/vision-memory-mcp)**: Multimodal visual layout cache, AX grounding, and video replay analysis.
- 🔐 **[`webcrypt`](https://github.com/putervision/webcrypt)**: Zero-dependency cryptographic vault, payload encryption, key management, and digital signatures.

---

## 🧪 Testing & Diagnostics

```bash
# Run unit & integration test matrix (30 suites, 247 tests)
npm test

# Run live MCP tool test runner (25 assertions, 100% verified)
node .agents/skills/webcrypt-mcp/scripts/exercise_tools.js

# Audit environment & project configuration health
webcrypt doctor
```

---

## ⚖️ License & Disclaimers

Developed and maintained by [PuterVision](https://putervision.com). Released under the [MIT License](LICENSE).

- **100% Local Execution Guarantee**: All cryptographic operations execute locally in memory via standard W3C Web Crypto API (`crypto.subtle`). Zero external API calls, telemetry, or network transmissions.
- **Trademarks & Non-Affiliation**: Product names (Cursor, Claude, Google Antigravity, VS Code, GitHub Copilot, Windsurf, Cline, Zed) are property of their respective owners and used solely for compatibility identification.
