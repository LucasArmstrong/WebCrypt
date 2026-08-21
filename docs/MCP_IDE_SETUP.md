# WebCrypt MCP: Multi-IDE Installation & Agent Setup Guide

This guide provides comprehensive instructions for installing, configuring, and using the **WebCrypt Model Context Protocol (MCP) Server** across all major AI code editors and agent environments.

---

## Table of Contents

0. [Why Use WebCrypt MCP? (Key Benefits)](#0-why-use-webcrypt-mcp-key-benefits)
1. [Automatic Zero-Configuration Setup](#1-automatic-zero-configuration-setup)
2. [Google Antigravity](#2-google-antigravity)
3. [Cursor IDE](#3-cursor-ide)
4. [Claude Desktop](#4-claude-desktop)
5. [VS Code / GitHub Copilot Agent](#5-vs-code--github-copilot-agent)
6. [Windsurf / Codeium Cascade](#6-windsurf--codeium-cascade)
7. [Cline / Roo Code](#7-cline--roo-code)
8. [Zed Editor](#8-zed-editor)
9. [Health Diagnostics & Verification (`doctor`)](#9-health-diagnostics--verification-doctor)
10. [Global Multi-Project Management](#10-global-multi-project-management)
11. [Agent Skill & Tool Calling Reference](#11-agent-skill--tool-calling-reference)

---

## 0. Why Use WebCrypt MCP? (Key Benefits)

AI coding agents routinely handle sensitive material: API keys, database credentials, architecture plans, and multi-agent conversation logs.

**WebCrypt MCP** equips agents with an autonomous, zero-dependency cryptographic vault directly in their toolbelt:

- 🔐 **Confidential Local Vaulting**: Encrypts credentials and state memory before writing to disk, preventing plaintext leaks in prompt histories and git logs.
- 🛡️ **Cryptographic Provenance**: Signs release outputs, code refactors, and test evidence packs using standard ECDSA / HMAC digital signatures.
- 🤝 **Inter-Agent Security**: Generates ephemeral JWK keypairs (RSA-4096 / ECDH) for end-to-end encrypted subagent communication.
- 🧠 **PuterVision Triad Standard**: Seamless synergy with `state-memory-mcp` (workflow DAG) and `vision-memory-mcp` (visual cache).
- ⚡ **Zero Native Dependencies**: 100% W3C Web Crypto API (`crypto.subtle`) execution across Node.js 18+, Bun, browsers, and edge environments.
- ⚛️ **Post-Quantum Ready**: Forward-secure Kyber KEM and Dilithium signatures.

---

## 1. Automatic Zero-Configuration Setup

The fastest way to configure WebCrypt for any project is to install it globally and run `webcrypt init`:

```bash
# 1. Install globally
npm install -g webcrypt

# 2. Run init inside your project root
cd /path/to/my-project
webcrypt init
```

_(Or via npx without global install: `npx -y webcrypt init`)_

### What `webcrypt init` Does Automatically:

1. **Registers Project**: Saves project path into global registry `~/.webcrypt/projects.json`.
2. **Installs Agent Skill**: Generates `.agents/skills/webcrypt-mcp/SKILL.md`.
3. **Scaffolds MCP Configurations**: Creates/updates `.cursor/mcp.json` and `.vscode/mcp.json`.
4. **Configures Global Antigravity**: Merges MCP server into `~/.gemini/config/config.json`.
5. **Injects Agent Workflow Rules**: Adds standard `<!-- webcrypt-mcp:start -->` blocks to `.agents/AGENTS.md`, `.cursorrules`, `.windsurfrules`, `.gemini/instructions.md`, `.github/copilot-instructions.md`, and `CLAUDE.md`.

---

## 2. Google Antigravity

Google Antigravity automatically discovers MCP servers defined in global configuration or local workspaces.

### Global Configuration (`~/.gemini/config/config.json`)

Add `webcrypt` under `mcpServers`:

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

### Auto-Run Permissions (Bypass Prompts)

To allow Antigravity to run cryptographic operations seamlessly without prompting:

```json
{
  "globalPermissionGrants": {
    "allow": ["command(webcrypt-mcp)", "command(npx webcrypt mcp)"]
  }
}
```

### Verification in Antigravity:

1. Open Antigravity and check the MCP servers list.
2. `webcrypt` will be listed with 6 active tools: `encrypt_payload`, `decrypt_payload`, `manage_keys`, `crypto_hash`, `sign_verify`, `pqc_kem_sign`.

---

## 3. Cursor IDE

Cursor supports project-specific MCP configurations located in `.cursor/mcp.json`.

### Project Configuration (`.cursor/mcp.json`)

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

### Project Rules (`.cursorrules`)

Ensure your `.cursorrules` includes the WebCrypt workflow block:

```markdown
<!-- webcrypt-mcp:start -->

# Cryptographic Vault & Security (webcrypt-mcp)

Whenever saving sensitive credentials, tokens, or private workflow states, encrypt them using `encrypt_payload(mode: "data", password: "...")` or `encrypt_payload(mode: "symmetric", password: "...")`. Use `manage_keys(action: "generate", type: "rsa" | "ecdh" | "hmac")` to generate keys for inter-agent communication.

<!-- webcrypt-mcp:end -->
```

### Verification in Cursor:

1. Navigate to **Cursor Settings** -> **Features** -> **MCP**.
2. Verify `webcrypt` shows a green status dot with 6 tools available.

---

## 4. Claude Desktop

Claude Desktop connects to MCP servers over standard input/output (stdio).

### Configuration File Locations:

- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Linux**: `~/.config/Claude/claude_desktop_config.json`
- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

### Configuration Snippet:

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

---

## 5. VS Code / GitHub Copilot Agent

VS Code supports MCP via the official MCP extension or GitHub Copilot Agent mode.

### Workspace Configuration (`.vscode/mcp.json`)

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

### Instruction File (`.github/copilot-instructions.md`)

```markdown
<!-- webcrypt-mcp:start -->

# Cryptographic Vault & Security (webcrypt-mcp)

When handling secret tokens or encrypting vault artifacts, invoke `webcrypt` MCP tools.

<!-- webcrypt-mcp:end -->
```

---

## 6. Windsurf / Codeium Cascade

Windsurf stores global MCP registrations in `~/.codeium/windsurf/mcp_config.json`.

### Configuration (`~/.codeium/windsurf/mcp_config.json`)

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

---

## 7. Cline / Roo Code

Cline and Roo Code manage MCP servers through `cline_mcp_settings.json`.

### Settings Snippet (`cline_mcp_settings.json`):

```json
{
  "mcpServers": {
    "webcrypt": {
      "command": "npx",
      "args": ["-y", "webcrypt", "mcp"],
      "disabled": false,
      "autoApprove": [
        "encrypt_payload",
        "decrypt_payload",
        "manage_keys",
        "crypto_hash",
        "sign_verify",
        "pqc_kem_sign"
      ]
    }
  }
}
```

---

## 8. Zed Editor

Zed supports MCP servers natively through settings.

### Configuration (`~/.config/zed/settings.json`):

```json
{
  "context_servers": {
    "webcrypt": {
      "command": {
        "path": "npx",
        "args": ["-y", "webcrypt", "mcp"]
      }
    }
  }
}
```

---

## 9. Health Diagnostics & Verification (`doctor`)

To verify that your environment, SubtleCrypto engines, skill files, and MCP configs are functioning properly:

```bash
# Check current project health
webcrypt doctor

# Audit all registered projects across your machine
webcrypt doctor-global
```

_Example Doctor Output:_

```
🩺 Running WebCrypt health diagnostics for: /path/to/my-project

  ✅ Node.js Runtime: v22.22.2 (Supported)
  ✅ Web Crypto Engine: AES-GCM, PBKDF2, RSA-OAEP, ECDH subtle engine operational
  ✅ Agent Skill (.agents/skills/webcrypt-mcp/SKILL.md): Installed (3060 bytes)
  ✅ IDE MCP Server Registration: Configured in .cursor/mcp.json
  ✅ Agent Instruction Markers: Active across 5 instruction files

Overall Health: ✅ HEALTHY
```

---

## 10. Global Multi-Project Management

WebCrypt maintains an index of your initialized projects in `~/.webcrypt/projects.json`:

```bash
# List all registered projects
webcrypt projects

# Synchronize all projects with the latest skills & instruction updates
webcrypt init-global

# Scan an entire directory tree (e.g. workspace) and auto-register all projects
webcrypt init-global --scan ~/workspaces

# Remove stale / deleted projects from registry
webcrypt doctor-global --clean-stale
```

---

## 11. Agent Skill & Tool Calling Reference

When WebCrypt is active, AI agents can use these 6 tools directly:

| Tool                  | Action               | Example Agent Invocation                                                           |
| :-------------------- | :------------------- | :--------------------------------------------------------------------------------- |
| **`encrypt_payload`** | Symmetric Encryption | `encrypt_payload({ mode: "data", data: { token: "abc" }, password: "pass" })`      |
| **`decrypt_payload`** | Symmetric Decryption | `decrypt_payload({ mode: "data", ciphertext: "...", password: "pass" })`           |
| **`manage_keys`**     | Keypair Generation   | `manage_keys({ action: "generate", type: "rsa", modulusLength: 4096 })`            |
| **`crypto_hash`**     | Compute Hashes       | `crypto_hash({ algorithm: "SHA-256", data: "hello", encoding: "hex" })`            |
| **`sign_verify`**     | ECDSA / HMAC Sign    | `sign_verify({ action: "sign", algorithm: "HMAC", data: "proof", password: "p" })` |
| **`pqc_kem_sign`**    | Kyber / Hybrid KEM   | `pqc_kem_sign({ action: "generate_kyber_keypair", level: "Kyber768" })`            |
