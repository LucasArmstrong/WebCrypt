# WebCrypt CLI Reference Guide

WebCrypt provides a comprehensive CLI for project initialization, IDE & agent scaffolding, workspace-wide multi-project synchronization, environment diagnostics, and direct cryptographic utilities.

---

## 📦 Installation

```bash
# Global installation (recommended for CLI usage)
npm install -g webcrypt

# Or run on-demand via npx
npx webcrypt <command>
```

---

## 🛠️ Command Index

| Command                      | Description                                                                       |
| :--------------------------- | :-------------------------------------------------------------------------------- |
| **`webcrypt init`**          | Scaffold MCP configs, agent skills, and rules into the current project.           |
| **`webcrypt doctor`**        | Run environment, runtime, and configuration health checks.                        |
| **`webcrypt init-global`**   | Synchronize and re-scaffold all registered projects across your machine.          |
| **`webcrypt doctor-global`** | Run health diagnostics on all registered projects.                                |
| **`webcrypt projects`**      | List, manage, and inspect all registered projects in `~/.webcrypt/projects.json`. |
| **`webcrypt encrypt`**       | Directly encrypt a text string with a password using AES-256-GCM.                 |
| **`webcrypt decrypt`**       | Directly decrypt a base64 ciphertext with a password.                             |
| **`webcrypt keygen`**        | Generate high-entropy passwords, RSA keypairs, or ECDH keys from the terminal.    |
| **`webcrypt mcp`**           | Launch the WebCrypt Model Context Protocol server over stdio JSON-RPC 2.0.        |

---

## 1. `webcrypt init`

Initializes WebCrypt MCP configuration, agent skills, and IDE instruction files in the current working directory.

```bash
webcrypt init [options]
```

### Options

| Flag               | Description                                                              | Default                   |
| :----------------- | :----------------------------------------------------------------------- | :------------------------ |
| `-p, --path <dir>` | Target project directory to initialize                                   | Current working directory |
| `--all`            | Generate configurations for all supported IDEs                           | `true`                    |
| `--cursor`         | Scaffold `.cursor/mcp.json` and update `.cursorrules`                    | `true`                    |
| `--vscode`         | Scaffold `.vscode/mcp.json` and update `.github/copilot-instructions.md` | `true`                    |
| `--claude`         | Scaffold `claude_desktop_config.json` snippet and update `CLAUDE.md`     | `true`                    |
| `--windsurf`       | Scaffold Windsurf MCP config and update `.windsurfrules`                 | `true`                    |
| `--gemini`         | Update `.gemini/instructions.md`                                         | `true`                    |
| `--no-agents`      | Skip creating `.agents/skills/webcrypt-mcp/SKILL.md`                     | `false`                   |
| `--no-register`    | Do not register project in `~/.webcrypt/projects.json`                   | `false`                   |

---

## 2. `webcrypt doctor`

Audits the current project and runtime environment for cryptographic support, file permissions, and MCP registration.

```bash
webcrypt doctor [options]
```

### Options

| Flag               | Description                                                                 |
| :----------------- | :-------------------------------------------------------------------------- |
| `-p, --path <dir>` | Path to project to inspect                                                  |
| `--fix`            | Automatically repair missing agent instruction markers or skill definitions |
| `--json`           | Output health report in machine-readable JSON format                        |

---

## 3. `webcrypt init-global`

Scans workspaces and updates all projects registered in `~/.webcrypt/projects.json` with the latest skill templates, manifests, and rules.

```bash
# Update all existing registered projects
webcrypt init-global

# Discover and register all projects within a parent folder
webcrypt init-global --scan ~/workspaces
```

### Options

| Flag                 | Description                                                                       |
| :------------------- | :-------------------------------------------------------------------------------- |
| `--scan <directory>` | Recursively scan directory tree for Node.js / git projects and auto-register them |
| `--depth <number>`   | Maximum recursion search depth (default: `4`)                                     |
| `--clean-stale`      | Automatically remove deleted project paths from the global index                  |

---

## 4. `webcrypt doctor-global`

Runs health checks across every project listed in your global registry.

```bash
webcrypt doctor-global [--clean-stale]
```

---

## 5. `webcrypt projects`

Inspects and manages projects registered in `~/.webcrypt/projects.json`.

```bash
# List all registered projects
webcrypt projects

# Output project list as JSON
webcrypt projects --json

# Remove stale paths that no longer exist on disk
webcrypt projects --clean-stale
```

---

## 6. Direct Cryptographic CLI Utilities

### `webcrypt encrypt`

Encrypts plaintext into a base64 ciphertext using AES-256-GCM + 600k PBKDF2:

```bash
webcrypt encrypt "Confidential data" -p "my-strong-password"
```

### `webcrypt decrypt`

Decrypts base64 ciphertext back to plaintext:

```bash
webcrypt decrypt "base64-ciphertext-here" -p "my-strong-password"
```

### `webcrypt keygen`

Generates cryptographic material directly in the terminal:

```bash
# Generate high-entropy password (hex)
webcrypt keygen password [--length 32]

# Generate RSA-4096 or RSA-2048 keypair
webcrypt keygen rsa [--bits 4096]

# Generate ECDH P-256 or P-384 keypair
webcrypt keygen ecdh [--curve P-256]
```

---

## 7. `webcrypt mcp`

Launches the stdio Model Context Protocol (MCP) server for connection to Google Antigravity, Cursor, Claude Desktop, VS Code, Cline, and Zed.

```bash
webcrypt mcp
```

_Note: In IDE configuration files, specify `"command": "npx", "args": ["-y", "webcrypt", "mcp"]`._
