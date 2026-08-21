#!/usr/bin/env node
// bin/webcrypt.js
// WebCrypt CLI, MCP Server Launcher & Global Registry Manager

import path from "path";

const args = process.argv.slice(2);
const command = args[0];

function printHelp() {
  console.log(`
WebCrypt v1.0.0 — Zero-Dependency Cryptography & Agent Tooling Suite
Maintained by PuterVision (https://putervision.com)

Usage:
  webcrypt <command> [options]

Project & Agent Commands:
  init [dir]                    Scaffold MCP config, agent skill, and rules into project
  init-global [options]         Re-initialize across all projects registered in ~/.webcrypt/projects.json
                                Options: --clean-stale, --scan <dir>
  doctor [dir] [options]        Run environment and configuration health checks (--json)
  doctor-global [options]       Run health checks across all registered projects
                                Options: --clean-stale, --json
  projects [options]            List all registered projects in ~/.webcrypt/projects.json
                                Options: --clean-stale

MCP & Cryptography Commands:
  mcp                           Start the WebCrypt MCP Server (stdio JSON-RPC)
  encrypt <text> -p <pass>      Encrypt text with password (AES-256-GCM)
  decrypt <b64> -p <pass>       Decrypt base64 ciphertext with password
  keygen [type]                 Generate cryptographic keys (rsa, ecdh, password)
  --version, -v                 Display version
  --help, -h                    Display this help message

Examples:
  webcrypt init
  webcrypt init-global --scan ~/workspaces
  webcrypt doctor
  webcrypt doctor-global --clean-stale
  webcrypt projects
  npx webcrypt mcp
`);
}

async function main() {
  if (!command || command === "--help" || command === "-h") {
    printHelp();
    return;
  }

  if (command === "--version" || command === "-v") {
    console.log("webcrypt v1.0.0");
    return;
  }

  if (command === "mcp") {
    const { startMCPServer } = await import("../src/mcp/server.js");
    startMCPServer();
    return;
  }

  if (command === "init") {
    const { runInit } = await import("../src/cli/init.js");
    const targetDir =
      args[1] && !args[1].startsWith("-")
        ? args[1].startsWith("/")
          ? args[1]
          : path.resolve(process.cwd(), args[1])
        : process.cwd();
    await runInit(targetDir);
    return;
  }

  if (command === "init-global") {
    const { runInitGlobal } = await import("../src/cli/init.js");
    const cleanStale = args.includes("--clean-stale");
    const scanIdx = args.indexOf("--scan");
    const scan = scanIdx !== -1 ? args[scanIdx + 1] : null;
    await runInitGlobal({ cleanStale, scan });
    return;
  }

  if (command === "doctor") {
    const { runDoctor } = await import("../src/cli/doctor.js");
    const isJson = args.includes("--json");
    const targetDir =
      args[1] && !args[1].startsWith("-")
        ? args[1].startsWith("/")
          ? args[1]
          : path.resolve(process.cwd(), args[1])
        : process.cwd();
    await runDoctor(targetDir, { json: isJson });
    return;
  }

  if (command === "doctor-global") {
    const { runDoctorGlobal } = await import("../src/cli/doctor.js");
    const isJson = args.includes("--json");
    const cleanStale = args.includes("--clean-stale");
    await runDoctorGlobal({ json: isJson, cleanStale });
    return;
  }

  if (command === "projects") {
    const { getRegistry, pruneStaleProjects } = await import("../src/cli/registry.js");
    if (args.includes("--clean-stale")) {
      const { removed } = pruneStaleProjects();
      if (removed.length > 0) {
        console.log(`🧹 Cleaned ${removed.length} stale project entries.`);
      }
    }
    const registry = getRegistry();
    const entries = Object.entries(registry);
    if (entries.length === 0) {
      console.log("No registered projects in ~/.webcrypt/projects.json.");
      return;
    }
    console.log(`\nRegistered Projects (${entries.length}):`);
    console.log("-----------------------------------------");
    for (const [slug, p] of entries) {
      console.log(`  • ${slug.padEnd(20)} => ${p}`);
    }
    console.log("");
    return;
  }

  if (command === "encrypt") {
    const text = args[1];
    const passIdx = args.indexOf("-p");
    const password = passIdx !== -1 ? args[passIdx + 1] : null;
    if (!text || !password) {
      console.error("Error: Text and password (-p <password>) required.");
      process.exit(1);
    }
    const { WebCrypt } = await import("../src/WebCrypt.js");
    const wc = new WebCrypt();
    const encrypted = await wc.encryptText(text, password);
    console.log(encrypted);
    return;
  }

  if (command === "decrypt") {
    const ciphertext = args[1];
    const passIdx = args.indexOf("-p");
    const password = passIdx !== -1 ? args[passIdx + 1] : null;
    if (!ciphertext || !password) {
      console.error("Error: Ciphertext and password (-p <password>) required.");
      process.exit(1);
    }
    try {
      const { WebCrypt } = await import("../src/WebCrypt.js");
      const wc = new WebCrypt();
      const decrypted = await wc.decryptText(ciphertext, password);
      console.log(decrypted);
    } catch (e) {
      console.error("Decryption failed: wrong password or invalid data.");
      process.exit(1);
    }
    return;
  }

  if (command === "keygen") {
    const type = args[1] || "password";
    if (type === "password") {
      const { WebCrypt } = await import("../src/WebCrypt.js");
      const wc = new WebCrypt();
      const pass = wc.generateRandomPassword(32);
      console.log(`Generated 32-byte secure key/password:\n${pass}`);
    } else if (type === "rsa") {
      console.log("Generating RSA-4096 keypair...");
      const { WebCryptAsym } = await import("../src/WebCryptAsym.js");
      const asym = new WebCryptAsym();
      const keys = await asym.generateKeyPair(4096);
      const pubJwk = await asym._crypto.subtle.exportKey("jwk", keys.publicKey);
      const privJwk = await asym._crypto.subtle.exportKey("jwk", keys.privateKey);
      console.log("Public Key (JWK):", JSON.stringify(pubJwk));
      console.log("Private Key (JWK):", JSON.stringify(privJwk));
    } else if (type === "ecdh") {
      console.log("Generating ECDH P-256 keypair...");
      const { WebCryptAsym } = await import("../src/WebCryptAsym.js");
      const asym = new WebCryptAsym();
      const keys = await asym.generateECDHKeyPair("P-256");
      const pubJwk = await asym._crypto.subtle.exportKey("jwk", keys.publicKey);
      const privJwk = await asym._crypto.subtle.exportKey("jwk", keys.privateKey);
      console.log("Public Key (JWK):", JSON.stringify(pubJwk));
      console.log("Private Key (JWK):", JSON.stringify(privJwk));
    } else {
      console.error(`Unknown keygen type: ${type}`);
      process.exit(1);
    }
    return;
  }

  console.error(`Unknown command: ${command}`);
  printHelp();
  process.exit(1);
}

main().catch(err => {
  console.error("WebCrypt CLI error:", err);
  process.exit(1);
});
