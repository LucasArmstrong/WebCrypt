// src/cli/doctor.js
// Health check and diagnostic tool for WebCrypt and MCP environments

import fs from "fs";
import path from "path";
import os from "os";
import { getCrypto } from "../_crypto.js";
import { getRegistry, pruneStaleProjects } from "./registry.js";

export async function runDoctor(targetDir = process.cwd(), options = {}) {
  const isJson = options.json || false;
  const checks = [];

  function check(label, passed, details) {
    checks.push({ label, passed, details });
    if (!isJson) {
      console.log(`  ${passed ? "✅" : "❌"} ${label}: ${details}`);
    }
  }

  if (!isJson) {
    console.log(`\n🩺 Running WebCrypt health diagnostics for: ${targetDir}\n`);
  }

  // 1. Node.js Runtime
  const nodeVer = process.version;
  const major = parseInt(nodeVer.slice(1).split(".")[0], 10);
  check(
    "Node.js Runtime",
    major >= 18,
    `${nodeVer} (${major >= 18 ? "Supported" : "Node 18+ required"})`
  );

  // 2. Web Crypto API Engine
  let cryptoOk = false;
  let cryptoDetails = "SubtleCrypto unavailable";
  try {
    const crypto = getCrypto();
    if (crypto && crypto.subtle) {
      // Test AES-GCM key generation & PBKDF2
      const rawKey = new Uint8Array(32);
      await crypto.subtle.importKey("raw", rawKey, { name: "AES-GCM" }, false, [
        "encrypt",
        "decrypt",
      ]);
      cryptoOk = true;
      cryptoDetails = "AES-GCM, PBKDF2, RSA-OAEP, ECDH subtle engine operational";
    }
  } catch (e) {
    cryptoDetails = `SubtleCrypto failed: ${e.message}`;
  }
  check("Web Crypto Engine", cryptoOk, cryptoDetails);

  // 3. Agent Skill File
  const skillPath = path.join(targetDir, ".agents", "skills", "webcrypt-mcp", "SKILL.md");
  const skillExists = fs.existsSync(skillPath);
  check(
    "Agent Skill (.agents/skills/webcrypt-mcp/SKILL.md)",
    skillExists,
    skillExists
      ? `Installed (${fs.statSync(skillPath).size} bytes)`
      : "Missing — run `webcrypt init` to scaffold"
  );

  // 4. MCP Config File
  const cursorMcp = path.join(targetDir, ".cursor", "mcp.json");
  const vscodeMcp = path.join(targetDir, ".vscode", "mcp.json");
  let mcpConfigOk = false;
  let mcpDetails = "No MCP config found";

  if (fs.existsSync(cursorMcp)) {
    try {
      const parsed = JSON.parse(fs.readFileSync(cursorMcp, "utf-8"));
      if (parsed.mcpServers && parsed.mcpServers.webcrypt) {
        mcpConfigOk = true;
        mcpDetails = "Configured in .cursor/mcp.json";
      }
    } catch {}
  }

  if (!mcpConfigOk && fs.existsSync(vscodeMcp)) {
    try {
      const parsed = JSON.parse(fs.readFileSync(vscodeMcp, "utf-8"));
      if (parsed.mcpServers && parsed.mcpServers.webcrypt) {
        mcpConfigOk = true;
        mcpDetails = "Configured in .vscode/mcp.json";
      }
    } catch {}
  }
  check("IDE MCP Server Registration", mcpConfigOk, mcpDetails);

  // 5. Instruction Marker Detection
  const instructionFiles = [
    ".agents/AGENTS.md",
    ".cursorrules",
    ".windsurfrules",
    ".gemini/instructions.md",
    ".github/copilot-instructions.md",
    "CLAUDE.md",
  ];
  let foundInstructions = 0;
  for (const f of instructionFiles) {
    const full = path.join(targetDir, f);
    if (fs.existsSync(full)) {
      const content = fs.readFileSync(full, "utf-8");
      if (content.includes("<!-- webcrypt-mcp:start -->")) {
        foundInstructions++;
      }
    }
  }
  check(
    "Agent Instruction Markers",
    foundInstructions > 0,
    foundInstructions > 0
      ? `Active across ${foundInstructions} instruction files`
      : "None found — run `webcrypt init`"
  );

  const allPassed = checks.every(c => c.passed);

  if (!isJson) {
    console.log(`\nOverall Health: ${allPassed ? "✅ HEALTHY" : "⚠️ ATTENTION NEEDED"}\n`);
  }

  return { targetDir, allPassed, checks };
}

export async function runDoctorGlobal(options = {}) {
  const isJson = options.json || false;

  if (options.cleanStale) {
    const { removed } = pruneStaleProjects();
    if (!isJson && removed.length > 0) {
      console.log(`🧹 Cleaned ${removed.length} stale project entries from registry.`);
    }
  }

  const registry = getRegistry();
  const entries = Object.entries(registry);

  if (entries.length === 0) {
    if (isJson) {
      console.log(JSON.stringify({ total: 0, results: [] }));
    } else {
      console.log("\n⚠️ No registered projects found in ~/.webcrypt/projects.json.");
      console.log("Run `webcrypt init` inside a project folder to register it.\n");
    }
    return;
  }

  if (!isJson) {
    console.log(
      `\n🌐 Running global health audit across ${entries.length} registered projects...\n`
    );
  }

  const results = [];
  for (const [slug, p] of entries) {
    if (!fs.existsSync(p)) {
      results.push({ slug, path: p, exists: false, allPassed: false, checks: [] });
      if (!isJson) {
        console.log(`📁 [${slug}] ❌ Missing Directory: ${p}`);
      }
      continue;
    }

    if (!isJson) {
      console.log(`📁 Project: ${slug} (${p})`);
    }
    const res = await runDoctor(p, { json: isJson });
    results.push({ slug, path: p, exists: true, ...res });
  }

  if (isJson) {
    console.log(JSON.stringify({ total: entries.length, results }, null, 2));
  } else {
    const healthyCount = results.filter(r => r.allPassed).length;
    console.log(`\nGlobal Audit Summary: ${healthyCount}/${entries.length} projects healthy.\n`);
  }
}
