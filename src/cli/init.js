// src/cli/init.js
// Automated project initialization and agent skill scaffolding for WebCrypt

import fs from "fs";
import path from "path";
import os from "os";
import { getSkillTemplate, getInstructionsTemplate } from "./templates.js";
import { registerProject, getRegistry, pruneStaleProjects } from "./registry.js";

const MARKER_START = "<!-- webcrypt-mcp:start -->";
const MARKER_END = "<!-- webcrypt-mcp:end -->";

const INSTRUCTION_TARGETS = [
  ".cursorrules",
  ".windsurfrules",
  ".gemini/instructions.md",
  ".github/copilot-instructions.md",
  "CLAUDE.md",
  ".agents/AGENTS.md",
];

function ensureDir(filePath) {
  const dir = path.dirname(filePath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
}

function updateFileWithMarker(filePath, newContent) {
  ensureDir(filePath);
  let content = "";
  if (fs.existsSync(filePath)) {
    content = fs.readFileSync(filePath, "utf-8");
  }

  const startIdx = content.indexOf(MARKER_START);
  const endIdx = content.indexOf(MARKER_END);

  if (startIdx !== -1 && endIdx !== -1 && endIdx >= startIdx) {
    // Replace existing block
    const before = content.slice(0, startIdx).trimEnd();
    const after = content.slice(endIdx + MARKER_END.length).trimStart();
    const updated =
      (before ? before + "\n\n" : "") + newContent + (after ? "\n\n" + after : "") + "\n";
    fs.writeFileSync(filePath, updated, "utf-8");
    return "updated";
  } else {
    // Append
    const updated = (content.trim() ? content.trim() + "\n\n" : "") + newContent + "\n";
    fs.writeFileSync(filePath, updated, "utf-8");
    return content ? "appended" : "created";
  }
}

function mergeMcpConfig(configPath) {
  ensureDir(configPath);
  let json = { mcpServers: {} };
  if (fs.existsSync(configPath)) {
    try {
      json = JSON.parse(fs.readFileSync(configPath, "utf-8"));
      if (!json.mcpServers) json.mcpServers = {};
    } catch (e) {
      json = { mcpServers: {} };
    }
  }

  json.mcpServers.webcrypt = {
    command: "npx",
    args: ["-y", "webcrypt", "mcp"],
  };

  fs.writeFileSync(configPath, JSON.stringify(json, null, 2) + "\n", "utf-8");
}

export async function runInit(targetDir = process.cwd(), options = {}) {
  const resolvedDir = path.resolve(targetDir);
  const projectName = path.basename(resolvedDir);

  if (!options.silent) {
    console.log(`\n🔒 Initializing WebCrypt MCP & Agent Customizations for: ${resolvedDir}\n`);
  }

  // 1. Register in Global Registry (~/.webcrypt/projects.json)
  registerProject(projectName, resolvedDir);

  const results = [];

  // 2. Scaffold Agent Skill (.agents/skills/webcrypt-mcp/SKILL.md)
  const skillPath = path.join(resolvedDir, ".agents", "skills", "webcrypt-mcp", "SKILL.md");
  ensureDir(skillPath);
  fs.writeFileSync(skillPath, getSkillTemplate(), "utf-8");
  results.push(`✅ Created Agent Skill: .agents/skills/webcrypt-mcp/SKILL.md`);

  // 3. Scaffold IDE MCP Configurations
  const cursorMcpPath = path.join(resolvedDir, ".cursor", "mcp.json");
  mergeMcpConfig(cursorMcpPath);
  results.push(`✅ Configured Cursor MCP: .cursor/mcp.json`);

  const vscodeMcpPath = path.join(resolvedDir, ".vscode", "mcp.json");
  if (fs.existsSync(path.join(resolvedDir, ".vscode"))) {
    mergeMcpConfig(vscodeMcpPath);
    results.push(`✅ Configured VS Code MCP: .vscode/mcp.json`);
  }

  // 4. Global Antigravity Config (if ~/.gemini/config/config.json exists)
  const homeDir = os.homedir();
  const globalAntigravityConfig = path.join(homeDir, ".gemini", "config", "config.json");
  if (fs.existsSync(globalAntigravityConfig)) {
    try {
      mergeMcpConfig(globalAntigravityConfig);
      results.push(`✅ Configured Global Antigravity: ~/.gemini/config/config.json`);
    } catch (e) {}
  }

  // 5. Scaffold Agent Instruction Files
  const instructionsBlock = getInstructionsTemplate();

  for (const relPath of INSTRUCTION_TARGETS) {
    const fullPath = path.join(resolvedDir, relPath);
    if (fs.existsSync(fullPath) || relPath === ".agents/AGENTS.md") {
      const action = updateFileWithMarker(fullPath, instructionsBlock);
      results.push(`✅ ${action.toUpperCase()} ${relPath}`);
    }
  }

  if (!options.silent) {
    results.forEach(r => console.log(`   ${r}`));
    console.log(`
🎉 WebCrypt initialization complete!
------------------------------------
Registered in ~/.webcrypt/projects.json as: "${projectName.toLowerCase()}"
`);
  }

  return { targetDir: resolvedDir, projectName, results };
}

export async function runInitGlobal(options = {}) {
  console.log("\n🌐 Running global multi-project WebCrypt initialization...\n");

  if (options.cleanStale) {
    const { removed } = pruneStaleProjects();
    if (removed.length > 0) {
      console.log(`🧹 Cleaned ${removed.length} stale project entries.`);
    }
  }

  if (options.scan) {
    const scanRoot = path.resolve(options.scan);
    if (fs.existsSync(scanRoot)) {
      console.log(`🔍 Scanning directory for sub-projects: ${scanRoot}`);
      const entries = fs.readdirSync(scanRoot, { withFileTypes: true });
      for (const ent of entries) {
        if (ent.isDirectory() && !ent.name.startsWith(".")) {
          const subPath = path.join(scanRoot, ent.name);
          if (
            fs.existsSync(path.join(subPath, "package.json")) ||
            fs.existsSync(path.join(subPath, ".git"))
          ) {
            registerProject(ent.name, subPath);
          }
        }
      }
    }
  }

  const registry = getRegistry();
  const entries = Object.entries(registry);

  if (entries.length === 0) {
    console.log("⚠️ No registered projects found in ~/.webcrypt/projects.json.");
    console.log("Run `webcrypt init` inside a project or `webcrypt init-global --scan <path>`.\n");
    return;
  }

  let count = 0;
  for (const [slug, p] of entries) {
    if (!fs.existsSync(p)) {
      console.log(`📁 [${slug}] ⚠️ Skipped (directory not found: ${p})`);
      continue;
    }
    console.log(`📁 Re-initializing: ${slug} (${p})`);
    await runInit(p, { silent: true });
    console.log(`   ✅ Synced MCP configuration, skill, and instruction files.`);
    count++;
  }

  console.log(`\n🎉 Global initialization complete! Updated ${count} projects.\n`);
}
