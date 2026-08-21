import fs from "fs";
import path from "path";
import os from "os";
import { runInit, runInitGlobal } from "../src/cli/init.js";
import { runDoctor, runDoctorGlobal } from "../src/cli/doctor.js";
import {
  getRegistry,
  registerProject,
  unregisterProject,
  pruneStaleProjects,
} from "../src/cli/registry.js";

describe("WebCrypt CLI, Registry & Doctor", () => {
  let tmpDir;
  let origEnv;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "webcrypt-test-"));
    origEnv = process.env.WEBCRYPT_REGISTRY_PATH;
    process.env.WEBCRYPT_REGISTRY_PATH = path.join(tmpDir, "projects.json");
  });

  afterEach(() => {
    process.env.WEBCRYPT_REGISTRY_PATH = origEnv;
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  test("registers, unregisters, and prunes projects", () => {
    const p1 = path.join(tmpDir, "proj1");
    fs.mkdirSync(p1, { recursive: true });

    registerProject("proj1", p1);
    let reg = getRegistry();
    expect(reg["proj1"]).toBe(p1);

    unregisterProject("proj1");
    reg = getRegistry();
    expect(reg["proj1"]).toBeUndefined();

    registerProject("proj-stale", path.join(tmpDir, "nonexistent"));
    const pruneRes = pruneStaleProjects();
    expect(pruneRes.removed.length).toBe(1);
    expect(pruneRes.removed[0].slug).toBe("proj-stale");
  });

  test("runInit creates skill, mcp config, and instruction markers", async () => {
    const projDir = path.join(tmpDir, "my-app");
    fs.mkdirSync(projDir, { recursive: true });

    const res = await runInit(projDir, { silent: true });
    expect(res.projectName).toBe("my-app");

    const skillPath = path.join(projDir, ".agents", "skills", "webcrypt-mcp", "SKILL.md");
    expect(fs.existsSync(skillPath)).toBe(true);
    const skillContent = fs.readFileSync(skillPath, "utf-8");
    expect(skillContent).toContain("name: webcrypt-mcp");

    const cursorMcp = path.join(projDir, ".cursor", "mcp.json");
    expect(fs.existsSync(cursorMcp)).toBe(true);
    const mcpJson = JSON.parse(fs.readFileSync(cursorMcp, "utf-8"));
    expect(mcpJson.mcpServers.webcrypt).toBeDefined();

    const agentsMd = path.join(projDir, ".agents", "AGENTS.md");
    expect(fs.existsSync(agentsMd)).toBe(true);
    const agentsContent = fs.readFileSync(agentsMd, "utf-8");
    expect(agentsContent).toContain("<!-- webcrypt-mcp:start -->");
  });

  test("runDoctor verifies healthy project setup", async () => {
    const projDir = path.join(tmpDir, "healthy-app");
    fs.mkdirSync(projDir, { recursive: true });
    await runInit(projDir, { silent: true });

    const docRes = await runDoctor(projDir, { json: true });
    expect(docRes.allPassed).toBe(true);
    expect(docRes.checks.length).toBeGreaterThanOrEqual(4);
  });

  test("runDoctorGlobal audits registered projects", async () => {
    const projDir = path.join(tmpDir, "global-app");
    fs.mkdirSync(projDir, { recursive: true });
    await runInit(projDir, { silent: true });

    // Output capture
    const logs = [];
    const origLog = console.log;
    console.log = (...args) => logs.push(args.join(" "));

    try {
      await runDoctorGlobal({ json: false, cleanStale: true });
    } finally {
      console.log = origLog;
    }

    const output = logs.join("\n");
    expect(output).toContain("Global Audit Summary");
  });

  test("runDoctorGlobal audits mixed valid and missing projects", async () => {
    const pValid = path.join(tmpDir, "valid-app");
    fs.mkdirSync(pValid, { recursive: true });
    await runInit(pValid, { silent: true });

    registerProject("missing-app", path.join(tmpDir, "does-not-exist-dir"));

    const logs = [];
    const origLog = console.log;
    console.log = (...args) => logs.push(args.join(" "));

    try {
      await runDoctorGlobal({ json: false, cleanStale: false });
    } finally {
      console.log = origLog;
    }

    const output = logs.join("\n");
    expect(output).toContain("Missing Directory");
    expect(output).toContain("Global Audit Summary");
  });

  test("runInitGlobal ignores subdirectories without package.json or .git", async () => {
    const workspaceDir = path.join(tmpDir, "workspace-misc");
    const emptySub = path.join(workspaceDir, "empty-sub");
    fs.mkdirSync(emptySub, { recursive: true });

    await runInitGlobal({ scan: workspaceDir });
    const reg = getRegistry();
    expect(reg["empty-sub"]).toBeUndefined();
  });
});
