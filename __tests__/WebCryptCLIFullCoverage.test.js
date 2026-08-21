import fs from "fs";
import path from "path";
import os from "os";
import { getCrypto } from "../src/_crypto.js";
import {
  isValidBase64,
  arrayBufferToBase64,
  base64ToArrayBuffer,
  base64ToUint8Array,
} from "../src/_base64.js";
import { runInit, runInitGlobal } from "../src/cli/init.js";
import { runDoctor, runDoctorGlobal } from "../src/cli/doctor.js";
import {
  getRegistry,
  registerProject,
  unregisterProject,
  pruneStaleProjects,
} from "../src/cli/registry.js";

describe("WebCrypt CLI, Registry & Low-Level Helpers Full Coverage", () => {
  let tmpDir;
  let origEnv;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "webcrypt-cov-"));
    origEnv = process.env.WEBCRYPT_REGISTRY_PATH;
    process.env.WEBCRYPT_REGISTRY_PATH = path.join(tmpDir, "projects.json");
  });

  afterEach(() => {
    process.env.WEBCRYPT_REGISTRY_PATH = origEnv;
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  test("getCrypto returns subtle crypto instance and handles error when unavailable", () => {
    const crypto = getCrypto();
    expect(crypto).toBeDefined();
    expect(crypto.subtle).toBeDefined();

    // Test error when globalThis.crypto is unavailable
    const origCrypto = globalThis.crypto;
    try {
      globalThis.crypto = undefined;
      expect(() => getCrypto()).toThrow(
        "Web Crypto API (crypto.subtle) is not available in this environment"
      );
    } finally {
      globalThis.crypto = origCrypto;
    }
  });

  test("isValidBase64 validates varied string shapes", () => {
    expect(isValidBase64("")).toBe(false);
    expect(isValidBase64(null)).toBe(false);
    expect(isValidBase64(123)).toBe(false);
    expect(isValidBase64("A")).toBe(false); // Mod 4 == 1
    expect(isValidBase64("Invalid $$$ Character")).toBe(false);
    expect(isValidBase64("SGVsbG8gV29ybGQ=")).toBe(true);
    expect(isValidBase64("YWJjZA==")).toBe(true);
  });

  test("base64 type error assertions", () => {
    expect(() => base64ToArrayBuffer(123)).toThrow(TypeError);
    expect(() => base64ToUint8Array(null)).toThrow(TypeError);
  });

  test("base64 unpadded string decoding", () => {
    // "hello" -> "aGVsbG8=" (unpadded "aGVsbG8")
    const buf = base64ToArrayBuffer("aGVsbG8");
    const u8 = base64ToUint8Array("aGVsbG8");
    expect(buf.byteLength).toBe(5);
    expect(u8.length).toBe(5);
  });

  test("registry corrupted JSON and temp file handling", () => {
    const regPath = path.join(tmpDir, "projects.json");
    fs.writeFileSync(regPath, "{ malformed json");

    // Creates temp file to test cleanup
    const tempFile = path.join(tmpDir, "projects.json.tmp.12345");
    fs.writeFileSync(tempFile, "temp");

    const reg = getRegistry();
    expect(reg).toEqual({});
    expect(fs.existsSync(tempFile)).toBe(false); // Cleaned up
  });

  test("unregistering nonexistent project is safe no-op", () => {
    unregisterProject("nonexistent-slug");
    expect(getRegistry()).toEqual({});
  });

  test("runInit replaces existing marker in file rather than appending", async () => {
    const projDir = path.join(tmpDir, "marker-app");
    fs.mkdirSync(projDir, { recursive: true });

    const agentsMd = path.join(projDir, ".agents", "AGENTS.md");
    fs.mkdirSync(path.dirname(agentsMd), { recursive: true });
    fs.writeFileSync(
      agentsMd,
      "# Title\n\n<!-- webcrypt-mcp:start -->\nOLD CONTENT\n<!-- webcrypt-mcp:end -->\n\nFooter"
    );

    await runInit(projDir, { silent: true });

    const updated = fs.readFileSync(agentsMd, "utf-8");
    expect(updated).toContain("# Title");
    expect(updated).toContain("Cryptographic Vault & Security");
    expect(updated).not.toContain("OLD CONTENT");
    expect(updated).toContain("Footer");
  });

  test("runInit creates vscode config when .vscode directory exists", async () => {
    const projDir = path.join(tmpDir, "vscode-app");
    fs.mkdirSync(path.join(projDir, ".vscode"), { recursive: true });

    await runInit(projDir, { silent: true });

    const vscodeMcp = path.join(projDir, ".vscode", "mcp.json");
    expect(fs.existsSync(vscodeMcp)).toBe(true);
  });

  test("runDoctorGlobal with empty registry and JSON mode", async () => {
    const logs = [];
    const origLog = console.log;
    console.log = (...args) => logs.push(args.join(" "));

    try {
      await runDoctorGlobal({ json: true, cleanStale: true });
    } finally {
      console.log = origLog;
    }

    const output = JSON.parse(logs.join(""));
    expect(output.total).toBe(0);
    expect(output.results).toEqual([]);
  });

  test("runDoctor handles missing project directory gracefully", async () => {
    const missingDir = path.join(tmpDir, "does-not-exist");
    const docRes = await runDoctor(missingDir, { json: true });
    expect(docRes.allPassed).toBe(false);
  });

  test("runInitGlobal handles empty registry and scan option", async () => {
    const logs = [];
    const origLog = console.log;
    console.log = (...args) => logs.push(args.join(" "));

    try {
      await runInitGlobal({ scan: null, cleanStale: true });
    } finally {
      console.log = origLog;
    }

    expect(logs.join(" ")).toContain("No registered projects found");
  });
});
