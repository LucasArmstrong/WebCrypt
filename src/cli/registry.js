// src/cli/registry.js
// Global project registry manager for WebCrypt (~/.webcrypt/projects.json)

import fs from "fs";
import path from "path";
import os from "os";

export const DEFAULT_REGISTRY_PATH = path.join(os.homedir(), ".webcrypt", "projects.json");

export function getRegistryPath() {
  return process.env.WEBCRYPT_REGISTRY_PATH || DEFAULT_REGISTRY_PATH;
}

let registryCache = null;
const CACHE_TTL_MS = 5000;

function cleanupTempFiles() {
  try {
    const regPath = getRegistryPath();
    const dir = path.dirname(regPath);
    if (!fs.existsSync(dir)) return;
    const files = fs.readdirSync(dir);
    for (const f of files) {
      if (f.startsWith("projects.json.tmp.")) {
        try {
          fs.unlinkSync(path.join(dir, f));
        } catch {}
      }
    }
  } catch {}
}

export function getRegistry() {
  cleanupTempFiles();
  const now = Date.now();
  if (registryCache && now - registryCache.timestamp < CACHE_TTL_MS) {
    return registryCache.registry;
  }

  const regPath = getRegistryPath();
  try {
    if (fs.existsSync(regPath)) {
      const raw = fs.readFileSync(regPath, "utf-8");
      const registry = JSON.parse(raw) || {};
      registryCache = { registry, timestamp: now };
      return registry;
    }
  } catch (e) {}

  return {};
}

export function registerProject(name, projectPath) {
  try {
    const resolved = path.resolve(projectPath);
    if (resolved === os.homedir()) return;

    registryCache = null;
    const registry = getRegistry();
    const slug = name.toLowerCase().replace(/[^a-z0-9_-]/g, "-");
    registry[slug] = resolved;

    const regPath = getRegistryPath();
    const dir = path.dirname(regPath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }

    const tmpPath = `${regPath}.tmp.${Math.random().toString(36).substring(2)}`;
    fs.writeFileSync(tmpPath, JSON.stringify(registry, null, 2), {
      encoding: "utf-8",
      mode: 0o600,
    });
    fs.renameSync(tmpPath, regPath);
  } catch (e) {}
}

export function unregisterProject(name) {
  try {
    registryCache = null;
    const registry = getRegistry();
    const slug = name.toLowerCase();
    if (registry[slug]) {
      delete registry[slug];
      const regPath = getRegistryPath();
      const tmpPath = `${regPath}.tmp.${Math.random().toString(36).substring(2)}`;
      fs.writeFileSync(tmpPath, JSON.stringify(registry, null, 2), {
        encoding: "utf-8",
        mode: 0o600,
      });
      fs.renameSync(tmpPath, regPath);
    }
  } catch (e) {}
}

export function pruneStaleProjects() {
  const registry = getRegistry();
  const active = {};
  const removed = [];

  for (const [slug, p] of Object.entries(registry)) {
    if (fs.existsSync(p)) {
      active[slug] = p;
    } else {
      removed.push({ slug, path: p });
    }
  }

  if (removed.length > 0) {
    registryCache = null;
    const regPath = getRegistryPath();
    const tmpPath = `${regPath}.tmp.${Math.random().toString(36).substring(2)}`;
    fs.writeFileSync(tmpPath, JSON.stringify(active, null, 2), {
      encoding: "utf-8",
      mode: 0o600,
    });
    fs.renameSync(tmpPath, regPath);
  }

  return { active, removed };
}
