// src/_crypto.js
// Centralized Web Crypto API resolution helper for browser and Node.js

/**
 * Returns the active Web Crypto API instance (with subtle property).
 * Supports browser window, Web Workers, Node.js 18+, and edge runtimes.
 *
 * @returns {Crypto} Active crypto instance
 * @throws {Error} If crypto.subtle is not available in the current environment
 */
export function getCrypto() {
  if (typeof globalThis !== "undefined" && globalThis.crypto && globalThis.crypto.subtle) {
    return globalThis.crypto;
  }

  throw new Error("Web Crypto API (crypto.subtle) is not available in this environment");
}
