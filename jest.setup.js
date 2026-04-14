// jest.setup.js
import { TextEncoder, TextDecoder } from "node:util";
import { webcrypto } from "node:crypto";
import { Blob, File } from "node:buffer";

globalThis.TextEncoder = TextEncoder;
globalThis.TextDecoder = TextDecoder;
globalThis.crypto = webcrypto;
globalThis.Blob = globalThis.Blob || Blob;
globalThis.File = globalThis.File || File;

// CryptoKey is not a global in Node.js 18 — expose it for tests
// In Node 18, it lives on webcrypto; in Node 20+, it may be global
if (typeof globalThis.CryptoKey === "undefined") {
  globalThis.CryptoKey = webcrypto.CryptoKey || crypto.webcrypto?.CryptoKey;
}
