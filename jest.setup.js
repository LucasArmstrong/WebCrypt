// jest.setup.js
import { TextEncoder, TextDecoder } from "node:util";
import { webcrypto } from "node:crypto";
import { Blob, File } from "node:buffer";

if (!globalThis.TextEncoder) globalThis.TextEncoder = TextEncoder;
if (!globalThis.TextDecoder) globalThis.TextDecoder = TextDecoder;

try {
  Object.defineProperty(globalThis, "crypto", {
    value: webcrypto,
    writable: true,
    configurable: true,
  });
} catch (e) {
  globalThis.crypto = webcrypto;
}

if (!globalThis.Blob) globalThis.Blob = Blob;
if (!globalThis.File) globalThis.File = File;

import { WebCryptPQC } from "./src/WebCryptPQC.js";

// Enable PQC stub testing in unit test environment
WebCryptPQC.enableStubTesting(true);
