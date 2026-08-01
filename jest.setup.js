// jest.setup.js
import { TextEncoder, TextDecoder } from "node:util";
import { webcrypto } from "node:crypto";
import { Blob, File } from "node:buffer";

globalThis.TextEncoder = TextEncoder;
globalThis.TextDecoder = TextDecoder;
globalThis.crypto = webcrypto;
globalThis.Blob = globalThis.Blob || Blob;
globalThis.File = globalThis.File || File;

import { WebCryptPQC } from "./src/WebCryptPQC.js";

// Enable PQC stub testing in unit test environment
WebCryptPQC.enableStubTesting(true);
