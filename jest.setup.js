// jest.setup.js
import { TextEncoder, TextDecoder } from "node:util";
import { webcrypto } from "node:crypto";

globalThis.TextEncoder = TextEncoder;
globalThis.TextDecoder = TextDecoder;
globalThis.crypto = webcrypto;
