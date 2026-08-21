import { WebCrypt } from "../src/WebCrypt.js";
import { WebCryptAsym } from "../src/WebCryptAsym.js";

describe("Multi-Chunk File Encryption (>8MB)", () => {
  let wc;
  let wca;

  beforeEach(() => {
    wc = new WebCrypt();
    wca = new WebCryptAsym();
  });

  afterEach(() => {
    wc.stopAutoCleanup();
    wca.stopAutoCleanup();
  });

  test("Symmetric encryptFile/decryptFile round-trip for 9MB file (crosses 8MB chunk boundary)", async () => {
    const size = 9 * 1024 * 1024; // 9MB
    const buffer = new Uint8Array(size);
    // Fill with pseudo-random deterministic pattern
    for (let i = 0; i < size; i += 1024) {
      buffer[i] = (i * 31) % 256;
      buffer[i + 1] = (i * 37) % 256;
    }
    buffer[size - 1] = 0xef;
    buffer[size - 2] = 0xbe;

    const file = new Blob([buffer], { type: "application/octet-stream" });
    const password = "multi-chunk-password-123!";

    const { blob: encryptedBlob } = await wc.encryptFile(file, password);
    expect(encryptedBlob.size).toBeGreaterThan(size);

    const { blob: decryptedBlob } = await wc.decryptFile(encryptedBlob, password);
    const decryptedBytes = new Uint8Array(await decryptedBlob.arrayBuffer());

    expect(decryptedBytes.byteLength).toBe(size);
    expect(decryptedBytes[0]).toBe(buffer[0]);
    expect(decryptedBytes[size - 1]).toBe(buffer[size - 1]);
    expect(decryptedBytes[8 * 1024 * 1024]).toBe(buffer[8 * 1024 * 1024]);
  }, 30000);

  test("Symmetric encryptFile/decryptFile with parallelChunks: 4 for 16MB file", async () => {
    const size = 16 * 1024 * 1024; // 16MB (exactly 2 chunks of 8MB)
    const buffer = new Uint8Array(size);
    for (let i = 0; i < size; i += 4096) {
      buffer[i] = (i * 17) % 256;
    }

    const file = new Blob([buffer], { type: "application/octet-stream" });
    const password = "parallel-chunks-password-456!";

    const { blob: encryptedBlob } = await wc.encryptFile(file, password, { parallelChunks: 4 });
    const { blob: decryptedBlob } = await wc.decryptFile(encryptedBlob, password, {
      parallelChunks: 4,
    });
    const decryptedBytes = new Uint8Array(await decryptedBlob.arrayBuffer());

    expect(decryptedBytes.byteLength).toBe(size);
    expect(decryptedBytes[0]).toBe(buffer[0]);
    expect(decryptedBytes[size - 1]).toBe(buffer[size - 1]);
  }, 30000);

  test("Asymmetric encryptFile/decryptFile round-trip for 9MB file", async () => {
    const size = 9 * 1024 * 1024;
    const buffer = new Uint8Array(size);
    buffer[0] = 0x42;
    buffer[8 * 1024 * 1024] = 0x99;
    buffer[size - 1] = 0x77;

    const file = new Blob([buffer], { type: "application/octet-stream" });
    const keys = await wca.generateKeyPair(2048);

    const { blob: encryptedBlob } = await wca.encryptFile(file, keys.publicKey);
    const { blob: decryptedBlob } = await wca.decryptFile(encryptedBlob, keys.privateKey);
    const decryptedBytes = new Uint8Array(await decryptedBlob.arrayBuffer());

    expect(decryptedBytes.byteLength).toBe(size);
    expect(decryptedBytes[0]).toBe(0x42);
    expect(decryptedBytes[8 * 1024 * 1024]).toBe(0x99);
    expect(decryptedBytes[size - 1]).toBe(0x77);
  }, 30000);
});
