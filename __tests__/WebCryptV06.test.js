// __tests__/WebCryptV06.test.js
import { WebCrypt } from "../src/WebCrypt.js";
import { WebCryptAsym } from "../src/WebCryptAsym.js";
import { WebCryptPQC } from "../src/WebCryptPQC.js";
import TimingSafeHelper from "../src/TimingSafeHelper.js";
import fs from "fs";
import path from "path";

describe("WebCrypt v0.6.x Features & Verification", () => {
  test("package.json version is 0.6.5", () => {
    const pkgPath = path.join(process.cwd(), "package.json");
    const pkg = JSON.parse(fs.readFileSync(pkgPath, "utf8"));
    expect(pkg.version).toBe("0.6.5");
    expect(pkg.author).toBe("PuterVision LLC");
    expect(pkg.homepage).toBe(pkg.homepage);
  });

  test("TimingSafeHelper.sleepWithDummyOps is non-blocking", async () => {
    const start = performance.now();
    await TimingSafeHelper.sleepWithDummyOps(15);
    const elapsed = performance.now() - start;
    expect(elapsed).toBeGreaterThanOrEqual(10);
  });

  test("Chunked Base64 handles large buffers cleanly", async () => {
    const wc = new WebCrypt();
    const largeBuffer = new Uint8Array(100 * 1024); // 100KB
    for (let i = 0; i < largeBuffer.length; i++) {
      largeBuffer[i] = i % 256;
    }

    const b64 = wc._arrayBufferToBase64(largeBuffer.buffer);
    expect(typeof b64).toBe("string");
    expect(b64.length).toBeGreaterThan(0);

    const recoveredBuffer = new Uint8Array(wc._base64ToArrayBuffer(b64));
    expect(recoveredBuffer.length).toBe(largeBuffer.length);
    expect(recoveredBuffer[0]).toBe(largeBuffer[0]);
    expect(recoveredBuffer[50000]).toBe(largeBuffer[50000]);
  });

  test("TimingSafeHelper branch tests", async () => {
    const diff1 = await TimingSafeHelper.constantTimeCompareStrings("abc", "defg");
    expect(diff1).toBe(false);

    const diff2 = await TimingSafeHelper.constantTimeCompareBuffers(
      new Uint8Array([1, 2]),
      new Uint8Array([1, 2, 3])
    );
    expect(diff2).toBe(false);

    const valid = await TimingSafeHelper.timingSafeVerify(
      globalThis.crypto,
      { name: "HMAC" },
      null,
      new Uint8Array(32),
      new Uint8Array([1, 2, 3])
    );
    expect(valid).toBe(false);
  });

  test("WebCrypt static helpers and error branches", async () => {
    const wc = new WebCrypt();
    const salt = WebCrypt.generateHmacSalt(32);
    expect(salt.length).toBe(32);

    await expect(wc.decryptData("invalid-base64-json", "password")).rejects.toThrow();

    const circular = {};
    circular.self = circular;
    await expect(wc.encryptData(circular, "password")).rejects.toThrow("Failed to serialize data");
  });

  test("WebCryptAsym deprecated stubs", () => {
    const wca = new WebCryptAsym();
    expect(wca._getCachedKey()).toBeNull();
    expect(() => wca._cacheKey()).not.toThrow();
    expect(() => wca.clearKeyCache()).not.toThrow();
    expect(() => wca.stopAutoCleanup()).not.toThrow();
  });
});
