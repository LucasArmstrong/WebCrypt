// __tests__/WebCryptV06.test.js
import { WebCrypt } from "../src/WebCrypt.js";
import { WebCryptAsym } from "../src/WebCryptAsym.js";
import { WebCryptPQC } from "../src/WebCryptPQC.js";
import TimingSafeHelper from "../src/TimingSafeHelper.js";
import fs from "fs";
import path from "path";

describe("WebCrypt v0.6.x Features & Verification", () => {
  test("package.json version is 0.6.3", () => {
    const pkgPath = path.join(process.cwd(), "package.json");
    const pkg = JSON.parse(fs.readFileSync(pkgPath, "utf8"));
    expect(pkg.version).toBe("0.6.3");
    expect(pkg.author).toBe("PuterVision LLC");
    expect(pkg.homepage).toBe("https://putervision.com");
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
});
