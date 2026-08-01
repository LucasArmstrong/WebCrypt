// __tests__/WebCrypt100Coverage.test.js
import { WebCrypt } from "../src/WebCrypt.js";

describe("WebCrypt 100% Coverage Edge Cases", () => {
  let wc;

  beforeEach(() => {
    wc = new WebCrypt();
  });

  test("encryptText and decryptText invalid password error traps", async () => {
    await expect(wc.decryptText(null, "pass")).rejects.toThrow();
    await expect(wc.decryptText("invalid-b64-str", "pass")).rejects.toThrow();
  });

  test("encryptFile and decryptFile invalid input error traps", async () => {
    await expect(wc.encryptFile(null, "pass")).rejects.toThrow();
    await expect(wc.decryptFile(null, "pass")).rejects.toThrow();

    const shortUint8 = new Uint8Array(5);
    await expect(wc.decryptFile(shortUint8, "pass")).rejects.toThrow();
  });

  test("generateHmacSalt static helper", () => {
    const salt = WebCrypt.generateHmacSalt(16);
    expect(salt.length).toBe(16);
  });

  test("decryptData with invalid base64 input", async () => {
    await expect(wc.decryptData("!!!invalid-base64!!!", "password")).rejects.toThrow();
  });
});
