import { WebCryptAsym } from "../src/WebCryptAsym.js";

describe("WebCryptAsym Argon2 Enhanced Fallback", () => {
  let asym;

  beforeEach(() => {
    asym = new WebCryptAsym();
  });

  afterEach(() => {
    asym.stopAutoCleanup();
  });

  test("deriveKeyArgon2Enhanced does not throw uncaught error and falls back to PBKDF2", async () => {
    const password = "my-argon2-test-password";
    const salt = new Uint8Array(16);
    salt.fill(0xaa);

    let key;
    expect(async () => {
      key = await asym.deriveKeyArgon2Enhanced(password, salt, {
        memory: 65536,
        iterations: 3,
        parallelism: 1,
        keyLength: 256,
      });
    }).not.toThrow();

    const derived = await asym.deriveKeyArgon2Enhanced(password, salt, {
      memory: 65536,
      iterations: 3,
      parallelism: 1,
      keyLength: 256,
    });
    expect(derived).toBeDefined();
    expect(derived.type).toBe("secret");
    expect(derived.algorithm.name).toBe("AES-GCM");
  });
});
