// __tests__/TimingSafeHelperFull.test.js
import TimingSafeHelper from "../src/TimingSafeHelper.js";

describe("TimingSafeHelper Full Coverage", () => {
  test("timingSafeDerive timing-safe key derivation wrapper", async () => {
    const kdfFn = async (password, salt) => {
      const encoder = new TextEncoder();
      const input = new Uint8Array(password.length + salt.length);
      input.set(encoder.encode(password));
      input.set(salt, password.length);
      const digest = await globalThis.crypto.subtle.digest("SHA-256", input);
      return new Uint8Array(digest);
    };

    const salt = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);

    const derivedKey = await TimingSafeHelper.timingSafeDerive(kdfFn, "correct-password", salt);
    expect(derivedKey).toBeDefined();

    // Error handling in timingSafeDerive
    const errorKdfFn = async () => {
      throw new Error("KDF Error");
    };

    await expect(TimingSafeHelper.timingSafeDerive(errorKdfFn, "any-password")).rejects.toThrow(
      "KDF Error"
    );
  });

  test("sleepWithDummyOps with startTime timestamp parameter", async () => {
    const start = performance.now();
    await TimingSafeHelper.sleepWithDummyOps(15, start);
    const elapsed = performance.now() - start;
    expect(elapsed).toBeGreaterThanOrEqual(10);
  });
});
