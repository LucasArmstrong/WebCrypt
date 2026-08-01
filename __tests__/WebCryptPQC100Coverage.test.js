// __tests__/WebCryptPQC100Coverage.test.js
import { WebCryptPQC } from "../src/WebCryptPQC.js";

describe("WebCryptPQC 100% Coverage Expansion", () => {
  let pqc;

  beforeEach(() => {
    pqc = new WebCryptPQC();
    WebCryptPQC.enableStubTesting(true);
  });

  test("Kyber error handling traps for invalid parameters and keys", async () => {
    // Invalid ciphertext length
    await expect(
      pqc.kyberDecapsulate("short", "invalid-key", WebCryptPQC.KYBER_768)
    ).rejects.toThrow();

    // Invalid Kyber level
    await expect(pqc.kyberEncapsulate("pubkey", "KYBER_UNKNOWN")).rejects.toThrow(
      "Unsupported Kyber level"
    );
    await expect(pqc.kyberDecapsulate("ct", "privkey", "KYBER_UNKNOWN")).rejects.toThrow(
      "Unsupported Kyber level"
    );
  });

  test("Dilithium error handling traps for invalid parameters and keys", async () => {
    // Invalid Dilithium level
    await expect(pqc.dilithiumSign("data", "privkey", "DILITHIUM_UNKNOWN")).rejects.toThrow(
      "Unsupported Dilithium level"
    );
    await expect(pqc.dilithiumVerify("data", "sig", "pubkey", "DILITHIUM_UNKNOWN")).rejects.toThrow(
      "Unsupported Dilithium level"
    );
  });

  test("Hybrid PQC encapsulation error handling traps", async () => {
    await expect(pqc.hybridEncapsulate(null, WebCryptPQC.KYBER_768)).rejects.toThrow();
    await expect(pqc.hybridDecapsulate(null, "priv", WebCryptPQC.KYBER_768)).rejects.toThrow();
  });

  test("SHA3 hash fallback warnings", async () => {
    const hash256 = await pqc._sha3Hash(new Uint8Array([1, 2, 3]), 256);
    expect(hash256).toBeDefined();

    const hash384 = await pqc._sha3Hash(new Uint8Array([1, 2, 3]), 384);
    expect(hash384).toBeDefined();

    const hash512 = await pqc._sha3Hash(new Uint8Array([1, 2, 3]), 512);
    expect(hash512).toBeDefined();
  });
});
