// __tests__/WebCryptPQCFullCoverage.test.js
import { WebCryptPQC } from "../src/WebCryptPQC.js";

describe("WebCryptPQC Full Coverage Expansion", () => {
  let pqc;

  beforeEach(() => {
    pqc = new WebCryptPQC();
    WebCryptPQC.enableStubTesting(true);
  });

  test("Kyber key generation, encapsulation, and decapsulation", async () => {
    const keyPair = await pqc.generateKyberKeyPair(WebCryptPQC.KYBER_768);
    expect(keyPair.publicKey).toBeDefined();
    expect(keyPair.privateKey).toBeDefined();

    const encap = await pqc.kyberEncapsulate(keyPair.publicKey, WebCryptPQC.KYBER_768);
    expect(encap.ciphertext).toBeDefined();
    expect(encap.sharedSecret).toBeDefined();

    const decapSecret = await pqc.kyberDecapsulate(
      encap.ciphertext,
      keyPair.privateKey,
      WebCryptPQC.KYBER_768
    );
    expect(decapSecret).toBeDefined();
    expect(decapSecret.byteLength).toBe(encap.sharedSecret.byteLength);
  });

  test("Dilithium key generation, signing, and verification", async () => {
    const keyPair = await pqc.generateDilithiumKeyPair(WebCryptPQC.DILITHIUM_3);
    expect(keyPair.publicKey).toBeDefined();
    expect(keyPair.privateKey).toBeDefined();

    const data = "Message to sign with post-quantum Dilithium-3";
    const signature = await pqc.dilithiumSign(data, keyPair.privateKey, WebCryptPQC.DILITHIUM_3);
    expect(signature).toBeDefined();

    const valid = await pqc.dilithiumVerify(
      data,
      signature,
      keyPair.publicKey,
      WebCryptPQC.DILITHIUM_3
    );
    expect(valid).toBe(true);
  });

  test("Invalid security level traps and disabled stub testing mode", async () => {
    await expect(pqc.generateKyberKeyPair("INVALID_LEVEL")).rejects.toThrow(
      "Unsupported Kyber level"
    );
    await expect(pqc.generateDilithiumKeyPair("INVALID_LEVEL")).rejects.toThrow(
      "Unsupported Dilithium level"
    );

    // Disable stub testing mode and verify it throws placeholder notice
    WebCryptPQC.enableStubTesting(false);
    await expect(pqc.generateKyberKeyPair()).rejects.toThrow("placeholder stub");
    await expect(pqc.generateDilithiumKeyPair()).rejects.toThrow("placeholder stub");

    // Re-enable for cleanup
    WebCryptPQC.enableStubTesting(true);
  });
});
