import { WebCryptPQC } from "../src/WebCryptPQC.js";
import { WebCryptAsym } from "../src/WebCryptAsym.js";

describe("WebCryptPQC - Hybrid Encryption", () => {
  let pqc;
  let asym;

  beforeEach(() => {
    pqc = new WebCryptPQC();
    asym = new WebCryptAsym();
  });

  test("hybrid encapsulation combines Kyber and RSA", async () => {
    const rsaKeys = await asym.generateKeyPair();
    const kyberKeys = await pqc.generateKyberKeyPair("Kyber768");

    const result = await pqc.hybridEncapsulate(rsaKeys.publicKey, kyberKeys.publicKey, "Kyber768");

    expect(result).toHaveProperty("sharedSecret");
    expect(result).toHaveProperty("kyberCiphertext");
    expect(result).toHaveProperty("rsaWrappedSharedSecret");

    expect(result.sharedSecret).toBeInstanceOf(Uint8Array);
    expect(result.kyberCiphertext).toBeInstanceOf(Uint8Array);
    expect(result.rsaWrappedSharedSecret).toBeInstanceOf(Uint8Array);
  });

  test("hybrid decapsulation recovers shared secret", async () => {
    const rsaKeys = await asym.generateKeyPair();
    const kyberKeys = await pqc.generateKyberKeyPair("Kyber768");

    const { kyberCiphertext, rsaWrappedSharedSecret } = await pqc.hybridEncapsulate(
      rsaKeys.publicKey,
      kyberKeys.publicKey,
      "Kyber768"
    );

    const recovered = await pqc.hybridDecapsulate(
      kyberCiphertext,
      rsaWrappedSharedSecret,
      rsaKeys.privateKey,
      kyberKeys.privateKey,
      "Kyber768"
    );

    expect(recovered).toBeInstanceOf(Uint8Array);
    expect(recovered.byteLength).toBe(32);
  });

  test("hybrid works with all Kyber levels", async () => {
    for (const level of ["Kyber512", "Kyber768", "Kyber1024"]) {
      const rsaKeys = await asym.generateKeyPair();
      const kyberKeys = await pqc.generateKyberKeyPair(level);

      const result = await pqc.hybridEncapsulate(rsaKeys.publicKey, kyberKeys.publicKey, level);

      expect(result.sharedSecret.byteLength).toBe(32);
      expect(result.kyberCiphertext).toBeDefined();
      expect(result.rsaWrappedSharedSecret).toBeDefined();
    }
  }, 15000); // Increase timeout for hybrid operations
});
