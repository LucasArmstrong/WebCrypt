import { WebCryptPQC } from "../src/WebCryptPQC.js";
import { WebCryptAsym } from "../src/WebCryptAsym.js";

describe("WebCryptPQC Kyber KEM & Hybrid Round-Trip", () => {
  let pqc;
  let asym;

  beforeAll(() => {
    WebCryptPQC.enableStubTesting(true);
  });

  afterAll(() => {
    WebCryptPQC.enableStubTesting(false);
  });

  beforeEach(() => {
    pqc = new WebCryptPQC();
    asym = new WebCryptAsym();
  });

  afterEach(() => {
    asym.stopAutoCleanup();
  });

  test("Kyber512 encapsulate and decapsulate recover identical shared secret", async () => {
    const { publicKey, privateKey } = await pqc.generateKyberKeyPair(WebCryptPQC.KYBER_512);
    const { ciphertext, sharedSecret } = await pqc.kyberEncapsulate(
      publicKey,
      WebCryptPQC.KYBER_512
    );
    const recoveredSecret = await pqc.kyberDecapsulate(
      ciphertext,
      privateKey,
      WebCryptPQC.KYBER_512
    );

    expect(Buffer.from(recoveredSecret).toString("hex")).toBe(
      Buffer.from(sharedSecret).toString("hex")
    );
  });

  test("Kyber768 encapsulate and decapsulate recover identical shared secret", async () => {
    const { publicKey, privateKey } = await pqc.generateKyberKeyPair(WebCryptPQC.KYBER_768);
    const { ciphertext, sharedSecret } = await pqc.kyberEncapsulate(
      publicKey,
      WebCryptPQC.KYBER_768
    );
    const recoveredSecret = await pqc.kyberDecapsulate(
      ciphertext,
      privateKey,
      WebCryptPQC.KYBER_768
    );

    expect(Buffer.from(recoveredSecret).toString("hex")).toBe(
      Buffer.from(sharedSecret).toString("hex")
    );
  });

  test("Kyber1024 encapsulate and decapsulate recover identical shared secret", async () => {
    const { publicKey, privateKey } = await pqc.generateKyberKeyPair(WebCryptPQC.KYBER_1024);
    const { ciphertext, sharedSecret } = await pqc.kyberEncapsulate(
      publicKey,
      WebCryptPQC.KYBER_1024
    );
    const recoveredSecret = await pqc.kyberDecapsulate(
      ciphertext,
      privateKey,
      WebCryptPQC.KYBER_1024
    );

    expect(Buffer.from(recoveredSecret).toString("hex")).toBe(
      Buffer.from(sharedSecret).toString("hex")
    );
  });

  test("hybridEncapsulate / hybridDecapsulate round-trip matches shared secret", async () => {
    const rsaKeys = await asym.generateKeyPair(2048);
    const kyberKeys = await pqc.generateKyberKeyPair(WebCryptPQC.KYBER_768);

    const { combinedCiphertext, hybridSecret } = await pqc.hybridEncapsulate(
      rsaKeys.publicKey,
      kyberKeys.publicKey,
      WebCryptPQC.KYBER_768
    );

    const recoveredSecret = await pqc.hybridDecapsulate(
      combinedCiphertext,
      rsaKeys.privateKey,
      kyberKeys.privateKey,
      WebCryptPQC.KYBER_768
    );

    expect(Buffer.from(recoveredSecret).toString("hex")).toBe(
      Buffer.from(hybridSecret).toString("hex")
    );
  });
});
