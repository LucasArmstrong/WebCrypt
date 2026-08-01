// __tests__/IndexExports.test.js
import { WebCrypt, WebCryptAsym, WebCryptPQC, TimingSafeHelper } from "../src/index.js";

describe("Index Entry Point Exports", () => {
  test("exports WebCrypt, WebCryptAsym, WebCryptPQC, and TimingSafeHelper", () => {
    expect(WebCrypt).toBeDefined();
    expect(WebCryptAsym).toBeDefined();
    expect(WebCryptPQC).toBeDefined();
    expect(TimingSafeHelper).toBeDefined();

    const wc = new WebCrypt();
    expect(wc).toBeInstanceOf(WebCrypt);

    const wca = new WebCryptAsym();
    expect(wca).toBeInstanceOf(WebCryptAsym);

    const wcPqc = new WebCryptPQC();
    expect(wcPqc).toBeInstanceOf(WebCryptPQC);
  });
});
