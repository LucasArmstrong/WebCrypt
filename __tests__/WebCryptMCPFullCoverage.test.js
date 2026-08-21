import { EventEmitter } from "events";
import { WebCryptMCPServer, startMCPServer } from "../src/mcp/server.js";
import { handleToolCall } from "../src/mcp/handlers.js";

describe("WebCrypt MCP Server & Handlers Deep Coverage", () => {
  let server;

  beforeEach(() => {
    server = new WebCryptMCPServer();
  });

  test("handles ping, notifications, and method not found", async () => {
    const pingRes = await server.handleMessage({
      jsonrpc: "2.0",
      id: 101,
      method: "ping",
    });
    expect(pingRes.result).toEqual({});

    const notifRes = await server.handleMessage({
      jsonrpc: "2.0",
      method: "notifications/initialized",
    });
    expect(notifRes).toBeNull();

    const otherNotifRes = await server.handleMessage({
      jsonrpc: "2.0",
      method: "custom/notification",
    });
    expect(otherNotifRes).toBeNull();

    const nullMsg = await server.handleMessage(null);
    expect(nullMsg).toBeNull();

    const unknownRes = await server.handleMessage({
      jsonrpc: "2.0",
      id: 102,
      method: "unknown_method",
    });
    expect(unknownRes.error.code).toBe(-32601);
  });

  test("runs stdio stream reader and line buffering in start()", done => {
    const mockStdin = new EventEmitter();
    const mockStdout = {
      data: "",
      write(chunk) {
        this.data += chunk;
      },
    };

    const stdioServer = new WebCryptMCPServer({
      stdin: mockStdin,
      stdout: mockStdout,
    });
    stdioServer.start();

    // 1. Partial chunk followed by rest of line
    mockStdin.emit("data", '{"jsonrpc":"2.0","id":1,"method"');
    mockStdin.emit("data", ':"ping"}\n');

    // 2. Empty line & malformed line
    mockStdin.emit("data", "\n");
    mockStdin.emit("data", "{ invalid json }\n");

    // 3. Close stream
    mockStdin.emit("end");

    setImmediate(() => {
      expect(mockStdout.data).toContain('"result":{}');
      expect(mockStdout.data).toContain('"code":-32700');
      done();
    });
  });

  test("startMCPServer factory function initializes and returns server", () => {
    const s = startMCPServer();
    expect(s).toBeInstanceOf(WebCryptMCPServer);
    expect(s.name).toBe("webcrypt");
  });

  test("send() ignores falsy response", () => {
    let called = false;
    const mockStdout = {
      write() {
        called = true;
      },
    };
    const s = new WebCryptMCPServer({ stdout: mockStdout });
    s.send(null);
    expect(called).toBe(false);
  });

  // -------------------------------------------------------------
  // Tool Handler Error Cases & Comprehensive Branches
  // -------------------------------------------------------------

  test("encrypt_payload error branches", async () => {
    await expect(handleToolCall("encrypt_payload", { mode: "symmetric" })).rejects.toThrow(
      "Missing 'password'"
    );

    await expect(handleToolCall("encrypt_payload", { mode: "data" })).rejects.toThrow(
      "Missing 'password'"
    );

    await expect(
      handleToolCall("encrypt_payload", { mode: "asymmetric", data: "hi" })
    ).rejects.toThrow("Missing 'public_key_jwk'");

    await expect(
      handleToolCall("encrypt_payload", { mode: "invalid_mode", data: "hi" })
    ).rejects.toThrow("Unsupported mode");
  });

  test("decrypt_payload error branches", async () => {
    await expect(handleToolCall("decrypt_payload", {})).rejects.toThrow("Missing 'ciphertext'");

    await expect(
      handleToolCall("decrypt_payload", { mode: "symmetric", ciphertext: "abc" })
    ).rejects.toThrow("Missing 'password'");

    await expect(
      handleToolCall("decrypt_payload", { mode: "data", ciphertext: "abc" })
    ).rejects.toThrow("Missing 'password'");

    await expect(
      handleToolCall("decrypt_payload", { mode: "asymmetric", ciphertext: "abc" })
    ).rejects.toThrow("Missing 'private_key_jwk'");

    await expect(
      handleToolCall("decrypt_payload", { mode: "invalid_mode", ciphertext: "abc" })
    ).rejects.toThrow("Unsupported mode");
  });

  test("manage_keys branches & error handling", async () => {
    // Random password
    const pwdRes = await handleToolCall("manage_keys", { action: "generate_random_password" });
    expect(pwdRes.password).toBeDefined();

    // ECDH Keygen
    const ecdhRes = await handleToolCall("manage_keys", {
      action: "generate",
      type: "ecdh",
      namedCurve: "P-384",
    });
    expect(ecdhRes.type).toBe("ecdh");
    expect(ecdhRes.publicKey).toBeDefined();

    // HMAC Keygen
    const hmacRes = await handleToolCall("manage_keys", { action: "generate", type: "hmac" });
    expect(hmacRes.type).toBe("hmac");
    expect(hmacRes.key_b64).toBeDefined();

    // Invalid type & action
    await expect(
      handleToolCall("manage_keys", { action: "generate", type: "invalid" })
    ).rejects.toThrow("Unsupported key type");

    await expect(handleToolCall("manage_keys", { action: "invalid_action" })).rejects.toThrow(
      "Unsupported action"
    );
  });

  test("crypto_hash base64 encoding and SHA-512 / SHA3-512", async () => {
    await expect(handleToolCall("crypto_hash", {})).rejects.toThrow("Missing 'data'");

    const sha512 = await handleToolCall("crypto_hash", {
      algorithm: "SHA-512",
      data: "hello world",
      encoding: "base64",
    });
    expect(sha512.digest).toBeDefined();
    expect(sha512.encoding).toBe("base64");

    const sha3_512 = await handleToolCall("crypto_hash", {
      algorithm: "SHA3-512",
      data: "hello world",
      encoding: "base64",
    });
    expect(sha3_512.digest).toBeDefined();
  });

  test("sign_verify RSA-PSS, HMAC-SHA3 and error branches", async () => {
    await expect(handleToolCall("sign_verify", { action: "sign" })).rejects.toThrow(
      "Missing 'data'"
    );

    // Missing password for HMAC
    await expect(
      handleToolCall("sign_verify", { action: "sign", algorithm: "HMAC", data: "test" })
    ).rejects.toThrow("Missing 'password'");

    await expect(
      handleToolCall("sign_verify", { action: "sign", algorithm: "HMAC-SHA3", data: "test" })
    ).rejects.toThrow("Missing 'password'");

    await expect(
      handleToolCall("sign_verify", { action: "sign", algorithm: "ECDSA", data: "test" })
    ).rejects.toThrow("Missing 'key_jwk'");

    await expect(
      handleToolCall("sign_verify", { action: "sign", algorithm: "unsupported", data: "test" })
    ).rejects.toThrow("Unsupported sign algorithm");

    // Verify error branches
    await expect(handleToolCall("sign_verify", { action: "verify", data: "test" })).rejects.toThrow(
      "Missing 'signature'"
    );

    await expect(
      handleToolCall("sign_verify", {
        action: "verify",
        algorithm: "HMAC",
        data: "test",
        signature: "sig",
      })
    ).rejects.toThrow("Missing 'password'");

    await expect(
      handleToolCall("sign_verify", {
        action: "verify",
        algorithm: "HMAC-SHA3",
        data: "test",
        signature: "sig",
      })
    ).rejects.toThrow("Missing 'password'");

    await expect(
      handleToolCall("sign_verify", {
        action: "verify",
        algorithm: "ECDSA",
        data: "test",
        signature: "sig",
      })
    ).rejects.toThrow("Missing 'key_jwk'");

    await expect(
      handleToolCall("sign_verify", {
        action: "verify",
        algorithm: "unsupported",
        data: "test",
        signature: "sig",
      })
    ).rejects.toThrow("Unsupported verify algorithm");

    await expect(
      handleToolCall("sign_verify", { action: "unsupported_action", data: "test" })
    ).rejects.toThrow("Unsupported action");

    // HMAC-SHA3 sign & verify roundtrip
    const hmacSign = await handleToolCall("sign_verify", {
      action: "sign",
      algorithm: "HMAC-SHA3",
      data: "hello hmac sha3",
      password: "secret-pass",
    });
    expect(hmacSign.signature).toBeDefined();

    const hmacVerify = await handleToolCall("sign_verify", {
      action: "verify",
      algorithm: "HMAC-SHA3",
      data: "hello hmac sha3",
      signature: hmacSign.signature,
      password: "secret-pass",
    });
    expect(hmacVerify.valid).toBe(true);
  });

  test("pqc_kem_sign validation and error branches", async () => {
    await expect(handleToolCall("pqc_kem_sign", { action: "kyber_encapsulate" })).rejects.toThrow(
      "Missing 'public_key_b64'"
    );

    await expect(handleToolCall("pqc_kem_sign", { action: "kyber_decapsulate" })).rejects.toThrow(
      "Missing 'ciphertext_b64'"
    );

    await expect(handleToolCall("pqc_kem_sign", { action: "hybrid_encapsulate" })).rejects.toThrow(
      "Missing 'rsa_public_key_jwk'"
    );

    await expect(handleToolCall("pqc_kem_sign", { action: "hybrid_decapsulate" })).rejects.toThrow(
      "Missing required parameters"
    );

    await expect(handleToolCall("pqc_kem_sign", { action: "dilithium_sign" })).rejects.toThrow(
      "Missing 'data'"
    );

    await expect(handleToolCall("pqc_kem_sign", { action: "dilithium_verify" })).rejects.toThrow(
      "Missing 'data'"
    );

    await expect(handleToolCall("pqc_kem_sign", { action: "invalid_pqc_action" })).rejects.toThrow(
      "Unsupported PQC action"
    );
  });
});
