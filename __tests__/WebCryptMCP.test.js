import { WebCryptMCPServer } from "../src/mcp/server.js";
import { WEBCRYPT_MCP_TOOLS } from "../src/mcp/tools.js";

describe("WebCrypt MCP Server", () => {
  let server;

  beforeEach(() => {
    server = new WebCryptMCPServer();
  });

  test("implements MCP initialize handshake", async () => {
    const response = await server.handleMessage({
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: {
        protocolVersion: "2024-11-05",
        capabilities: {},
        clientInfo: { name: "test-client", version: "1.0.0" },
      },
    });

    expect(response).toBeDefined();
    expect(response.id).toBe(1);
    expect(response.result.protocolVersion).toBe("2024-11-05");
    expect(response.result.serverInfo.name).toBe("webcrypt");
    expect(response.result.serverInfo.version).toBe("1.0.0");
    expect(response.result.capabilities.tools).toBeDefined();
  });

  test("handles notifications/initialized gracefully", async () => {
    const response = await server.handleMessage({
      jsonrpc: "2.0",
      method: "notifications/initialized",
      params: {},
    });

    expect(response).toBeNull();
  });

  test("lists all registered tools with schemas", async () => {
    const response = await server.handleMessage({
      jsonrpc: "2.0",
      id: 2,
      method: "tools/list",
      params: {},
    });

    expect(response.result.tools).toHaveLength(WEBCRYPT_MCP_TOOLS.length);
    const toolNames = response.result.tools.map(t => t.name);
    expect(toolNames).toContain("encrypt_payload");
    expect(toolNames).toContain("decrypt_payload");
    expect(toolNames).toContain("manage_keys");
    expect(toolNames).toContain("crypto_hash");
    expect(toolNames).toContain("sign_verify");
    expect(toolNames).toContain("pqc_kem_sign");
  });

  test("tool: encrypt_payload & decrypt_payload symmetric roundtrip", async () => {
    const encRes = await server.handleMessage({
      jsonrpc: "2.0",
      id: 3,
      method: "tools/call",
      params: {
        name: "encrypt_payload",
        arguments: {
          mode: "symmetric",
          data: "Secret message from agent",
          password: "super-secure-password",
        },
      },
    });

    expect(encRes.result.isError).toBeUndefined();
    const encResult = JSON.parse(encRes.result.content[0].text);
    expect(encResult.ciphertext).toBeDefined();

    const decRes = await server.handleMessage({
      jsonrpc: "2.0",
      id: 4,
      method: "tools/call",
      params: {
        name: "decrypt_payload",
        arguments: {
          mode: "symmetric",
          ciphertext: encResult.ciphertext,
          password: "super-secure-password",
        },
      },
    });

    const decResult = JSON.parse(decRes.result.content[0].text);
    expect(decResult.data).toBe("Secret message from agent");
  });

  test("tool: encrypt_payload & decrypt_payload data mode roundtrip", async () => {
    const testObject = { user: "agent-007", roles: ["admin", "crypto"], active: true };

    const encRes = await server.handleMessage({
      jsonrpc: "2.0",
      id: 5,
      method: "tools/call",
      params: {
        name: "encrypt_payload",
        arguments: {
          mode: "data",
          data: testObject,
          password: "data-pass",
        },
      },
    });

    const encResult = JSON.parse(encRes.result.content[0].text);
    expect(encResult.ciphertext).toBeDefined();

    const decRes = await server.handleMessage({
      jsonrpc: "2.0",
      id: 6,
      method: "tools/call",
      params: {
        name: "decrypt_payload",
        arguments: {
          mode: "data",
          ciphertext: encResult.ciphertext,
          password: "data-pass",
        },
      },
    });

    const decResult = JSON.parse(decRes.result.content[0].text);
    expect(decResult.data).toEqual(testObject);
  });

  test("tool: manage_keys & asymmetric encrypt/decrypt roundtrip", async () => {
    const keyRes = await server.handleMessage({
      jsonrpc: "2.0",
      id: 7,
      method: "tools/call",
      params: {
        name: "manage_keys",
        arguments: {
          action: "generate",
          type: "rsa",
          modulusLength: 2048,
        },
      },
    });

    const keyResult = JSON.parse(keyRes.result.content[0].text);
    expect(keyResult.publicKey).toBeDefined();
    expect(keyResult.privateKey).toBeDefined();

    const encRes = await server.handleMessage({
      jsonrpc: "2.0",
      id: 8,
      method: "tools/call",
      params: {
        name: "encrypt_payload",
        arguments: {
          mode: "asymmetric",
          data: "Top secret asymmetric agent message",
          public_key_jwk: keyResult.publicKey,
        },
      },
    });

    const encResult = JSON.parse(encRes.result.content[0].text);

    const decRes = await server.handleMessage({
      jsonrpc: "2.0",
      id: 9,
      method: "tools/call",
      params: {
        name: "decrypt_payload",
        arguments: {
          mode: "asymmetric",
          ciphertext: encResult.ciphertext,
          private_key_jwk: keyResult.privateKey,
        },
      },
    });

    const decResult = JSON.parse(decRes.result.content[0].text);
    expect(decResult.data).toBe("Top secret asymmetric agent message");
  });

  test("tool: crypto_hash computes SHA-256 and SHA3-256 digests", async () => {
    const sha256Res = await server.handleMessage({
      jsonrpc: "2.0",
      id: 10,
      method: "tools/call",
      params: {
        name: "crypto_hash",
        arguments: {
          algorithm: "SHA-256",
          data: "WebCrypt PuterVision",
          encoding: "hex",
        },
      },
    });

    const sha256Result = JSON.parse(sha256Res.result.content[0].text);
    expect(sha256Result.digest).toHaveLength(64);

    const sha3Res = await server.handleMessage({
      jsonrpc: "2.0",
      id: 11,
      method: "tools/call",
      params: {
        name: "crypto_hash",
        arguments: {
          algorithm: "SHA3-256",
          data: "WebCrypt PuterVision",
          encoding: "hex",
        },
      },
    });

    const sha3Result = JSON.parse(sha3Res.result.content[0].text);
    expect(sha3Result.digest).toHaveLength(64);
  });

  test("tool: sign_verify HMAC and HMAC-SHA3", async () => {
    const signRes = await server.handleMessage({
      jsonrpc: "2.0",
      id: 12,
      method: "tools/call",
      params: {
        name: "sign_verify",
        arguments: {
          action: "sign",
          algorithm: "HMAC",
          data: "Authenticated statement",
          password: "hmac-auth-pass",
        },
      },
    });

    const signResult = JSON.parse(signRes.result.content[0].text);
    expect(signResult.signature).toBeDefined();

    const verifyRes = await server.handleMessage({
      jsonrpc: "2.0",
      id: 13,
      method: "tools/call",
      params: {
        name: "sign_verify",
        arguments: {
          action: "verify",
          algorithm: "HMAC",
          data: "Authenticated statement",
          signature: signResult.signature,
          password: "hmac-auth-pass",
        },
      },
    });

    const verifyResult = JSON.parse(verifyRes.result.content[0].text);
    expect(verifyResult.valid).toBe(true);
  });

  test("tool: pqc_kem_sign Kyber encapsulate and decapsulate", async () => {
    const keyRes = await server.handleMessage({
      jsonrpc: "2.0",
      id: 14,
      method: "tools/call",
      params: {
        name: "pqc_kem_sign",
        arguments: {
          action: "generate_kyber_keypair",
          level: "Kyber768",
        },
      },
    });

    const keyResult = JSON.parse(keyRes.result.content[0].text);
    expect(keyResult.publicKey_b64).toBeDefined();
    expect(keyResult.privateKey_b64).toBeDefined();

    const encRes = await server.handleMessage({
      jsonrpc: "2.0",
      id: 15,
      method: "tools/call",
      params: {
        name: "pqc_kem_sign",
        arguments: {
          action: "kyber_encapsulate",
          level: "Kyber768",
          public_key_b64: keyResult.publicKey_b64,
        },
      },
    });

    const encResult = JSON.parse(encRes.result.content[0].text);
    expect(encResult.ciphertext_b64).toBeDefined();
    expect(encResult.sharedSecret_b64).toBeDefined();

    const decRes = await server.handleMessage({
      jsonrpc: "2.0",
      id: 16,
      method: "tools/call",
      params: {
        name: "pqc_kem_sign",
        arguments: {
          action: "kyber_decapsulate",
          level: "Kyber768",
          ciphertext_b64: encResult.ciphertext_b64,
          private_key_b64: keyResult.privateKey_b64,
        },
      },
    });

    const decResult = JSON.parse(decRes.result.content[0].text);
    expect(decResult.sharedSecret_b64).toBe(encResult.sharedSecret_b64);
  });

  test("tool: pqc_kem_sign hybrid encapsulate and decapsulate", async () => {
    const rsaKeyRes = await server.handleMessage({
      jsonrpc: "2.0",
      id: 20,
      method: "tools/call",
      params: {
        name: "manage_keys",
        arguments: { action: "generate", type: "rsa", modulusLength: 2048 },
      },
    });
    const rsaKeys = JSON.parse(rsaKeyRes.result.content[0].text);

    const kyberKeyRes = await server.handleMessage({
      jsonrpc: "2.0",
      id: 21,
      method: "tools/call",
      params: {
        name: "pqc_kem_sign",
        arguments: { action: "generate_kyber_keypair", level: "Kyber768" },
      },
    });
    const kyberKeys = JSON.parse(kyberKeyRes.result.content[0].text);

    const encRes = await server.handleMessage({
      jsonrpc: "2.0",
      id: 22,
      method: "tools/call",
      params: {
        name: "pqc_kem_sign",
        arguments: {
          action: "hybrid_encapsulate",
          level: "Kyber768",
          rsa_public_key_jwk: rsaKeys.publicKey,
          public_key_b64: kyberKeys.publicKey_b64,
        },
      },
    });
    const encResult = JSON.parse(encRes.result.content[0].text);
    expect(encResult.sharedSecret_b64).toBeDefined();

    const decRes = await server.handleMessage({
      jsonrpc: "2.0",
      id: 23,
      method: "tools/call",
      params: {
        name: "pqc_kem_sign",
        arguments: {
          action: "hybrid_decapsulate",
          level: "Kyber768",
          rsa_private_key_jwk: rsaKeys.privateKey,
          private_key_b64: kyberKeys.privateKey_b64,
          kyber_ciphertext_b64: encResult.kyberCiphertext_b64,
          rsa_wrapped_secret_b64: encResult.rsaWrappedSecret_b64,
        },
      },
    });
    const decResult = JSON.parse(decRes.result.content[0].text);
    expect(decResult.sharedSecret_b64).toBe(encResult.sharedSecret_b64);
  });

  test("tool: pqc_kem_sign Dilithium sign and verify", async () => {
    const keyRes = await server.handleMessage({
      jsonrpc: "2.0",
      id: 24,
      method: "tools/call",
      params: {
        name: "pqc_kem_sign",
        arguments: { action: "generate_dilithium_keypair", level: "Dilithium3" },
      },
    });
    const keys = JSON.parse(keyRes.result.content[0].text);

    const signRes = await server.handleMessage({
      jsonrpc: "2.0",
      id: 25,
      method: "tools/call",
      params: {
        name: "pqc_kem_sign",
        arguments: {
          action: "dilithium_sign",
          level: "Dilithium3",
          data: "Dilithium signed statement",
          private_key_b64: keys.privateKey_b64,
        },
      },
    });
    const signResult = JSON.parse(signRes.result.content[0].text);
    expect(signResult.signature_b64).toBeDefined();

    const verifyRes = await server.handleMessage({
      jsonrpc: "2.0",
      id: 26,
      method: "tools/call",
      params: {
        name: "pqc_kem_sign",
        arguments: {
          action: "dilithium_verify",
          level: "Dilithium3",
          data: "Dilithium signed statement",
          signature_b64: signResult.signature_b64,
          public_key_b64: keys.publicKey_b64,
        },
      },
    });
    const verifyResult = JSON.parse(verifyRes.result.content[0].text);
    expect(verifyResult.valid).toBe(true);
  });

  test("handles unknown tool calls gracefully with error payload", async () => {
    const response = await server.handleMessage({
      jsonrpc: "2.0",
      id: 99,
      method: "tools/call",
      params: {
        name: "unknown_nonexistent_tool",
        arguments: {},
      },
    });

    expect(response.result.isError).toBe(true);
    expect(response.result.content[0].text).toContain("Unknown tool");
  });
});
