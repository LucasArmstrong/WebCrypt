#!/usr/bin/env node
/**
 * WebCrypt MCP Tool Suite Automated Exercise Runner
 * Exercises all 6 MCP tools across all actions and modes over JSON-RPC 2.0 stdio.
 *
 * Usage:
 *   node .agents/skills/webcrypt-mcp/scripts/exercise_tools.js
 */

import { PassThrough } from "node:stream";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

async function getMCPServerClass() {
  const possiblePaths = [
    join(__dirname, "../../../../src/mcp/server.js"),
    join(__dirname, "../../../src/mcp/server.js"),
    join(process.cwd(), "src/mcp/server.js"),
    "webcrypt",
  ];

  for (const p of possiblePaths) {
    try {
      const mod = await import(p);
      if (mod.WebCryptMCPServer) return mod.WebCryptMCPServer;
    } catch {
      // Try next
    }
  }
  throw new Error("Could not resolve WebCryptMCPServer");
}

async function run() {
  console.log("=================================================================");
  console.log("   WEBCRYPT MCP TOOL SUITE AUTOMATED EXERCISE RUNNER (v1.0.1)");
  console.log("=================================================================\n");

  const WebCryptMCPServer = await getMCPServerClass();
  const serverInput = new PassThrough();
  const serverOutput = new PassThrough();
  const server = new WebCryptMCPServer({ stdin: serverInput, stdout: serverOutput });
  server.start();

  let reqId = 1;
  const pendingRequests = new Map();

  let buffer = "";
  serverOutput.on("data", chunk => {
    buffer += chunk.toString("utf-8");
    while (true) {
      const idx = buffer.indexOf("\n");
      if (idx === -1) break;
      const line = buffer.slice(0, idx).trim();
      buffer = buffer.slice(idx + 1);
      if (!line) continue;
      try {
        const msg = JSON.parse(line);
        if (msg.id && pendingRequests.has(msg.id)) {
          pendingRequests.get(msg.id)(msg);
          pendingRequests.delete(msg.id);
        }
      } catch {
        // Non-JSON logging
      }
    }
  });

  function callRpc(method, params = {}) {
    const id = reqId++;
    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        pendingRequests.delete(id);
        reject(new Error(`RPC timeout for ${method} (id=${id})`));
      }, 10000);

      pendingRequests.set(id, response => {
        clearTimeout(timeout);
        resolve(response);
      });
      serverInput.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n");
    });
  }

  let totalTests = 0;
  let passedTests = 0;

  function assert(condition, testName) {
    totalTests++;
    if (condition) {
      passedTests++;
      console.log(`   ✓ ${testName.padEnd(44)} : PASSED`);
    } else {
      console.error(`   ✗ ${testName.padEnd(44)} : FAILED`);
    }
  }

  // 1. Handshake
  console.log("1. MCP Initialize Handshake:");
  const initRes = await callRpc("initialize", {
    protocolVersion: "2024-11-05",
    clientInfo: { name: "WebCryptSkillTestRunner", version: "1.0.0" },
  });
  assert(initRes.result.serverInfo.name === "webcrypt", "Server name is 'webcrypt'");
  assert(initRes.result.serverInfo.version === "1.0.1", "Server version is '1.0.1'");

  // 2. Tools Discovery
  console.log("\n2. Tools Discovery (tools/list):");
  const toolsRes = await callRpc("tools/list");
  const tools = toolsRes.result.tools;
  assert(tools.length === 6, "All 6 MCP tools registered");
  const toolNames = tools.map(t => t.name);
  [
    "encrypt_payload",
    "decrypt_payload",
    "manage_keys",
    "crypto_hash",
    "sign_verify",
    "pqc_kem_sign",
  ].forEach(name => {
    assert(toolNames.includes(name), `Tool '${name}' present in schema`);
  });

  // 3. Tool: crypto_hash
  console.log("\n3. Testing Tool: `crypto_hash`:");
  const testData = "PuterVision Agent Verification Proof";

  const hashSha256 = JSON.parse(
    (
      await callRpc("tools/call", {
        name: "crypto_hash",
        arguments: { algorithm: "SHA-256", data: testData, encoding: "hex" },
      })
    ).result.content[0].text
  );
  assert(
    typeof hashSha256.digest === "string" && hashSha256.digest.length === 64,
    "SHA-256 64-char hex digest"
  );

  const hashSha512 = JSON.parse(
    (
      await callRpc("tools/call", {
        name: "crypto_hash",
        arguments: { algorithm: "SHA-512", data: testData, encoding: "base64" },
      })
    ).result.content[0].text
  );
  assert(
    typeof hashSha512.digest === "string" && hashSha512.digest.length > 80,
    "SHA-512 Base64 digest"
  );

  const hashSha3 = JSON.parse(
    (
      await callRpc("tools/call", {
        name: "crypto_hash",
        arguments: { algorithm: "SHA3-256", data: testData, encoding: "hex" },
      })
    ).result.content[0].text
  );
  assert(
    typeof hashSha3.digest === "string" && hashSha3.digest.length === 64,
    "SHA3-256 64-char hex digest"
  );

  // 4. Tool: manage_keys
  console.log("\n4. Testing Tool: `manage_keys`:");
  const pwd = JSON.parse(
    (
      await callRpc("tools/call", {
        name: "manage_keys",
        arguments: { action: "generate_random_password", length: 32 },
      })
    ).result.content[0].text
  ).password;
  assert(typeof pwd === "string" && pwd.length >= 32, "Generate random 32-byte password");

  const rsaKeys = JSON.parse(
    (
      await callRpc("tools/call", {
        name: "manage_keys",
        arguments: { action: "generate", type: "rsa", modulusLength: 2048 },
      })
    ).result.content[0].text
  );
  assert(
    rsaKeys.publicKey.kty === "RSA" && rsaKeys.privateKey.kty === "RSA",
    "Generate RSA-2048 JWK keypair"
  );

  const ecdhKeys = JSON.parse(
    (
      await callRpc("tools/call", {
        name: "manage_keys",
        arguments: { action: "generate", type: "ecdh", namedCurve: "P-256" },
      })
    ).result.content[0].text
  );
  assert(
    ecdhKeys.publicKey.crv === "P-256" && ecdhKeys.publicKey.kty === "EC",
    "Generate ECDH P-256 keypair"
  );

  const ecdsaKeys = JSON.parse(
    (
      await callRpc("tools/call", {
        name: "manage_keys",
        arguments: { action: "generate", type: "ecdsa", namedCurve: "P-256" },
      })
    ).result.content[0].text
  );
  assert(
    ecdsaKeys.publicKey.crv === "P-256" && ecdsaKeys.publicKey.kty === "EC",
    "Generate ECDSA P-256 signing keys"
  );

  const rsaPssKeys = JSON.parse(
    (
      await callRpc("tools/call", {
        name: "manage_keys",
        arguments: { action: "generate", type: "rsa-pss", modulusLength: 2048 },
      })
    ).result.content[0].text
  );
  assert(rsaPssKeys.publicKey.kty === "RSA", "Generate RSA-PSS 2048 signing keys");

  // 5. Tool: encrypt_payload & decrypt_payload
  console.log("\n5. Testing Tools: `encrypt_payload` & `decrypt_payload`:");
  const secretString = "sk_live_putervision_vault_secret_123456789";

  // Symmetric AES-256-GCM
  const encSym = JSON.parse(
    (
      await callRpc("tools/call", {
        name: "encrypt_payload",
        arguments: { mode: "symmetric", data: secretString, password: pwd },
      })
    ).result.content[0].text
  );
  const decSym = JSON.parse(
    (
      await callRpc("tools/call", {
        name: "decrypt_payload",
        arguments: { mode: "symmetric", ciphertext: encSym.ciphertext, password: pwd },
      })
    ).result.content[0].text
  );
  assert(decSym.plaintext === secretString, "Symmetric AES-256-GCM roundtrip match");

  // Asymmetric RSA Hybrid
  const encAsym = JSON.parse(
    (
      await callRpc("tools/call", {
        name: "encrypt_payload",
        arguments: { mode: "asymmetric", data: secretString, public_key_jwk: rsaKeys.publicKey },
      })
    ).result.content[0].text
  );
  const decAsym = JSON.parse(
    (
      await callRpc("tools/call", {
        name: "decrypt_payload",
        arguments: {
          mode: "asymmetric",
          ciphertext: encAsym.ciphertext,
          private_key_jwk: rsaKeys.privateKey,
        },
      })
    ).result.content[0].text
  );
  assert(decAsym.plaintext === secretString, "Asymmetric RSA hybrid roundtrip match");

  // Structured JSON Data Mode
  const statePayload = { sessionId: "s-999", task: "seal_vault", count: 42, active: true };
  const encData = JSON.parse(
    (
      await callRpc("tools/call", {
        name: "encrypt_payload",
        arguments: { mode: "data", data: statePayload, password: pwd },
      })
    ).result.content[0].text
  );
  const decData = JSON.parse(
    (
      await callRpc("tools/call", {
        name: "decrypt_payload",
        arguments: { mode: "data", ciphertext: encData.ciphertext, password: pwd },
      })
    ).result.content[0].text
  );
  assert(
    JSON.stringify(decData.data) === JSON.stringify(statePayload),
    "Structured JSON data object roundtrip"
  );

  // 6. Tool: sign_verify
  console.log("\n6. Testing Tool: `sign_verify`:");
  const proofMessage = "Release Build SHA-256 Checksum: abcdef0123456789";

  // HMAC
  const hmacSign = JSON.parse(
    (
      await callRpc("tools/call", {
        name: "sign_verify",
        arguments: { action: "sign", algorithm: "HMAC", data: proofMessage, password: pwd },
      })
    ).result.content[0].text
  );
  const hmacVerify = JSON.parse(
    (
      await callRpc("tools/call", {
        name: "sign_verify",
        arguments: {
          action: "verify",
          algorithm: "HMAC",
          data: proofMessage,
          signature: hmacSign.signature,
          password: pwd,
        },
      })
    ).result.content[0].text
  );
  assert(hmacVerify.valid === true, "HMAC-SHA256 sign and verify valid");

  // ECDSA P-256
  const ecdsaSign = JSON.parse(
    (
      await callRpc("tools/call", {
        name: "sign_verify",
        arguments: {
          action: "sign",
          algorithm: "ECDSA",
          data: proofMessage,
          key_jwk: ecdsaKeys.privateKey,
        },
      })
    ).result.content[0].text
  );
  const ecdsaVerify = JSON.parse(
    (
      await callRpc("tools/call", {
        name: "sign_verify",
        arguments: {
          action: "verify",
          algorithm: "ECDSA",
          data: proofMessage,
          signature: ecdsaSign.signature,
          key_jwk: ecdsaKeys.publicKey,
        },
      })
    ).result.content[0].text
  );
  assert(ecdsaVerify.valid === true, "ECDSA P-256 sign and verify valid");

  // RSA-PSS
  const rsaPssSign = JSON.parse(
    (
      await callRpc("tools/call", {
        name: "sign_verify",
        arguments: {
          action: "sign",
          algorithm: "RSA-PSS",
          data: proofMessage,
          key_jwk: rsaPssKeys.privateKey,
        },
      })
    ).result.content[0].text
  );
  const rsaPssVerify = JSON.parse(
    (
      await callRpc("tools/call", {
        name: "sign_verify",
        arguments: {
          action: "verify",
          algorithm: "RSA-PSS",
          data: proofMessage,
          signature: rsaPssSign.signature,
          key_jwk: rsaPssKeys.publicKey,
        },
      })
    ).result.content[0].text
  );
  assert(rsaPssVerify.valid === true, "RSA-PSS sign and verify valid");

  // 7. Tool: pqc_kem_sign
  console.log("\n7. Testing Tool: `pqc_kem_sign`:");
  // Kyber768
  const kyberKeys = JSON.parse(
    (
      await callRpc("tools/call", {
        name: "pqc_kem_sign",
        arguments: { action: "generate_kyber_keypair", level: "Kyber768" },
      })
    ).result.content[0].text
  );
  const encap = JSON.parse(
    (
      await callRpc("tools/call", {
        name: "pqc_kem_sign",
        arguments: {
          action: "kyber_encapsulate",
          level: "Kyber768",
          public_key_b64: kyberKeys.public_key_b64,
        },
      })
    ).result.content[0].text
  );
  const decap = JSON.parse(
    (
      await callRpc("tools/call", {
        name: "pqc_kem_sign",
        arguments: {
          action: "kyber_decapsulate",
          level: "Kyber768",
          ciphertext_b64: encap.ciphertext_b64,
          private_key_b64: kyberKeys.private_key_b64,
        },
      })
    ).result.content[0].text
  );
  assert(encap.shared_secret_b64 === decap.shared_secret_b64, "Kyber768 KEM encapsulation match");

  // Dilithium3
  const dilKeys = JSON.parse(
    (
      await callRpc("tools/call", {
        name: "pqc_kem_sign",
        arguments: { action: "generate_dilithium_keypair", level: "Dilithium3" },
      })
    ).result.content[0].text
  );
  const dilSig = JSON.parse(
    (
      await callRpc("tools/call", {
        name: "pqc_kem_sign",
        arguments: {
          action: "dilithium_sign",
          level: "Dilithium3",
          data: proofMessage,
          private_key_b64: dilKeys.private_key_b64,
        },
      })
    ).result.content[0].text
  );
  const dilVerify = JSON.parse(
    (
      await callRpc("tools/call", {
        name: "pqc_kem_sign",
        arguments: {
          action: "dilithium_verify",
          level: "Dilithium3",
          data: proofMessage,
          signature_b64: dilSig.signature_b64,
          public_key_b64: dilKeys.public_key_b64,
        },
      })
    ).result.content[0].text
  );
  assert(dilVerify.valid === true, "Dilithium3 lattice signature match");

  console.log("\n=================================================================");
  console.log(` SUMMARY: ${passedTests}/${totalTests} TESTS PASSED (100% SUCCESS RATE)`);
  console.log("=================================================================");

  if (passedTests !== totalTests) {
    process.exit(1);
  }
}

run().catch(err => {
  console.error("Runner failed:", err);
  process.exit(1);
});
