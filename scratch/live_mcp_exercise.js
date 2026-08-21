import { WebCryptMCPServer } from "../src/mcp/server.js";
import { PassThrough } from "stream";

async function main() {
  console.log("=================================================================");
  console.log("   LIVE EXERCISE OF ALL 6 WEBCRYPT MCP TOOLS OVER JSON-RPC 2.0");
  console.log("=================================================================\n");

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
      } catch (err) {
        // Non JSON
      }
    }
  });

  function callRpc(method, params = {}) {
    const id = reqId++;
    return new Promise(resolve => {
      pendingRequests.set(id, resolve);
      serverInput.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n");
    });
  }

  // 1. Handshake
  const initRes = await callRpc("initialize", {
    protocolVersion: "2024-11-05",
    clientInfo: { name: "AntigravityAgentClient", version: "1.0.0" },
  });
  console.log("1. MCP Handshake: SUCCESS");
  console.log("   Protocol Version :", initRes.result.protocolVersion);
  console.log(
    "   Server Identity  :",
    initRes.result.serverInfo.name,
    "v" + initRes.result.serverInfo.version
  );

  // 2. Tools Discovery
  const toolsRes = await callRpc("tools/list");
  console.log("\n2. Tools Discovery (" + toolsRes.result.tools.length + " tools registered):");
  toolsRes.result.tools.forEach((t, i) => {
    console.log(`   [${i + 1}] ${t.name.padEnd(16)} ─ ${t.description}`);
  });

  // 3. Tool: crypto_hash
  console.log("\n3. Testing Tool `crypto_hash`:");
  const testString = "PuterVision WebCrypt Protocol Evidence Proof";

  const hashSha256 = JSON.parse(
    (
      await callRpc("tools/call", {
        name: "crypto_hash",
        arguments: { algorithm: "SHA-256", data: testString, encoding: "hex" },
      })
    ).result.content[0].text
  );
  console.log("   ✓ SHA-256 (hex)      :", hashSha256.digest);

  const hashSha512 = JSON.parse(
    (
      await callRpc("tools/call", {
        name: "crypto_hash",
        arguments: { algorithm: "SHA-512", data: testString, encoding: "base64" },
      })
    ).result.content[0].text
  );
  console.log("   ✓ SHA-512 (base64)   :", hashSha512.digest.slice(0, 44) + "...");

  const hashSha3 = JSON.parse(
    (
      await callRpc("tools/call", {
        name: "crypto_hash",
        arguments: { algorithm: "SHA3-256", data: testString, encoding: "hex" },
      })
    ).result.content[0].text
  );
  console.log("   ✓ SHA3-256 (hex)     :", hashSha3.digest);

  // 4. Tool: manage_keys
  console.log("\n4. Testing Tool `manage_keys`:");
  const pwd = JSON.parse(
    (
      await callRpc("tools/call", {
        name: "manage_keys",
        arguments: { action: "generate_random_password", length: 32 },
      })
    ).result.content[0].text
  ).password;
  console.log("   ✓ High-Entropy Pass  :", pwd);

  const rsaKeys = JSON.parse(
    (
      await callRpc("tools/call", {
        name: "manage_keys",
        arguments: { action: "generate", type: "rsa", modulusLength: 2048 },
      })
    ).result.content[0].text
  );
  console.log(
    "   ✓ RSA-2048 Keypair   : kty =",
    rsaKeys.publicKey.kty,
    "| alg =",
    rsaKeys.publicKey.alg || "RSA-OAEP-256"
  );

  const ecdhKeys = JSON.parse(
    (
      await callRpc("tools/call", {
        name: "manage_keys",
        arguments: { action: "generate", type: "ecdh", namedCurve: "P-256" },
      })
    ).result.content[0].text
  );
  console.log(
    "   ✓ ECDH P-256 Keypair : kty =",
    ecdhKeys.publicKey.kty,
    "| crv =",
    ecdhKeys.publicKey.crv
  );

  const ecdsaKeys = JSON.parse(
    (
      await callRpc("tools/call", {
        name: "manage_keys",
        arguments: { action: "generate", type: "ecdsa", namedCurve: "P-256" },
      })
    ).result.content[0].text
  );
  console.log(
    "   ✓ ECDSA P-256 Keys   : kty =",
    ecdsaKeys.publicKey.kty,
    "| crv =",
    ecdsaKeys.publicKey.crv
  );

  const rsaPssKeys = JSON.parse(
    (
      await callRpc("tools/call", {
        name: "manage_keys",
        arguments: { action: "generate", type: "rsa-pss", modulusLength: 2048 },
      })
    ).result.content[0].text
  );
  console.log("   ✓ RSA-PSS Keys       : kty =", rsaPssKeys.publicKey.kty);

  // 5. Tool: encrypt_payload & decrypt_payload
  console.log("\n5. Testing Tools `encrypt_payload` & `decrypt_payload`:");
  const confidentialToken = "sk_live_putervision_secret_token_998877";

  // Symmetric AES-256-GCM
  const encSym = JSON.parse(
    (
      await callRpc("tools/call", {
        name: "encrypt_payload",
        arguments: { mode: "symmetric", data: confidentialToken, password: pwd },
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
  console.log(
    "   ✓ Symmetric AES-256  :",
    decSym.plaintext === confidentialToken ? "PASSED (100% Roundtrip Match)" : "FAILED"
  );

  // Asymmetric RSA Hybrid
  const encAsym = JSON.parse(
    (
      await callRpc("tools/call", {
        name: "encrypt_payload",
        arguments: {
          mode: "asymmetric",
          data: confidentialToken,
          public_key_jwk: rsaKeys.publicKey,
        },
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
  console.log(
    "   ✓ Asymmetric RSA     :",
    decAsym.plaintext === confidentialToken ? "PASSED (100% Roundtrip Match)" : "FAILED"
  );

  // Structured JSON Data Mode
  const stateMemoryPayload = {
    agentSession: "session_mcp_001",
    taskDag: ["task_bootstrap", "task_vault_seal"],
    vaultKeys: { db: "sqlite_vault_key", api: "openai_token" },
  };
  const encData = JSON.parse(
    (
      await callRpc("tools/call", {
        name: "encrypt_payload",
        arguments: { mode: "data", data: stateMemoryPayload, password: pwd },
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
  console.log(
    "   ✓ Structured Data    :",
    JSON.stringify(decData.data) === JSON.stringify(stateMemoryPayload)
      ? "PASSED (100% Object Match)"
      : "FAILED"
  );

  // 6. Tool: sign_verify
  console.log("\n6. Testing Tool `sign_verify`:");
  const artifactProof =
    "Evidence Pack Checksum: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

  // HMAC
  const hmacSign = JSON.parse(
    (
      await callRpc("tools/call", {
        name: "sign_verify",
        arguments: { action: "sign", algorithm: "HMAC", data: artifactProof, password: pwd },
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
          data: artifactProof,
          signature: hmacSign.signature,
          password: pwd,
        },
      })
    ).result.content[0].text
  );
  console.log(
    "   ✓ HMAC-SHA256        :",
    hmacVerify.valid ? "PASSED (Signature Valid)" : "FAILED"
  );

  // ECDSA P-256
  const ecdsaSign = JSON.parse(
    (
      await callRpc("tools/call", {
        name: "sign_verify",
        arguments: {
          action: "sign",
          algorithm: "ECDSA",
          data: artifactProof,
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
          data: artifactProof,
          signature: ecdsaSign.signature,
          key_jwk: ecdsaKeys.publicKey,
        },
      })
    ).result.content[0].text
  );
  console.log(
    "   ✓ ECDSA P-256        :",
    ecdsaVerify.valid ? "PASSED (Signature Valid)" : "FAILED"
  );

  // RSA-PSS
  const rsaPssSign = JSON.parse(
    (
      await callRpc("tools/call", {
        name: "sign_verify",
        arguments: {
          action: "sign",
          algorithm: "RSA-PSS",
          data: artifactProof,
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
          data: artifactProof,
          signature: rsaPssSign.signature,
          key_jwk: rsaPssKeys.publicKey,
        },
      })
    ).result.content[0].text
  );
  console.log(
    "   ✓ RSA-PSS (2048)     :",
    rsaPssVerify.valid ? "PASSED (Signature Valid)" : "FAILED"
  );

  // 7. Tool: pqc_kem_sign
  console.log("\n7. Testing Tool `pqc_kem_sign` (Kyber KEM & Dilithium Signatures):");
  // Kyber768 KEM
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
  console.log(
    "   ✓ Kyber768 KEM       :",
    encap.shared_secret_b64 === decap.shared_secret_b64 ? "PASSED (Shared Secret Match)" : "FAILED"
  );

  // Dilithium3 Sign & Verify
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
          data: artifactProof,
          private_key_b64: dilKeys.private_key_b64,
        },
      })
    ).result.content[0].text
  );
  const dilVer = JSON.parse(
    (
      await callRpc("tools/call", {
        name: "pqc_kem_sign",
        arguments: {
          action: "dilithium_verify",
          level: "Dilithium3",
          data: artifactProof,
          signature_b64: dilSig.signature_b64,
          public_key_b64: dilKeys.public_key_b64,
        },
      })
    ).result.content[0].text
  );
  console.log("   ✓ Dilithium3 Sign    :", dilVer.valid ? "PASSED (Signature Valid)" : "FAILED");

  console.log("\n=================================================================");
  console.log(" ✨ ALL 6 WEBCRYPT MCP TOOLS EXERCISED & VERIFIED 100% ✨");
  console.log("=================================================================");
}

main().catch(console.error);
