// src/mcp/handlers.js
// Tool execution handlers for WebCrypt MCP Server

import { WebCrypt } from "../WebCrypt.js";
import { WebCryptAsym } from "../WebCryptAsym.js";
import { WebCryptPQC } from "../WebCryptPQC.js";
import { arrayBufferToBase64, base64ToArrayBuffer, base64ToUint8Array } from "../_base64.js";
import { getCrypto } from "../_crypto.js";

let _wc, _asym, _pqc;
function getWC() {
  return _wc || (_wc = new WebCrypt());
}
function getAsym() {
  return _asym || (_asym = new WebCryptAsym());
}
function getPQC() {
  if (!_pqc) {
    _pqc = new WebCryptPQC();
    WebCryptPQC.enableStubTesting(true);
  }
  return _pqc;
}

export async function handleToolCall(name, args = {}) {
  switch (name) {
    case "encrypt_payload": {
      const mode = args.mode || "symmetric";
      if (mode === "symmetric") {
        if (!args.password)
          throw new Error("Missing 'password' parameter for symmetric encryption");
        const plaintext = typeof args.data === "string" ? args.data : JSON.stringify(args.data);
        const ciphertext = await getWC().encryptText(plaintext, args.password);
        return { ciphertext, mode: "symmetric" };
      } else if (mode === "data") {
        if (!args.password) throw new Error("Missing 'password' parameter for data encryption");
        const ciphertext = await getWC().encryptData(args.data, args.password);
        return { ciphertext, mode: "data" };
      } else if (mode === "asymmetric") {
        if (!args.public_key_jwk)
          throw new Error("Missing 'public_key_jwk' parameter for asymmetric encryption");
        const crypto = getCrypto();
        const publicKey = await crypto.subtle.importKey(
          "jwk",
          args.public_key_jwk,
          WebCryptAsym.RSA_ALGORITHM,
          true,
          ["encrypt"]
        );
        const plaintext = typeof args.data === "string" ? args.data : JSON.stringify(args.data);
        const ciphertext = await getAsym().encryptText(plaintext, publicKey);
        return { ciphertext, mode: "asymmetric" };
      }
      throw new Error(`Unsupported mode: ${mode}`);
    }

    case "decrypt_payload": {
      const mode = args.mode || "symmetric";
      if (!args.ciphertext) throw new Error("Missing 'ciphertext' parameter");

      if (mode === "symmetric") {
        if (!args.password)
          throw new Error("Missing 'password' parameter for symmetric decryption");
        const decrypted = await getWC().decryptText(args.ciphertext, args.password);
        return { data: decrypted, plaintext: decrypted, mode: "symmetric" };
      } else if (mode === "data") {
        if (!args.password) throw new Error("Missing 'password' parameter for data decryption");
        const decrypted = await getWC().decryptData(args.ciphertext, args.password);
        return { data: decrypted, mode: "data" };
      } else if (mode === "asymmetric") {
        if (!args.private_key_jwk)
          throw new Error("Missing 'private_key_jwk' parameter for asymmetric decryption");
        const crypto = getCrypto();
        const privateKey = await crypto.subtle.importKey(
          "jwk",
          args.private_key_jwk,
          WebCryptAsym.RSA_ALGORITHM,
          true,
          ["decrypt"]
        );
        const decrypted = await getAsym().decryptText(args.ciphertext, privateKey);
        return { data: decrypted, plaintext: decrypted, mode: "asymmetric" };
      }
      throw new Error(`Unsupported mode: ${mode}`);
    }

    case "manage_keys": {
      const action = args.action;
      if (action === "generate_random_password") {
        const password = getWC().generateRandomPassword(args.length || 32);
        return { password, length: args.length || 32 };
      } else if (action === "generate") {
        const type = args.type || "rsa";
        const crypto = getCrypto();
        if (type === "rsa") {
          const modulusLength = args.modulusLength || 4096;
          const keyPair = await getAsym().generateKeyPair(modulusLength);
          const publicKeyJwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
          const privateKeyJwk = await crypto.subtle.exportKey("jwk", keyPair.privateKey);
          return { type: "rsa", modulusLength, publicKey: publicKeyJwk, privateKey: privateKeyJwk };
        } else if (type === "ecdh") {
          const namedCurve = args.namedCurve || "P-256";
          const keyPair = await getAsym().generateECDHKeyPair(namedCurve);
          const publicKeyJwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
          const privateKeyJwk = await crypto.subtle.exportKey("jwk", keyPair.privateKey);
          return { type: "ecdh", namedCurve, publicKey: publicKeyJwk, privateKey: privateKeyJwk };
        } else if (type === "ecdsa") {
          const namedCurve = args.namedCurve || "P-256";
          const keyPair = await getAsym().generateSigningKeyPair(namedCurve);
          const publicKeyJwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
          const privateKeyJwk = await crypto.subtle.exportKey("jwk", keyPair.privateKey);
          return { type: "ecdsa", namedCurve, publicKey: publicKeyJwk, privateKey: privateKeyJwk };
        } else if (type === "rsa-pss") {
          const modulusLength = args.modulusLength || 2048;
          const keyPair = await crypto.subtle.generateKey(
            {
              name: "RSA-PSS",
              modulusLength,
              publicExponent: new Uint8Array([1, 0, 1]),
              hash: "SHA-256",
            },
            true,
            ["sign", "verify"]
          );
          const publicKeyJwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
          const privateKeyJwk = await crypto.subtle.exportKey("jwk", keyPair.privateKey);
          return {
            type: "rsa-pss",
            modulusLength,
            publicKey: publicKeyJwk,
            privateKey: privateKeyJwk,
          };
        } else if (type === "hmac") {
          const rawBytes = crypto.getRandomValues(new Uint8Array(args.length || 32));
          return { type: "hmac", key_b64: arrayBufferToBase64(rawBytes) };
        }
        throw new Error(`Unsupported key type: ${type}`);
      }
      throw new Error(`Unsupported action: ${action}`);
    }

    case "crypto_hash": {
      if (!args.data) throw new Error("Missing 'data' parameter");
      const algo = args.algorithm || "SHA-256";
      const encoding = args.encoding || "hex";
      const crypto = getCrypto();
      const inputBytes = new TextEncoder().encode(args.data);

      let digestBytes;
      if (algo.startsWith("SHA3-")) {
        const bitLength = parseInt(algo.replace("SHA3-", ""), 10) || 256;
        digestBytes = await getPQC()._sha3Hash(inputBytes, bitLength);
      } else {
        const buffer = await crypto.subtle.digest(algo, inputBytes);
        digestBytes = new Uint8Array(buffer);
      }

      let digest;
      if (encoding === "hex") {
        digest = Array.from(digestBytes, b => b.toString(16).padStart(2, "0")).join("");
      } else {
        digest = arrayBufferToBase64(digestBytes);
      }

      return { algorithm: algo, encoding, digest };
    }

    case "sign_verify": {
      const action = args.action;
      const algo = args.algorithm || "ECDSA";
      const data = args.data;
      if (!data) throw new Error("Missing 'data' parameter");

      if (action === "sign") {
        if (algo === "HMAC") {
          if (!args.password) throw new Error("Missing 'password' for HMAC");
          const key = await getWC().generateHmacKey(args.password);
          const tag = await getWC().computeHmac(data, key);
          return { algorithm: algo, signature: tag };
        } else if (algo === "HMAC-SHA3") {
          if (!args.password) throw new Error("Missing 'password' for HMAC-SHA3");
          const key = await getWC().generateHmacKeySHA3(args.password);
          const tag = await getWC().computeHmacSHA3(data, key);
          return { algorithm: algo, signature: tag };
        } else if (algo === "ECDSA" || algo === "RSA-PSS") {
          if (!args.key_jwk) throw new Error(`Missing 'key_jwk' for ${algo} signing`);
          const crypto = getCrypto();
          const importParams =
            algo === "ECDSA"
              ? { name: "ECDSA", namedCurve: args.key_jwk.crv || "P-256" }
              : { name: "RSA-PSS", hash: "SHA-256" };
          const privateKey = await crypto.subtle.importKey(
            "jwk",
            args.key_jwk,
            importParams,
            false,
            ["sign"]
          );
          const sig = await getAsym().signTextWithAlgorithm(data, privateKey, algo);
          return { algorithm: algo, signature: sig };
        }
        throw new Error(`Unsupported sign algorithm: ${algo}`);
      } else if (action === "verify") {
        if (!args.signature) throw new Error("Missing 'signature' parameter to verify");
        if (algo === "HMAC") {
          if (!args.password) throw new Error("Missing 'password' for HMAC");
          const key = await getWC().generateHmacKey(args.password);
          const valid = await getWC().verifyHmac(data, args.signature, key);
          return { algorithm: algo, valid };
        } else if (algo === "HMAC-SHA3") {
          if (!args.password) throw new Error("Missing 'password' for HMAC-SHA3");
          const key = await getWC().generateHmacKeySHA3(args.password);
          const valid = await getWC().verifyHmacSHA3(data, args.signature, key);
          return { algorithm: algo, valid };
        } else if (algo === "ECDSA" || algo === "RSA-PSS") {
          if (!args.key_jwk) throw new Error(`Missing 'key_jwk' for ${algo} verification`);
          const crypto = getCrypto();
          const importParams =
            algo === "ECDSA"
              ? { name: "ECDSA", namedCurve: args.key_jwk.crv || "P-256" }
              : { name: "RSA-PSS", hash: "SHA-256" };
          const publicKey = await crypto.subtle.importKey(
            "jwk",
            args.key_jwk,
            importParams,
            false,
            ["verify"]
          );
          const valid = await getAsym().verifyTextWithAlgorithm(
            data,
            args.signature,
            publicKey,
            algo
          );
          return { algorithm: algo, valid };
        }
        throw new Error(`Unsupported verify algorithm: ${algo}`);
      }
      throw new Error(`Unsupported action: ${action}`);
    }

    case "pqc_kem_sign": {
      const action = args.action;
      const level = args.level || "Kyber768";
      const pqcInst = getPQC();

      if (action === "generate_kyber_keypair") {
        const keyPair = await pqcInst.generateKyberKeyPair(level);
        const pubB64 = pqcInst.kyberPublicKeyToBase64(keyPair.publicKey);
        const privB64 = pqcInst.kyberPrivateKeyToBase64(keyPair.privateKey);
        return {
          algorithm: "Kyber",
          level,
          public_key_b64: pubB64,
          private_key_b64: privB64,
          publicKey_b64: pubB64,
          privateKey_b64: privB64,
        };
      } else if (action === "kyber_encapsulate") {
        const pubKeyB64 = args.public_key_b64 || args.publicKey_b64;
        if (!pubKeyB64) throw new Error("Missing 'public_key_b64'");
        const pubKey = pqcInst.kyberPublicKeyFromBase64(pubKeyB64);
        const { ciphertext, sharedSecret } = await pqcInst.kyberEncapsulate(pubKey, level);
        const ctB64 = arrayBufferToBase64(ciphertext);
        const ssB64 = arrayBufferToBase64(sharedSecret);
        return {
          level,
          ciphertext_b64: ctB64,
          shared_secret_b64: ssB64,
          ciphertextB64: ctB64,
          sharedSecret_b64: ssB64,
          sharedSecretB64: ssB64,
        };
      } else if (action === "kyber_decapsulate") {
        const ctB64 = args.ciphertext_b64 || args.ciphertextB64;
        const privKeyB64 = args.private_key_b64 || args.privateKey_b64;
        if (!ctB64 || !privKeyB64) {
          throw new Error("Missing 'ciphertext_b64' or 'private_key_b64'");
        }
        const ciphertext = base64ToUint8Array(ctB64);
        const privKey = pqcInst.kyberPrivateKeyFromBase64(privKeyB64);
        const sharedSecret = await pqcInst.kyberDecapsulate(ciphertext, privKey, level);
        const ssB64 = arrayBufferToBase64(sharedSecret);
        return {
          level,
          shared_secret_b64: ssB64,
          sharedSecret_b64: ssB64,
          sharedSecretB64: ssB64,
        };
      } else if (action === "hybrid_encapsulate") {
        const pubKeyB64 = args.public_key_b64 || args.publicKey_b64;
        const rsaPubKeyJwk = args.rsa_public_key_jwk || args.rsaPublicKeyJwk;
        if (!rsaPubKeyJwk || !pubKeyB64) {
          throw new Error("Missing 'rsa_public_key_jwk' or 'public_key_b64'");
        }
        const crypto = getCrypto();
        const rsaPubKey = await crypto.subtle.importKey(
          "jwk",
          rsaPubKeyJwk,
          WebCryptAsym.RSA_ALGORITHM,
          true,
          ["encrypt"]
        );
        const kyberPubKey = pqcInst.kyberPublicKeyFromBase64(pubKeyB64);
        const result = await pqcInst.hybridEncapsulate(rsaPubKey, kyberPubKey, level);
        const ssB64 = arrayBufferToBase64(result.sharedSecret);
        const ctB64 = arrayBufferToBase64(result.kyberCiphertext);
        const rsaWrappedB64 = arrayBufferToBase64(result.rsaWrappedSharedSecret);
        return {
          level,
          shared_secret_b64: ssB64,
          sharedSecret_b64: ssB64,
          kyber_ciphertext_b64: ctB64,
          kyberCiphertext_b64: ctB64,
          rsa_wrapped_secret_b64: rsaWrappedB64,
          rsaWrappedSecret_b64: rsaWrappedB64,
        };
      } else if (action === "hybrid_decapsulate") {
        const rsaPrivKeyJwk = args.rsa_private_key_jwk || args.rsaPrivateKeyJwk;
        const privKeyB64 = args.private_key_b64 || args.privateKey_b64;
        const kyberCtB64 = args.kyber_ciphertext_b64 || args.kyberCiphertext_b64;
        const rsaWrappedB64 = args.rsa_wrapped_secret_b64 || args.rsaWrappedSecret_b64;
        if (!rsaPrivKeyJwk || !privKeyB64 || !kyberCtB64 || !rsaWrappedB64) {
          throw new Error("Missing required parameters for hybrid_decapsulate");
        }
        const crypto = getCrypto();
        const rsaPrivKey = await crypto.subtle.importKey(
          "jwk",
          rsaPrivKeyJwk,
          WebCryptAsym.RSA_ALGORITHM,
          true,
          ["decrypt"]
        );
        const kyberPrivKey = pqcInst.kyberPrivateKeyFromBase64(privKeyB64);
        const kyberCiphertext = base64ToUint8Array(kyberCtB64);
        const rsaWrappedSecret = base64ToUint8Array(rsaWrappedB64);

        const sharedSecret = await pqcInst.hybridDecapsulate(
          kyberCiphertext,
          rsaWrappedSecret,
          rsaPrivKey,
          kyberPrivKey,
          level
        );
        const ssB64 = arrayBufferToBase64(sharedSecret);
        return {
          level,
          shared_secret_b64: ssB64,
          sharedSecret_b64: ssB64,
        };
      } else if (action === "generate_dilithium_keypair") {
        const dilithiumLevel = args.level || "Dilithium3";
        const keyPair = await pqcInst.generateDilithiumKeyPair(dilithiumLevel);
        const pubB64 = pqcInst.dilithiumPublicKeyToBase64(keyPair.publicKey);
        const privB64 = pqcInst.dilithiumPrivateKeyToBase64(keyPair.privateKey);
        return {
          algorithm: "Dilithium",
          level: dilithiumLevel,
          public_key_b64: pubB64,
          private_key_b64: privB64,
          publicKey_b64: pubB64,
          privateKey_b64: privB64,
        };
      } else if (action === "dilithium_sign") {
        const privKeyB64 = args.private_key_b64 || args.privateKey_b64;
        if (!args.data || !privKeyB64) {
          throw new Error("Missing 'data' or 'private_key_b64'");
        }
        const privKey = pqcInst.dilithiumPrivateKeyFromBase64(privKeyB64);
        const sig = await pqcInst.dilithiumSign(args.data, privKey, args.level || "Dilithium3");
        const sigB64 = arrayBufferToBase64(sig);
        return {
          algorithm: "Dilithium",
          level: args.level || "Dilithium3",
          signature_b64: sigB64,
          signatureB64: sigB64,
        };
      } else if (action === "dilithium_verify") {
        const pubKeyB64 = args.public_key_b64 || args.publicKey_b64;
        const sigB64 = args.signature_b64 || args.signatureB64;
        if (!args.data || !sigB64 || !pubKeyB64) {
          throw new Error("Missing 'data', 'signature_b64', or 'public_key_b64'");
        }
        const pubKey = pqcInst.dilithiumPublicKeyFromBase64(pubKeyB64);
        const sig = base64ToUint8Array(sigB64);
        const valid = await pqcInst.dilithiumVerify(
          args.data,
          sig,
          pubKey,
          args.level || "Dilithium3"
        );
        return {
          algorithm: "Dilithium",
          valid,
        };
      }
      throw new Error(`Unsupported PQC action: ${action}`);
    }

    default:
      throw new Error(`Unknown tool: ${name}`);
  }
}
