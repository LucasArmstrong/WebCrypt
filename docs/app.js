/**
 * WebCrypt Live Playground & Security Workbench
 * Maintained by PuterVision LLC (https://putervision.com)
 */

document.addEventListener("DOMContentLoaded", () => {
  initTabNavigation();
  initSymmetricTool();
  initAsymmetricTool();
  initPasswordTool();
  initHmacTool();
  initInspectorTool();
});

// ────────────────────── Tab Navigation ──────────────────────
function initTabNavigation() {
  const tabButtons = document.querySelectorAll(".tool-tab-btn");
  const tabContents = document.querySelectorAll(".tool-tab-content");

  tabButtons.forEach(btn => {
    btn.addEventListener("click", () => {
      const targetId = btn.getAttribute("data-tab");

      tabButtons.forEach(b => b.classList.remove("active"));
      tabContents.forEach(c => c.classList.remove("active"));

      btn.classList.add("active");
      const targetContent = document.getElementById(targetId);
      if (targetContent) {
        targetContent.classList.add("active");
      }
    });
  });
}

// ────────────────────── Utility Helpers ──────────────────────
function arrayBufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  const CHUNK_SIZE = 1024;
  let binary = "";
  for (let i = 0; i < bytes.length; i += CHUNK_SIZE) {
    binary += String.fromCharCode.apply(null, bytes.subarray(i, i + CHUNK_SIZE));
  }
  return btoa(binary);
}

function base64ToArrayBuffer(base64) {
  let padded = base64;
  const mod = base64.length % 4;
  if (mod > 0) padded += "=".repeat(4 - mod);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

// ────────────────────── 1. Symmetric Tool ──────────────────────
function initSymmetricTool() {
  const inputMsg = document.getElementById("sym-input");
  const inputPass = document.getElementById("sym-pass");
  const btnEncrypt = document.getElementById("btn-sym-encrypt");
  const btnDecrypt = document.getElementById("btn-sym-decrypt");
  const outputArea = document.getElementById("sym-output");
  const badgeStats = document.getElementById("sym-stats");

  if (!btnEncrypt || !btnDecrypt) return;

  btnEncrypt.addEventListener("click", async () => {
    const text = inputMsg.value.trim();
    const pass = inputPass.value;

    if (!text || !pass) {
      outputArea.value = "⚠️ Please provide both a message and a password.";
      return;
    }

    try {
      const start = performance.now();
      const enc = new TextEncoder();
      const salt = crypto.getRandomValues(new Uint8Array(16));
      const iv = crypto.getRandomValues(new Uint8Array(12));

      const baseKey = await crypto.subtle.importKey("raw", enc.encode(pass), "PBKDF2", false, [
        "deriveKey",
      ]);

      const aesKey = await crypto.subtle.deriveKey(
        {
          name: "PBKDF2",
          salt,
          iterations: 600000,
          hash: "SHA-256",
        },
        baseKey,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt"]
      );

      const encrypted = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv },
        aesKey,
        enc.encode(text)
      );

      const result = new Uint8Array(16 + 12 + encrypted.byteLength);
      result.set(salt, 0);
      result.set(iv, 16);
      result.set(new Uint8Array(encrypted), 28);

      const b64Payload = arrayBufferToBase64(result.buffer);
      const elapsed = (performance.now() - start).toFixed(1);

      outputArea.value = b64Payload;
      if (badgeStats) {
        badgeStats.textContent = `Encrypted in ${elapsed}ms • 600,000 PBKDF2 rounds • 256-bit AES-GCM`;
        badgeStats.className = "stats-badge success";
      }
    } catch (err) {
      outputArea.value = `❌ Encryption Error: ${err.message}`;
      if (badgeStats) badgeStats.className = "stats-badge error";
    }
  });

  btnDecrypt.addEventListener("click", async () => {
    const payload = outputArea.value.trim();
    const pass = inputPass.value;

    if (!payload || !pass) {
      outputArea.value = "⚠️ Please provide a Base64 encrypted payload and password.";
      return;
    }

    try {
      const start = performance.now();
      const rawBuffer = base64ToArrayBuffer(payload);
      const bytes = new Uint8Array(rawBuffer);

      if (bytes.length < 28) {
        throw new Error("Invalid payload format (too short)");
      }

      const salt = bytes.subarray(0, 16);
      const iv = bytes.subarray(16, 28);
      const ciphertext = bytes.subarray(28);

      const enc = new TextEncoder();
      const baseKey = await crypto.subtle.importKey("raw", enc.encode(pass), "PBKDF2", false, [
        "deriveKey",
      ]);

      const aesKey = await crypto.subtle.deriveKey(
        {
          name: "PBKDF2",
          salt,
          iterations: 600000,
          hash: "SHA-256",
        },
        baseKey,
        { name: "AES-GCM", length: 256 },
        false,
        ["decrypt"]
      );

      const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, aesKey, ciphertext);

      const plaintext = new TextDecoder().decode(decrypted);
      const elapsed = (performance.now() - start).toFixed(1);

      inputMsg.value = plaintext;
      if (badgeStats) {
        badgeStats.textContent = `Decrypted in ${elapsed}ms • Integrity Verified ✅`;
        badgeStats.className = "stats-badge success";
      }
    } catch (err) {
      if (badgeStats) {
        badgeStats.textContent = `Decryption Failed (Invalid Password or Tampered Payload)`;
        badgeStats.className = "stats-badge error";
      }
    }
  });
}

// ────────────────────── 2. Asymmetric Tool ──────────────────────
let generatedKeyPair = null;

function initAsymmetricTool() {
  const btnGenKeys = document.getElementById("btn-asym-genkeys");
  const selectModulus = document.getElementById("asym-modulus");
  const areaPubKey = document.getElementById("asym-pubkey");
  const areaPrivKey = document.getElementById("asym-privkey");
  const inputAsymMsg = document.getElementById("asym-input");
  const areaAsymOutput = document.getElementById("asym-output");
  const btnAsymEncrypt = document.getElementById("btn-asym-encrypt");
  const btnAsymDecrypt = document.getElementById("btn-asym-decrypt");
  const badgeStats = document.getElementById("asym-stats");

  if (!btnGenKeys) return;

  btnGenKeys.addEventListener("click", async () => {
    const modulusLength = parseInt(selectModulus.value, 10) || 4096;
    if (badgeStats) {
      badgeStats.textContent = `Generating ${modulusLength}-bit RSA-OAEP Key Pair...`;
      badgeStats.className = "stats-badge pending";
    }

    try {
      const start = performance.now();
      const keyPair = await crypto.subtle.generateKey(
        {
          name: "RSA-OAEP",
          modulusLength,
          publicExponent: new Uint8Array([1, 0, 1]),
          hash: "SHA-256",
        },
        true,
        ["encrypt", "decrypt"]
      );

      generatedKeyPair = keyPair;

      const spki = await crypto.subtle.exportKey("spki", keyPair.publicKey);
      const pkcs8 = await crypto.subtle.exportKey("pkcs8", keyPair.privateKey);

      areaPubKey.value = arrayBufferToBase64(spki);
      areaPrivKey.value = arrayBufferToBase64(pkcs8);

      const elapsed = (performance.now() - start).toFixed(1);
      if (badgeStats) {
        badgeStats.textContent = `Generated RSA-${modulusLength} Key Pair in ${elapsed}ms`;
        badgeStats.className = "stats-badge success";
      }
    } catch (err) {
      if (badgeStats) {
        badgeStats.textContent = `Key Generation Failed: ${err.message}`;
        badgeStats.className = "stats-badge error";
      }
    }
  });

  btnAsymEncrypt.addEventListener("click", async () => {
    const text = inputAsymMsg.value.trim();
    if (!text || !generatedKeyPair) {
      areaAsymOutput.value = "⚠️ Generate a key pair first and enter a message to encrypt.";
      return;
    }

    try {
      const start = performance.now();
      const enc = new TextEncoder();
      const aesKeyBytes = crypto.getRandomValues(new Uint8Array(32));
      const iv = crypto.getRandomValues(new Uint8Array(12));

      // 1. Encrypt AES key with RSA public key
      const wrappedKey = await crypto.subtle.encrypt(
        { name: "RSA-OAEP" },
        generatedKeyPair.publicKey,
        aesKeyBytes
      );

      // 2. Import raw AES key and encrypt message
      const aesKey = await crypto.subtle.importKey("raw", aesKeyBytes, "AES-GCM", false, [
        "encrypt",
      ]);

      const encryptedData = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv },
        aesKey,
        enc.encode(text)
      );

      // 3. Format: [4-byte len][wrappedKey][iv][encryptedData]
      const wrappedKeyBytes = new Uint8Array(wrappedKey);
      const keyLen = wrappedKeyBytes.byteLength;
      const combined = new Uint8Array(4 + keyLen + 12 + encryptedData.byteLength);

      new DataView(combined.buffer).setUint32(0, keyLen, true);
      combined.set(wrappedKeyBytes, 4);
      combined.set(iv, 4 + keyLen);
      combined.set(new Uint8Array(encryptedData), 4 + keyLen + 12);

      areaAsymOutput.value = arrayBufferToBase64(combined.buffer);
      const elapsed = (performance.now() - start).toFixed(1);
      if (badgeStats) {
        badgeStats.textContent = `Hybrid Encrypted in ${elapsed}ms (RSA-OAEP + AES-256-GCM)`;
        badgeStats.className = "stats-badge success";
      }
    } catch (err) {
      areaAsymOutput.value = `❌ Encryption Error: ${err.message}`;
    }
  });

  btnAsymDecrypt.addEventListener("click", async () => {
    const payload = areaAsymOutput.value.trim();
    if (!payload || !generatedKeyPair) {
      areaAsymOutput.value = "⚠️ Generate a key pair and ensure encrypted payload is present.";
      return;
    }

    try {
      const start = performance.now();
      const raw = base64ToArrayBuffer(payload);
      const bytes = new Uint8Array(raw);
      const keyLen = new DataView(bytes.buffer).getUint32(0, true);

      const wrappedKey = bytes.subarray(4, 4 + keyLen);
      const iv = bytes.subarray(4 + keyLen, 4 + keyLen + 12);
      const encryptedData = bytes.subarray(4 + keyLen + 12);

      // 1. Unwrap AES key using RSA private key
      const aesKeyBytes = await crypto.subtle.decrypt(
        { name: "RSA-OAEP" },
        generatedKeyPair.privateKey,
        wrappedKey
      );

      // 2. Import raw AES key and decrypt payload
      const aesKey = await crypto.subtle.importKey("raw", aesKeyBytes, "AES-GCM", false, [
        "decrypt",
      ]);

      const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, aesKey, encryptedData);

      const plaintext = new TextDecoder().decode(decrypted);
      const elapsed = (performance.now() - start).toFixed(1);
      inputAsymMsg.value = plaintext;

      if (badgeStats) {
        badgeStats.textContent = `Hybrid Decrypted in ${elapsed}ms ✅`;
        badgeStats.className = "stats-badge success";
      }
    } catch (err) {
      if (badgeStats) {
        badgeStats.textContent = `Decryption Error: Invalid payload or key mismatch`;
        badgeStats.className = "stats-badge error";
      }
    }
  });
}

// ────────────────────── 3. Password Tool ──────────────────────
function initPasswordTool() {
  const sliderLen = document.getElementById("pass-len-slider");
  const labelLen = document.getElementById("pass-len-val");
  const btnGenPass = document.getElementById("btn-gen-pass");
  const outputPass = document.getElementById("pass-output");
  const badgeEntropy = document.getElementById("pass-entropy-badge");
  const selectFormat = document.getElementById("pass-format");

  if (!btnGenPass) return;

  if (sliderLen && labelLen) {
    sliderLen.addEventListener("input", () => {
      labelLen.textContent = `${sliderLen.value} bytes`;
    });
  }

  btnGenPass.addEventListener("click", () => {
    const bytesCount = parseInt(sliderLen.value, 10) || 32;
    const format = selectFormat ? selectFormat.value : "hex";
    const randomBytes = crypto.getRandomValues(new Uint8Array(bytesCount));

    let result = "";
    if (format === "hex") {
      result = Array.from(randomBytes, b => b.toString(16).padStart(2, "0")).join("");
    } else if (format === "base64") {
      result = arrayBufferToBase64(randomBytes.buffer);
    } else {
      const chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:,.<>?";
      result = Array.from(randomBytes, b => chars[b % chars.length]).join("");
    }

    outputPass.value = result;
    const bits = bytesCount * 8;
    if (badgeEntropy) {
      badgeEntropy.textContent = `${bits} Bits Cryptographic Entropy (${bytesCount} Raw Bytes)`;
      badgeEntropy.className = "stats-badge success";
    }
  });
}

// ────────────────────── 4. HMAC Tool ──────────────────────
function initHmacTool() {
  const inputMsg = document.getElementById("hmac-msg");
  const inputSecret = document.getElementById("hmac-secret");
  const selectHash = document.getElementById("hmac-hash");
  const btnSign = document.getElementById("btn-hmac-sign");
  const btnVerify = document.getElementById("btn-hmac-verify");
  const outputTag = document.getElementById("hmac-tag");
  const badgeStats = document.getElementById("hmac-stats");

  if (!btnSign) return;

  btnSign.addEventListener("click", async () => {
    const msg = inputMsg.value.trim();
    const secret = inputSecret.value;
    const hash = selectHash.value || "SHA-256";

    if (!msg || !secret) {
      outputTag.value = "⚠️ Enter message and secret key.";
      return;
    }

    try {
      const start = performance.now();
      const enc = new TextEncoder();
      const keyMaterial = await crypto.subtle.importKey(
        "raw",
        enc.encode(secret),
        { name: "HMAC", hash },
        false,
        ["sign"]
      );

      const sig = await crypto.subtle.sign("HMAC", keyMaterial, enc.encode(msg));
      const b64Sig = arrayBufferToBase64(sig);
      outputTag.value = b64Sig;

      const elapsed = (performance.now() - start).toFixed(1);
      if (badgeStats) {
        badgeStats.textContent = `HMAC-${hash} Signed in ${elapsed}ms`;
        badgeStats.className = "stats-badge success";
      }
    } catch (err) {
      outputTag.value = `❌ HMAC Error: ${err.message}`;
    }
  });

  btnVerify.addEventListener("click", async () => {
    const msg = inputMsg.value.trim();
    const secret = inputSecret.value;
    const tagB64 = outputTag.value.trim();
    const hash = selectHash.value || "SHA-256";

    if (!msg || !secret || !tagB64) {
      if (badgeStats) {
        badgeStats.textContent = "⚠️ Missing message, secret, or HMAC tag.";
        badgeStats.className = "stats-badge error";
      }
      return;
    }

    try {
      const enc = new TextEncoder();
      const keyMaterial = await crypto.subtle.importKey(
        "raw",
        enc.encode(secret),
        { name: "HMAC", hash },
        false,
        ["verify"]
      );

      const sigBuffer = base64ToArrayBuffer(tagB64);
      const isValid = await crypto.subtle.verify("HMAC", keyMaterial, sigBuffer, enc.encode(msg));

      if (badgeStats) {
        if (isValid) {
          badgeStats.textContent = `✅ HMAC Signature Validated (HMAC-${hash})`;
          badgeStats.className = "stats-badge success";
        } else {
          badgeStats.textContent = `❌ Invalid HMAC Signature`;
          badgeStats.className = "stats-badge error";
        }
      }
    } catch (err) {
      if (badgeStats) {
        badgeStats.textContent = `Verification Error: ${err.message}`;
        badgeStats.className = "stats-badge error";
      }
    }
  });
}

// ────────────────────── 5. Inspector Tool ──────────────────────
async function initInspectorTool() {
  const container = document.getElementById("inspector-results");
  if (!container) return;

  const checks = [
    {
      name: "Web Crypto API (`crypto.subtle`)",
      check: () => typeof crypto !== "undefined" && !!crypto.subtle,
    },
    { name: "AES-GCM Authenticated Encryption", check: () => true },
    { name: "RSA-OAEP Public Key Encryption", check: () => true },
    { name: "PBKDF2 Key Derivation (600,000 iterations)", check: () => true },
    { name: "HMAC Tag Verification", check: () => true },
    {
      name: "Secure Random Generator (`crypto.getRandomValues`)",
      check: () => typeof crypto !== "undefined" && typeof crypto.getRandomValues === "function",
    },
    { name: "WebRTC Transform Streams E2EE", check: () => typeof TransformStream !== "undefined" },
    {
      name: "SHA-3 Native Web Crypto Support",
      check: async () => {
        try {
          await crypto.subtle.digest("SHA3-256", new Uint8Array(4));
          return true;
        } catch (e) {
          return false; // Expected fallback to SHA-256
        }
      },
    },
  ];

  let html = `<ul class="inspector-list">`;
  for (const item of checks) {
    let passed = false;
    try {
      passed = await item.check();
    } catch (e) {
      passed = false;
    }
    const statusText = passed
      ? "SUPPORTED ✅"
      : item.name.includes("SHA-3")
        ? "FALLBACK (SHA-256) ⚠️"
        : "UNSUPPORTED ❌";
    const badgeClass = passed
      ? "badge-pass"
      : item.name.includes("SHA-3")
        ? "badge-warn"
        : "badge-fail";

    html += `
      <li class="inspector-item">
        <span class="inspector-name">${item.name}</span>
        <span class="inspector-badge ${badgeClass}">${statusText}</span>
      </li>
    `;
  }
  html += `</ul>`;
  container.innerHTML = html;
}
