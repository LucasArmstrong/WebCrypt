// src/_base64.js
// Stack-safe, high-performance Base64 encoding/decoding for Uint8Arrays and ArrayBuffers.

const CHUNK_SIZE = 32768; // 32KB chunks prevent call stack overflow on large buffers

/**
 * Validates whether a string is valid Base64 formatted.
 * @param {string} str
 * @returns {boolean}
 */
export function isValidBase64(str) {
  if (typeof str !== "string" || str.length === 0) return false;
  const clean = str.replace(/[\r\n\s]/g, "");
  if (clean.length % 4 === 1) return false;
  return /^[A-Za-z0-9+/]+={0,2}$/.test(clean);
}

/**
 * Encodes an ArrayBuffer or Uint8Array to a Base64 string in stack-safe chunks.
 * @param {ArrayBuffer|Uint8Array} buffer
 * @returns {string} Base64 string
 */
export function arrayBufferToBase64(buffer) {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.length; i += CHUNK_SIZE) {
    binary += String.fromCharCode.apply(null, bytes.subarray(i, i + CHUNK_SIZE));
  }
  return btoa(binary);
}

/**
 * Decodes a Base64 string to an ArrayBuffer.
 * @param {string} base64
 * @returns {ArrayBuffer}
 */
export function base64ToArrayBuffer(base64) {
  if (typeof base64 !== "string") {
    throw new TypeError("Base64 string expected");
  }
  let padded = base64.trim();
  const mod = padded.length % 4;
  if (mod > 0) {
    padded += "=".repeat(4 - mod);
  }
  const bytes = Uint8Array.from(atob(padded), c => c.charCodeAt(0));
  return bytes.buffer;
}

/**
 * Decodes a Base64 string to a Uint8Array.
 * @param {string} base64
 * @returns {Uint8Array}
 */
export function base64ToUint8Array(base64) {
  if (typeof base64 !== "string") {
    throw new TypeError("Base64 string expected");
  }
  let padded = base64.trim();
  const mod = padded.length % 4;
  if (mod > 0) {
    padded += "=".repeat(4 - mod);
  }
  return Uint8Array.from(atob(padded), c => c.charCodeAt(0));
}
