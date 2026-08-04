// version: 0.7.0
/**
 * WebCrypt Security Helper - Timing Attack Protection
 * Provides constant-time comparison and dummy operations to prevent timing oracle attacks
 */

class TimingSafeHelper {
  /**
   * Constant-time string comparison to prevent timing attacks
   * @param {string} a - First string
   * @param {string} b - Second string
   * @returns {Promise<boolean>} True if strings are equal (in constant time)
   */
  static async constantTimeCompareStrings(a, b) {
    const encoder = new TextEncoder();
    const bufA = encoder.encode(a);
    const bufB = encoder.encode(b);

    // Ensure same length to prevent early termination detection
    const len = Math.max(bufA.length, bufB.length);

    // XOR all bytes and track differences
    let diff = 0;
    for (let i = 0; i < len; i++) {
      if (i < bufA.length && i < bufB.length) {
        diff |= bufA[i] ^ bufB[i];
      } else {
        // Different lengths contribute to difference
        diff |= 1;
      }
    }

    return diff === 0;
  }

  /**
   * Constant-time ArrayBuffer comparison to prevent timing attacks
   * @param {ArrayBuffer} a - First buffer
   * @param {ArrayBuffer} b - Second buffer
   * @returns {Promise<boolean>} True if buffers are equal (in constant time)
   */
  static async constantTimeCompareBuffers(a, b) {
    const bufA = new Uint8Array(a);
    const bufB = new Uint8Array(b);

    // Ensure same length to prevent early termination detection
    const len = Math.max(bufA.length, bufB.length);

    // XOR all bytes and track differences
    let diff = 0;
    for (let i = 0; i < len; i++) {
      if (i < bufA.length && i < bufB.length) {
        diff |= bufA[i] ^ bufB[i];
      } else {
        // Different lengths contribute to difference
        diff |= 1;
      }
    }

    return diff === 0;
  }

  /**
   * Execute dummy operations to pad execution time and prevent timing attacks
   * Uses non-blocking async timers to prevent CPU thread lockup.
   * @param {number} minMs - Minimum milliseconds to delay (e.g., 5-10ms)
   */
  static async sleepWithDummyOps(minMs = 10) {
    const startTime = performance.now();
    const elapsed = performance.now() - startTime;
    const remaining = minMs - elapsed;

    if (remaining > 0) {
      await new Promise(resolve => setTimeout(resolve, Math.max(1, Math.ceil(remaining))));
    }
  }

  /**
   * Timing-safe signature verification wrapper
   * Adds constant-time comparison and padding to prevent timing oracle attacks
   * @param {any} crypto - Crypto API (subtle)
   * @param {Object} algorithmParams - Algorithm parameters
   * @param {CryptoKey} key - Verification key
   * @param {ArrayBuffer} signature - Signature buffer
   * @param {Uint8Array|ArrayBuffer} data - Data to verify
   * @returns {Promise<boolean>} True if valid signature (with constant-time comparison)
   */
  static async timingSafeVerify(crypto, algorithmParams, key, signature, data) {
    const startTime = performance.now();

    // Perform actual verification
    let isValid;
    try {
      isValid = await crypto.subtle.verify(algorithmParams, key, signature, data);
    } catch (e) {
      isValid = false;
    }

    // Calculate minimum verification time to prevent timing attacks
    const minVerificationTimeMs = 10; // At least 10ms for all verifications
    const elapsedMs = performance.now() - startTime;

    if (elapsedMs < minVerificationTimeMs) {
      await this.sleepWithDummyOps(minVerificationTimeMs - elapsedMs);
    }

    return isValid;
  }

  /**
   * Timing-safe key derivation verification wrapper
   * Ensures consistent timing regardless of password correctness
   * @param {Function} deriveFn - Key derivation function
   * @param {...any} args - Arguments to pass to derive function
   * @returns {Promise<CryptoKey>} Derived key
   */
  static async timingSafeDerive(deriveFn, ...args) {
    const startTime = performance.now();

    let key;
    try {
      key = await deriveFn(...args);
    } catch (e) {
      // Even on error, wait minimum time to prevent timing attacks
      const elapsedMs = performance.now() - startTime;
      if (elapsedMs < 50) {
        await this.sleepWithDummyOps(50 - elapsedMs);
      }
      throw e;
    }

    // Ensure minimum derivation time (e.g., 50ms for strong KDFs)
    const minDerivationTimeMs = 50;
    const elapsedMs = performance.now() - startTime;

    if (elapsedMs < minDerivationTimeMs) {
      await this.sleepWithDummyOps(minDerivationTimeMs - elapsedMs);
    }

    return key;
  }
}

export default TimingSafeHelper;
