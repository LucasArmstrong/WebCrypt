// src/TimingSafeHelper.d.ts

/**
 * Timing-safe utilities to prevent side-channel timing attacks.
 */
export class TimingSafeHelper {
  /**
   * Constant-time string comparison to prevent timing side-channel attacks.
   */
  static constantTimeCompareStrings(a: string, b: string): Promise<boolean>;

  /**
   * Constant-time Uint8Array comparison to prevent timing side-channel attacks.
   */
  static constantTimeCompareBuffers(a: Uint8Array, b: Uint8Array): Promise<boolean>;

  /**
   * Sleep with dummy operations to add timing noise.
   */
  static sleepWithDummyOps(minMs?: number): Promise<void>;

  /**
   * Timing-safe signature verification.
   */
  static timingSafeVerify(
    crypto: any,
    algorithmParams: any,
    key: CryptoKey,
    signature: Uint8Array,
    data: Uint8Array
  ): Promise<boolean>;

  /**
   * Timing-safe wrapper for key derivation functions.
   */
  static timingSafeDerive<T>(deriveFn: (...args: any[]) => Promise<T>, ...args: any[]): Promise<T>;
}

export default TimingSafeHelper;
