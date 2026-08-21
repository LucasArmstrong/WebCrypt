import { WebCryptAsym } from "../src/WebCryptAsym.js";

describe("WebCryptAsym WebRTC Transform Variants Security", () => {
  let asym;

  beforeEach(() => {
    asym = new WebCryptAsym();
  });

  afterEach(() => {
    asym.stopAutoCleanup();
  });

  test("createEncryptTransformWithProgress encrypts first frame and returns ArrayBuffer", async () => {
    const keys = await asym.generateKeyPair(2048);
    let progressReported = 0;
    const onProgress = bytes => {
      progressReported = bytes;
    };

    const encryptTransform = await asym.createEncryptTransformWithProgress(
      keys.publicKey,
      onProgress
    );
    const decryptTransform = await asym.createDecryptTransform(keys.privateKey);

    const plaintextStr = "Top secret first frame payload!";
    const originalPayload = new TextEncoder().encode(plaintextStr);
    const frame1 = { data: originalPayload.buffer.slice(0) };

    let transformedFrame1 = null;
    await encryptTransform(frame1, {
      enqueue: f => {
        transformedFrame1 = f;
      },
    });

    expect(transformedFrame1).toBeDefined();
    // Verify it is an ArrayBuffer (standard WebRTC spec)
    expect(transformedFrame1.data instanceof ArrayBuffer).toBe(true);

    // Verify first frame data does NOT contain plaintext in raw form
    const encryptedBytes = new Uint8Array(transformedFrame1.data);
    const plaintextBytes = new TextEncoder().encode(plaintextStr);
    const encKeyLen = new DataView(encryptedBytes.buffer).getUint32(0, true);
    const payloadPortion = encryptedBytes.slice(4 + encKeyLen + 12); // header = 4 + encKey + iv

    // Raw payload portion must not match raw plaintext
    let match = true;
    if (payloadPortion.length === plaintextBytes.length) {
      for (let i = 0; i < plaintextBytes.length; i++) {
        if (payloadPortion[i] !== plaintextBytes[i]) {
          match = false;
          break;
        }
      }
    } else {
      match = false;
    }
    expect(match).toBe(false);

    // Verify round-trip decryption of frame 1
    let decryptedFrame1 = null;
    await decryptTransform(transformedFrame1, {
      enqueue: f => {
        decryptedFrame1 = f;
      },
    });

    expect(decryptedFrame1).toBeDefined();
    expect(new TextDecoder().decode(decryptedFrame1.data)).toBe(plaintextStr);
  });
});
