import { describe, expect, it } from "vitest";
import { hashBlob, Sha256, toHex } from "./sha256";

const enc = new TextEncoder();
const hexOf = (s: string | Uint8Array) => new Sha256().update(typeof s === "string" ? enc.encode(s) : s).hex();

describe("Sha256", () => {
  // FIPS 180-4 / NIST CAVP example vectors.
  it("matches the NIST vectors", () => {
    expect(hexOf("")).toBe("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    expect(hexOf("abc")).toBe("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    expect(hexOf("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")).toBe(
      "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
    );
    expect(
      hexOf("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"),
    ).toBe("cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1");
  });

  it("hashes one million 'a' fed in odd-sized pieces", () => {
    const h = new Sha256();
    const piece = enc.encode("a".repeat(997));
    let left = 1_000_000;
    while (left > 0) {
      const n = Math.min(left, piece.length);
      h.update(piece.subarray(0, n));
      left -= n;
    }
    expect(h.hex()).toBe("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
  });

  it("agrees with WebCrypto across block boundaries and split points", async () => {
    for (const len of [1, 55, 56, 63, 64, 65, 119, 120, 127, 128, 1000, 4097]) {
      const data = new Uint8Array(len);
      crypto.getRandomValues(data);
      const want = toHex(new Uint8Array(await crypto.subtle.digest("SHA-256", data)));
      expect(hexOf(data)).toBe(want);
      const split = Math.floor(len / 3);
      expect(new Sha256().update(data.subarray(0, split)).update(data.subarray(split)).hex()).toBe(want);
    }
  });

  it("refuses to be reused after digest", () => {
    const h = new Sha256();
    h.digest();
    expect(() => h.update(new Uint8Array(1))).toThrow();
    expect(() => h.digest()).toThrow();
  });

  it("hashBlob reports progress and supports cancellation", async () => {
    const data = new Uint8Array(9 * 1024 * 1024);
    crypto.getRandomValues(data.subarray(0, 65536));
    const progress: number[] = [];
    const hex = await hashBlob(new Blob([data]), (done) => progress.push(done));
    expect(hex).toBe(toHex(new Uint8Array(await crypto.subtle.digest("SHA-256", data))));
    expect(progress.at(-1)).toBe(data.length);
    expect(progress.length).toBe(3);
    await expect(hashBlob(new Blob([data]), undefined, () => true)).rejects.toThrow();
  });
});
