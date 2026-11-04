import { describe, expect, it } from "vitest";
import { isLayerDigest, layerTitle, moreLayersText, shortLayerDigest } from "./imageLayers";

const HEX = Array.from({ length: 64 }, (_, i) => "0123456789abcdef"[(i * 5 + 1) % 16]).join("");

describe("image layers", () => {
  it("shortens only a well-formed sha256 digest", () => {
    expect(isLayerDigest(`sha256:${HEX}`)).toBe(true);
    expect(shortLayerDigest(`sha256:${HEX}`)).toBe(HEX.slice(0, 12));
    // Anything else (from scanned data) is shown as it is, never cut into something it isn't.
    for (const odd of [HEX, `sha256:${HEX.toUpperCase()}`, `sha512:${HEX}`, `sha256:${HEX}x`, "javascript:alert(1)", "<img src=x>"]) {
      expect(isLayerDigest(odd)).toBe(false);
      expect(shortLayerDigest(odd)).toBe(odd);
    }
  });

  it("titles the card with the index and the short digest", () => {
    expect(layerTitle({ digest: `sha256:${HEX}`, index: 4, count: 2 })).toBe(`Found in image layer 4 (${HEX.slice(0, 12)})`);
    expect(layerTitle({ digest: `sha256:${HEX}`, index: 0, count: 1 })).toBe(`Found in image layer 0 (${HEX.slice(0, 12)})`);
    expect(layerTitle({ digest: "x", index: -1, count: 1 })).toBe("Found in image layer ? (x)");
  });

  it("says how many later layers hold it too", () => {
    expect(moreLayersText(1)).toBeNull();
    expect(moreLayersText(0)).toBeNull();
    expect(moreLayersText(Number.NaN)).toBeNull();
    expect(moreLayersText(2)).toBe("It is also in 1 later layer.");
    expect(moreLayersText(5)).toBe("It is also in 4 later layers.");
  });
});
