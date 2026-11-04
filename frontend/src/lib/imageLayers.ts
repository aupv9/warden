import type { Issue, IssueImageLayer } from "../api/types";

// v0.7 wave 2: secrets Gitleaks finds in an image's layers (Issue.image_layer: the lowest layer
// that holds the secret, and how many do). A layer digest comes from the scanned image: it is
// shown as text with a copy button, never as a link, and anything that isn't a well-formed
// sha256 digest is shown as it is, never shortened into something it isn't.

const LAYER_DIGEST_RE = /^sha256:[0-9a-f]{64}$/;

export function isLayerDigest(d: string): boolean {
  return LAYER_DIGEST_RE.test(d);
}

/** The first 12 hex characters of a well-formed digest (as `docker history` prints them);
 *  anything else unchanged. */
export function shortLayerDigest(d: string): string {
  return isLayerDigest(d) ? d.slice("sha256:".length, "sha256:".length + 12) : d;
}

export function hasImageLayer(i: Pick<Issue, "image_layer">): i is Pick<Issue, "image_layer"> & { image_layer: IssueImageLayer } {
  return !!i.image_layer;
}

/** "Found in image layer 3 (3f2a9c41b7d0)". */
export function layerTitle(l: IssueImageLayer): string {
  return `Found in image layer ${layerIndex(l)} (${shortLayerDigest(l.digest)})`;
}

function layerIndex(l: IssueImageLayer): string {
  return Number.isInteger(l.index) && l.index >= 0 ? String(l.index) : "?";
}

/** "It is also in 2 later layers." when more than one layer holds it; null otherwise. */
export function moreLayersText(count: number): string | null {
  if (!Number.isFinite(count) || count <= 1) return null;
  const more = Math.floor(count) - 1;
  return `It is also in ${more.toLocaleString("en-US")} later layer${more === 1 ? "" : "s"}.`;
}

export const IMAGE_LAYER_ROTATE =
  "Rotate this secret. Deleting the file in a later layer doesn't remove it from the image: every layer ships with it, and anyone who pulls the image can read this one.";
