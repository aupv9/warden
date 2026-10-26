// Computes the upload's SHA-256 off the main thread, reporting progress. It only reads the bytes
// to hash them; nothing about the archive's contents is interpreted.
import { hashBlob } from "./sha256";

export type HashRequest = { file: Blob };
export type HashMessage =
  | { type: "progress"; done: number; total: number }
  | { type: "done"; hex: string }
  | { type: "error" };

// Typed loosely on purpose: pulling in the "webworker" lib would clash with "DOM" in the one tsconfig.
const scope = self as unknown as {
  postMessage(msg: HashMessage): void;
  onmessage: ((e: MessageEvent<HashRequest>) => void) | null;
};

scope.onmessage = (e) => {
  let last = 0;
  hashBlob(e.data.file, (done, total) => {
    const now = Date.now();
    if (now - last > 100 || done === total) {
      last = now;
      scope.postMessage({ type: "progress", done, total });
    }
  }).then(
    (hex) => scope.postMessage({ type: "done", hex }),
    () => scope.postMessage({ type: "error" }),
  );
};
