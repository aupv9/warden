import { describe, expect, it } from "vitest";
import { safeExternalUrl, startDownload } from "./url";
import type { DownloadDom } from "./url";

function fakeDom() {
  const clicked: { href: string; download: string; rel: string }[] = [];
  let appended = 0;
  let removed = 0;
  const dom: DownloadDom = {
    createElement: () => {
      const a = {
        href: "",
        download: "",
        rel: "",
        style: {} as Partial<CSSStyleDeclaration>,
        click() {
          clicked.push({ href: a.href, download: a.download, rel: a.rel });
        },
        remove() {
          removed += 1;
        },
      };
      return a;
    },
    append: () => {
      appended += 1;
    },
  };
  return { dom, clicked, counts: () => ({ appended, removed }) };
}

describe("presigned downloads (SBOM)", () => {
  it("follows an absolute http(s) URL with a temporary <a download>", () => {
    const { dom, clicked, counts } = fakeDom();
    const url = "https://s3.example.test/warden/sboms/o/s.cdx.json?X-Amz-Expires=300&X-Amz-Signature=abc";
    expect(startDownload(url, "web-1234abcd.cdx.json", dom)).toBe(true);
    expect(clicked).toEqual([{ href: url, download: "web-1234abcd.cdx.json", rel: "noopener noreferrer" }]);
    expect(counts()).toEqual({ appended: 1, removed: 1 });
    expect(startDownload("http://localhost:9000/warden/x.cdx.json", "x", dom)).toBe(true);
  });

  it("never follows anything that isn't absolute http(s)", () => {
    for (const bad of [
      "javascript:alert(1)",
      "JaVaScRiPt:alert(1)",
      " javascript:alert(1)",
      "data:application/json,{}",
      "data:text/html,<script>alert(1)</script>",
      "blob:https://app.example/1",
      "file:///etc/passwd",
      "//evil.example/x",
      "/api/v1/x",
      "ftp://x.example/a",
      "vbscript:x",
      "",
      "not a url",
    ]) {
      const { dom, clicked } = fakeDom();
      expect(startDownload(bad, "x.cdx.json", dom), bad).toBe(false);
      expect(clicked).toEqual([]);
    }
  });

  it("shares the console-link rule (lib/signIn re-exports it)", () => {
    expect(safeExternalUrl("https://id.example.com/admin/")).toBe("https://id.example.com/admin/");
    expect(safeExternalUrl("javascript:alert(1)")).toBeNull();
  });
});
