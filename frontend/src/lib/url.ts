// URLs that come from the server (an operator's console link, a presigned download) are
// followed only when they are absolute http(s) URLs. Anything else (javascript:, data:,
// blob:, relative or protocol-relative paths, junk) is never put in an href.

/** The URL in canonical form if it is an absolute http(s) URL with a host, else null. */
export function safeExternalUrl(raw: string | null | undefined): string | null {
  if (!raw) return null;
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return null;
  }
  if (url.protocol !== "https:" && url.protocol !== "http:") return null;
  if (!url.hostname) return null;
  return url.href;
}

/** Minimal DOM surface, so tests can check what would be clicked without a browser. */
export interface DownloadDom {
  createElement(tag: "a"): Pick<HTMLAnchorElement, "href" | "download" | "rel" | "click" | "remove"> & { style?: Partial<CSSStyleDeclaration> };
  append(el: unknown): void;
}

/**
 * Starts the browser download of a presigned attachment URL (an SBOM): a click on a
 * temporary `<a download>`. The file is never fetched, parsed or rendered by the page; the
 * storage server answers with `Content-Disposition: attachment`, so the page stays where it is.
 * Returns false, and does nothing, for a URL that isn't absolute http(s).
 */
export function startDownload(raw: string, fileName: string, dom?: DownloadDom): boolean {
  const href = safeExternalUrl(raw);
  if (!href) return false;
  const d: DownloadDom = dom ?? {
    createElement: (tag) => document.createElement(tag),
    append: (el) => document.body.append(el as Node),
  };
  const a = d.createElement("a");
  a.href = href;
  // Ignored cross-origin (the attachment header names the file), used same-origin.
  a.download = fileName;
  a.rel = "noopener noreferrer";
  if (a.style) a.style.display = "none";
  d.append(a);
  a.click();
  a.remove();
  return true;
}
