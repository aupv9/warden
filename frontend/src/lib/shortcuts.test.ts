import { describe, expect, it } from "vitest";
import { isInteractiveTarget, isTypingTarget, matchShortcut } from "./shortcuts";
import type { KeyLike } from "./shortcuts";

// Fake event targets: just the fields the matcher reads.
const el = (tagName: string, extra: Record<string, unknown> = {}) => ({
  tagName,
  getAttribute: (n: string) => (extra.attrs as Record<string, string> | undefined)?.[n] ?? null,
  ...extra,
});
const body = el("BODY");
const key = (k: string, target: unknown = body, mods: Partial<KeyLike> = {}): KeyLike => ({
  key: k,
  metaKey: false,
  ctrlKey: false,
  altKey: false,
  target,
  ...mods,
});
const closed = { dialogOpen: false };

describe("keyboard shortcuts", () => {
  it("maps the documented keys", () => {
    expect(matchShortcut(key("j"), closed)).toBe("next");
    expect(matchShortcut(key("k"), closed)).toBe("prev");
    expect(matchShortcut(key("Enter"), closed)).toBe("open");
    expect(matchShortcut(key("Escape"), closed)).toBe("close");
    expect(matchShortcut(key("a"), closed)).toBe("assign");
    expect(matchShortcut(key("x"), closed)).toBe("select");
    expect(matchShortcut(key("/"), closed)).toBe("search");
    expect(matchShortcut(key("k", body, { metaKey: true }), closed)).toBe("palette");
    expect(matchShortcut(key("k", body, { ctrlKey: true }), closed)).toBe("palette");
  });

  it("ignores other keys and modified letters", () => {
    expect(matchShortcut(key("q"), closed)).toBeNull();
    expect(matchShortcut(key("j", body, { metaKey: true }), closed)).toBeNull();
    expect(matchShortcut(key("a", body, { ctrlKey: true }), closed)).toBeNull();
    expect(matchShortcut(key("j", body, { altKey: true }), closed)).toBeNull();
    expect(matchShortcut(key("k", body, { metaKey: true, altKey: true }), closed)).toBeNull();
  });

  it("never fires while typing in a field", () => {
    const fields = [
      el("INPUT", { type: "text" }),
      el("INPUT", { type: "search" }),
      el("INPUT", { type: "" }),
      el("INPUT", { type: "date" }),
      el("TEXTAREA"),
      el("SELECT"),
      el("DIV", { isContentEditable: true }),
      el("DIV", { attrs: { role: "combobox" } }),
    ];
    for (const f of fields) {
      for (const k of ["j", "k", "a", "x", "/", "Enter", "Escape"]) expect(matchShortcut(key(k, f), closed)).toBeNull();
      expect(matchShortcut(key("k", f, { metaKey: true }), closed)).toBeNull();
    }
    expect(isTypingTarget(el("INPUT", { type: "checkbox" }))).toBe(false);
    // A checkbox in the list is not a text field: J/K and X still work there.
    expect(matchShortcut(key("x", el("INPUT", { type: "checkbox" })), closed)).toBe("select");
  });

  it("never fires while a dialog is open", () => {
    const open = { dialogOpen: true };
    for (const k of ["j", "k", "a", "x", "/", "Enter", "Escape"]) expect(matchShortcut(key(k), open)).toBeNull();
    expect(matchShortcut(key("k", body, { metaKey: true }), open)).toBeNull();
  });

  it("leaves Enter to links and buttons, and skips handled or composing keys", () => {
    expect(isInteractiveTarget(el("A"))).toBe(true);
    expect(matchShortcut(key("Enter", el("A")), closed)).toBeNull();
    expect(matchShortcut(key("Enter", el("BUTTON")), closed)).toBeNull();
    expect(matchShortcut(key("Enter", el("DIV", { attrs: { role: "button" } })), closed)).toBeNull();
    // Other shortcuts still work with focus on a link (e.g. J from a row link).
    expect(matchShortcut(key("j", el("A")), closed)).toBe("next");
    expect(matchShortcut(key("j", body, { defaultPrevented: true }), closed)).toBeNull();
    expect(matchShortcut(key("j", body, { isComposing: true }), closed)).toBeNull();
  });
});
