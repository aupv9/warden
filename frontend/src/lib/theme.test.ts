import { beforeEach, describe, expect, it, vi } from "vitest";
import { getTheme, initTheme, setTheme } from "./theme";

// Tests run in Node: a minimal <html> element and storage stand in for the browser.
let attrs: Map<string, string>;
let store: Map<string, string>;
let storageBroken: boolean;

beforeEach(() => {
  attrs = new Map();
  store = new Map();
  storageBroken = false;
  const guard = () => {
    if (storageBroken) throw new Error("blocked");
  };
  vi.stubGlobal("document", {
    documentElement: {
      setAttribute: (k: string, v: string) => attrs.set(k, v),
      removeAttribute: (k: string) => attrs.delete(k),
    },
  });
  vi.stubGlobal("localStorage", {
    getItem: (k: string) => (guard(), store.get(k) ?? null),
    setItem: (k: string, v: string) => (guard(), store.set(k, v)),
    removeItem: (k: string) => (guard(), store.delete(k)),
  });
});

describe("theme", () => {
  it("defaults to system and sets no attribute, so CSS follows the OS", () => {
    expect(initTheme()).toBe("system");
    expect(attrs.has("data-theme")).toBe(false);
  });

  it("applies and remembers an explicit choice", () => {
    setTheme("dark");
    expect(attrs.get("data-theme")).toBe("dark");
    expect(store.get("warden.theme")).toBe("dark");
    attrs.clear();
    expect(initTheme()).toBe("dark");
    expect(attrs.get("data-theme")).toBe("dark");
  });

  it("going back to system clears the attribute and the stored value", () => {
    setTheme("light");
    setTheme("system");
    expect(attrs.has("data-theme")).toBe(false);
    expect(store.has("warden.theme")).toBe(false);
  });

  it("ignores a tampered stored value", () => {
    store.set("warden.theme", "<script>");
    expect(initTheme()).toBe("system");
    expect(attrs.has("data-theme")).toBe(false);
  });

  it("still switches when storage throws", () => {
    storageBroken = true;
    setTheme("dark");
    expect(getTheme()).toBe("dark");
    expect(attrs.get("data-theme")).toBe("dark");
    expect(initTheme()).toBe("system");
  });
});
