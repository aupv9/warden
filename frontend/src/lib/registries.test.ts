import { describe, expect, it } from "vitest";
// The contract, read as text: the UI's patterns must be the server's.
import openapiRaw from "../../../backend/internal/api/openapi.json?raw";
import type { RegistryCredential } from "../api/types";
import {
  createCredentialBody,
  credentialFormReducer,
  lastUsedText,
  NEW_CREDENTIAL_FORM,
  PULL_REF_MAX,
  PULL_REF_RE,
  pulledFromText,
  pullRefHost,
  REGISTRY_EXISTS,
  REGISTRY_HOST_RE,
  REGISTRY_LIMIT,
  registryConflictText,
  registryErrorLabel,
  registryErrorText,
  testResultText,
  updateCredentialBody,
  validateCredentialForm,
  validateHost,
  validatePassword,
  validatePullRef,
} from "./registries";
import { isPullFailure, isRejected, scanErrorMessages } from "./scanErrors";

const schemas = (JSON.parse(openapiRaw) as { components: { schemas: Record<string, { properties: Record<string, { pattern?: string; maxLength?: number }> }> } })
  .components.schemas;

// A made-up digest, built at test time.
const DIGEST = `sha256:${Array.from({ length: 64 }, (_, i) => "0123456789abcdef"[(i * 7 + 3) % 16]).join("")}`;
const REF = `ghcr.io/acme/api@${DIGEST}`;

const cred: RegistryCredential = {
  id: "00000000-0000-4000-8000-0000000000c1",
  host: "ghcr.io",
  username: "acme-bot",
  created_by: null,
  created_at: "2026-10-01T10:00:00Z",
  updated_at: "2026-10-01T10:00:00Z",
  last_used_at: null,
  last_error: null,
};

describe("the contract's patterns", () => {
  it("are the ones in openapi.json", () => {
    const source = (p: string | undefined) => new RegExp(p ?? "").source;
    expect(PULL_REF_RE.source).toBe(source(schemas.PullScanRequest!.properties.image_ref!.pattern));
    expect(PULL_REF_MAX).toBe(schemas.PullScanRequest!.properties.image_ref!.maxLength);
    expect(REGISTRY_HOST_RE.source).toBe(source(schemas.CreateRegistryCredentialRequest!.properties.host!.pattern));
    expect(REGISTRY_HOST_RE.source).toBe(source(schemas.RegistryCredential!.properties.host!.pattern));
  });
});

describe("image reference to pull", () => {
  it("accepts a reference pinned by digest, with a host, port and nested path", () => {
    expect(validatePullRef(REF)).toBeNull();
    expect(validatePullRef(`  ${REF}  `)).toBeNull();
    expect(validatePullRef(`registry.example.com:5000/team/app/worker@${DIGEST}`)).toBeNull();
    expect(validatePullRef(`docker.io/library/alpine@${DIGEST}`)).toBeNull();
    expect(validatePullRef(`localhost:5000/app@${DIGEST}`)).toBeNull();
  });

  it("refuses tags and says to pin by digest", () => {
    expect(validatePullRef("ghcr.io/acme/api:1.4.2")).toMatch(/Pin the image by digest: registry\/repository@sha256:…/);
    expect(validatePullRef("ghcr.io/acme/api")).toMatch(/never pulls by tag/);
    expect(validatePullRef(`ghcr.io/acme/api:1.4.2@${DIGEST}`)).toMatch(/Leave out the tag/);
    expect(validatePullRef(`ghcr.io/acme/api:latest@${DIGEST}`)).not.toBeNull();
  });

  it("refuses everything the server's pattern refuses", () => {
    const bad = [
      "",
      `https://ghcr.io/acme/api@${DIGEST}`,
      `GHCR.io/acme/api@${DIGEST}`,
      `alpine@${DIGEST}`,
      `ghcr.io/acme/api@sha256:${"a".repeat(63)}`,
      `ghcr.io/acme/api@sha256:${"A".repeat(64)}`,
      `ghcr.io/acme/api@sha512:${"a".repeat(64)}`,
      `ghcr.io/acme/api@${DIGEST}x`,
      `ghcr.io/acme/api@${DIGEST}\nghcr.io/evil/x@${DIGEST}`,
      `ghcr.io/acme/api@${DIGEST}?x=1`,
      `ghcr.io/acme/../api@${DIGEST}`,
      `ghcr.io//api@${DIGEST}`,
      `ghcr.io/acme/api @${DIGEST}`,
      `user:pass@ghcr.io/acme/api@${DIGEST}`,
      `ghcr.io/acme/api@@${DIGEST}`,
      `ghcr.io/${"a".repeat(600)}@${DIGEST}`,
      `-ghcr.io/acme/api@${DIGEST}`,
    ];
    for (const b of bad) {
      expect(validatePullRef(b), b).not.toBeNull();
      // Never weaker than the contract: whatever passes here passes the server's pattern.
      expect(PULL_REF_RE.test(b.trim()) && b.trim().length <= PULL_REF_MAX).toBe(false);
    }
  });

  it("asks for the registry host where the server would read the first path part as one", () => {
    // The contract's pattern takes "library" for a host; Warden would then try to reach it.
    expect(PULL_REF_RE.test(`library/alpine@${DIGEST}`)).toBe(true);
    expect(validatePullRef(`library/alpine@${DIGEST}`)).toMatch(/Start with the registry host, such as docker\.io\/library\/alpine/);
  });

  it("the host and the Pulled from line come from the reference", () => {
    expect(pullRefHost(REF)).toBe("ghcr.io");
    expect(pullRefHost(`registry.example.com:5000/a/b@${DIGEST}`)).toBe("registry.example.com:5000");
    expect(pullRefHost("ghcr.io/acme/api:1")).toBeNull();
    expect(pulledFromText({ image_ref: REF, target: "ghcr.io/acme/api" })).toBe("Pulled from ghcr.io");
    expect(pulledFromText({ image_ref: null, target: "quay.io/acme/x" })).toBe("Pulled from quay.io");
    expect(pulledFromText({ image_ref: "<img src=x>", target: "" })).toBe("Pulled from its registry");
  });
});

describe("registry host", () => {
  it("accepts hosts with a dot and an optional port; lower-cases what was typed", () => {
    expect(validateHost("ghcr.io")).toBeNull();
    expect(validateHost(" GHCR.io ")).toBeNull();
    expect(createCredentialBody({ host: " GHCR.io ", username: " bot ", password: " p w " })).toEqual({ host: "ghcr.io", username: "bot", password: " p w " });
    expect(validateHost("registry.example.com:5000")).toBeNull();
  });

  it("refuses schemes, paths, IP literals, user info and bare names, with what to do", () => {
    expect(validateHost("")).toMatch(/Enter the registry's host/);
    expect(validateHost("https://ghcr.io")).toMatch(/Leave out https:\/\//);
    expect(validateHost("ghcr.io/acme")).toMatch(/without a path/);
    expect(validateHost("10.0.0.5")).toMatch(/not an IP address/);
    expect(validateHost("169.254.169.254:80")).toMatch(/not an IP address/);
    expect(validateHost("[::1]:5000")).toMatch(/not an IP address/);
    expect(validateHost("bot@ghcr.io")).toMatch(/username goes in its own field/);
    expect(validateHost("registry")).toMatch(/with a dot/);
    expect(validateHost("ghcr.io:99999")).toMatch(/1 to 65535/);
    expect(validateHost("a_b.example")).not.toBeNull();
    expect(validateHost(`${`${"a".repeat(60)}.`.repeat(5)}io`)).toMatch(/At most 253/);
  });

  it("password: required on create, optional on change, never trimmed", () => {
    expect(validatePassword("", true)).toMatch(/password or access token/);
    expect(validatePassword("", false)).toBeNull();
    expect(validatePassword("x".repeat(4097), false)).toMatch(/4096/);
    expect(validateCredentialForm(NEW_CREDENTIAL_FORM, false)).toEqual({ host: expect.any(String), username: expect.any(String), password: expect.any(String) });
    expect(validateCredentialForm({ host: "", username: "bot", password: "" }, true)).toEqual({});
  });
});

describe("the add / change form", () => {
  it("drops the password from its state once submitted, and never prefills it", () => {
    // Built at test time, never a literal (CLAUDE.md).
    const pw = ["tok", Math.random().toString(36).slice(2)].join("_");
    let s = credentialFormReducer(NEW_CREDENTIAL_FORM, { type: "set", patch: { host: "ghcr.io", username: "bot", password: pw } });
    expect(s.password).toBe(pw);
    s = credentialFormReducer(s, { type: "submitted" });
    expect(s).toEqual({ host: "ghcr.io", username: "bot", password: "" });
    expect(JSON.stringify(s)).not.toContain(pw);
    expect(credentialFormReducer(s, { type: "reset", form: { host: "x.io", username: "u", password: pw } }).password).toBe("");
  });

  it("change sends only what changed; an empty password keeps the stored one", () => {
    expect(updateCredentialBody({ host: "ghcr.io", username: "acme-bot", password: "" }, cred)).toBeNull();
    expect(updateCredentialBody({ host: "ghcr.io", username: "other", password: "" }, cred)).toEqual({ username: "other" });
    expect(updateCredentialBody({ host: "ghcr.io", username: "acme-bot", password: "n" }, cred)).toEqual({ password: "n" });
  });

  it("409 on create: says whether the host has credentials or the org has 20", () => {
    expect(registryConflictText([cred], "ghcr.io")).toBe(REGISTRY_EXISTS);
    const twenty = Array.from({ length: 20 }, (_, i) => ({ host: `r${i}.example` }));
    expect(registryConflictText(twenty, "new.example")).toBe(REGISTRY_LIMIT);
  });
});

describe("words for the list and the test", () => {
  it("each last_error, and a fallback for values the UI doesn't know", () => {
    expect(registryErrorText(null)).toBeNull();
    expect(registryErrorText("unauthorized")).toMatch(/refused these credentials/);
    expect(registryErrorText("unreachable")).toMatch(/couldn't reach/);
    expect(registryErrorText("blocked")).toMatch(/private or internal address/);
    expect(registryErrorText("<b>new</b>")).toBe("The last attempt with these credentials failed.");
    expect(registryErrorLabel("<b>new</b>")).toBe("Failed");
    expect(testResultText({ ok: true, error: null }, "ghcr.io")).toBe("Warden signed in to ghcr.io with these credentials.");
    expect(testResultText({ ok: false, error: "unauthorized" }, "ghcr.io")).toMatch(/refused/);
    expect(lastUsedText({ last_used_at: null })).toBe("Not used yet");
    expect(lastUsedText({ last_used_at: "2026-11-03T08:00:00Z" }, new Date("2026-11-03T10:00:00Z"))).toBe("Used 2 h ago");
  });

  it("PULL_* scan errors: said in words, Failed (not Rejected), no server details", () => {
    for (const code of ["PULL_UNAUTHORIZED", "PULL_NOT_FOUND", "PULL_TOO_LARGE", "PULL_BLOCKED", "PULL_PLATFORM", "PULL_FAILED"]) {
      const m = scanErrorMessages(code);
      expect(m.short).not.toBe("failed");
      expect(m.full).not.toContain(code);
      expect(m.full).not.toMatch(/The scan failed \(/);
      const scan = { status: "failed" as const, error_code: code };
      expect(isPullFailure(scan)).toBe(true);
      expect(isRejected(scan)).toBe(false);
    }
    expect(scanErrorMessages("PULL_UNAUTHORIZED").full).toMatch(/Registries/);
    expect(isPullFailure({ status: "failed", error_code: "IMAGE_INVALID" })).toBe(false);
  });
});
