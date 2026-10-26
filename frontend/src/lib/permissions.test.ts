import { describe, expect, it } from "vitest";
// The Go source of truth, read as text: the UI's copy must match it exactly.
import rbacGo from "../../../backend/internal/domain/rbac/rbac.go?raw";
import { can, canComment, MATRIX, matrixCell, OWN_ISSUE_ONLY_FOR_DEVELOPER } from "./permissions";

const GO_NAMES: Record<string, string> = {
  OrgAdmin: "org_admin",
  SecurityLead: "security_lead",
  Member: "member",
  Owner: "owner",
  Developer: "developer",
  Viewer: "viewer",
};

function parseGoMatrix(src: string): Record<string, string[]> {
  const perms = Object.fromEntries([...src.matchAll(/^\s*(\w+)\s+Perm\s*=\s*"(\w+)"/gm)].map((m) => [m[1]!, m[2]!]));
  const block = src.slice(src.indexOf("var Matrix"), src.indexOf("}\n", src.indexOf("var Matrix")));
  const out: Record<string, string[]> = {};
  for (const m of block.matchAll(/^\s*(\w+):\s*\{([^}]*)\}/gm)) {
    out[perms[m[1]!]!] = m[2]!
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean)
      .map((r) => GO_NAMES[r]!);
  }
  return out;
}

describe("permission matrix", () => {
  it("matches backend/internal/domain/rbac.Matrix", () => {
    const go = parseGoMatrix(rbacGo);
    expect(Object.keys(go).length).toBeGreaterThan(10);
    expect(MATRIX).toEqual(go);
  });

  it("matches the own-issue rule for developers", () => {
    expect(rbacGo).toMatch(/ownIssueOnlyForDeveloper = \[\]Perm\{UpdateIssue\}/);
    expect(OWN_ISSUE_ONLY_FOR_DEVELOPER).toEqual(["update_issue"]);
    expect(matrixCell("update_issue", "developer")).toBe("Own issues");
    expect(matrixCell("run_scan", "viewer")).toBe("–");
  });

  it("combines org role and project role", () => {
    expect(can("run_scan", "org_admin", null)).toBe(false);
    expect(can("run_scan", "member", "developer")).toBe(true);
    expect(can("decide_exception", "member", "owner")).toBe(false);
    expect(can("view_audit_log", "security_lead")).toBe(true);
    expect(canComment("member", "viewer")).toBe(false);
    expect(canComment("member", "developer")).toBe(true);
  });
});
