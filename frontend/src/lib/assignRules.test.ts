import { describe, expect, it } from "vitest";
import type { ProjectMember } from "../api/types";
import {
  describeRule,
  emptyDraft,
  fromDraft,
  GLOB_MAX,
  MAX_RULES,
  moveRule,
  serverRuleErrors,
  toDraft,
  validateRules,
} from "./assignRules";
import { githubActionsSnippet, gitlabCiSnippet } from "./ciSnippets";

const member = (id: string, name: string, role: ProjectMember["role"] = "developer"): ProjectMember => ({
  user: { id, email: `${id}@acme.example`, display_name: name },
  role,
});
const members = [member("an", "An Nguyen"), member("minh", "Minh Pham", "owner")];

describe("auto-assign rule validation", () => {
  it("needs at least one matcher and an assignee who is a project member", () => {
    const d = emptyDraft();
    const r = validateRules([d], members);
    expect(r.valid).toBe(false);
    expect(r.rules[0]!.match).toMatch(/at least one condition/);
    expect(r.rules[0]!.assignee_id).toMatch(/Choose who/);

    const ok = validateRules([{ ...d, tool: "gitleaks", assignee_id: "an" }], members);
    expect(ok.valid).toBe(true);

    const left = validateRules([{ ...d, tool: "gitleaks", assignee_id: "someone-who-left" }], members);
    expect(left.rules[0]!.assignee_id).toMatch(/no longer a member/);
  });

  it("limits the path glob to 200 printable characters", () => {
    const base = { ...emptyDraft(), assignee_id: "an" };
    expect(validateRules([{ ...base, path_glob: "a".repeat(GLOB_MAX) }], members).valid).toBe(true);
    expect(validateRules([{ ...base, path_glob: "a".repeat(GLOB_MAX + 1) }], members).rules[0]!.path_glob).toMatch(/200/);
    expect(validateRules([{ ...base, path_glob: "src/\u0000**" }], members).rules[0]!.path_glob).toMatch(/printable/);
    // Whitespace alone is not a matcher.
    expect(validateRules([{ ...base, path_glob: "   " }], members).rules[0]!.match).toBeDefined();
  });

  it("allows at most 50 rules", () => {
    const rule = { ...emptyDraft(), severity_at_least: "high" as const, assignee_id: "an" };
    expect(validateRules(Array.from({ length: MAX_RULES }, () => ({ ...rule })), members).valid).toBe(true);
    const over = validateRules(Array.from({ length: MAX_RULES + 1 }, () => ({ ...rule })), members);
    expect(over.valid).toBe(false);
    expect(over.list).toMatch(/at most 50/);
  });

  it("sends only the matchers that are set, with the glob trimmed", () => {
    const d = { ...emptyDraft(), path_glob: "  deploy/**  ", severity_at_least: "high" as const, assignee_id: "an" };
    expect(fromDraft(d)).toEqual({ match: { path_glob: "deploy/**", severity_at_least: "high" }, assignee_id: "an" });
    const back = toDraft({ match: { tool: "trivy" }, assignee_id: "minh" });
    expect(back).toMatchObject({ path_glob: "", tool: "trivy", severity_at_least: "", assignee_id: "minh" });
  });

  it("maps server field errors to rules", () => {
    const { rules, other } = serverRuleErrors(
      { "items[1].assignee_id": "not a project member", "items[0].match.path_glob": "too long", "items[0].match": "needs a matcher", items: "too many", "items[9].assignee_id": "x" },
      2,
    );
    expect(rules[1]!.assignee_id).toBe("not a project member");
    expect(rules[0]!.path_glob).toBe("too long");
    expect(rules[0]!.match).toBe("needs a matcher");
    expect(other).toEqual(["items: too many", "items[9].assignee_id: x"]);
  });
});

describe("auto-assign rule order", () => {
  it("moves a rule up or down one place; first match wins, so order is data", () => {
    const list = ["a", "b", "c"];
    expect(moveRule(list, 2, -1)).toEqual(["a", "c", "b"]);
    expect(moveRule(list, 0, 1)).toEqual(["b", "a", "c"]);
    expect(list).toEqual(["a", "b", "c"]);
  });
  it("returns the same array for moves past either end", () => {
    const list = ["a", "b"];
    expect(moveRule(list, 0, -1)).toBe(list);
    expect(moveRule(list, 1, 1)).toBe(list);
    expect(moveRule(list, 5, -1)).toBe(list);
  });
  it("describes rules in words for people who can't edit them", () => {
    expect(describeRule({ match: { path_glob: "deploy/**", severity_at_least: "high" }, assignee_id: "minh" }, members)).toEqual({
      when: "Path matches deploy/** and severity is High or above",
      who: "Minh Pham",
      left: false,
    });
    expect(describeRule({ match: { tool: "gitleaks" }, assignee_id: "gone" }, members)).toMatchObject({ who: "a former member", left: true });
  });
});

describe("CI snippets", () => {
  const p = { url: "https://warden.example", orgId: "org-1", projectId: "proj-1" };
  it("fill in the org and project and read the token from a CI secret", () => {
    const gh = githubActionsSnippet(p);
    expect(gh).toContain("--org org-1");
    expect(gh).toContain("--project proj-1");
    expect(gh).toContain("WARDEN_TOKEN: ${{ secrets.WARDEN_TOKEN }}");
    const gl = gitlabCiSnippet(p);
    expect(gl).toContain("--org org-1 --project proj-1");
    expect(gl).toContain("WARDEN_TOKEN");
  });
  it("never contain a token", () => {
    for (const s of [githubActionsSnippet(p), gitlabCiSnippet(p)]) {
      expect(s).not.toMatch(/wdn_/);
      expect(s).not.toMatch(/--token/);
    }
  });
});
