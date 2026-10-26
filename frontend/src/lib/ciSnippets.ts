// CI setup snippets for the Project Settings "CI setup" card. They run the `warden` CLI
// (backend/cmd/warden) with the org and project IDs filled in. The token is never part of a
// snippet, not even right after it was created: it is read from a CI secret variable named
// WARDEN_TOKEN (the CLI takes it from $WARDEN_TOKEN only, never from a flag).

export interface SnippetParams {
  url: string;
  orgId: string;
  projectId: string;
  failOn?: "critical" | "high" | "medium" | "low";
}

export const CLI_INSTALL = "go install github.com/aupv9/warden/backend/cmd/warden@latest";

function scanArgs(p: SnippetParams): string[] {
  return [`--url ${p.url}`, `--org ${p.orgId}`, `--project ${p.projectId}`, `--fail-on ${p.failOn ?? "high"}`];
}

export function githubActionsSnippet(p: SnippetParams): string {
  return [
    "# .github/workflows/warden.yml",
    "name: Warden",
    "on:",
    "  push:",
    "    branches: [main]",
    "  pull_request:",
    "",
    "permissions:",
    "  contents: read",
    "",
    "jobs:",
    "  scan:",
    "    runs-on: ubuntu-latest",
    "    steps:",
    "      - uses: actions/checkout@v4",
    "      - uses: actions/setup-go@v5",
    "        with:",
    '          go-version: "1.27"',
    "      # Pin the CLI to the release that matches your Warden server.",
    `      - run: ${CLI_INSTALL}`,
    "      - name: Scan and check the gate",
    "        env:",
    "          # Repository secret: Settings > Secrets and variables > Actions.",
    "          WARDEN_TOKEN: ${{ secrets.WARDEN_TOKEN }}",
    "        run: >-",
    "          warden scan",
    ...scanArgs(p).map((a) => `          ${a}`),
  ].join("\n");
}

export function gitlabCiSnippet(p: SnippetParams): string {
  return [
    "# .gitlab-ci.yml",
    "warden:",
    "  stage: test",
    "  image: golang:1.27",
    "  # WARDEN_TOKEN: Settings > CI/CD > Variables, with Masked and Protected on.",
    "  script:",
    "    # Pin the CLI to the release that matches your Warden server.",
    `    - ${CLI_INSTALL}`,
    `    - warden scan ${scanArgs(p).join(" ")}`,
    "  rules:",
    '    - if: $CI_PIPELINE_SOURCE == "merge_request_event"',
    "    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH",
  ].join("\n");
}

/** Where the UI is served is where the API is (same origin). */
export function serverUrl(): string {
  return typeof window !== "undefined" && window.location?.origin ? window.location.origin : "https://warden.example";
}
