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

// The CLI comes from the Warden release archives, checked against the release checksums (and,
// on GitHub, its build-provenance attestation) before it runs: never `go install …@latest`.
// Actions are pinned by commit SHA, like Warden's own workflows.
export const CLI_VERSION = "v0.2.0";
const CHECKOUT = "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1";

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
    "  pull_request: # pull requests from forks get no secrets, so they aren't scanned",
    "",
    "permissions:",
    "  contents: read",
    "",
    "jobs:",
    "  scan:",
    "    runs-on: ubuntu-24.04",
    "    env:",
    `      WARDEN_VERSION: ${CLI_VERSION} # the release that matches your Warden server`,
    "    steps:",
    `      - uses: ${CHECKOUT}`,
    "        with: { persist-credentials: false }",
    "      - name: Install the Warden CLI (checksum and provenance verified)",
    "        env:",
    "          GH_TOKEN: ${{ github.token }}",
    "        run: |",
    '          a="warden_${WARDEN_VERSION}_linux_amd64"',
    '          gh release download "$WARDEN_VERSION" -R aupv9/warden -D "$RUNNER_TEMP" -p "$a.tar.gz" -p "warden_${WARDEN_VERSION}_checksums.txt"',
    '          cd "$RUNNER_TEMP"',
    '          sha256sum -c --ignore-missing "warden_${WARDEN_VERSION}_checksums.txt"',
    '          gh attestation verify "$a.tar.gz" -R aupv9/warden',
    '          tar -xzf "$a.tar.gz" --strip-components=1 "$a/warden"',
    "      - name: Scan and check the gate",
    "        env:",
    "          # Repository secret: Settings > Secrets and variables > Actions.",
    "          WARDEN_TOKEN: ${{ secrets.WARDEN_TOKEN }}",
    "        run: >-",
    '          "$RUNNER_TEMP/warden" scan',
    ...scanArgs(p).map((a) => `          ${a}`),
  ].join("\n");
}

export function gitlabCiSnippet(p: SnippetParams): string {
  return [
    "# .gitlab-ci.yml",
    "warden:",
    "  stage: test",
    "  image: alpine:3.22 # pin by digest",
    "  # WARDEN_TOKEN: Settings > CI/CD > Variables, with Masked and Protected on.",
    "  variables:",
    `    WARDEN_VERSION: ${CLI_VERSION} # the release that matches your Warden server`,
    "  script:",
    "    - apk add --no-cache git curl",
    '    - git config --global --add safe.directory "$CI_PROJECT_DIR"',
    '    - a="warden_${WARDEN_VERSION}_linux_amd64"',
    '    - base="https://github.com/aupv9/warden/releases/download/${WARDEN_VERSION}"',
    '    - curl -fsSLO "$base/$a.tar.gz" && curl -fsSLO "$base/warden_${WARDEN_VERSION}_checksums.txt"',
    '    - grep " $a.tar.gz\\$" "warden_${WARDEN_VERSION}_checksums.txt" | sha256sum -c -',
    '    - tar -xzf "$a.tar.gz" --strip-components=1 "$a/warden"',
    `    - ./warden scan ${scanArgs(p).join(" ")}`,
    "  rules:",
    "    # Protected variables only reach protected branches and tags.",
    '    - if: $CI_COMMIT_REF_PROTECTED == "true"',
  ].join("\n");
}

/** Where the UI is served is where the API is (same origin). */
export function serverUrl(): string {
  return typeof window !== "undefined" && window.location?.origin ? window.location.origin : "https://warden.example";
}
