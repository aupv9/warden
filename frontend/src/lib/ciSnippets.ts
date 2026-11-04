// CI setup snippets for the Project Settings "CI setup" card. They run the `warden` CLI
// (backend/cmd/warden) with the org and project IDs filled in. The token is never part of a
// snippet, not even right after it was created: it is read from a CI secret variable named
// WARDEN_TOKEN (the CLI takes it from $WARDEN_TOKEN only, never from a flag).

export interface SnippetParams {
  url: string;
  orgId: string;
  projectId: string;
  failOn?: "critical" | "high" | "medium" | "low";
  /** v0.4 wave 2: `--comment auto`, one summary comment on the pull / merge request, updated in
   *  place. The CI system's own token posts it (GitHub: the job's GITHUB_TOKEN; GitLab: a project
   *  access token in WARDEN_GITLAB_TOKEN); Warden keeps no GitHub or GitLab credentials. */
  comment?: boolean;
  /** v0.4 wave 2: a second, nightly job on the default branch with the full history and
   *  `warden scan --history` (secrets in git history). */
  history?: boolean;
  /** v0.8: import another tool's results with `warden import`: CodeQL's SARIF on GitHub (one
   *  category per language), the GitLab SAST report on GitLab. */
  imports?: boolean;
}

// The CLI comes from the Warden release archives, checked against the release checksums (and,
// on GitHub, its build-provenance attestation) before it runs: never `go install …@latest`.
// Actions are pinned by commit SHA, like Warden's own workflows.
export const CLI_VERSION = "v0.2.0";
const CHECKOUT = "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1";

function targetArgs(p: SnippetParams): string[] {
  return [`--url ${p.url}`, `--org ${p.orgId}`, `--project ${p.projectId}`];
}

function scanArgs(p: SnippetParams): string[] {
  return [...targetArgs(p), `--fail-on ${p.failOn ?? "high"}`];
}

/** v0.8: the CodeQL action, by major version. Unlike checkout, Warden's own workflows don't use it,
 *  so there is no reviewed commit to pin: the comment asks for one, as for the GitLab image. */
export const CODEQL_ACTION = "github/codeql-action";
const CODEQL_VERSION = "v4";
/** CodeQL writes `<language>.sarif` into the analyze step's `output` directory. */
export const CODEQL_OUTPUT = "codeql-results";
/** The report GitLab's SAST jobs write (artifacts:reports:sast). */
export const GITLAB_SAST_REPORT = "gl-sast-report.json";

/** The nightly history job's schedule (GitHub). Not on the hour, when shared runners are busiest. */
export const HISTORY_CRON = "23 2 * * *";

function githubInstallSteps(fetchAll: boolean): string[] {
  return [
    `      - uses: ${CHECKOUT}`,
    fetchAll ? "        with: { persist-credentials: false, fetch-depth: 0 } # the full history" : "        with: { persist-credentials: false }",
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
  ];
}

export function githubActionsSnippet(p: SnippetParams): string {
  const lines = [
    "# .github/workflows/warden.yml",
    "name: Warden",
    "on:",
    "  push:",
    "    branches: [main]",
    "  pull_request: # pull requests from forks get no secrets, so they aren't scanned",
    ...(p.history ? ["  schedule:", `    - cron: "${HISTORY_CRON}" # nightly, on the default branch: secrets in the git history`] : []),
    "",
    "permissions:",
    "  contents: read",
    "",
    "jobs:",
    "  scan:",
    ...(p.history ? ["    if: github.event_name != 'schedule'"] : []),
    "    runs-on: ubuntu-24.04",
    ...(p.comment
      ? ["    permissions:", "      contents: read", "      pull-requests: write # --comment: one summary comment on the pull request"]
      : []),
    "    env:",
    `      WARDEN_VERSION: ${CLI_VERSION} # the release that matches your Warden server`,
    "    steps:",
    ...githubInstallSteps(false),
    "      - name: Scan and check the gate",
    "        env:",
    "          # Repository secret: Settings > Secrets and variables > Actions.",
    "          WARDEN_TOKEN: ${{ secrets.WARDEN_TOKEN }}",
    ...(p.comment ? ["          # The job's own token, used only to write the comment; Warden never sees it.", "          GITHUB_TOKEN: ${{ github.token }}"] : []),
    "        run: >-",
    '          "$RUNNER_TEMP/warden" scan',
    ...scanArgs(p).map((a) => `          ${a}`),
    ...(p.comment ? ["          --comment auto"] : []),
  ];
  if (p.imports) {
    lines.push(
      "",
      "  # Import CodeQL's results: one category per language, so each language's import fixes only its own.",
      "  codeql:",
      ...(p.history ? ["    if: github.event_name != 'schedule'"] : []),
      "    runs-on: ubuntu-24.04",
      "    strategy:",
      "      matrix:",
      "        language: [python] # your repository's languages",
      "    env:",
      `      WARDEN_VERSION: ${CLI_VERSION}`,
      "    steps:",
      ...githubInstallSteps(false),
      `      - uses: ${CODEQL_ACTION}/init@${CODEQL_VERSION} # pin by commit SHA`,
      "        with:",
      "          languages: ${{ matrix.language }}",
      `      - uses: ${CODEQL_ACTION}/analyze@${CODEQL_VERSION} # pin by commit SHA`,
      "        with:",
      '          category: "/language:${{ matrix.language }}/"',
      `          output: ${CODEQL_OUTPUT} # writes <language>.sarif here`,
      "          upload: never # upload: always also sends it to GitHub code scanning (security-events: write)",
      "      - name: Import the CodeQL results into Warden",
      "        env:",
      "          WARDEN_TOKEN: ${{ secrets.WARDEN_TOKEN }}",
      "        run: >-",
      '          "$RUNNER_TEMP/warden" import --tool codeql',
      '          --category "/language:${{ matrix.language }}/"',
      ...targetArgs(p).map((a) => `          ${a}`),
      `          "${CODEQL_OUTPUT}/\${{ matrix.language }}.sarif"`,
    );
  }
  if (p.history) {
    lines.push(
      "",
      "  history:",
      "    if: github.event_name == 'schedule'",
      "    runs-on: ubuntu-24.04",
      "    env:",
      `      WARDEN_VERSION: ${CLI_VERSION}`,
      "    steps:",
      ...githubInstallSteps(true),
      "      - name: Scan the git history for secrets",
      "        env:",
      "          WARDEN_TOKEN: ${{ secrets.WARDEN_TOKEN }}",
      "        run: >-",
      '          "$RUNNER_TEMP/warden" scan --history',
      ...scanArgs(p).map((a) => `          ${a}`),
    );
  }
  return lines.join("\n");
}

function gitlabInstall(): string[] {
  return [
    "    - apk add --no-cache git curl",
    '    - git config --global --add safe.directory "$CI_PROJECT_DIR"',
    '    - a="warden_${WARDEN_VERSION}_linux_amd64"',
    '    - base="https://github.com/aupv9/warden/releases/download/${WARDEN_VERSION}"',
    '    - curl -fsSLO "$base/$a.tar.gz" && curl -fsSLO "$base/warden_${WARDEN_VERSION}_checksums.txt"',
    '    - grep " $a.tar.gz\\$" "warden_${WARDEN_VERSION}_checksums.txt" | sha256sum -c -',
    '    - tar -xzf "$a.tar.gz" --strip-components=1 "$a/warden"',
  ];
}

export function gitlabCiSnippet(p: SnippetParams): string {
  const lines = [
    "# .gitlab-ci.yml",
    ...(p.imports ? ["include:", "  - template: Jobs/SAST.gitlab-ci.yml # GitLab SAST, imported into Warden below", ""] : []),
    "warden:",
    "  stage: test",
    "  image: alpine:3.22 # pin by digest",
    "  # WARDEN_TOKEN: Settings > CI/CD > Variables, with Masked and Protected on.",
    ...(p.comment
      ? [
          "  # WARDEN_GITLAB_TOKEN: a project access token with the api scope, stored as a Masked variable",
          "  # (CI_JOB_TOKEN can't write merge request notes). Used only for --comment.",
        ]
      : []),
    "  variables:",
    `    WARDEN_VERSION: ${CLI_VERSION} # the release that matches your Warden server`,
    "  script:",
    ...gitlabInstall(),
    `    - ./warden scan ${scanArgs(p).join(" ")}${p.comment ? " --comment auto" : ""}`,
    "  rules:",
    ...(p.history ? ['    - if: $CI_PIPELINE_SOURCE == "schedule"', "      when: never"] : []),
    "    # Protected variables only reach protected branches and tags.",
    '    - if: $CI_COMMIT_REF_PROTECTED == "true"',
    ...(p.comment
      ? [
          "    # Merge request pipelines, for the comment. They get Protected variables only when the",
          "    # source branch is protected: protect it, or turn Protected off for both tokens.",
          '    - if: $CI_PIPELINE_SOURCE == "merge_request_event"',
        ]
      : []),
  ];
  if (p.imports) {
    lines.push(
      "",
      "warden-import-sast:",
      "  stage: test",
      "  image: alpine:3.22 # pin by digest",
      `  needs: [semgrep-sast] # the SAST job whose ${GITLAB_SAST_REPORT} is imported`,
      "  variables:",
      `    WARDEN_VERSION: ${CLI_VERSION}`,
      "  script:",
      ...gitlabInstall(),
      `    - ./warden import --tool gitlab-sast --format gitlab-sast ${targetArgs(p).join(" ")} ${GITLAB_SAST_REPORT}`,
      "  rules:",
      ...(p.history ? ['    - if: $CI_PIPELINE_SOURCE == "schedule"', "      when: never"] : []),
      '    - if: $CI_COMMIT_REF_PROTECTED == "true"',
    );
  }
  if (p.history) {
    lines.push(
      "",
      "warden-history:",
      "  stage: test",
      "  image: alpine:3.22 # pin by digest",
      "  variables:",
      `    WARDEN_VERSION: ${CLI_VERSION}`,
      "    GIT_DEPTH: 0 # the full history",
      "  script:",
      ...gitlabInstall(),
      `    - ./warden scan --history ${scanArgs(p).join(" ")}`,
      "  rules:",
      "    # A pipeline schedule (Build > Pipeline schedules) on the default branch, e.g. nightly.",
      '    - if: $CI_PIPELINE_SOURCE == "schedule" && $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH',
    );
  }
  return lines.join("\n");
}

/** Where the UI is served is where the API is (same origin). */
export function serverUrl(): string {
  return typeof window !== "undefined" && window.location?.origin ? window.location.origin : "https://warden.example";
}
