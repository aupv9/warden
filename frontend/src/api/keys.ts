import type { QueryParams } from "./client";

// Query keys. Everything org-scoped starts with ["org", orgId] so that switching org never
// shows another org's cached data, and a prefix invalidates a whole resource.
export const qk = {
  me: ["me"] as const,
  org: (orgId: string) => ["org", orgId] as const,
  orgDetail: (orgId: string) => ["org", orgId, "detail"] as const,
  summary: (orgId: string) => ["org", orgId, "summary"] as const,
  members: (orgId: string) => ["org", orgId, "members"] as const,
  signIn: (orgId: string) => ["org", orgId, "sign-in"] as const,
  projects: (orgId: string) => ["org", orgId, "projects"] as const,
  project: (orgId: string, projectId: string) => ["org", orgId, "projects", projectId] as const,
  projectMembers: (orgId: string, projectId: string) => ["org", orgId, "projects", projectId, "members"] as const,
  scans: (orgId: string, projectId: string) => ["org", orgId, "projects", projectId, "scans"] as const,
  scanAll: (orgId: string) => ["org", orgId, "scan"] as const,
  scan: (orgId: string, scanId: string) => ["org", orgId, "scan", scanId] as const,
  issueLists: (orgId: string) => ["org", orgId, "issues"] as const,
  issues: (orgId: string, query: QueryParams) => ["org", orgId, "issues", query] as const,
  issueAll: (orgId: string) => ["org", orgId, "issue"] as const,
  issue: (orgId: string, issueId: string) => ["org", orgId, "issue", issueId] as const,
  issueEvents: (orgId: string, issueId: string) => ["org", orgId, "issue", issueId, "events"] as const,
  issueComments: (orgId: string, issueId: string) => ["org", orgId, "issue", issueId, "comments"] as const,
  exceptionLists: (orgId: string) => ["org", orgId, "exceptions"] as const,
  exceptions: (orgId: string, tab: string) => ["org", orgId, "exceptions", tab] as const,
  auditLogs: (orgId: string) => ["org", orgId, "audit"] as const,
  auditLog: (orgId: string, query: QueryParams) => ["org", orgId, "audit", query] as const,
  // v0.2
  projectList: (orgId: string, includeArchived: boolean) => ["org", orgId, "projects", { include_archived: includeArchived }] as const,
  tokens: (orgId: string, projectId: string) => ["org", orgId, "projects", projectId, "tokens"] as const,
  assignRules: (orgId: string, projectId: string) => ["org", orgId, "projects", projectId, "assign-rules"] as const,
  metricsAll: (orgId: string) => ["org", orgId, "metrics"] as const,
  metrics: (orgId: string, query: QueryParams) => ["org", orgId, "metrics", query] as const,
  // Under the issue-list prefix, so every issue change refreshes the saved-view counts too.
  issueCounts: (orgId: string, projectId: string | undefined) => ["org", orgId, "issues", "counts", projectId ?? null] as const,
  // v0.3
  licensePolicy: (orgId: string) => ["org", orgId, "license-policy"] as const,
  vulnData: (orgId: string) => ["org", orgId, "vuln-data"] as const,
  // v0.4
  components: (orgId: string, query: QueryParams) => ["org", orgId, "components", query] as const,
  componentUsage: (orgId: string, query: QueryParams) => ["org", orgId, "components", "usage", query] as const,
  projectComponents: (orgId: string, projectId: string, query: QueryParams) => ["org", orgId, "projects", projectId, "components", query] as const,
  projectTargets: (orgId: string, projectId: string) => ["org", orgId, "projects", projectId, "targets"] as const,
  // v0.5 wave 2
  orgTargets: (orgId: string, kind: string) => ["org", orgId, "targets", kind] as const,
  componentEcosystems: (orgId: string) => ["org", orgId, "components", "ecosystems"] as const,
  // v0.4 wave 2. No key ever holds a webhook URL or signing secret (webhooks.test.ts).
  webhooks: (orgId: string) => ["org", orgId, "webhooks"] as const,
  webhookDeliveries: (orgId: string, webhookId: string) => ["org", orgId, "webhooks", webhookId, "deliveries"] as const,
  // v0.5 wave 2: one log per state filter, under the prefix above (so a test refreshes all).
  webhookDeliveryLog: (orgId: string, webhookId: string, state: string) => ["org", orgId, "webhooks", webhookId, "deliveries", state || "all"] as const,
  // v0.6: the org's own scan rules. No key holds a rule body or a test snippet (scanRules.test.ts):
  // a test's result (lines and messages) is keyed by its id only.
  scanRules: (orgId: string) => ["org", orgId, "scan-rules"] as const,
  scanRuleList: (orgId: string) => ["org", orgId, "scan-rules", "list"] as const,
  scanRule: (orgId: string, ruleId: string) => ["org", orgId, "scan-rules", "rule", ruleId] as const,
  scanRuleVersions: (orgId: string, ruleId: string) => ["org", orgId, "scan-rules", "rule", ruleId, "versions"] as const,
  ruleTest: (orgId: string, testId: string) => ["org", orgId, "rule-tests", testId] as const,
  // v0.7 wave 2: registry credentials. No key holds a password (registries.test.ts); the server
  // never returns one.
  registries: (orgId: string) => ["org", orgId, "registries"] as const,
  // Notifications belong to the user, not to an org.
  notificationsAll: ["notifications"] as const,
  unreadCount: ["notifications", "unread-count"] as const,
  notifications: (unreadOnly: boolean) => ["notifications", "list", { unread: unreadOnly }] as const,
  notificationPrefs: ["notification-prefs"] as const,
};
