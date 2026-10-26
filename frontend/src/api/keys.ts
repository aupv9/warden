import type { QueryParams } from "./client";

// Query keys. Everything org-scoped starts with ["org", orgId] so that switching org never
// shows another org's cached data, and a prefix invalidates a whole resource.
export const qk = {
  me: ["me"] as const,
  org: (orgId: string) => ["org", orgId] as const,
  orgDetail: (orgId: string) => ["org", orgId, "detail"] as const,
  summary: (orgId: string) => ["org", orgId, "summary"] as const,
  members: (orgId: string) => ["org", orgId, "members"] as const,
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
  auditLog: (orgId: string, query: QueryParams) => ["org", orgId, "audit", query] as const,
};
