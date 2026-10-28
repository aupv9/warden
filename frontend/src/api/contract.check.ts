// Compile-time check that the hand-written types in types.ts agree with the
// backend's OpenAPI document (schema.d.ts, from `npm run gen:api`). tsc fails on drift.
import type { components } from "./schema";
import type * as T from "./types";
type S = components["schemas"];
// Server responses must fit what the UI expects.
type Fits<A, B extends A> = B;
export type C1 = Fits<T.Me, S["Me"]>;
export type C2 = Fits<T.Org, S["Org"]>;
export type C3 = Fits<T.OrgSummary, S["OrgSummary"]>;
export type C4 = Fits<T.OrgMember, S["OrgMember"]>;
export type C5 = Fits<T.Project, S["Project"]>;
export type C6 = Fits<T.ProjectMember, S["ProjectMember"]>;
export type C7 = Fits<T.Scan, S["Scan"]>;
export type C8 = Fits<T.CreateScanResponse, S["CreatedScan"]>;
export type C9 = Fits<T.IssueSummary, S["IssueSummary"]>;
export type C10 = Fits<T.Issue, S["Issue"]>;
export type C11 = Fits<T.IssueEvent, S["IssueEvent"]>;
export type C12 = Fits<T.Comment, S["Comment"]>;
export type C13 = Fits<T.ExceptionRequest, S["ExceptionRequest"]>;
export type C14 = Fits<T.AuditEntry, S["AuditEntry"]>;
export type C15 = Fits<T.ApiToken, S["ApiToken"]>;
export type C16 = Fits<T.CreatedToken, S["CreatedToken"]>;
export type C17 = Fits<T.TokenRef, S["TokenRef"]>;
export type C18 = Fits<T.Gate, S["Gate"]>;
export type C19 = Fits<T.Notification, S["Notification"]>;
export type C20 = Fits<T.NotificationPref, S["NotificationPref"]>;
export type C21 = Fits<T.AssignRule, S["AssignRule"]>;
export type C22 = Fits<T.Metrics, S["Metrics"]>;
export type C23 = Fits<T.IssueCounts, S["IssueCounts"]>;
export type C24 = Fits<T.SignInSettings, S["SignInSettings"]>;
// v0.3
export type C25 = Fits<T.SbomDownload, S["SbomDownload"]>;
export type C26 = Fits<T.LicensePolicy, S["LicensePolicy"]>;
export type C27 = Fits<T.VulnData, S["VulnData"]>;
export type C28 = Fits<T.VulnDataSource, S["VulnDataSource"]>;
export type C29 = Fits<T.ScanKind, S["ScanKind"]>;
export type C30 = Fits<T.LicenseAction, S["LicenseAction"]>;
export type C31 = Fits<T.LicenseCategory, keyof S["LicensePolicy"]["categories"]>;
// v0.4
export type C32 = Fits<T.ComponentSummary, S["ComponentSummary"]>;
export type C33 = Fits<T.ComponentUsage, S["ComponentUsage"]>;
export type C34 = Fits<T.ProjectComponent, S["ProjectComponent"]>;
export type C35 = Fits<T.ProjectTarget, S["ProjectTarget"]>;
export type C36 = Fits<T.SbomFormat, S["SbomFormat"]>;
export type C37 = Fits<S["SbomFormat"], T.SbomFormat>;
export type C38 = Fits<T.Ecosystem, S["Ecosystem"]>;
export type C39 = Fits<T.NotificationType, S["NotificationPref"]["type"]>;
export type C40 = Fits<S["NotificationPref"]["type"], T.NotificationType>;
// Every sort and issue-list filter value the UI sends is one the server accepts.
type IssueListQuery = NonNullable<import("./schema").operations["listIssues"]["parameters"]["query"]>;
export type Q1 = Fits<NonNullable<IssueListQuery["sort"]>, T.IssueSort>;
export type Q2 = Fits<NonNullable<IssueListQuery["kind"]>, import("../lib/issueFilters").IssueKindFilter>;
export type Q3 = Fits<NonNullable<IssueListQuery["source"]>, import("../lib/issueFilters").IssueSourceFilter>;
// v0.4: the SBOM format parameter and the component list filters.
type SbomQuery = NonNullable<import("./schema").operations["getScanSbom"]["parameters"]["query"]>;
export type Q4 = Fits<NonNullable<SbomQuery["format"]>, T.SbomFormatParam>;
type ComponentQuery = NonNullable<import("./schema").operations["listComponents"]["parameters"]["query"]>;
export type Q5 = Fits<keyof ComponentQuery, keyof import("../lib/components").ComponentApiQuery>;
type ProjectComponentQuery = NonNullable<import("./schema").operations["listProjectComponents"]["parameters"]["query"]>;
export type Q6 = Fits<keyof ProjectComponentQuery, keyof import("../lib/components").ProjectComponentApiQuery>;
// Every error code the server sends is one the UI knows, and the server's list has the newest.
export type E1 = Fits<T.ApiErrorCode, S["Error"]["code"]>;
export type E2 = Fits<S["Error"]["code"], "MFA_NOT_ENABLED">;
// UI request bodies must fit what the server accepts.
export type R1 = Fits<S["AddMemberRequest"], T.AddOrgMemberBody>;
export type R2 = Fits<S["CreateProjectRequest"], T.CreateProjectBody>;
export type R3 = Fits<S["CreateScanRequest"], T.CreateScanBody>;
export type R4 = Fits<S["TransitionRequest"], T.TransitionBody>;
export type R5 = Fits<S["BulkAssignRequest"], T.BulkAssignBody>;
export type R6 = Fits<S["CreateExceptionRequest"], T.CreateExceptionBody>;
export type R7 = Fits<S["DecisionRequest"], T.DecisionBody>;
export type R8 = Fits<S["CreateTokenRequest"], T.CreateTokenBody>;
export type R9 = Fits<S["MarkReadRequest"], T.MarkReadBody>;
export type R10 = Fits<S["OrgPolicyRequest"], T.UpdatePolicyBody>;
export type R11 = Fits<S["SignInPolicyRequest"], T.SignInPolicyInput>;
export type R12 = Fits<S["LicensePolicyRequest"], T.LicensePolicyInput>;
