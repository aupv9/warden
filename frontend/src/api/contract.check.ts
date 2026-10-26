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
// UI request bodies must fit what the server accepts.
export type R1 = Fits<S["AddMemberRequest"], T.AddOrgMemberBody>;
export type R2 = Fits<S["CreateProjectRequest"], T.CreateProjectBody>;
export type R3 = Fits<S["CreateScanRequest"], T.CreateScanBody>;
export type R4 = Fits<S["TransitionRequest"], T.TransitionBody>;
export type R5 = Fits<S["BulkAssignRequest"], T.BulkAssignBody>;
export type R6 = Fits<S["CreateExceptionRequest"], T.CreateExceptionBody>;
export type R7 = Fits<S["DecisionRequest"], T.DecisionBody>;
