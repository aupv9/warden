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
// v0.4 wave 2
type Ops = import("./schema").operations;
export type C41 = Fits<S["ScanKind"], T.ScanKind>;
export type C42 = Fits<T.Limits, S["Limits"]>;
export type C43 = Fits<T.IssueCommit, NonNullable<S["Issue"]["commit"]>>;
export type C44 = Fits<T.WebhookKind, S["WebhookKind"]>;
export type C45 = Fits<S["WebhookKind"], T.WebhookKind>;
export type C46 = Fits<T.WebhookEventType, S["WebhookEventType"]>;
export type C47 = Fits<S["WebhookEventType"], T.WebhookEventType>;
export type C48 = Fits<T.Webhook, S["Webhook"]>;
export type C49 = Fits<T.CreatedWebhook, S["CreatedWebhook"]>;
export type C50 = Fits<T.WebhookSecret, S["WebhookSecret"]>;
export type C51 = Fits<T.WebhookDelivery, S["WebhookDelivery"]>;
export type C52 = Fits<S["WebhookDelivery"]["type"], T.WebhookDeliveryType>;
export type C53 = Fits<NonNullable<S["WebhookDelivery"]["error"]>, T.WebhookDeliveryError>;
export type C54 = Fits<T.WebhookList, Ops["listWebhooks"]["responses"][200]["content"]["application/json"]["data"]>;
export type C55 = Fits<T.Page<T.WebhookDelivery>, Ops["listWebhookDeliveries"]["responses"][200]["content"]["application/json"]["data"]>;
export type C56 = Fits<T.WebhookDelivery, Ops["testWebhook"]["responses"][202]["content"]["application/json"]["data"]>;
export type C57 = Fits<T.WebhookSecret, Ops["rotateWebhookSecret"]["responses"][200]["content"]["application/json"]["data"]>;
// v0.5 wave 1
export type C58 = Fits<T.WebConfig, S["WebConfig"]>;
export type C59 = Fits<S["WebConfig"], T.WebConfig>;
export type C60 = Fits<T.WebConfig, Ops["getWebConfig"]["responses"][200]["content"]["application/json"]["data"]>;
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
export type E2 = Fits<S["Error"]["code"], "WEBHOOK_LIMIT" | "SECRETS_KEY_MISSING" | "RULE_INVALID">;
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
// v0.4 wave 2
export type R13 = Fits<S["CreateWebhookRequest"], T.CreateWebhookBody>;
export type R14 = Fits<S["UpdateWebhookRequest"], T.UpdateWebhookBody>;
type DeliveriesQuery = NonNullable<Ops["listWebhookDeliveries"]["parameters"]["query"]>;
export type Q7 = Fits<keyof DeliveriesQuery, "limit" | "cursor" | "state">;
// v0.5 wave 2
// `data` of a JSON response; a string (which no object type fits) if the shape isn't there.
type Json<O extends keyof Ops, C extends keyof Ops[O]["responses"]> = Ops[O]["responses"][C] extends { content: { "application/json": { data: infer D } } }
  ? D
  : "no JSON data";
export type C61 = Fits<T.OrgTarget, S["OrgTarget"]>;
export type C62 = Fits<T.ItemList<T.OrgTarget>, Json<"listOrgTargets", 200>>;
export type C63 = Fits<T.ItemList<T.EcosystemCount>, Json<"listComponentEcosystems", 200>>;
export type C64 = Fits<T.AuditVerification, S["AuditVerification"]>;
export type C65 = Fits<T.AuditVerification, Json<"verifyAuditLog", 200>>;
export type C66 = Fits<T.BulkAssignResult, Json<"bulkAssignIssues", 200>>;
export type Q8 = Fits<NonNullable<DeliveriesQuery["state"]>, T.WebhookDeliveryState>;
export type Q9 = Fits<T.WebhookDeliveryState, NonNullable<DeliveriesQuery["state"]>>;
// The CSV export takes the issue list's filters, and the list takes every one the UI sends.
type ExportQuery = NonNullable<Ops["exportIssuesCSV"]["parameters"]["query"]>;
type FilterKeys = keyof import("../lib/issueFilters").IssueFilterQuery;
// v0.8: the export doesn't take external_tool (or source=import) yet; IssueList turns it off
// while those filters are set (exportBlockedReason).
export type Q10 = Fits<keyof ExportQuery, keyof import("../lib/issueFilters").IssueExportQuery>;
export type Q11 = Fits<keyof IssueListQuery, FilterKeys>;
type OrgTargetsQuery = NonNullable<Ops["listOrgTargets"]["parameters"]["query"]>;
export type Q12 = Fits<NonNullable<OrgTargetsQuery["kind"]>, "image" | "import">;
// v0.6 wave 1: the org's own scan rules.
export type C67 = Fits<T.ScanRuleTool, S["ScanRuleTool"]>;
export type C68 = Fits<S["ScanRuleTool"], T.ScanRuleTool>;
export type C69 = Fits<T.RuleProblem, S["RuleProblem"]>;
export type C70 = Fits<T.ScanRule, S["ScanRule"]>;
export type C71 = Fits<T.ScanRuleVersion, S["ScanRuleVersion"]>;
export type C72 = Fits<T.RuleValidation, S["RuleValidation"]>;
export type C73 = Fits<T.RuleTest, S["RuleTest"]>;
export type C74 = Fits<S["RuleTest"]["state"], T.RuleTestState>;
export type C75 = Fits<NonNullable<S["RuleTest"]["error"]>, T.RuleTestError>;
export type C76 = Fits<T.ScanRuleRef, S["ScanRuleRef"]>;
export type C77 = Fits<T.IssueOrgRule, NonNullable<S["Issue"]["org_rule"]>>;
export type C78 = Fits<T.ItemList<T.ScanRule>, Json<"listScanRules", 200>>;
export type C79 = Fits<T.ScanRule, Json<"createScanRule", 201>>;
export type C80 = Fits<T.ScanRule, Json<"getScanRule", 200>>;
export type C81 = Fits<T.ScanRule, Json<"updateScanRule", 200>>;
export type C82 = Fits<T.Page<T.ScanRuleVersion>, Json<"listScanRuleVersions", 200>>;
export type C83 = Fits<T.RuleValidation, Json<"validateScanRule", 200>>;
export type C84 = Fits<T.RuleTest, Json<"testScanRule", 202>>;
export type C85 = Fits<T.RuleTest, Json<"getScanRuleTest", 200>>;
export type R15 = Fits<S["CreateScanRuleRequest"], T.CreateScanRuleBody>;
export type R16 = Fits<S["UpdateScanRuleRequest"], T.UpdateScanRuleBody>;
export type R17 = Fits<S["RuleTestRequest"], T.RuleTestRequest>;
type ValidateBody = Ops["validateScanRule"]["requestBody"]["content"]["application/json"];
export type R18 = Fits<ValidateBody, T.ValidateRuleBody>;
type RuleListQuery = NonNullable<Ops["listScanRules"]["parameters"]["query"]>;
export type Q13 = Fits<keyof RuleListQuery, "tool">;
type RuleDeleteQuery = Ops["deleteScanRule"]["parameters"]["query"];
export type Q14 = Fits<RuleDeleteQuery, { version: number }>;
type VersionsQuery = NonNullable<Ops["listScanRuleVersions"]["parameters"]["query"]>;
export type Q15 = Fits<keyof VersionsQuery, "limit" | "cursor">;
// v0.7 wave 1: a scan's org rule links to the rule that ran by id (null before v0.7). Both
// directions, so a field the UI treats as nullable can't silently become required or vanish.
export type C86 = Fits<T.ScanRuleRef["scan_rule_id"], S["ScanRuleRef"]["scan_rule_id"]>;
export type C87 = Fits<S["ScanRuleRef"]["scan_rule_id"], T.ScanRuleRef["scan_rule_id"]>;
// v0.7 wave 2: registry credentials, scans of pulled images, secrets in image layers. Fields the
// UI shows or branches on are checked both ways, so they can't silently become optional or vanish.
export type C88 = Fits<T.RegistryCredential, S["RegistryCredential"]>;
export type C89 = Fits<S["RegistryCredential"], T.RegistryCredential>;
export type C90 = Fits<T.RegistryError, NonNullable<S["RegistryCredential"]["last_error"]>>;
export type C91 = Fits<NonNullable<S["RegistryCredential"]["last_error"]>, T.RegistryError>;
export type C92 = Fits<T.ItemList<T.RegistryCredential>, Json<"listRegistryCredentials", 200>>;
export type C93 = Fits<T.RegistryCredential, Json<"createRegistryCredential", 201>>;
export type C94 = Fits<T.RegistryCredential, Json<"updateRegistryCredential", 200>>;
export type C95 = Fits<T.RegistryTestResult, Json<"testRegistryCredential", 200>>;
export type C96 = Fits<Json<"testRegistryCredential", 200>, T.RegistryTestResult>;
export type C97 = Fits<T.Scan, Json<"createPullScan", 201>>;
export type C98 = Fits<T.Scan["pulled"], S["Scan"]["pulled"]>;
export type C99 = Fits<S["Scan"]["pulled"], T.Scan["pulled"]>;
export type C100 = Fits<T.IssueImageLayer, NonNullable<S["Issue"]["image_layer"]>>;
export type C101 = Fits<NonNullable<S["Issue"]["image_layer"]>, T.IssueImageLayer>;
export type C102 = Fits<T.Issue["image_layer"], S["Issue"]["image_layer"]>;
export type C103 = Fits<S["Issue"]["image_layer"], T.Issue["image_layer"]>;
export type R19 = Fits<S["CreateRegistryCredentialRequest"], T.CreateRegistryCredentialBody>;
export type R20 = Fits<S["UpdateRegistryCredentialRequest"], T.UpdateRegistryCredentialBody>;
export type R21 = Fits<S["PullScanRequest"], T.PullScanBody>;
type PullBody = Ops["createPullScan"]["requestBody"]["content"]["application/json"];
export type R22 = Fits<PullBody, T.PullScanBody>;
type RegistryUpdateBody = Ops["updateRegistryCredential"]["requestBody"]["content"]["application/json"];
export type R23 = Fits<RegistryUpdateBody, T.UpdateRegistryCredentialBody>;
// v0.8 wave 1: results imported from another tool (SARIF, GitLab SAST). Both directions for every
// field the UI shows or branches on, so none can silently become optional, widen or vanish.
export type C104 = Fits<T.Tool, S["Tool"]>;
export type C105 = Fits<S["Tool"], T.Tool>;
export type C106 = Fits<T.ScanImport, S["ScanImport"]>;
export type C107 = Fits<S["ScanImport"], T.ScanImport>;
export type C108 = Fits<T.Scan["import"], S["Scan"]["import"]>;
export type C109 = Fits<S["Scan"]["import"], T.Scan["import"]>;
export type C110 = Fits<T.Issue["external_tool"], S["Issue"]["external_tool"]>;
export type C111 = Fits<S["Issue"]["external_tool"], T.Issue["external_tool"]>;
export type C112 = Fits<T.ImportFormat, S["ScanImport"]["format"]>;
export type C113 = Fits<S["ScanImport"]["format"], T.ImportFormat>;
export type C114 = Fits<T.CreateScanResponse, Json<"createImportScan", 201>>;
export type R24 = Fits<S["ImportScanRequest"], T.ImportScanBody>;
type ImportBody = Ops["createImportScan"]["requestBody"]["content"]["application/json"];
export type R25 = Fits<ImportBody, T.ImportScanBody>;
// The issue list's Source filter covers every source the server has, and the imported-tool filter
// is the contract's parameter.
export type Q16 = Fits<import("../lib/issueFilters").IssueSourceFilter, NonNullable<IssueListQuery["source"]>>;
export type Q17 = Fits<NonNullable<IssueListQuery["external_tool"]>, NonNullable<import("../lib/issueFilters").IssueFilterQuery["external_tool"]>>;
