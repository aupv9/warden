import { MutationCache, QueryCache, QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { useState } from "react";
import { createBrowserRouter, Navigate, Outlet, RouterProvider } from "react-router";
import type { RouteObject } from "react-router";
import { ApiError } from "./api/client";
import { errorMessage, isForbidden, isToastedActionError, isUnauthorized, supportReference } from "./api/errors";
import type { ErrorOverrides } from "./api/errors";
import { AuthBoot, AuthGate, sessionEnded } from "./auth/AuthGate";
import { appBoot } from "./auth/boot";
import { Toaster } from "./components/Toaster";
import { NotFoundPage, OrgLayout, OrgNotFound } from "./layout/OrgLayout";
import { lazyRoute } from "./lib/lazyRoute";
import { showToast } from "./lib/toast";
import { Home } from "./routes/Home";
import { RouteError } from "./routes/NotFound";

// react-router (data router) gives nested layouts (org → project tabs), URL search params for
// the filters and NavLink active states without extra code.
//
// Every page is a lazy chunk (Suspense boundaries with a skeleton sit in OrgLayout and
// ProjectLayout); the entry chunk keeps only auth, the shell and shared components.
const OverviewPage = lazyRoute(() => import("./routes/Overview"), "OverviewPage");
const ProjectsPage = lazyRoute(() => import("./routes/Projects"), "ProjectsPage");
const ProjectLayout = lazyRoute(() => import("./routes/ProjectLayout"), "ProjectLayout");
const ProjectIssuesTab = lazyRoute(() => import("./routes/ProjectLayout"), "ProjectIssuesTab");
const ProjectMembersTab = lazyRoute(() => import("./routes/ProjectLayout"), "ProjectMembersTab");
const ProjectScansTab = lazyRoute(() => import("./routes/ProjectScans"), "ProjectScansTab");
const ProjectSettingsTab = lazyRoute(() => import("./routes/ProjectSettings"), "ProjectSettingsTab");
const IssuesPage = lazyRoute(() => import("./routes/IssueList"), "IssuesPage");
const ComponentsPage = lazyRoute(() => import("./routes/Components"), "ComponentsPage");
const ProjectComponentsTab = lazyRoute(() => import("./routes/ProjectComponents"), "ProjectComponentsTab");
const ExceptionsPage = lazyRoute(() => import("./routes/Exceptions"), "ExceptionsPage");
const MembersPage = lazyRoute(() => import("./routes/Members"), "MembersPage");
const AuditLogPage = lazyRoute(() => import("./routes/AuditLog"), "AuditLogPage");
const OrgSettingsPage = lazyRoute(() => import("./routes/OrgSettings"), "OrgSettingsPage");
const PreferencesPage = lazyRoute(() => import("./routes/Preferences"), "PreferencesPage");
const IntegrationsPage = lazyRoute(() => import("./routes/Integrations"), "IntegrationsPage");
const ScanRulesPage = lazyRoute(() => import("./routes/ScanRules"), "ScanRulesPage");
const ScanRulePage = lazyRoute(() => import("./routes/ScanRule"), "ScanRulePage");

export function createQueryClient(): QueryClient {
  const qc: QueryClient = new QueryClient({
    queryCache: new QueryCache({
      onError: (err) => {
        // 401 after the silent refresh failed: back to sign-in with the generic message.
        if (isUnauthorized(err)) sessionEnded.dispatchEvent(new Event("ended"));
      },
    }),
    mutationCache: new MutationCache({
      onError: (err, _vars, _result, mutation) => {
        if (isUnauthorized(err)) {
          sessionEnded.dispatchEvent(new Event("ended"));
          return;
        }
        // MFA_REQUIRED swaps the org's pages for the two-factor explanation (lib/mfa.ts) and is
        // not a toast (isToastedActionError is false for it).
        // Errors with no better place go to a toast (DESIGN.md "API error.code"); 403 also
        // refetches so the page shows only what the role allows.
        if (!isToastedActionError(err)) return;
        // v0.6: a mutation whose screen shows every error in place (the rule test dialog).
        if (mutation.meta?.inlineErrors) return;
        const rateLimited = err instanceof ApiError && err.code === "RATE_LIMITED";
        // A mutation may word a code itself (meta.errorMessages), e.g. the webhook test's 429.
        const overrides = (mutation.meta?.errorMessages ?? undefined) as ErrorOverrides | undefined;
        const custom = err instanceof ApiError && !!overrides?.[err.code];
        showToast({
          tone: rateLimited ? "warning" : "error",
          title: rateLimited && !custom ? "Slow down." : undefined,
          message: errorMessage(err, overrides),
          reference: supportReference(err),
        });
        if (isForbidden(err)) void qc.invalidateQueries();
      },
    }),
    defaultOptions: {
      queries: {
        // Don't hammer the API with retries of 4xx answers; retry network/5xx twice.
        retry: (count, err) => !(err instanceof ApiError && err.status >= 400 && err.status < 500) && count < 2,
        staleTime: 15_000,
      },
    },
  });
  return qc;
}

export const appRoutes: RouteObject[] = [
  {
    path: "/",
    element: <Outlet />,
    errorElement: <RouteError />,
    children: [
      { index: true, element: <Home /> },
      {
        path: "orgs/:orgId",
        element: <OrgLayout />,
        children: [
          { index: true, element: <Navigate to="projects" replace /> },
          { path: "overview", element: <OverviewPage /> },
          { path: "projects", element: <ProjectsPage /> },
          {
            path: "projects/:projectId",
            element: <ProjectLayout />,
            children: [
              { index: true, element: <Navigate to="issues" replace /> },
              { path: "issues", element: <ProjectIssuesTab /> },
              { path: "scans", element: <ProjectScansTab /> },
              { path: "components", element: <ProjectComponentsTab /> },
              { path: "members", element: <ProjectMembersTab /> },
              { path: "settings", element: <ProjectSettingsTab /> },
            ],
          },
          // One page for the list and an opened issue, so the list stays mounted (scroll,
          // selection) while the split view's pane changes. IssuesPage decides between the
          // split view (≥ 1200 px) and the issue as its own page.
          { path: "issues", element: <IssuesPage />, children: [{ path: ":issueId", element: null }] },
          { path: "components", element: <ComponentsPage /> },
          { path: "exceptions", element: <ExceptionsPage /> },
          { path: "members", element: <MembersPage /> },
          { path: "audit-log", element: <AuditLogPage /> },
          { path: "settings", element: <OrgSettingsPage /> },
          // v0.6: the org's own Opengrep and Gitleaks rules; `new` and a rule's page (with its
          // history) share one route.
          { path: "settings/scan-rules", element: <ScanRulesPage /> },
          { path: "settings/scan-rules/:ruleId", element: <ScanRulePage /> },
          // v0.4 wave 2: webhooks and Slack (org admins and security leads).
          { path: "integrations", element: <IntegrationsPage /> },
          // Notification preferences are the user's own (they apply in every org); the page
          // sits under the org so the navigation stays.
          { path: "preferences", element: <PreferencesPage /> },
          { path: "*", element: <OrgNotFound /> },
        ],
      },
      { path: "*", element: <NotFoundPage /> },
    ],
  },
];

export function App() {
  const [qc] = useState(createQueryClient);
  const [router] = useState(() => createBrowserRouter(appRoutes));
  return (
    <QueryClientProvider client={qc}>
      <AuthBoot boot={appBoot}>
        {(authFailed) => (
          <AuthGate authFailed={authFailed}>
            <RouterProvider router={router} />
          </AuthGate>
        )}
      </AuthBoot>
      <Toaster />
    </QueryClientProvider>
  );
}
