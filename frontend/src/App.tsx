import { MutationCache, QueryCache, QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { useState } from "react";
import { createBrowserRouter, Navigate, Outlet, RouterProvider } from "react-router";
import type { RouteObject } from "react-router";
import { ApiError } from "./api/client";
import { errorMessage, isForbidden, isToastedActionError, isUnauthorized, supportReference } from "./api/errors";
import { AuthGate, sessionEnded } from "./auth/AuthGate";
import { Toaster } from "./components/Toaster";
import { NotFoundPage, OrgLayout, OrgNotFound } from "./layout/OrgLayout";
import { showToast } from "./lib/toast";
import { AuditLogPage } from "./routes/AuditLog";
import { ExceptionsPage } from "./routes/Exceptions";
import { Home } from "./routes/Home";
import { IssuesPage } from "./routes/IssueList";
import { MembersPage } from "./routes/Members";
import { RouteError } from "./routes/NotFound";
import { ProjectIssuesTab, ProjectLayout, ProjectMembersTab, ProjectSettingsTab } from "./routes/ProjectLayout";
import { ProjectScansTab } from "./routes/ProjectScans";
import { ProjectsPage } from "./routes/Projects";

// react-router (data router) gives nested layouts (org → project tabs), URL search params for
// the filters and NavLink active states without extra code.

export function createQueryClient(): QueryClient {
  const qc: QueryClient = new QueryClient({
    queryCache: new QueryCache({
      onError: (err) => {
        // 401 after the silent refresh failed: back to sign-in with the generic message.
        if (isUnauthorized(err)) sessionEnded.dispatchEvent(new Event("ended"));
      },
    }),
    mutationCache: new MutationCache({
      onError: (err) => {
        if (isUnauthorized(err)) {
          sessionEnded.dispatchEvent(new Event("ended"));
          return;
        }
        // Errors with no better place go to a toast (DESIGN.md "API error.code"); 403 also
        // refetches so the page shows only what the role allows.
        if (!isToastedActionError(err)) return;
        const rateLimited = err instanceof ApiError && err.code === "RATE_LIMITED";
        showToast({
          tone: rateLimited ? "warning" : "error",
          title: rateLimited ? "Slow down." : undefined,
          message: errorMessage(err),
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
          { path: "projects", element: <ProjectsPage /> },
          {
            path: "projects/:projectId",
            element: <ProjectLayout />,
            children: [
              { index: true, element: <Navigate to="issues" replace /> },
              { path: "issues", element: <ProjectIssuesTab /> },
              { path: "scans", element: <ProjectScansTab /> },
              { path: "members", element: <ProjectMembersTab /> },
              { path: "settings", element: <ProjectSettingsTab /> },
            ],
          },
          // One page for the list and an opened issue, so the list stays mounted (scroll,
          // selection) while the split view's pane changes. IssuesPage decides between the
          // split view (≥ 1200 px) and the issue as its own page.
          { path: "issues", element: <IssuesPage />, children: [{ path: ":issueId", element: null }] },
          { path: "exceptions", element: <ExceptionsPage /> },
          { path: "members", element: <MembersPage /> },
          { path: "audit-log", element: <AuditLogPage /> },
          { path: "*", element: <OrgNotFound /> },
        ],
      },
      { path: "*", element: <NotFoundPage /> },
    ],
  },
];

export function App({ authFailed }: { authFailed: boolean }) {
  const [qc] = useState(createQueryClient);
  const [router] = useState(() => createBrowserRouter(appRoutes));
  return (
    <QueryClientProvider client={qc}>
      <AuthGate authFailed={authFailed}>
        <RouterProvider router={router} />
      </AuthGate>
      <Toaster />
    </QueryClientProvider>
  );
}
