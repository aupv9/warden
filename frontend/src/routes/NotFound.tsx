import { isRouteErrorResponse, useRouteError } from "react-router";

/** Last-resort boundary for render errors. Shows no error detail (it could contain data). */
export function RouteError() {
  const err = useRouteError();
  const notFound = isRouteErrorResponse(err) && err.status === 404;
  return (
    <main className="center-page">
      <div className="card">
        <h1 style={{ fontSize: 22 }}>{notFound ? "Not found" : "Something went wrong"}</h1>
        <p className="muted">
          {notFound
            ? "This page doesn't exist, or you don't have access to it."
            : "The page hit an unexpected error. Reload to try again."}
        </p>
        <p>
          <a href="/">Back to Warden</a>
        </p>
      </div>
    </main>
  );
}
