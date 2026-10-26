import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { App } from "./App";
import { userManager } from "./auth/oidc";

async function boot() {
  if (new URLSearchParams(window.location.search).has("code")) {
    await userManager.signinRedirectCallback();
    window.history.replaceState({}, "", "/");
  }
  createRoot(document.getElementById("root")!).render(
    <StrictMode>
      <QueryClientProvider client={new QueryClient()}>
        <App />
      </QueryClientProvider>
    </StrictMode>,
  );
}

void boot();
