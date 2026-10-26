// Fonts are bundled and served by Warden itself (no runtime font CDN).
import "@fontsource/inter/400.css";
import "@fontsource/inter/500.css";
import "@fontsource/inter/600.css";
import "@fontsource/jetbrains-mono/400.css";
import "@fontsource/jetbrains-mono/500.css";
import "./styles/tokens.css";
import "./styles/app.css";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { App } from "./App";
import { isMockMode } from "./api/client";
import { completeSignIn, isAuthCallback } from "./auth/oidc";
import { initTheme } from "./lib/theme";

// Before the first render, so an explicit Light/Dark choice doesn't flash the other theme.
initTheme();

async function boot() {
  let authFailed = false;
  if (!isMockMode && isAuthCallback(window.location.search)) {
    let next = "/";
    try {
      next = await completeSignIn();
    } catch {
      // Any failure (state mismatch, IdP error, expired code) shows one generic message.
      authFailed = true;
    }
    // Drop ?code=&state= from the address bar and history.
    window.history.replaceState({}, "", next);
  }
  createRoot(document.getElementById("root")!).render(
    <StrictMode>
      <App authFailed={authFailed} />
    </StrictMode>,
  );
}

void boot();
