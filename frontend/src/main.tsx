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
import { appBoot } from "./auth/boot";
import { initTheme } from "./lib/theme";

// Before the first render, so an explicit Light/Dark choice doesn't flash the other theme.
initTheme();

// Fetch the sign-in settings (and finish a sign-in redirect) while React renders the splash.
appBoot.start();

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
