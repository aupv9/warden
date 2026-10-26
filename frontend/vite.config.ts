/// <reference types="vitest/config" />
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: { "/api": "http://localhost:8010" },
  },
  build: {
    // No source maps in the shipped bundle.
    sourcemap: false,
    rolldownOptions: {
      output: {
        // Pages are lazy chunks (App.tsx). The libraries every page needs go into a few vendor
        // chunks next to the entry: they change far less often than app code, so browsers keep
        // them cached across Warden upgrades, and they download in parallel (modulepreload).
        codeSplitting: {
          groups: [
            { name: "vendor-react", test: /node_modules[\\/](react|react-dom|scheduler)[\\/]/ },
            { name: "vendor-router", test: /node_modules[\\/](react-router|cookie|set-cookie-parser)[\\/]/ },
            { name: "vendor-query", test: /node_modules[\\/]@tanstack[\\/]/ },
            { name: "vendor-oidc", test: /node_modules[\\/](oidc-client-ts|jwt-decode)[\\/]/ },
          ],
        },
      },
    },
  },
  test: {
    environment: "node",
    setupFiles: ["src/test/setup.ts"],
    include: ["src/**/*.test.ts", "src/**/*.test.tsx"],
  },
});
