import { vi } from "vitest";

// auth/oidc would fetch GET /web-config and build a UserManager on first use; tests run in Node,
// and no screen test needs a real IdP. Tests that care about tokens pass their own ApiDeps to
// api(); src/auth/*.test.ts test the real module (vi.importActual).
vi.mock("../auth/oidc", () => ({
  accessToken: async () => null,
  refreshAccessToken: async () => null,
  getUserManager: () => new Promise(() => {}),
}));
