import { vi } from "vitest";

// auth/oidc builds a UserManager from window.location at import time; tests run in Node, and
// no test needs a real IdP. Tests that care about tokens pass their own ApiDeps to api().
vi.mock("../auth/oidc", () => ({
  accessToken: async () => null,
  refreshAccessToken: async () => null,
  userManager: {},
}));
