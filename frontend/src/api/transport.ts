// Dev-only mock transport (VITE_MOCK=1 with `npm run dev`). `import.meta.env.DEV` is replaced by
// `false` in production builds, so this branch and the dynamic import of the fixtures are removed
// from the bundle; `npm run build` must never contain mock data (checked in the build notes).
//
// Its own module (not client.ts) so auth/webConfig.ts can use it without an import cycle
// (client.ts → auth/oidc.ts → auth/webConfig.ts).
const MOCK = import.meta.env.DEV && import.meta.env.VITE_MOCK === "1";
let mockFetch: Promise<typeof fetch> | undefined;

export function transport(url: string, init: RequestInit): Promise<Response> {
  if (MOCK) {
    mockFetch ??= import("./mock/server").then((m) => m.mockFetch);
    return mockFetch.then((f) => f(url, init));
  }
  return fetch(url, init);
}

export const isMockMode = MOCK;
