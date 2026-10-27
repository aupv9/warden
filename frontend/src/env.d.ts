interface ImportMetaEnv {
  readonly VITE_OIDC_ISSUER?: string;
  readonly VITE_OIDC_CLIENT_ID?: string;
  /** "1" with `npm run dev` serves contract-shaped fixtures instead of the API. Ignored in builds. */
  readonly VITE_MOCK?: string;
  readonly VITE_OIDC_SCOPE?: string;
  readonly VITE_OIDC_AUDIENCE?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
