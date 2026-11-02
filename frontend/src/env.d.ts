interface ImportMetaEnv {
  /** "1" with `npm run dev` serves contract-shaped fixtures instead of the API. Ignored in builds. */
  readonly VITE_MOCK?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
