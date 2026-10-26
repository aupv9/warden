// Decorative icons: aria-hidden; the control or text next to them carries the meaning.

type P = { size?: number };

function Svg({ size = 18, children, stroke = "currentColor" }: { size?: number; children: React.ReactNode; stroke?: string }) {
  return (
    <svg aria-hidden="true" width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={stroke} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" style={{ flex: "0 0 auto" }}>
      {children}
    </svg>
  );
}

export function ShieldIcon({ size = 28 }: P) {
  return (
    <svg aria-hidden="true" width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="#2DD4BF" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round" style={{ flex: "0 0 auto" }}>
      <path d="M12 3l7 3v5c0 4.5-3 8.5-7 10-4-1.5-7-5.5-7-10V6l7-3z" />
      <path d="M9 12l2 2 4-4" />
    </svg>
  );
}

export function SearchIcon({ size = 16 }: P) {
  return (
    <Svg size={size}>
      <circle cx="11" cy="11" r="7" />
      <path d="M20 20l-3.5-3.5" />
    </Svg>
  );
}

export function UploadIcon({ size = 28 }: P) {
  return (
    <Svg size={size} stroke="#0F766E">
      <path d="M12 16V4" />
      <path d="M7 9l5-5 5 5" />
      <path d="M4 16v3a1 1 0 001 1h14a1 1 0 001-1v-3" />
    </Svg>
  );
}

export function CloseIcon({ size = 18 }: P) {
  return (
    <Svg size={size}>
      <path d="M6 6l12 12M18 6L6 18" />
    </Svg>
  );
}

export function CheckIcon({ size = 18 }: P) {
  return (
    <Svg size={size}>
      <path d="M5 12l5 5 9-10" />
    </Svg>
  );
}

export function AlertIcon({ size = 18 }: P) {
  return (
    <Svg size={size}>
      <circle cx="12" cy="12" r="9" />
      <path d="M12 7.5v5.5M12 16.5v.01" />
    </Svg>
  );
}

export function ClockIcon({ size = 18 }: P) {
  return (
    <Svg size={size}>
      <circle cx="12" cy="12" r="9" />
      <path d="M12 7v5l3 2" />
    </Svg>
  );
}

export function RefreshIcon({ size = 18 }: P) {
  return (
    <Svg size={size}>
      <path d="M20 11a8 8 0 10-2.3 5.7" />
      <path d="M20 4v7h-7" />
    </Svg>
  );
}

export function LockIcon({ size = 18 }: P) {
  return (
    <Svg size={size}>
      <rect x="5" y="11" width="14" height="10" rx="2" />
      <path d="M8 11V8a4 4 0 018 0v3" />
    </Svg>
  );
}

export function MenuIcon({ size = 22 }: P) {
  return (
    <Svg size={size}>
      <path d="M4 7h16M4 12h16M4 17h16" />
    </Svg>
  );
}

export function FileIcon({ size = 16 }: P) {
  return (
    <Svg size={size}>
      <path d="M14 3H6a1 1 0 00-1 1v16a1 1 0 001 1h12a1 1 0 001-1V8z" />
      <path d="M14 3v5h5" />
    </Svg>
  );
}

export function FilterIcon({ size = 16 }: P) {
  return (
    <Svg size={size}>
      <path d="M4 6h16M7 12h10M10 18h4" />
    </Svg>
  );
}

export function ChevronIcon({ size = 16, up }: P & { up?: boolean }) {
  return (
    <Svg size={size}>
      <path d={up ? "M6 15l6-6 6 6" : "M6 9l6 6 6-6"} />
    </Svg>
  );
}

export function BackIcon({ size = 16 }: P) {
  return (
    <Svg size={size}>
      <path d="M15 6l-6 6 6 6" />
    </Svg>
  );
}

export function BuildingIcon({ size = 22 }: P) {
  return (
    <Svg size={size}>
      <path d="M4 21V8l8-5 8 5v13" />
      <path d="M9 21v-6h6v6" />
    </Svg>
  );
}
