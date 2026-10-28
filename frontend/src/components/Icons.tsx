// Decorative icons: aria-hidden; the control or text next to them carries the meaning.

type P = { size?: number };

function Svg({ size = 16, children, strokeWidth = 2 }: { size?: number; children: React.ReactNode; strokeWidth?: number }) {
  return (
    <svg
      aria-hidden="true"
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={strokeWidth}
      strokeLinecap="round"
      strokeLinejoin="round"
      style={{ flex: "0 0 auto" }}
    >
      {children}
    </svg>
  );
}

/** The Warden mark: a filled ink shield with a white check. */
export function ShieldIcon({ size = 20 }: P) {
  return (
    <svg aria-hidden="true" width={size} height={size} viewBox="0 0 24 24" style={{ flex: "0 0 auto" }}>
      <path d="M12 2l8 3.5v6c0 5-3.4 9.3-8 10.5-4.6-1.2-8-5.5-8-10.5v-6L12 2z" fill="var(--ink)" />
      <path d="M9 12l2 2 4-4" stroke="var(--surface)" strokeWidth="2" fill="none" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

export function SearchIcon({ size = 14 }: P) {
  return (
    <Svg size={size}>
      <circle cx="11" cy="11" r="7" />
      <path d="M20 20l-3.5-3.5" />
    </Svg>
  );
}

export function UploadIcon({ size = 24 }: P) {
  return (
    <Svg size={size} strokeWidth={1.75}>
      <path d="M12 16V4" />
      <path d="M7 9l5-5 5 5" />
      <path d="M4 16v3a1 1 0 001 1h14a1 1 0 001-1v-3" />
    </Svg>
  );
}

export function CloseIcon({ size = 16 }: P) {
  return (
    <Svg size={size}>
      <path d="M6 6l12 12M18 6L6 18" />
    </Svg>
  );
}

export function CheckIcon({ size = 16 }: P) {
  return (
    <Svg size={size}>
      <path d="M5 12l5 5 9-10" />
    </Svg>
  );
}

export function AlertIcon({ size = 16 }: P) {
  return (
    <Svg size={size}>
      <circle cx="12" cy="12" r="9" />
      <path d="M12 7.5v5.5M12 16.5v.01" />
    </Svg>
  );
}

export function ClockIcon({ size = 16 }: P) {
  return (
    <Svg size={size}>
      <circle cx="12" cy="12" r="9" />
      <path d="M12 7v5l3 2" />
    </Svg>
  );
}

export function RefreshIcon({ size = 16 }: P) {
  return (
    <Svg size={size}>
      <path d="M20 11a8 8 0 10-2.3 5.7" />
      <path d="M20 4v7h-7" />
    </Svg>
  );
}

export function LockIcon({ size = 16 }: P) {
  return (
    <Svg size={size}>
      <rect x="5" y="11" width="14" height="10" rx="2" />
      <path d="M8 11V8a4 4 0 018 0v3" />
    </Svg>
  );
}

export function MenuIcon({ size = 20 }: P) {
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

export function FilterIcon({ size = 14 }: P) {
  return (
    <Svg size={size}>
      <path d="M4 6h16M7 12h10M10 18h4" />
    </Svg>
  );
}

export function ChevronIcon({ size = 14, up }: P & { up?: boolean }) {
  return (
    <Svg size={size}>
      <path d={up ? "M6 15l6-6 6 6" : "M6 9l6 6 6-6"} />
    </Svg>
  );
}

export function ChevronRightIcon({ size = 14 }: P) {
  return (
    <Svg size={size}>
      <path d="M9 6l6 6-6 6" />
    </Svg>
  );
}

export function UpDownIcon({ size = 14 }: P) {
  return (
    <Svg size={size}>
      <path d="M7 10l5-5 5 5M7 14l5 5 5-5" />
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

export function PlusIcon({ size = 14 }: P) {
  return (
    <Svg size={size}>
      <path d="M12 5v14M5 12h14" />
    </Svg>
  );
}

export function BuildingIcon({ size = 20 }: P) {
  return (
    <Svg size={size}>
      <path d="M4 21V8l8-5 8 5v13" />
      <path d="M9 21v-6h6v6" />
    </Svg>
  );
}

// Navigation icons (15 px in the sidebar).
export function IssuesIcon({ size = 15 }: P) {
  return (
    <Svg size={size}>
      <circle cx="12" cy="12" r="9" />
      <circle cx="12" cy="12" r="3" />
    </Svg>
  );
}

/** v0.4: a package (the component inventory). */
export function PackageIcon({ size = 15 }: P) {
  return (
    <Svg size={size}>
      <path d="M12 3l8 4.5v9L12 21l-8-4.5v-9L12 3z" />
      <path d="M4 7.5l8 4.5 8-4.5" />
      <path d="M12 12v9" />
    </Svg>
  );
}

export function ProjectsIcon({ size = 15 }: P) {
  return (
    <Svg size={size}>
      <rect x="3.5" y="3.5" width="7" height="7" rx="1.5" />
      <rect x="13.5" y="3.5" width="7" height="7" rx="1.5" />
      <rect x="3.5" y="13.5" width="7" height="7" rx="1.5" />
      <rect x="13.5" y="13.5" width="7" height="7" rx="1.5" />
    </Svg>
  );
}

export function ExceptionsIcon({ size = 15 }: P) {
  return (
    <Svg size={size}>
      <path d="M12 3l8 4v5c0 4.4-3.4 8.4-8 9-4.6-.6-8-4.6-8-9V7l8-4z" />
    </Svg>
  );
}

export function MembersIcon({ size = 15 }: P) {
  return (
    <Svg size={size}>
      <circle cx="9" cy="8" r="3.5" />
      <path d="M2.5 20c.6-3.6 3.2-5.5 6.5-5.5s5.9 1.9 6.5 5.5" />
      <path d="M16 4.8a3.5 3.5 0 010 6.4M18 14.8c2 .7 3.2 2.4 3.5 5.2" />
    </Svg>
  );
}

export function AuditIcon({ size = 15 }: P) {
  return (
    <Svg size={size}>
      <path d="M6 3h9l4 4v14H6z" />
      <path d="M9 11h7M9 15h7M9 7h3" />
    </Svg>
  );
}

export function SignOutIcon({ size = 15 }: P) {
  return (
    <Svg size={size}>
      <path d="M15 4h4v16h-4" />
      <path d="M10 16l-4-4 4-4M6 12h10" />
    </Svg>
  );
}

export function SystemThemeIcon({ size = 14 }: P) {
  return (
    <Svg size={size}>
      <rect x="3" y="4" width="18" height="12" rx="2" />
      <path d="M8 20h8M12 16v4" />
    </Svg>
  );
}

export function SunIcon({ size = 14 }: P) {
  return (
    <Svg size={size}>
      <circle cx="12" cy="12" r="4" />
      <path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4" />
    </Svg>
  );
}

export function MoonIcon({ size = 14 }: P) {
  return (
    <Svg size={size}>
      <path d="M20 14.5A8 8 0 019.5 4a8 8 0 1010.5 10.5z" />
    </Svg>
  );
}

// ---- v0.2 ----

export function OverviewIcon({ size = 15 }: P) {
  return (
    <Svg size={size}>
      <path d="M4 20V10M10 20V4M16 20v-7M21 20H3" />
    </Svg>
  );
}

export function SettingsIcon({ size = 15 }: P) {
  return (
    <Svg size={size}>
      <path d="M4 7h10M18 7h2M4 17h2M10 17h10" />
      <circle cx="16" cy="7" r="2" />
      <circle cx="8" cy="17" r="2" />
    </Svg>
  );
}

export function BellIcon({ size = 16 }: P) {
  return (
    <Svg size={size}>
      <path d="M6 16V11a6 6 0 0112 0v5l1.5 2h-15L6 16z" />
      <path d="M10 21h4" />
    </Svg>
  );
}

export function ArchiveIcon({ size = 16 }: P) {
  return (
    <Svg size={size}>
      <rect x="3" y="4" width="18" height="4" rx="1" />
      <path d="M5 8v11a1 1 0 001 1h12a1 1 0 001-1V8M10 12h4" />
    </Svg>
  );
}

export function KeyIcon({ size = 16 }: P) {
  return (
    <Svg size={size}>
      <circle cx="8" cy="15" r="4" />
      <path d="M11 12l9-9M17 6l3 3M15 8l2 2" />
    </Svg>
  );
}

export function CopyIcon({ size = 14 }: P) {
  return (
    <Svg size={size}>
      <rect x="9" y="9" width="11" height="11" rx="2" />
      <path d="M5 15V5a1 1 0 011-1h10" />
    </Svg>
  );
}

export function ArrowUpIcon({ size = 14 }: P) {
  return (
    <Svg size={size}>
      <path d="M12 19V5M6 11l6-6 6 6" />
    </Svg>
  );
}

export function ArrowDownIcon({ size = 14 }: P) {
  return (
    <Svg size={size}>
      <path d="M12 5v14M6 13l6 6 6-6" />
    </Svg>
  );
}

export function DownloadIcon({ size = 14 }: P) {
  return (
    <Svg size={size}>
      <path d="M12 4v12" />
      <path d="M7 11l5 5 5-5" />
      <path d="M4 16v3a1 1 0 001 1h14a1 1 0 001-1v-3" />
    </Svg>
  );
}

export function TrashIcon({ size = 14 }: P) {
  return (
    <Svg size={size}>
      <path d="M4 7h16M10 11v6M14 11v6M6 7l1 13h10l1-13M9 7V4h6v3" />
    </Svg>
  );
}
