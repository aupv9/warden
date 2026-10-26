import { initials } from "../lib/format";

// Avatar backgrounds all keep white initials at ≥ 4.5:1. The colour is picked from the name, so
// a person keeps the same colour everywhere. Avatars are decorative: the name is always next to
// them (or in the accessible name of the control around them).
const AVATAR_COLORS = ["#4F46E5", "#0F766E", "#B45309", "#7C3AED", "#BE185D", "#1D4ED8", "#15803D", "#C2410C"];

// Project dots are decorative too (the name and key are next to them).
const PROJECT_COLORS = ["#4F46E5", "#0EA5A4", "#D97706", "#E5484D", "#7C3AED", "#2B9A66", "#0284C7", "#DB2777", "#65A30D"];

/** FNV-1a with a final bit mix, so short keys (WEB, PAY) spread over the palette. */
export function hashIndex(s: string, n: number): number {
  let h = 0x811c9dc5;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  h ^= h >>> 15;
  h = Math.imul(h, 0x2c1b3c6d) >>> 0;
  h ^= h >>> 12;
  return (h >>> 0) % n;
}

export function Avatar({ name, size = 20 }: { name: string; size?: number }) {
  return (
    <span
      className="avatar"
      aria-hidden="true"
      style={{
        width: size,
        height: size,
        fontSize: Math.max(9, Math.round(size * 0.45)),
        background: AVATAR_COLORS[hashIndex(name, AVATAR_COLORS.length)],
      }}
    >
      {initials(name)}
    </span>
  );
}

export function ProjectDot({ projectKey }: { projectKey: string }) {
  return <span className="project-dot" aria-hidden="true" style={{ background: PROJECT_COLORS[hashIndex(projectKey, PROJECT_COLORS.length)] }} />;
}
