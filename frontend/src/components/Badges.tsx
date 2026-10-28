import type { ReactNode } from "react";
import type { IssueStatus, ScanStatus, Severity, ToolStatus } from "../api/types";
import { SCAN_STATUS_LABELS, SEVERITY_LABELS, STATUS_LABELS, TOOL_STATUS_LABELS } from "../lib/format";
import { MALICIOUS_LABEL } from "../lib/malicious";

/** v0.4: a red "Malicious" tag (an OSV malicious-package advisory), with its full accessible
 *  name; the word carries the meaning, the colour is a second cue. */
export function MaliciousTag() {
  return (
    <span className="tag mal-tag" title={MALICIOUS_LABEL}>
      <span aria-hidden="true">Malicious</span>
      <span className="visually-hidden">{MALICIOUS_LABEL}</span>
    </span>
  );
}

type Tone = "default" | "success" | "accent" | "danger" | "warn";

/** A small neutral tag (role, exception type). Square-ish corners: full pills are for counts only. */
export function Pill({ tone = "default", children, title }: { tone?: Tone; children: ReactNode; title?: string }) {
  return (
    <span className={tone === "default" ? "tag" : `tag tag-${tone}`} title={title}>
      {children}
    </span>
  );
}

/** A count in a full pill (navigation, tabs). */
export function Count({ children, label }: { children: ReactNode; label?: string }) {
  return (
    <span className="count">
      {children}
      {label && <span className="visually-hidden"> {label}</span>}
    </span>
  );
}

/** Severity: an 8 px rounded square plus the label. Never colour alone (DESIGN.md). */
export function SeverityMark({ severity, count, quiet }: { severity: Severity; count?: number; quiet?: boolean }) {
  return (
    <span className={quiet ? "sev quiet" : "sev"}>
      <span className={`sev-dot sev-${severity}`} aria-hidden="true" />
      {count !== undefined && <span className="num">{count}</span>}
      {SEVERITY_LABELS[severity]}
    </span>
  );
}

/** The status icon on its own (decorative; the label next to it carries the meaning). */
export function StatusIcon({ status, size = 12 }: { status: IssueStatus; size?: number }) {
  const common = { width: size, height: size, viewBox: "0 0 12 12", "aria-hidden": true as const, className: "st-icon" };
  switch (status) {
    case "open":
      return (
        <svg {...common}>
          <circle cx="6" cy="6" r="4.75" fill="none" stroke="var(--st-open)" strokeWidth="1.5" />
        </svg>
      );
    case "assigned":
      // Half ring: someone owns it, work hasn't started.
      return (
        <svg {...common}>
          <circle cx="6" cy="6" r="4.75" fill="none" stroke="var(--st-track)" strokeWidth="1.5" />
          <path d="M6 1.25 A4.75 4.75 0 0 0 6 10.75" fill="none" stroke="var(--st-progress)" strokeWidth="1.5" />
        </svg>
      );
    case "in_progress":
      // Full ring with a filled quarter: work has started.
      return (
        <svg {...common}>
          <circle cx="6" cy="6" r="4.75" fill="none" stroke="var(--st-progress)" strokeWidth="1.5" />
          <path d="M6 6 V2.75 A3.25 3.25 0 0 1 9.25 6 Z" fill="var(--st-progress)" />
        </svg>
      );
    case "reopened":
      return (
        <svg {...common}>
          <circle cx="6" cy="6" r="4.75" fill="none" stroke="var(--st-reopened)" strokeWidth="1.5" strokeDasharray="2.2 1.6" />
        </svg>
      );
    case "fixed":
    case "verified":
      return (
        <svg {...common}>
          <circle cx="6" cy="6" r="5.5" fill={status === "fixed" ? "var(--st-fixed)" : "var(--st-verified)"} />
          <path d="M3.6 6.1 5.2 7.7 8.4 4.5" fill="none" stroke="#fff" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
      );
    case "false_positive":
    case "risk_accepted":
      return (
        <svg {...common}>
          <circle cx="6" cy="6" r="4.75" fill="none" stroke="var(--st-closed)" strokeWidth="1.5" />
          <path d="M2.9 9.1 9.1 2.9" stroke="var(--st-closed)" strokeWidth="1.5" strokeLinecap="round" />
        </svg>
      );
  }
}

/** Status: a ring icon plus the label. */
export function StatusMark({ status }: { status: IssueStatus }) {
  return (
    <span className="st">
      <StatusIcon status={status} />
      {STATUS_LABELS[status]}
    </span>
  );
}

type DotTone = "neutral" | "accent" | "success" | "warn" | "danger";

/** A small dot plus a label, for scan and scanner states. */
export function DotMark({ tone, children, pulse }: { tone: DotTone; children: ReactNode; pulse?: boolean }) {
  return (
    <span className={`dotmark dot-${tone}`}>
      <span className={pulse ? "dot pulse" : "dot"} aria-hidden="true" />
      {children}
    </span>
  );
}

export function ScanStatusMark({ status, rejected, children }: { status: ScanStatus; rejected?: boolean; children?: ReactNode }) {
  if (rejected) return <DotMark tone="danger">Rejected</DotMark>;
  const tone: DotTone =
    status === "completed"
      ? "success"
      : status === "failed"
        ? "danger"
        : status === "partial"
          ? "warn"
          : status === "running" || status === "queued" || status === "pending_upload"
            ? "accent"
            : "neutral";
  return (
    <DotMark tone={tone} pulse={status === "running"}>
      {children ?? SCAN_STATUS_LABELS[status]}
    </DotMark>
  );
}

export function ToolStatusMark({ status }: { status: ToolStatus }) {
  const tone: DotTone =
    status === "succeeded"
      ? "success"
      : status === "failed" || status === "timeout"
        ? "danger"
        : status === "running" || status === "queued"
          ? "accent"
          : "neutral";
  return (
    <DotMark tone={tone} pulse={status === "running"}>
      {TOOL_STATUS_LABELS[status]}
    </DotMark>
  );
}
