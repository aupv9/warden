import type { ReactNode } from "react";
import type { IssueStatus, ScanStatus, Severity, ToolStatus } from "../api/types";
import { SCAN_STATUS_LABELS, SEVERITY_LABELS, STATUS_LABELS, TOOL_STATUS_LABELS } from "../lib/format";

type Tone = "default" | "success" | "accent" | "danger" | "warn";

export function Pill({ tone = "default", children, title }: { tone?: Tone; children: ReactNode; title?: string }) {
  return (
    <span className={tone === "default" ? "pill" : `pill pill-${tone}`} title={title}>
      {children}
    </span>
  );
}

/** Severity always carries its label: never color alone (DESIGN.md). */
export function SeverityBadge({ severity, count }: { severity: Severity; count?: number }) {
  return (
    <span className={`sev sev-${severity}`}>
      {count !== undefined ? `${count} ${SEVERITY_LABELS[severity]}` : SEVERITY_LABELS[severity]}
    </span>
  );
}

export function StatusPill({ status }: { status: IssueStatus }) {
  const tone: Tone = status === "fixed" || status === "verified" ? "success" : "default";
  return <Pill tone={tone}>{STATUS_LABELS[status]}</Pill>;
}

export function ScanStatusPill({ status, rejected, children }: { status: ScanStatus; rejected?: boolean; children?: ReactNode }) {
  if (rejected) return <Pill tone="danger">Rejected</Pill>;
  const tone: Tone =
    status === "completed" ? "success" : status === "failed" ? "danger" : status === "partial" ? "warn" : status === "running" || status === "queued" ? "accent" : "default";
  return <Pill tone={tone}>{children ?? SCAN_STATUS_LABELS[status]}</Pill>;
}

export function ToolStatusPill({ status }: { status: ToolStatus }) {
  const tone: Tone =
    status === "succeeded" ? "success" : status === "failed" || status === "timeout" ? "danger" : status === "running" ? "accent" : "default";
  return <Pill tone={tone}>{TOOL_STATUS_LABELS[status]}</Pill>;
}
