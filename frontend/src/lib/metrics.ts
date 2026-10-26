import type { DayCount, Metrics, OpenByDay } from "../api/types";

// Pure helpers for the Overview page (contract E). Dates in the metrics are calendar days
// ("2026-10-26", UTC), so they are formatted in UTC to avoid shifting a day.

export const TREND_KEYS = ["critical", "high", "medium", "low"] as const;
export type TrendKey = (typeof TREND_KEYS)[number];

export function dayLabel(date: string, withYear = false): string {
  const d = new Date(`${date}T00:00:00Z`);
  if (Number.isNaN(d.getTime())) return date;
  return d.toLocaleDateString("en-US", { month: "short", day: "numeric", timeZone: "UTC", ...(withYear ? { year: "numeric" } : {}) });
}

export interface Bucket {
  /** First and last calendar day in the bucket. */
  start: string;
  end: string;
  label: string;
  added: number;
  fixed: number;
}

/** New vs fixed per day for 30 days, per week (7-day buckets ending on the last day) beyond
 *  that, so 90 and 180 days stay readable as columns. */
export function bucketNewFixed(added: DayCount[], fixed: DayCount[], days: number): Bucket[] {
  const size = days > 30 ? 7 : 1;
  const fixedBy = new Map(fixed.map((d) => [d.date, d.count]));
  const out: Bucket[] = [];
  // Walk from the end so the last bucket is a full, current week.
  for (let end = added.length; end > 0; end -= size) {
    const slice = added.slice(Math.max(0, end - size), end);
    const first = slice[0];
    const last = slice[slice.length - 1];
    if (!first || !last) continue;
    out.unshift({
      start: first.date,
      end: last.date,
      label: size === 1 ? dayLabel(first.date) : `${dayLabel(first.date)} – ${dayLabel(last.date)}`,
      added: slice.reduce((n, d) => n + d.count, 0),
      fixed: slice.reduce((n, d) => n + (fixedBy.get(d.date) ?? 0), 0),
    });
  }
  return out;
}

export function sum(list: DayCount[]): number {
  return list.reduce((n, d) => n + d.count, 0);
}

export function openTotal(d: OpenByDay | undefined): number {
  return d ? d.critical + d.high + d.medium + d.low : 0;
}

export interface SlaShare {
  total: number;
  inTime: number;
  late: number;
  overdue: number;
  /** Share of SLA outcomes that met the SLA: fixed in time ÷ (fixed in time + fixed late + open past SLA). */
  compliance: number | null;
}

export function slaShare(sla: Metrics["sla"]): SlaShare {
  const total = sla.fixed_in_time + sla.fixed_late + sla.open_overdue;
  const pct = (n: number) => (total ? n / total : 0);
  return {
    total,
    inTime: pct(sla.fixed_in_time),
    late: pct(sla.fixed_late),
    overdue: pct(sla.open_overdue),
    compliance: total ? sla.fixed_in_time / total : null,
  };
}

export function percent(x: number | null): string {
  if (x === null) return "–";
  const p = x * 100;
  return `${p > 0 && p < 1 ? "<1" : Math.round(p)}%`;
}

/** "31 hours", "4.2 days", "No fixes". */
export function formatHours(h: number | null): string {
  if (h === null) return "No fixes";
  if (h < 48) return `${Math.round(h)} ${Math.round(h) === 1 ? "hour" : "hours"}`;
  const d = h / 24;
  return `${d < 10 ? d.toFixed(1) : Math.round(d)} days`;
}

/** A "nice" axis maximum: 1, 2, 2.5 or 5 times a power of ten, at least `v`. */
export function niceMax(v: number): number {
  if (v <= 0) return 1;
  const p = 10 ** Math.floor(Math.log10(v));
  for (const m of [1, 2, 2.5, 5, 10]) if (m * p >= v) return m * p;
  return 10 * p;
}

export function signed(n: number): string {
  return n > 0 ? `+${n}` : n < 0 ? `−${-n}` : "±0";
}
