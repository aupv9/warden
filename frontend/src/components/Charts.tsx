import { useEffect, useId, useRef, useState } from "react";
import type { KeyboardEvent, PointerEvent as ReactPointerEvent, ReactNode } from "react";
import { SEVERITY_LABELS } from "../lib/format";
import type { Bucket, TrendKey } from "../lib/metrics";
import { dayLabel, niceMax, signed, TREND_KEYS } from "../lib/metrics";
import type { OpenByDay } from "../api/types";

// Hand-drawn SVG charts for the Overview page (no chart library). Marks follow the dataviz
// rules: 2 px lines with a 10 % area wash, columns ≤ 24 px with a 4 px rounded data end,
// hairline solid grid, text in text colours (never the series colour), a legend for two or
// more series, a hover layer, and an always-available table (in each chart's card). Colours
// come from the theme tokens, so light and dark both work. Labels are rendered as text nodes.

/** The element's content width, following resizes. Falls back to `initial` before layout
 *  (and in server rendering). */
export function useWidth<T extends HTMLElement>(initial = 320) {
  const ref = useRef<T>(null);
  const [width, setWidth] = useState(initial);
  useEffect(() => {
    const el = ref.current;
    if (!el || typeof ResizeObserver === "undefined") return;
    const ro = new ResizeObserver(([entry]) => {
      if (entry) setWidth(Math.max(120, Math.floor(entry.contentRect.width)));
    });
    ro.observe(el);
    return () => ro.disconnect();
  }, []);
  return [ref, width] as const;
}

export const SEV_COLOR: Record<TrendKey, string> = {
  critical: "var(--sev-critical)",
  high: "var(--sev-high)",
  medium: "var(--sev-medium)",
  low: "var(--sev-low)",
};

// ---------------------------------------------------------------------------------------
// Open issues by severity: small multiples. The four severity colours are close together
// (Critical/High especially), so instead of a stacked area each severity gets its own panel,
// named by its label; colour is only a secondary cue. Each panel has its own y scale, stated
// on the axis. One crosshair runs through all panels and every panel header shows the value
// at that day.
// ---------------------------------------------------------------------------------------

const PANEL_H = 96;
const PAD = { top: 8, right: 8, bottom: 4, left: 30 };

export function TrendPanels({ data, label }: { data: OpenByDay[]; label: string }) {
  const [hover, setHover] = useState<number | null>(null);
  const n = data.length;
  const first = data[0];
  const last = data[n - 1];
  const onKey = (e: KeyboardEvent<HTMLDivElement>) => {
    if (!n) return;
    const cur = hover ?? n - 1;
    const step = e.shiftKey ? 7 : 1;
    if (e.key === "ArrowLeft") setHover(Math.max(0, cur - step));
    else if (e.key === "ArrowRight") setHover(Math.min(n - 1, cur + step));
    else if (e.key === "Home") setHover(0);
    else if (e.key === "End") setHover(n - 1);
    else if (e.key === "Escape") setHover(null);
    else return;
    e.preventDefault();
  };
  return (
    <div
      className="trend-panels"
      role="group"
      aria-label={`${label}. Use the left and right arrow keys to read each day.`}
      tabIndex={0}
      onKeyDown={onKey}
      onBlur={() => setHover(null)}
    >
      {TREND_KEYS.map((k) => (
        <TrendPanel key={k} k={k} data={data} hover={hover} onHover={setHover} />
      ))}
      {first && last && (
        <div className="trend-x" aria-hidden="true">
          <span>{dayLabel(first.date)}</span>
          <span>{hover !== null && data[hover] ? dayLabel(data[hover].date, true) : ""}</span>
          <span>{dayLabel(last.date)}</span>
        </div>
      )}
    </div>
  );
}

function TrendPanel({ k, data, hover, onHover }: { k: TrendKey; data: OpenByDay[]; hover: number | null; onHover: (i: number | null) => void }) {
  const [ref, width] = useWidth<HTMLDivElement>();
  const clipId = useId();
  const n = data.length;
  const values = data.map((d) => d[k]);
  const max = niceMax(Math.max(1, ...values));
  const w = width;
  const iw = Math.max(1, w - PAD.left - PAD.right);
  const ih = PANEL_H - PAD.top - PAD.bottom;
  const x = (i: number) => PAD.left + (n <= 1 ? iw / 2 : (i / (n - 1)) * iw);
  const y = (v: number) => PAD.top + ih - (v / max) * ih;
  const line = values.map((v, i) => `${i ? "L" : "M"}${x(i).toFixed(1)},${y(v).toFixed(1)}`).join("");
  const area = n ? `${line}L${x(n - 1).toFixed(1)},${y(0)}L${x(0).toFixed(1)},${y(0)}Z` : "";
  const shownIdx = hover ?? n - 1;
  const shown = values[shownIdx] ?? 0;
  const start = values[0] ?? 0;
  const end = values[n - 1] ?? 0;

  const onMove = (e: ReactPointerEvent<SVGRectElement>) => {
    const box = e.currentTarget.getBoundingClientRect();
    const rel = (e.clientX - box.left) / Math.max(1, box.width);
    onHover(Math.max(0, Math.min(n - 1, Math.round(rel * (n - 1)))));
  };

  return (
    <div className="trend-panel" ref={ref}>
      <div className="trend-head">
        <span className="sev">
          <span className={`sev-dot sev-${k}`} aria-hidden="true" />
          {SEVERITY_LABELS[k]}
        </span>
        <span className="trend-value num">{shown}</span>
        <span className="trend-delta">
          {hover === null ? `${signed(end - start)} in ${n} days` : dayLabel(data[shownIdx]?.date ?? "")}
        </span>
      </div>
      <svg width={w} height={PANEL_H} aria-hidden="true" className="chart-svg">
        <defs>
          <clipPath id={clipId}>
            <rect x={PAD.left} y={0} width={iw} height={PANEL_H} />
          </clipPath>
        </defs>
        <line className="grid-line" x1={PAD.left} x2={w - PAD.right} y1={y(max)} y2={y(max)} />
        <line className="axis-line" x1={PAD.left} x2={w - PAD.right} y1={y(0)} y2={y(0)} />
        <text className="axis-text" x={PAD.left - 6} y={y(max) + 4} textAnchor="end">
          {max}
        </text>
        <text className="axis-text" x={PAD.left - 6} y={y(0)} textAnchor="end">
          0
        </text>
        <g clipPath={`url(#${clipId})`}>
          <path d={area} fill={SEV_COLOR[k]} opacity={0.1} />
          <path d={line} fill="none" stroke={SEV_COLOR[k]} strokeWidth={2} strokeLinejoin="round" strokeLinecap="round" />
        </g>
        {hover !== null && <line className="crosshair" x1={x(hover)} x2={x(hover)} y1={PAD.top - 4} y2={y(0)} />}
        {n > 0 && (
          <circle
            cx={x(shownIdx)}
            cy={y(shown)}
            r={4}
            fill={SEV_COLOR[k]}
            stroke="var(--surface)"
            strokeWidth={2}
          />
        )}
        <rect
          x={PAD.left}
          y={0}
          width={iw}
          height={PANEL_H}
          fill="transparent"
          onPointerMove={onMove}
          onPointerLeave={() => onHover(null)}
        />
      </svg>
    </div>
  );
}

// ---------------------------------------------------------------------------------------
// New vs fixed: diverging columns around one zero line (new up, fixed down), on one scale.
// ---------------------------------------------------------------------------------------

const NF_H = 200;
const NF_PAD = { top: 10, right: 8, bottom: 22, left: 34 };

/** A column with a 4 px rounded data end and a square base on the zero line. */
function columnPath(x: number, w: number, base: number, tip: number): string {
  const h = Math.abs(base - tip);
  if (h < 0.5) return "";
  const r = Math.min(4, w / 2, h);
  if (tip < base) {
    return `M${x},${base}V${tip + r}Q${x},${tip} ${x + r},${tip}H${x + w - r}Q${x + w},${tip} ${x + w},${tip + r}V${base}Z`;
  }
  return `M${x},${base}V${tip - r}Q${x},${tip} ${x + r},${tip}H${x + w - r}Q${x + w},${tip} ${x + w},${tip - r}V${base}Z`;
}

export function NewFixedChart({ buckets, perWeek }: { buckets: Bucket[]; perWeek: boolean }) {
  const [ref, width] = useWidth<HTMLDivElement>(640);
  const [hover, setHover] = useState<number | null>(null);
  const n = buckets.length;
  const max = niceMax(Math.max(1, ...buckets.map((b) => Math.max(b.added, b.fixed))));
  const iw = Math.max(1, width - NF_PAD.left - NF_PAD.right);
  const ih = NF_H - NF_PAD.top - NF_PAD.bottom;
  const mid = NF_PAD.top + ih / 2;
  const half = ih / 2;
  const slot = iw / Math.max(1, n);
  const colW = Math.max(2, Math.min(24, slot - 2));
  const scale = (v: number) => (v / max) * (half - 2);
  const labelEvery = Math.max(1, Math.ceil(n / Math.max(2, Math.floor(iw / 90))));
  const hb = hover !== null ? buckets[hover] : undefined;
  const tipLeft = hover !== null ? Math.min(Math.max(NF_PAD.left + slot * (hover + 0.5), 90), width - 90) : 0;

  return (
    <div className="chart-box" ref={ref}>
      <svg width={width} height={NF_H} aria-hidden="true" className="chart-svg">
        <line className="grid-line" x1={NF_PAD.left} x2={width - NF_PAD.right} y1={mid - half + 2} y2={mid - half + 2} />
        <line className="grid-line" x1={NF_PAD.left} x2={width - NF_PAD.right} y1={mid + half - 2} y2={mid + half - 2} />
        <text className="axis-text" x={NF_PAD.left - 6} y={mid - half + 6} textAnchor="end">
          {max}
        </text>
        <text className="axis-text" x={NF_PAD.left - 6} y={mid + 4} textAnchor="end">
          0
        </text>
        <text className="axis-text" x={NF_PAD.left - 6} y={mid + half + 2} textAnchor="end">
          {max}
        </text>
        {buckets.map((b, i) => {
          const cx = NF_PAD.left + slot * i + (slot - colW) / 2;
          const on = hover === i;
          return (
            <g key={b.start} className={hover !== null && !on ? "col dim" : "col"}>
              <path d={columnPath(cx, colW, mid - 1, mid - 1 - scale(b.added))} fill="var(--accent)" />
              <path d={columnPath(cx, colW, mid + 1, mid + 1 + scale(b.fixed))} fill="var(--st-verified)" />
              {i % labelEvery === 0 && (
                <text className="axis-text" x={NF_PAD.left + slot * i + slot / 2} y={NF_H - 6} textAnchor="middle">
                  {dayLabel(b.start)}
                </text>
              )}
              <rect
                x={NF_PAD.left + slot * i}
                y={NF_PAD.top}
                width={slot}
                height={ih}
                fill="transparent"
                onPointerEnter={() => setHover(i)}
                onPointerLeave={() => setHover(null)}
              />
            </g>
          );
        })}
        <line className="axis-line" x1={NF_PAD.left} x2={width - NF_PAD.right} y1={mid} y2={mid} />
      </svg>
      {hb && (
        <div className="chart-tip" style={{ left: tipLeft }} role="presentation">
          <span className="tip-head">{perWeek ? `Week ${hb.label}` : hb.label}</span>
          <span className="tip-row">
            <span className="tip-key" style={{ background: "var(--accent)" }} />
            <strong className="num">{hb.added}</strong> new
          </span>
          <span className="tip-row">
            <span className="tip-key" style={{ background: "var(--st-verified)" }} />
            <strong className="num">{hb.fixed}</strong> fixed
          </span>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------------------
// Small building blocks
// ---------------------------------------------------------------------------------------

export function Legend({ items }: { items: { color: string; label: ReactNode; shape?: "rect" | "line" }[] }) {
  return (
    <ul className="legend" aria-label="Legend">
      {items.map((it, i) => (
        <li key={i}>
          <span className={it.shape === "line" ? "legend-line" : "legend-swatch"} style={{ background: it.color }} aria-hidden="true" />
          {it.label}
        </li>
      ))}
    </ul>
  );
}

/** Horizontal bars, one per row, each value written at the bar's tip. */
export function BarRows({ rows, max }: { rows: { key: string; label: ReactNode; value: number | null; text: string }[]; max: number }) {
  return (
    <ul className="bar-rows">
      {rows.map((r) => (
        <li key={r.key}>
          <span className="bar-label">{r.label}</span>
          <span className="bar-track">
            {r.value !== null && <span className="bar-fill" style={{ width: `${Math.max(1.5, (r.value / max) * 100)}%` }} />}
            <span className={r.value === null ? "bar-value faint" : "bar-value"}>{r.text}</span>
          </span>
        </li>
      ))}
    </ul>
  );
}

/** A 100 % stacked bar with 2 px gaps between the segments. */
export function StackedBar({ parts, label }: { parts: { key: string; share: number; color: string; title: string }[]; label: string }) {
  const visible = parts.filter((p) => p.share > 0);
  return (
    <div className="stacked-bar" role="img" aria-label={label}>
      {visible.map((p) => (
        <span key={p.key} className="stacked-seg" title={p.title} style={{ flexGrow: p.share, background: p.color }} />
      ))}
      {visible.length === 0 && <span className="stacked-empty" />}
    </div>
  );
}
