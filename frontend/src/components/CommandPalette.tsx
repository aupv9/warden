import { useEffect, useId, useMemo, useRef, useState } from "react";
import type { KeyboardEvent } from "react";
import { useNavigate } from "react-router";
import { useIssues } from "../api/hooks/issues";
import { useProjects } from "../api/hooks/projects";
import { ISSUE_STATUSES } from "../api/types";
import { flattenPages } from "../api/paging";
import { useOrgCtx } from "../layout/OrgLayout";
import { can } from "../lib/permissions";
import { ProjectDot } from "./Avatar";
import { SeverityMark } from "./Badges";
import { SearchIcon } from "./Icons";

interface Item {
  id: string;
  group: "Issues" | "Projects" | "Pages";
  label: string;
  hint?: string;
  to: string;
  render?: () => React.ReactNode;
}

/** ⌘K / Ctrl+K: jump to an issue by key or title, a project, or a page. A modal <dialog> with a
 *  combobox and a listbox (arrow keys move, Enter goes, Esc closes). It only navigates; it never
 *  changes anything. */
export function CommandPalette({ open, onClose }: { open: boolean; onClose: () => void }) {
  const ref = useRef<HTMLDialogElement>(null);
  const opener = useRef<HTMLElement | null>(null);

  useEffect(() => {
    const d = ref.current;
    if (!d) return;
    if (open && !d.open) {
      opener.current = document.activeElement instanceof HTMLElement ? document.activeElement : null;
      d.showModal();
    } else if (!open && d.open) {
      d.close();
    }
    if (!open && opener.current) {
      opener.current.focus();
      opener.current = null;
    }
  }, [open]);

  return (
    <dialog
      ref={ref}
      className="palette"
      aria-label="Search or jump to"
      onCancel={(e) => {
        e.preventDefault();
        onClose();
      }}
      onClick={(e) => {
        if (e.target === ref.current) onClose();
      }}
    >
      {open && <PaletteBody onClose={onClose} />}
    </dialog>
  );
}

function PaletteBody({ onClose }: { onClose: () => void }) {
  const { orgId, org } = useOrgCtx();
  const navigate = useNavigate();
  const projects = useProjects(orgId);
  const [q, setQ] = useState("");
  const [debounced, setDebounced] = useState("");
  const [active, setActive] = useState(0);
  const listId = useId();
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => inputRef.current?.focus(), []);
  useEffect(() => {
    const t = setTimeout(() => setDebounced(q.trim().slice(0, 200)), 200);
    return () => clearTimeout(t);
  }, [q]);

  const issueQuery = useMemo(() => ({ q: debounced, status: ISSUE_STATUSES, limit: 8 }), [debounced]);
  const searchIssues = debounced.length >= 2;
  const issues = useIssues(orgId, issueQuery, searchIssues);

  const term = q.trim().toLowerCase();
  const base = `/orgs/${orgId}`;
  const items: Item[] = useMemo(() => {
    const pages: Item[] = [
      { id: "p-projects", group: "Pages", label: "Projects", to: `${base}/projects` },
      { id: "p-issues", group: "Pages", label: "Issues", to: `${base}/issues` },
      { id: "p-mine", group: "Pages", label: "Issues assigned to me", to: `${base}/issues?assignee=me` },
      { id: "p-sla", group: "Pages", label: "Issues past SLA", to: `${base}/issues?past_sla=true` },
      { id: "p-components", group: "Pages", label: "Components", to: `${base}/components` },
      { id: "p-malicious", group: "Pages", label: "Malicious packages", to: `${base}/issues?kind=malicious` },
      { id: "p-exceptions", group: "Pages", label: "Exceptions", to: `${base}/exceptions` },
      { id: "p-members", group: "Pages", label: "Members", to: `${base}/members` },
      ...(can("view_audit_log", org.role) ? [{ id: "p-audit", group: "Pages" as const, label: "Audit log", to: `${base}/audit-log` }] : []),
    ];
    const found: Item[] = searchIssues
      ? flattenPages(issues.data?.pages).map((i) => ({
          id: `i-${i.id}`,
          group: "Issues",
          label: `${i.key} ${i.title}`,
          to: `${base}/issues/${i.id}`,
          render: () => (
            <>
              <span className="mono faint">{i.key}</span>
              <span className="grow ellipsis">{i.title}</span>
              <SeverityMark severity={i.severity} quiet />
            </>
          ),
        }))
      : [];
    const projectItems: Item[] = (projects.data ?? [])
      .filter((p) => !term || p.name.toLowerCase().includes(term) || p.key.toLowerCase().includes(term))
      .slice(0, 6)
      .map((p) => ({
        id: `pr-${p.id}`,
        group: "Projects",
        label: p.name,
        hint: p.key,
        to: `${base}/projects/${p.id}`,
        render: () => (
          <>
            <ProjectDot projectKey={p.key} />
            <span className="grow ellipsis">{p.name}</span>
            <span className="mono faint">{p.key}</span>
          </>
        ),
      }));
    return [...found, ...projectItems, ...pages.filter((p) => !term || p.label.toLowerCase().includes(term))];
  }, [base, issues.data, org.role, projects.data, searchIssues, term]);

  useEffect(() => setActive(0), [term, items.length]);

  const go = (item: Item | undefined) => {
    if (!item) return;
    onClose();
    navigate(item.to);
  };

  const onKeyDown = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setActive((a) => Math.min(items.length - 1, a + 1));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setActive((a) => Math.max(0, a - 1));
    } else if (e.key === "Enter") {
      e.preventDefault();
      go(items[active]);
    }
  };

  useEffect(() => {
    document.getElementById(`${listId}-${active}`)?.scrollIntoView({ block: "nearest" });
  }, [active, listId]);

  const groups = (["Issues", "Projects", "Pages"] as const).map((g) => ({ g, rows: items.map((it, idx) => ({ it, idx })).filter((x) => x.it.group === g) }));
  const searching = searchIssues && (issues.isFetching || debounced !== q.trim());

  return (
    <div className="palette-body">
      <div className="palette-input">
        <SearchIcon size={16} />
        <input
          ref={inputRef}
          type="text"
          role="combobox"
          aria-label="Search or jump to"
          aria-expanded="true"
          aria-controls={listId}
          aria-autocomplete="list"
          aria-activedescendant={items.length ? `${listId}-${active}` : undefined}
          placeholder="Jump to an issue (WEB-41), a project or a page"
          value={q}
          maxLength={200}
          autoComplete="off"
          spellCheck={false}
          onChange={(e) => setQ(e.target.value)}
          onKeyDown={onKeyDown}
        />
        <button type="button" className="kbd kbd-btn" onClick={onClose} aria-label="Close">
          Esc
        </button>
      </div>
      <div id={listId} role="listbox" aria-label="Results" className="palette-list">
        {groups.map(({ g, rows }) =>
          rows.length === 0 ? null : (
            <div key={g} role="group" aria-label={g}>
              <div className="palette-group" aria-hidden="true">
                {g}
              </div>
              {rows.map(({ it, idx }) => (
                <div
                  key={it.id}
                  id={`${listId}-${idx}`}
                  role="option"
                  aria-selected={idx === active}
                  className={idx === active ? "palette-item active" : "palette-item"}
                  onMouseMove={() => setActive(idx)}
                  onClick={() => go(it)}
                >
                  {it.render ? it.render() : <span className="grow">{it.label}</span>}
                </div>
              ))}
            </div>
          ),
        )}
        {items.length === 0 && !searching && <p className="palette-empty">Nothing matches “{q.trim()}”.</p>}
      </div>
      <p className="palette-foot" aria-live="polite">
        {searching ? "Searching issues…" : searchIssues ? `${flattenPages(issues.data?.pages).length} matching issues` : "Type 2 or more characters to search issues."}
        <span className="palette-keys" aria-hidden="true">
          <kbd className="kbd">↑</kbd> <kbd className="kbd">↓</kbd> move · <kbd className="kbd">↵</kbd> open
        </span>
      </p>
    </div>
  );
}
