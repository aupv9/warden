import { useState } from "react";
import { Link } from "react-router";
import { useMarkRead, useNotifications, useUnreadCount } from "../api/hooks/notifications";
import { flattenPages } from "../api/paging";
import type { Me, Notification } from "../api/types";
import { relativeTime, userName } from "../lib/format";
import { badgeText, safeAppPath, unreadLabel } from "../lib/notifications";
import { Button } from "./Button";
import { BellIcon, CheckIcon } from "./Icons";
import { Popover } from "./Popover";
import { SkeletonBlock } from "./States";

/** The bell in the sidebar header (and the phone top bar): unread count, polled every 60 s
 *  while the tab is visible, and a popover with the latest notifications. */
export function NotificationsBell({ me, orgId }: { me: Me; orgId?: string }) {
  const unread = useUnreadCount();
  const [open, setOpen] = useState(false);
  const n = unread.data ?? 0;
  return (
    <Popover
      fixed
      buttonClassName="icon-btn bell-btn"
      buttonLabel={unreadLabel(n)}
      panelLabel="Notifications"
      panelClassName="notif-pop"
      open={open}
      onOpenChange={setOpen}
      button={
        <>
          <BellIcon />
          {n > 0 && (
            <span className="bell-badge num" aria-hidden="true">
              {badgeText(n)}
            </span>
          )}
        </>
      }
    >
      {(close) => <NotificationPanel me={me} orgId={orgId} unread={n} onNavigate={() => close(false)} />}
    </Popover>
  );
}

function NotificationPanel({ me, orgId, unread, onNavigate }: { me: Me; orgId?: string; unread: number; onNavigate: () => void }) {
  const list = useNotifications(true);
  const markRead = useMarkRead();
  const items = flattenPages(list.data?.pages);
  return (
    // Focus starts on the panel itself (not on "Mark all as read"); Tab moves into it.
    <div className="notif-panel" tabIndex={-1} data-autofocus>
      <div className="notif-head">
        <h2>Notifications</h2>
        <button
          type="button"
          className="btn-link small"
          disabled={unread === 0 || markRead.isPending}
          onClick={() => markRead.mutate({ all: true })}
        >
          Mark all as read
        </button>
      </div>
      {list.isPending ? (
        <div style={{ padding: 12 }}>
          <SkeletonBlock label="notifications" lines={4} />
        </div>
      ) : list.isError ? (
        <div className="notif-empty" role="alert">
          <p>Couldn't load notifications.</p>
          <Button size="sm" onClick={() => void list.refetch()}>
            Try again
          </Button>
        </div>
      ) : items.length === 0 ? (
        <div className="notif-empty">
          <p>You're all caught up.</p>
          <p className="faint small">Assignments, reopened issues, exception requests and decisions show up here.</p>
        </div>
      ) : (
        <ul className="notif-list" aria-label="Latest notifications">
          {items.map((item) => (
            <NotificationItem
              key={item.id}
              item={item}
              me={me}
              onOpen={() => {
                if (!item.read_at) markRead.mutate({ ids: [item.id] });
                onNavigate();
              }}
              onMarkRead={() => markRead.mutate({ ids: [item.id] })}
            />
          ))}
        </ul>
      )}
      <div className="notif-foot">
        {list.hasNextPage ? (
          <Button size="sm" busy={list.isFetchingNextPage} onClick={() => void list.fetchNextPage()}>
            {list.isFetchingNextPage ? "Loading…" : "Load older"}
          </Button>
        ) : (
          <span />
        )}
        {orgId && (
          <Link to={`/orgs/${orgId}/preferences`} className="small" onClick={onNavigate}>
            Notification preferences
          </Link>
        )}
      </div>
    </div>
  );
}

function NotificationItem({ item, me, onOpen, onMarkRead }: { item: Notification; me: Me; onOpen: () => void; onMarkRead: () => void }) {
  const href = safeAppPath(item.link);
  const orgName = me.orgs.find((o) => o.id === item.org_id)?.name;
  const unread = !item.read_at;
  // Server text (title, names) is rendered as text, never as HTML.
  const body = (
    <>
      <span className="notif-title">
        {unread && <span className="visually-hidden">Unread: </span>}
        {item.title}
      </span>
      <span className="notif-meta">
        {item.actor ? userName(item.actor) : "Warden"} · {relativeTime(item.created_at)}
        {orgName && me.orgs.length > 1 ? ` · ${orgName}` : ""}
      </span>
    </>
  );
  return (
    <li className={unread ? "notif-item unread" : "notif-item"}>
      <span className="notif-dot" aria-hidden="true" />
      {href ? (
        <Link to={href} className="notif-link" onClick={onOpen}>
          {body}
        </Link>
      ) : (
        <span className="notif-link">{body}</span>
      )}
      {unread && (
        <button type="button" className="icon-btn sm" aria-label={`Mark “${item.title}” as read`} title="Mark as read" onClick={onMarkRead}>
          <CheckIcon size={14} />
        </button>
      )}
    </li>
  );
}
