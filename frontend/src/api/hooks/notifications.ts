import { queryOptions, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../client";
import { qk } from "../keys";
import { useCursorList } from "../paging";
import type { ItemList, MarkReadBody, Notification, NotificationPref, Page, UnreadCount } from "../types";

/** Contract FE: poll the unread count every 60 s. */
export const UNREAD_POLL_MS = 60_000;

/** The unread count for the bell. Polls every 60 s, but only while the tab is visible:
 *  `refetchIntervalInBackground: false` makes TanStack Query skip the interval while its
 *  focusManager says the page is hidden (it listens to `visibilitychange`), and coming back
 *  to the tab refetches at once if the count is older than the interval. */
export function unreadCountOptions() {
  return queryOptions({
    queryKey: qk.unreadCount,
    queryFn: ({ signal }) => api<UnreadCount>("/me/notifications/unread-count", { signal }),
    select: (d: UnreadCount) => d.count,
    refetchInterval: UNREAD_POLL_MS,
    refetchIntervalInBackground: false,
    refetchOnWindowFocus: true,
    staleTime: UNREAD_POLL_MS,
  });
}

export function useUnreadCount() {
  return useQuery(unreadCountOptions());
}

/** The popover's list; loaded only while it is open. */
export function useNotifications(enabled: boolean) {
  return useCursorList<Page<Notification>>(qk.notifications(false), "/me/notifications", { limit: 20 }, { enabled });
}

export function useMarkRead() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: MarkReadBody) => api<void>("/me/notifications/read", { method: "POST", body }),
    onSuccess: () => qc.invalidateQueries({ queryKey: qk.notificationsAll }),
  });
}

export function useNotificationPrefs() {
  return useQuery({
    queryKey: qk.notificationPrefs,
    queryFn: ({ signal }) => api<ItemList<NotificationPref>>("/me/notification-prefs", { signal }),
    select: (d) => d.items,
  });
}

export function useSaveNotificationPrefs() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (items: NotificationPref[]) =>
      api<ItemList<NotificationPref>>("/me/notification-prefs", { method: "PUT", body: { items } }),
    onSuccess: (saved) => qc.setQueryData(qk.notificationPrefs, saved),
  });
}
