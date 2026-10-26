import { useInfiniteQuery } from "@tanstack/react-query";
import type { QueryKey } from "@tanstack/react-query";
import { api } from "./client";
import type { QueryParams } from "./client";
import type { Page } from "./types";

/** Cursor pagination: `?cursor=` + `next_cursor`, shown with a "Load more" button. */
export function useCursorList<P extends Page<unknown>>(
  key: QueryKey,
  path: string,
  query: QueryParams,
  opts: { enabled?: boolean } = {},
) {
  return useInfiniteQuery({
    queryKey: key,
    queryFn: ({ pageParam, signal }) => api<P>(path, { query: { ...query, cursor: pageParam }, signal }),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (last) => last.next_cursor ?? undefined,
    enabled: opts.enabled,
  });
}

export function flattenPages<T>(pages: { items: T[] }[] | undefined): T[] {
  return pages ? pages.flatMap((p) => p.items) : [];
}
