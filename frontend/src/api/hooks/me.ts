import { useQuery } from "@tanstack/react-query";
import { api } from "../client";
import { qk } from "../keys";
import type { Me } from "../types";

export function useMe(enabled = true) {
  return useQuery({
    queryKey: qk.me,
    queryFn: ({ signal }) => api<Me>("/me", { signal }),
    enabled,
    staleTime: 60_000,
  });
}
