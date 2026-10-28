import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import type { QueryClient } from "@tanstack/react-query";
import { api } from "../client";
import { qk } from "../keys";
import type { CreatedWebhook, CreateWebhookBody, Page, UpdateWebhookBody, Webhook, WebhookDelivery, WebhookList, WebhookSecret } from "../types";
import { TEST_RATE_LIMITED } from "../../lib/webhooks";

// v0.4 wave 2: webhooks and Slack channels (manage_integrations: org admins, security leads).
// Members never call these: the page and its navigation entry are hidden for them.

const webhooksPath = (orgId: string) => `/orgs/${encodeURIComponent(orgId)}/webhooks`;
const webhookPath = (orgId: string, id: string) => `${webhooksPath(orgId)}/${encodeURIComponent(id)}`;

export function useWebhooks(orgId: string, enabled = true) {
  return useQuery({
    queryKey: qk.webhooks(orgId),
    queryFn: ({ signal }) => api<WebhookList>(webhooksPath(orgId), { signal }),
    enabled,
  });
}

/** Options for the create mutation.
 *
 *  The create response is one of only two places a webhook's signing secret appears (rotate is
 *  the other). As for API tokens (hooks/tokens.ts), the mutation function hands the secret
 *  straight to `onSecret` (the dialog's component state) and resolves with the Webhook alone,
 *  so the secret never reaches TanStack Query's mutation or query caches, the URL, storage or a
 *  log. The request body holds the webhook URL, which for Slack is a credential: the mutation's
 *  variables are kept in the MutationCache too, so they are passed through a closure instead
 *  (mutate() takes no variables). webhooks.test.ts checks both. */
export function createWebhookMutation(
  qc: QueryClient,
  orgId: string,
  body: () => CreateWebhookBody,
  onSecret: (secret: string, webhook: Webhook) => void,
) {
  return {
    mutationFn: async (): Promise<Webhook> => {
      const { webhook, secret } = await api<CreatedWebhook>(webhooksPath(orgId), { method: "POST", body: body() });
      if (secret) onSecret(secret, webhook);
      return webhook;
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: qk.webhooks(orgId) }),
  };
}

export function useCreateWebhook(orgId: string, body: () => CreateWebhookBody, onSecret: (secret: string, webhook: Webhook) => void) {
  const qc = useQueryClient();
  return useMutation(createWebhookMutation(qc, orgId, body, onSecret));
}

/** PATCH a webhook. A new URL travels in the closure, like on create (never as variables). */
export function updateWebhookMutation(qc: QueryClient, orgId: string, id: string, body: () => UpdateWebhookBody) {
  return {
    mutationFn: () => api<Webhook>(webhookPath(orgId, id), { method: "PATCH", body: body() }),
    onSuccess: () => qc.invalidateQueries({ queryKey: qk.webhooks(orgId) }),
  };
}

export function useUpdateWebhook(orgId: string, id: string, body: () => UpdateWebhookBody) {
  const qc = useQueryClient();
  return useMutation(updateWebhookMutation(qc, orgId, id, body));
}

/** Turn a webhook on or off. Turning it on also resets the failure count on the server. */
export function useSetWebhookEnabled(orgId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) =>
      api<Webhook>(webhookPath(orgId, id), { method: "PATCH", body: { enabled } satisfies UpdateWebhookBody }),
    onSuccess: () => qc.invalidateQueries({ queryKey: qk.webhooks(orgId) }),
  });
}

/** New signing secret: same rules as create. Resolves with nothing; the secret goes to onSecret. */
export function rotateSecretMutation(qc: QueryClient, orgId: string, id: string, onSecret: (secret: string) => void) {
  return {
    mutationFn: async (): Promise<void> => {
      const { secret } = await api<WebhookSecret>(`${webhookPath(orgId, id)}/rotate-secret`, { method: "POST" });
      onSecret(secret);
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: qk.webhooks(orgId) }),
  };
}

export function useRotateSecret(orgId: string, id: string, onSecret: (secret: string) => void) {
  const qc = useQueryClient();
  return useMutation(rotateSecretMutation(qc, orgId, id, onSecret));
}

/** Queue a webhook.test delivery. 429 (10 per webhook per hour) has its own words. */
export function useTestWebhook(orgId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => api<WebhookDelivery>(`${webhookPath(orgId, id)}/test`, { method: "POST" }),
    meta: { errorMessages: { RATE_LIMITED: TEST_RATE_LIMITED } },
    onSuccess: (_d, id) => qc.invalidateQueries({ queryKey: qk.webhookDeliveries(orgId, id) }),
  });
}

export function useDeleteWebhook(orgId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => api<void>(webhookPath(orgId, id), { method: "DELETE" }),
    onSuccess: (_d, id) => {
      qc.removeQueries({ queryKey: qk.webhookDeliveries(orgId, id) });
      return qc.invalidateQueries({ queryKey: qk.webhooks(orgId) });
    },
  });
}

/** The delivery log, newest first, 50 at a time. `poll` refetches every few seconds (after
 *  "Send test"); the list itself is refreshed on every poll so the last delivery stays current. */
export function useWebhookDeliveries(orgId: string, id: string | null, pollMs: number | false) {
  return useInfiniteQuery({
    queryKey: qk.webhookDeliveries(orgId, id ?? ""),
    queryFn: ({ pageParam, signal }) =>
      api<Page<WebhookDelivery>>(`${webhookPath(orgId, id ?? "")}/deliveries`, { query: { limit: 50, cursor: pageParam }, signal }),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (last) => last.next_cursor ?? undefined,
    enabled: !!id,
    refetchInterval: pollMs,
  });
}
