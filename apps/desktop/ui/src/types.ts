export type Policy = { auto_rotate: boolean; interval: number | null; lead_time: number; grace: number };
export type Sink = { type: string; [k: string]: unknown };
export type McpPolicy = { allowed_hosts: string[]; header_name: string; header_template: string; run_with_secret: boolean };
export type ItemKind = { type: "admin" } | { type: "derived"; parent: string };
export type ProviderKind = "git_lab" | "aws_iam" | "cloudflare" | "open_ai" | "command" | "manual";
export type Provider = { kind: ProviderKind; config: Record<string, unknown> };

export type Item = {
  id: string; name: string; slug: string; kind: ItemKind; provider: Provider;
  provider_token_id: string | null; expires_at: string | null; created_at: string;
  rotated_at: string | null; policy: Policy; sinks: Sink[]; mcp: McpPolicy; tags: string[];
};
export type Summary = {
  id: string; name: string; provider: ProviderKind; kind: ItemKind; expires_at: string | null;
  next_rotation: string | null; sink_count: number; auto_rotate: boolean;
  status: "healthy" | "due" | "rotating" | "failed" | "reminder"; last_error: string | null; next_retry: string | null;
};
export type Draft = {
  name: string; slug: string; kind: ItemKind; provider: Provider; expires_at: string | null;
  policy: Policy; sinks: Sink[]; mcp: McpPolicy; tags: string[];
};
export type Status = { version: string; locked: boolean; device_id: string; item_count: number; inbox_count: number };
export type InboxEntry = { id: string; origin: string; label: string; captured_at: string; provider_hint?: string | null; expires_at?: string | null };
export type Coffee = { paid_year: number | null; reminder_due: boolean; link: string; pledged: boolean; ticket: string; price_label: string };
export type Audit = { at: string; device: string; item: string | null; action: string; detail: string };
export type Settings = { default_interval: number; coffee_reminder: boolean; keychain_cache: boolean };
export type McpClient = { id: string; name: string; capabilities: string[]; paired_at: string };
export type Device = { id: string; name: string; is_rotator_for: number; last_seen: string | null };
export type Kit = { secret_key: string; vault: string; device: string; ticket: string };
export type AppState = { daemon_up: boolean; vault_exists: boolean; status: Status | null; error: string | null; computer_name?: string };

export type StampName = "HEALTHY" | "DUE" | "ROTATING" | "FAILED" | "REMINDER";

export const DAY = 86400;
