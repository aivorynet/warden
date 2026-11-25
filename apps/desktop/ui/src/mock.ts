/** Sample data for the browser preview (no Tauri). Nothing here touches a real vault. */
import type { Audit, AppState, Coffee, InboxEntry, Item, McpClient, Settings, Sink, Status, Summary, ProviderKind } from "./types.js";
import { DAY } from "./types.js";

const now = Date.now();
const iso = (offsetSec: number): string => new Date(now + offsetSec * 1000).toISOString();
const uid = (n: number): string => `0193f2c4-8e1a-7b3d-9a52-4c6e1f0d${String(n).padStart(4, "0")}`;

const dotenv = (path: string, key: string): Sink => ({ type: "dotenv", path, key });
const ssh = (host: string, user: string, remote: string, key: string): Sink => ({
  type: "ssh", host, port: 22, user, identity_file: "~/.ssh/id_ed25519", known_hosts: "~/.ssh/known_hosts",
  remote_path: remote, format: { type: "toml", key_path: key.split(".") },
});

function mk(n: number, name: string, provider: ProviderKind, admin: boolean, nextIn: number | null, sinks: Sink[], extra: Partial<Item> = {}): Item {
  return {
    id: uid(n), name, slug: name, kind: admin ? { type: "admin" } : { type: "derived", parent: uid(1) },
    provider: { kind: provider, config: {} }, provider_token_id: null,
    expires_at: nextIn === null ? iso(26 * DAY) : iso(nextIn + 40 * DAY), created_at: iso(-60 * DAY), rotated_at: iso(-14 * DAY),
    policy: { auto_rotate: provider !== "manual", interval: 14 * DAY, lead_time: 7 * DAY, grace: 600 },
    sinks, mcp: { allowed_hosts: ["gitlab.com"], header_name: "PRIVATE-TOKEN", header_template: "{{secret}}", run_with_secret: false },
    tags: [], ...extra,
  };
}

const nextOf: Record<string, number | null> = {};
function seed(): Item[] {
  const list = [
    mk(1, "gitlab-admin", "git_lab", true, 12 * DAY, [dotenv("C:\\java\\workspace\\shop\\.env", "GITLAB_ADMIN"), dotenv("C:\\java\\workspace\\api\\.env", "GITLAB_ADMIN"), dotenv("C:\\java\\workspace\\web\\.env", "GITLAB_ADMIN")]),
    mk(2, "gitlab-ci-deploy", "git_lab", false, 3 * DAY, [dotenv("C:\\java\\workspace\\shop\\.env", "GITLAB_TOKEN"), ssh("build-01", "deploy", "/etc/runner/config.toml", "runners.token")]),
    mk(3, "cloudflare-dns", "cloudflare", true, 18 * 3600, [dotenv("C:\\java\\workspace\\dns\\.env", "CF_TOKEN"), dotenv("C:\\java\\workspace\\shop\\.env", "CF_TOKEN")]),
    mk(4, "aws-backup-writer", "aws_iam", false, 0, [dotenv("C:\\ops\\backup.env", "AWS_KEY"), dotenv("C:\\ops\\backup.env", "AWS_SECRET"), { type: "env_var", name: "AWS_BACKUP" }, ssh("backup-01", "ops", "/etc/backup.toml", "aws.key")]),
    mk(5, "openai-agents-prod", "open_ai", false, -3600, [dotenv("C:\\agents\\.env", "OPENAI_API_KEY"), { type: "env_var", name: "OPENAI_API_KEY" }, ssh("build-02", "ci", "/srv/agents/.env", "OPENAI")]),
    mk(6, "aws-ops-admin", "aws_iam", true, 21 * DAY, [dotenv("C:\\ops\\admin.env", "AWS_ADMIN")]),
    mk(7, "github-actions-pat", "manual", true, null, [dotenv("C:\\java\\workspace\\shop\\.env", "GH_PAT")], { expires_at: iso(11 * DAY) }),
  ];
  const next = [12 * DAY, 3 * DAY, 18 * 3600, 0, -3600, 21 * DAY, null];
  list.forEach((it, i) => (nextOf[it.id] = next[i] ?? null));
  return list;
}

let items = seed();
let settings: Settings = { default_interval: 30 * DAY, coffee_reminder: true, keychain_cache: true, quick_unlock: false };
let pledged = false;
let paidYear: number | null = null;
let inbox: InboxEntry[] = [
  { id: "0193f2c4-8e1a-7b3d-9a52-4c6e1f0d9001", origin: "dash.cloudflare.com", label: "cloudflare-dns", captured_at: iso(-120), provider_hint: "cloudflare", expires_at: iso(60 * DAY) },
  { id: "0193f2c4-8e1a-7b3d-9a52-4c6e1f0d9002", origin: "platform.openai.com", label: "openai-admin", captured_at: iso(-3600), provider_hint: "openai", expires_at: null },
];
let mcpClients: McpClient[] = [
  { id: "a1b2c3d4e5f6", name: "Claude Code", capabilities: ["mcp_use"], paired_at: "2026-11-12T10:00:00Z" },
  { id: "f6e5d4c3b2a1", name: "ops-agent", capabilities: ["mcp_use", "mcp_admin"], paired_at: "2026-11-20T10:00:00Z" },
  { id: "0a0a0a0a0a0a", name: "desktop", capabilities: ["full"], paired_at: "2026-11-01T10:00:00Z" },
];

/** Statuses that the sample daemon reports. */
const sampleStatus: Record<string, Pick<Summary, "status" | "last_error" | "next_retry">> = {
  [uid(4)]: { status: "rotating", last_error: null, next_retry: null },
  [uid(5)]: { status: "failed", last_error: "build-02 refused the SSH key. The new token is safe in the vault.", next_retry: iso(3600) },
};

const status = (): Status => ({ version: "2026.11.0", locked: false, device_id: "0193f2c4-8e1a-7b3d-9a52-4c6e1f0d0014", item_count: items.length, inbox_count: inbox.length });
const coffee = (): Coffee => ({ paid_year: paidYear, reminder_due: false, link: "https://buy.stripe.com/5kQbJ3csm21Xfz64DhdjO00", pledged, ticket: "AIVW-2026-6909", price_label: "pay what you want, 5 EUR suggested" });
const summary = (i: Item): Summary => ({
  id: i.id, name: i.name, provider: i.provider.kind, kind: i.kind, expires_at: i.expires_at,
  next_rotation: i.policy.auto_rotate ? iso(nextOf[i.id] ?? 30 * DAY) : null, sink_count: i.sinks.length, auto_rotate: i.policy.auto_rotate,
  ...(sampleStatus[i.id] ?? { status: i.provider.kind === "manual" ? "reminder" : i.policy.auto_rotate && (nextOf[i.id] ?? 1) <= 0 ? "due" : "healthy", last_error: null, next_retry: null }),
});
const audit = (id: string | null): Audit[] => {
  const base: Audit[] = [
    { at: iso(-14 * DAY), device: "d", item: uid(2), action: "put", detail: "gitlab-ci-deploy on PAUL-LAPTOP" },
    { at: iso(-28 * DAY), device: "d", item: uid(2), action: "put", detail: "gitlab-ci-deploy on PAUL-LAPTOP" },
    { at: iso(-42 * DAY), device: "d", item: uid(2), action: "put", detail: "gitlab-ci-deploy on PAUL-LAPTOP" },
    { at: iso(-9 * DAY), device: "d", item: uid(3), action: "put", detail: "cloudflare-dns on PAUL-LAPTOP" },
    { at: iso(-20 * DAY), device: "d", item: uid(1), action: "put", detail: "gitlab-admin on PAUL-LAPTOP" },
  ];
  return base.filter((a) => id === null || a.item === id).sort((a, b) => a.at.localeCompare(b.at));
};

const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

export async function mockApp(): Promise<AppState> {
  return { daemon_up: true, vault_exists: true, status: status(), error: null };
}

export async function mockCall(req: Record<string, any>): Promise<Record<string, any>> {
  await sleep(10);
  switch (req["type"]) {
    case "status": return { type: "status", ...status() };
    case "list_items": return { type: "items", items: items.map(summary) };
    case "get_item": {
      const it = items.find((i) => i.id === req["item"]);
      return it ? { type: "item", ...it } : { type: "error", code: "not_found", message: "item not found" };
    }
    case "add_item": {
      const d = req["draft"];
      const it: Item = { ...d, id: uid(100 + items.length), provider_token_id: null, created_at: iso(0), rotated_at: null };
      items.push(it);
      nextOf[it.id] = 14 * DAY;
      return { type: "added", item: it.id };
    }
    case "update_policy": {
      const it = items.find((i) => i.id === req["item"]);
      if (it) it.policy = req["policy"];
      return { type: "ok" };
    }
    case "update_item": {
      const it = items.find((i) => i.id === req["item"]);
      if (!it) return { type: "error", code: "not_found", message: "item not found" };
      if (req["name"] != null) it.name = req["name"];
      if (req["sinks"] != null) it.sinks = req["sinks"];
      if (req["mcp"] != null) it.mcp = req["mcp"];
      if (req["tags"] != null) it.tags = req["tags"];
      return { type: "ok" };
    }
    case "rotate_now": return { type: "ok" };
    case "delete_item": items = items.filter((i) => i.id !== req["item"]); return { type: "ok" };
    case "unlock": case "lock": case "lock_forget": case "unlock_quick": return { type: "ok" };
    case "inbox_list": return { type: "inbox", inbox };
    case "inbox_accept": inbox = inbox.filter((e) => e.id !== req["id"]); return { type: "added", item: uid(200) };
    case "inbox_reject": inbox = inbox.filter((e) => e.id !== req["id"]); return { type: "ok" };
    case "pair": return { type: "paired", capabilities: req["capabilities"], token: "aivw_SAMPLE_TOKEN_SHOWN_ONCE_0000000000000000" };
    case "get_settings": return { type: "settings", ...settings };
    case "set_settings": settings = req["settings"]; return { type: "ok" };
    case "coffee_status": return { type: "coffee", ...coffee() };
    case "coffee_mark_paid":
      paidYear = new Date().getFullYear();
      return { type: "coffee", ...coffee() };
    case "audit_list": return { type: "audit", audit: audit(req["item"] ?? null) };
    case "sign_pledge": pledged = true; return { type: "ok" };
    case "init": return { type: "ok", kit: { secret_key: "A3-7KQ2M-9XW4T-PR8D6-F2HNC-5JV9Q", vault: "0193f2c4-8e1a-7b3d-9a52-4c6e1f0d2b77", device: "PAUL-LAPTOP", ticket: "AIVW-2026-6909" } };
    case "list_clients": return { type: "clients", clients: mcpClients };
    case "unpair": mcpClients = mcpClients.filter((c) => c.id !== req["id"]); return { type: "ok" };
    case "list_devices": return { type: "devices", devices: [
      { id: "0193f2c4-8e1a-7b3d-9a52-4c6e1f0d0014", name: "PAUL-LAPTOP", is_rotator_for: items.length, last_seen: iso(-3600) },
      { id: "0193f2c4-8e1a-7b3d-9a52-4c6e1f0d0099", name: "build-01", is_rotator_for: 0, last_seen: iso(-3 * DAY) },
    ] };
    default: return { type: "error", code: "bad_request", message: `unknown request ${String(req["type"])}` };
  }
}
