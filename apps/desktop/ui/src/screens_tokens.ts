/** Token list, detail with policy editor, audit and inbox. */
import { h, replace } from "./dom.js";
import { call } from "./api.js";
import {
  S, cta, btn, days, errText, eyebrow, field, fmtDate, fmtDateTime, providerLabel, PROVIDERS, relTime, shortId, simpleBar, slugify, stamp, stampOf, toast, topbar,
} from "./view.js";
import type { Audit, InboxEntry, Item, Policy, Sink, Summary } from "./types.js";
import { DAY } from "./types.js";

const item = (s: Summary) => (s.kind.type === "admin" ? "admin" : "derived");

export async function tokens(root: HTMLElement): Promise<void> {
  const r = await call<{ items: Summary[] }>({ type: "list_items" });
  const items = r.items;
  const settings = await call({ type: "get_settings" });
  const def = settings["default_interval"] as number;
  const stamps = items.map((s) => stampOf(s));
  const due = stamps.filter((s) => s.name === "DUE").length;
  const failed = items.filter((_, i) => stamps[i]?.name === "FAILED");
  const places = items.reduce((n, s) => n + s.sink_count, 0);
  const next = (s: Summary, st: string): string => {
    if (st === "ROTATING") return "now";
    if (st === "FAILED") return "retry later";
    if (s.provider === "manual") return s.expires_at ? `renew by ${fmtDate(s.expires_at)}` : "no end date";
    return s.next_rotation ? relTime(s.next_rotation) : "manual";
  };
  const rows = items.map((s, i) => {
    const st = stamps[i]?.name ?? "HEALTHY";
    const kind = s.provider === "manual" ? "manual" : item(s) === "admin" ? "admin" : "derived";
    return h(
      "tr",
      {},
      h("td", { class: "id" }, shortId(s.id)),
      h("td", {}, h("button", { class: "nm", type: "button", onclick: () => S.go(`detail/${s.id}`) }, s.name), h("span", { class: "sub" }, `${providerLabel(s.provider)} · ${kind}`)),
      h("td", { class: "next" }, next(s, st)),
      h("td", { class: "r places" }, s.sink_count),
      h("td", {}, stamp(st)),
    );
  });
  replace(
    root,
    topbar("tokens"),
    h(
      "div",
      { class: "page" },
      h(
        "main",
        { class: "col" },
        eyebrow(`VAULT · ${items.length} TOKENS · DEFAULT EVERY ${Math.round(def / DAY)} DAYS`),
        h("h1", { class: "disp" }, "Your tokens"),
        h("p", { class: "lead" }, "Warden rotates each token on schedule and writes the new value to every place that uses it."),
        h("div", { class: "bar" }),
        items.length === 0
          ? h("p", { class: "empty" }, "No tokens yet. Add your first token.")
          : h(
              "div",
              { class: "tablewrap" },
              h("table", {}, h("thead", {}, h("tr", {}, h("th", {}, "ID"), h("th", {}, "TOKEN"), h("th", {}, "NEXT ROTATION"), h("th", { class: "r" }, "PLACES"), h("th", {}, "STATUS"))), h("tbody", {}, ...rows)),
            ),
      ),
      h(
        "aside",
        { class: "side" },
        h("span", { class: "side-head" }, "THIS WEEK"),
        h("div", { class: "stack" }, h("span", { class: "disp big" }, `${due} due`), h("span", { class: "small" }, `${items.length} tokens · ${places} places · ${failed.length} ${failed.length === 1 ? "needs" : "need"} you`)),
        ...failed.map((f) =>
          h("div", { class: "alert" }, h("span", { class: "k" }, "NEEDS YOU"), h("span", { class: "b" }, f.name), h("span", { class: "m" }, S.overrides[f.id]?.message ?? "The last rotation failed. The new token is safe in the vault.")),
        ),
        h("span", { class: "side-head gap" }, "DAEMON"),
        h("div", { class: "kv" }, h("span", {}, "Background rotation"), h("span", { class: "mono" }, S.app?.status?.locked ? "LOCKED" : "ON")),
        h("div", { class: "kv" }, h("span", {}, "Daemon version"), h("span", { class: "mono" }, S.app?.status?.version ?? "-")),
        h("div", { class: "kv" }, h("span", {}, "Default interval"), h("span", { class: "mono" }, `${Math.round(def / DAY)} days`)),
        h("div", { class: "stack" }, cta("Add a token", () => S.go("wizard"))),
      ),
    ),
  );
}

// ----------------------------------------------------------------- detail

const SINK_KIND: Record<string, string> = { dotenv: ".ENV", json: "JSON", toml: "TOML", yaml: "YAML", ssh: "SSH", env_var: "ENV", regex: "REGEX" };

export function sinkView(s: Sink): { kind: string; main: string; sub: string } {
  const kp = (v: unknown) => (Array.isArray(v) ? v.join(".") : String(v ?? ""));
  const fmt = s["format"] as Record<string, unknown> | undefined;
  switch (s.type) {
    case "dotenv": return { kind: ".ENV", main: String(s["key"]), sub: String(s["path"]) };
    case "json": return { kind: "JSON", main: String(s["pointer"]), sub: String(s["path"]) };
    case "toml": case "yaml": return { kind: SINK_KIND[s.type] ?? s.type, main: kp(s["key_path"]), sub: String(s["path"]) };
    case "ssh": return { kind: "SSH", main: kp(fmt?.["key_path"] ?? fmt?.["key"] ?? fmt?.["pointer"] ?? "value"), sub: `${s["user"]}@${s["host"]}:${s["remote_path"]}` };
    case "env_var": return { kind: "ENV", main: String(s["name"]), sub: "user environment variable" };
    default: return { kind: SINK_KIND[s.type] ?? s.type.toUpperCase(), main: String(s["pattern"] ?? ""), sub: String(s["path"] ?? "") };
  }
}

function select(options: [string, string][], value: string, onchange: (v: string) => void): HTMLSelectElement {
  const el = h("select", { class: "sel", onchange: () => onchange(el.value) });
  for (const [v, label] of options) el.append(h("option", { value: v, selected: v === value }, label));
  return el;
}

export function opts(values: number[], current: number | null, withDefault: string | null): [string, string][] {
  const set = [...new Set([...values, ...(current !== null ? [current] : [])])].sort((a, b) => a - b);
  const o: [string, string][] = set.map((d) => [String(d), `${d} days`]);
  return withDefault ? [["", withDefault], ...o] : o;
}

export async function detail(root: HTMLElement, id: string): Promise<void> {
  const it = await call<Item & { type: string }>({ type: "get_item", item: id });
  const list = (await call<{ items: Summary[] }>({ type: "list_items" })).items;
  const sum = list.find((s) => s.id === id);
  const settings = await call({ type: "get_settings" });
  const hist = (await call<{ audit: Audit[] }>({ type: "audit_list", item: id, limit: 20 })).audit.slice().reverse();
  const st = sum ? stampOf(sum) : { name: "HEALTHY" as const };
  const p: Policy = { ...it.policy };
  const nextEl = h("span", { class: "disp mid" }, sum?.next_rotation ? relTime(sum.next_rotation) : "manual");
  const nextSub = h("span", { class: "small" }, sum?.next_rotation ? `${fmtDate(sum.next_rotation)}, ${new Date(sum.next_rotation).toTimeString().slice(0, 5)}` : "Auto-rotate is off.");
  const save = async () => {
    try {
      await call({ type: "update_policy", item: id, policy: p });
      toast("ok", "POLICY SAVED", `${it.name}: the new policy is active.`);
      const again = (await call<{ items: Summary[] }>({ type: "list_items" })).items.find((s) => s.id === id);
      nextEl.textContent = again?.next_rotation ? relTime(again.next_rotation) : "manual";
      nextSub.textContent = again?.next_rotation ? fmtDate(again.next_rotation) : "Auto-rotate is off.";
    } catch (e) {
      toast("bad", "POLICY NOT SAVED", errText(e));
    }
  };
  const parent = it.kind.type === "derived" ? list.find((s) => s.id === (it.kind as { parent: string }).parent)?.name : null;
  const defDays = Math.round((settings["default_interval"] as number) / DAY);
  const rotateBtn = cta("Rotate now", async () => {
    rotateBtn.disabled = true;
    S.overrides[id] = { stamp: "ROTATING" };
    try {
      await call({ type: "rotate_now", item: id });
      delete S.overrides[id];
      toast("ok", "ROTATED", `${it.name}: the new value is written.`);
    } catch (e) {
      S.overrides[id] = { stamp: "FAILED", message: errText(e) };
      toast("bad", "ROTATION FAILED", `${it.name}: ${errText(e)}`);
    }
    await detail(root, id);
  });
  replace(
    root,
    topbar("tokens"),
    h(
      "div",
      { class: "page tight" },
      h(
        "main",
        { class: "col" },
        eyebrow(h("a", { href: "#tokens" }, "TOKENS"), ` · ${shortId(id)} · ${providerLabel(it.provider.kind).toUpperCase()} ${it.kind.type === "admin" ? "ADMIN" : "DERIVED"}`),
        h("div", { class: "titlerow" }, h("h1", { class: "disp sm" }, it.name), stamp(st.name)),
        h("p", { class: "lead small" }, parent ? `Derived from ${parent}. ` : "", `Name at provider: `, h("span", { class: "mono" }, `aivw_${it.slug}_${new Date().toISOString().slice(0, 10).replaceAll("-", "")}`)),
        st.name === "FAILED" ? h("div", { class: "alert" }, h("span", { class: "k" }, "ROTATION FAILED"), h("span", { class: "m" }, S.overrides[id]?.message ?? "The new token is safe in the vault.")) : null,
        h("div", { class: "bar" }),
        h("span", { class: "label" }, "PLACES"),
        h(
          "div",
          { class: "rows" },
          ...(it.sinks.length === 0 ? [h("div", { class: "empty" }, "No places yet.")] : []),
          ...it.sinks.map((s) => {
            const v = sinkView(s);
            return h("div", { class: "row" }, h("span", { class: "kind" }, v.kind), h("span", { class: "grow" }, h("span", { class: "a" }, v.main), h("span", { class: "b" }, v.sub)), h("span", { class: "stamp sm" }, it.rotated_at ? "WRITTEN" : "PENDING"));
          }),
          h("button", { class: "link", type: "button", disabled: true, title: "Changing places needs an update-item request in the daemon." }, "Add a place"),
        ),
        h("span", { class: "label" }, "HISTORY"),
        hist.length === 0
          ? h("p", { class: "hint" }, "No history yet.")
          : h("ol", { class: "hist" }, ...hist.map((a) => h("li", {}, `${fmtDateTime(a.at)} · ${a.action === "put" ? "saved" : a.action} · ${a.detail}`))),
      ),
      h(
        "aside",
        { class: "side" },
        h("span", { class: "side-head" }, "ROTATION"),
        h("label", { class: "toggle" }, "Rotate on its own", h("input", { type: "checkbox", checked: p.auto_rotate, onchange: (e: Event) => { p.auto_rotate = (e.target as HTMLInputElement).checked; void save(); } })),
        h("label", { class: "toggle" }, "Every", select(opts([7, 14, 30, 90].map((d) => d), p.interval === null ? null : Math.round(p.interval / DAY), `default (${defDays} d)`), p.interval === null ? "" : String(Math.round(p.interval / DAY)), (v) => { p.interval = v === "" ? null : Number(v) * DAY; void save(); })),
        h("label", { class: "toggle" }, "Before end date", select(opts([3, 7, 14], Math.round(p.lead_time / DAY), null), String(Math.round(p.lead_time / DAY)), (v) => { p.lead_time = Number(v) * DAY; void save(); })),
        h("div", { class: "stack" }, h("span", { class: "mono small steel" }, "NEXT ROTATION"), nextEl, nextSub, h("span", { class: "small" }, `Old token lives ${p.grace >= DAY ? days(p.grace) : Math.max(1, Math.round(p.grace / 60)) + " min"} more.`)),
        h("span", { class: "side-head gap" }, "MCP"),
        h("div", { class: "kv" }, h("span", {}, "Hosts"), h("span", { class: "mono" }, it.mcp.allowed_hosts.join(", ") || "none")),
        h("div", { class: "kv" }, h("span", {}, "Header"), h("span", { class: "mono" }, it.mcp.header_name)),
        h("p", { class: "hint" }, "Agents use this token through Warden. They never get the value."),
        rotateBtn,
        h("button", { class: "link danger", type: "button", onclick: async () => { if (!window.confirm(`Delete ${it.name}? This cannot be undone.`)) return; try { await call({ type: "delete_item", item: id }); S.go("tokens"); } catch (e) { toast("bad", "NOT DELETED", errText(e)); } } }, "Delete token"),
      ),
    ),
  );
}

// ----------------------------------------------------------------- audit

export async function auditScreen(root: HTMLElement): Promise<void> {
  const entries = (await call<{ audit: Audit[] }>({ type: "audit_list", item: null, limit: 200 })).audit.slice().reverse();
  replace(
    root,
    topbar("audit"),
    h(
      "div",
      { class: "page" },
      h(
        "main",
        { class: "col" },
        eyebrow(`AUDIT · ${entries.length} ENTRIES`),
        h("h1", { class: "disp" }, "Audit"),
        h("div", { class: "bar" }),
        entries.length === 0 ? h("p", { class: "empty" }, "Nothing yet.") : h("ol", { class: "hist" }, ...entries.map((a) => h("li", {}, `${fmtDateTime(a.at)} · ${a.action === "put" ? "saved" : a.action} · ${a.detail}`))),
      ),
    ),
  );
}

// ----------------------------------------------------------------- inbox

function inboxRow(e: InboxEntry, reload: () => void): HTMLElement {
  const hint = PROVIDERS.find((p) => p.hint === (e.provider_hint ?? "").toLowerCase())?.kind ?? "manual";
  const name = h("input", { value: slugify(e.label) });
  const prov = select(PROVIDERS.map((p) => [p.kind, p.label] as [string, string]), hint, () => {});
  const ends = h("input", { type: "date", value: e.expires_at ? e.expires_at.slice(0, 10) : "" });
  const form = h(
    "div",
    { class: "grid2", hidden: true },
    field("NAME", name),
    field("PROVIDER", prov),
    field("ENDS", ends),
    h("div", { class: "stack" }, btn("Add to vault", async () => {
      try {
        await call({
          type: "inbox_accept",
          id: e.id,
          draft: {
            name: name.value.trim(), slug: slugify(name.value), kind: { type: "admin" }, provider: { kind: prov.value, config: {} },
            expires_at: ends.value ? new Date(`${ends.value}T00:00:00Z`).toISOString() : null,
            policy: { auto_rotate: prov.value !== "manual", interval: null, lead_time: 3 * DAY, grace: DAY },
            sinks: [], mcp: { allowed_hosts: [], header_name: "Authorization", header_template: "Bearer {{secret}}", run_with_secret: false }, tags: [],
          },
        });
        toast("ok", "ADDED", `${name.value} is in the vault.`);
        reload();
      } catch (ex) {
        toast("bad", "NOT ADDED", errText(ex));
      }
    }, "solid")),
  );
  return h(
    "div",
    { class: "stack" },
    h(
      "div",
      { class: "row" },
      h("span", { class: "grow" }, h("span", { class: "a" }, e.label), h("span", { class: "b" }, `${e.origin.toUpperCase()} · ${relTime(e.captured_at).toUpperCase()}`)),
      h("span", { class: "stamp sm" }, "WAITING"),
      btn("Accept", () => { form.hidden = !form.hidden; }, "sm"),
      h("button", { class: "link danger", type: "button", onclick: async () => { try { await call({ type: "inbox_reject", id: e.id }); reload(); } catch (ex) { toast("bad", "NOT REJECTED", errText(ex)); } } }, "Reject"),
    ),
    form,
  );
}

export async function inbox(root: HTMLElement): Promise<void> {
  const entries = (await call<{ inbox: InboxEntry[] }>({ type: "inbox_list" })).inbox;
  S.inbox = entries.length;
  const reload = () => void S.refresh().then(() => inbox(root));
  replace(
    root,
    topbar("inbox"),
    h(
      "div",
      { class: "page" },
      h(
        "main",
        { class: "col" },
        eyebrow(`INBOX · ${entries.length} WAITING`),
        h("h1", { class: "disp" }, "Inbox"),
        h("p", { class: "lead" }, "Tokens that the Edge extension captured. A page cannot add a token by itself. You confirm each one here."),
        h("div", { class: "bar" }),
        entries.length === 0 ? h("p", { class: "empty" }, "Nothing waits. Captured tokens show up here.") : h("div", { class: "rows" }, ...entries.map((e) => inboxRow(e, reload))),
      ),
    ),
  );
}
