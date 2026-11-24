/** Shared state and building blocks for the screens. */
import { append, h, svg, type Child } from "./dom.js";
import type { AppState, Coffee, Kit, StampName, Summary } from "./types.js";
import { DAY } from "./types.js";

export const S = {
  app: null as AppState | null,
  coffee: null as Coffee | null,
  kit: null as Kit | null,
  inbox: 0,
  go: (_route: string): void => {},
  refresh: async (): Promise<void> => {},
};

const LOGO =
  '<svg role="img" aria-label="AIVory" width="64" height="22" viewBox="0 0 403 138"><path d="M-0,136.215l13.916,0l62.676,-111.474l62.578,111.474l13.968,0l-76.484,-136.215l-76.654,136.215Z" fill="#111213"/><path d="M200.399,136.215l11.439,0l-0.026,-136.215l-11.413,0l0,136.215Z" fill="#111213"/><path d="M325.722,111.475l-62.661,-111.436l-13.932,-0.039l76.593,136.215l76.593,-136.215l-13.917,0l-62.676,111.475Z" fill="#111213"/></svg>';
const ARROW =
  '<svg width="22" height="22" viewBox="0 0 22 22" fill="none" aria-hidden="true"><path d="M4 11 H18 M12 5 L18 11 L12 17" stroke="#111213" stroke-width="2.4"/></svg>';
const MUG =
  '<svg width="22" height="22" viewBox="0 0 22 22" fill="none" aria-hidden="true"><path d="M4 9 H16 V15 a4 4 0 0 1 -4 4 H8 a4 4 0 0 1 -4 -4 Z" stroke="#111213" stroke-width="1.8"/><path d="M16 11 h1.5 a2 2 0 0 1 0 4 H16" stroke="#111213" stroke-width="1.8"/><path d="M8 3 v3 M12 3 v3" stroke="#22C55E" stroke-width="1.8"/></svg>';

export const mug = (): Element => svg(MUG);

export function lockup(): HTMLElement {
  return h("div", { class: "lockup" }, svg(LOGO), h("span", { class: "rule" }), h("span", { class: "word" }, "WARDEN"));
}

export type NavKey = "tokens" | "inbox" | "audit" | "settings";

export function topbar(active: NavKey | null): HTMLElement {
  const link = (key: NavKey, label: string, extra?: Child) =>
    h("a", { href: `#${key}`, class: active === key ? "on" : "" }, label, extra);
  const device = S.app?.status ? S.app.status.device_id.slice(-8).toUpperCase() : "";
  const state = S.app?.status?.locked ? "LOCKED" : "UNLOCKED";
  return h(
    "header",
    { class: "topbar" },
    lockup(),
    h(
      "nav",
      { class: "nav", "aria-label": "Main" },
      link("tokens", "TOKENS"),
      link("inbox", "INBOX", S.inbox > 0 ? h("span", { class: "badge" }, S.inbox) : null),
      link("audit", "AUDIT"),
      link("settings", "SETTINGS"),
    ),
    h("span", { class: "meta-top" }, `${state}${device ? " · " + device : ""}`),
  );
}

export function simpleBar(right: Child): HTMLElement {
  return h("header", { class: "topbar" }, lockup(), right);
}

/** The black button with the green arrow square. */
export function cta(label: string, onclick: (e: Event) => void, opts: { disabled?: boolean; large?: boolean; type?: string } = {}): HTMLButtonElement {
  return h(
    "button",
    { class: `cta${opts.large ? " lg" : ""}`, type: opts.type ?? "button", disabled: opts.disabled, onclick },
    h("span", { class: "t" }, label),
    h("span", { class: "a" }, svg(ARROW)),
  );
}

export function btn(label: string, onclick: (e: Event) => void, cls = ""): HTMLButtonElement {
  return h("button", { class: `btn ${cls}`.trim(), type: "button", onclick }, label);
}

export function stamp(name: StampName, small = false, extra = ""): HTMLElement {
  return h("span", { class: `stamp ${name.toLowerCase()}${small ? " sm" : ""} ${extra}`.trim() }, name);
}

export function field(label: string, input: HTMLElement, cls = ""): HTMLLabelElement {
  return h("label", { class: `field ${cls}`.trim() }, label, input);
}

export function eyebrow(...kids: Child[]): HTMLElement {
  return h("span", { class: "eyebrow" }, ...kids);
}

export function toast(kind: "ok" | "bad", title: string, message: string): void {
  const box = document.getElementById("notices");
  if (!box) return;
  const el = h("div", { class: `note${kind === "bad" ? " bad" : ""}`, role: kind === "bad" ? "alert" : "status" }, h("span", { class: "st" }), h("div", { class: "bd" }, h("span", { class: "k" }, title), h("span", { class: "m" }, message)));
  append(box, [el]);
  setTimeout(() => el.remove(), 6000);
}

export function errText(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

// ----------------------------------------------------------------- formatting

export function shortId(id: string): string {
  return `AIVW-${id.slice(-4).toUpperCase()}`;
}

export function relTime(iso: string | null, nowMs = Date.now()): string {
  if (!iso) return "no end date";
  const d = new Date(iso).getTime() - nowMs;
  const past = d < 0;
  const s = Math.abs(d) / 1000;
  if (!past && s < 60) return "now";
  const n = s < 3600 ? [Math.round(s / 60), "min"] : s < 2 * DAY ? [Math.round(s / 3600), "h"] : [Math.round(s / DAY), "days"];
  return past ? `${n[0]} ${n[1]} ago` : `in ${n[0]} ${n[1]}`;
}

export function fmtDate(iso: string | null): string {
  if (!iso) return "-";
  return new Date(iso).toLocaleDateString("en-GB", { day: "numeric", month: "short", year: "numeric" });
}

export function fmtDateTime(iso: string): string {
  const d = new Date(iso);
  const p = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`;
}

export function days(sec: number): string {
  return `${Math.round(sec / DAY)} days`;
}

export const PROVIDERS: { kind: string; label: string; hint: string }[] = [
  { kind: "git_lab", label: "GitLab", hint: "gitlab" },
  { kind: "aws_iam", label: "AWS IAM", hint: "aws" },
  { kind: "cloudflare", label: "Cloudflare", hint: "cloudflare" },
  { kind: "open_ai", label: "OpenAI", hint: "openai" },
  { kind: "command", label: "Command (script)", hint: "command" },
  { kind: "manual", label: "Manual (reminder only)", hint: "manual" },
];

export const providerLabel = (kind: string): string => PROVIDERS.find((p) => p.kind === kind)?.label ?? kind;

/** The stamp of a token. The daemon reports the status. */
export function stampOf(s: Summary): { name: StampName } {
  return { name: s.status.toUpperCase() as StampName };
}

export function slugify(name: string): string {
  return name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "") || "token";
}
