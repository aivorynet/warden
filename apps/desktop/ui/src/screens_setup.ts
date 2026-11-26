/** Add wizard and settings. */
import { h, replace } from "./dom.js";
import { appPrefs, call, isTauri, listDevices, removeService, setAppPrefs, setOpenAtLogin, startService, quickUnlockInfo, listMcpClients, openUrl, unpairMcpClient } from "./api.js";
import { placePicker, type PlaceType } from "./place.js";
import { S, PROVIDERS, btn, cta, errText, eyebrow, field, fmtDate, providerLabel, simpleBar, slugify, toast, topbar } from "./view.js";
import { buyCoffee } from "./coffee.js";
import { aiToolsList } from "./screens_connect.js";
import { opts, sinkView } from "./screens_tokens.js";
import type { AppPrefs, Coffee, Device, McpClient, Settings, Sink, Summary } from "./types.js";
import { DAY } from "./types.js";

const STEPS = ["THE PROVIDER", "THE TOKEN", "THE PLACES", "THE POLICY"];
const TITLES = ["Which provider", "The admin token", "Where it goes", "How often"];
const LEADS = [
  "Warden creates and rotates tokens at this provider.",
  "Warden keeps this admin token in the vault. It goes to the daemon and nowhere else.",
  "Warden writes the new value to each place after each rotation, then reads it back.",
  "Warden rotates on this schedule. Agents use the token through Warden and never see it.",
];

type W = {
  step: number; provider: string; name: string; token: string; ends: string; config: string; parent: string;
  sinks: Sink[]; type: PlaceType; f: Record<string, string>;
  auto: boolean; interval: string; lead: number; hosts: string;
};

const sample = (): Partial<W> =>
  isTauri ? {} : {
    provider: "git_lab", name: "gitlab-ci-deploy", token: "glpat-sample", ends: "2027-02-01", type: "SSH FILE",
    f: { host: "build-01.example.org", user: "deploy", remote: "/etc/runner/config.toml", key: "runners.token", ssh: "~/.ssh/id_ed25519", known: "~/.ssh/known_hosts", format: "toml" },
    sinks: [{ type: "dotenv", path: "C:\\java\\workspace\\shop\\.env", key: "GITLAB_TOKEN" }],
  };

export async function wizard(root: HTMLElement, startStep = 1): Promise<void> {
  const admins = (await call<{ items: Summary[] }>({ type: "list_items" })).items.filter((s) => s.kind.type === "admin" && s.provider !== "manual");
  const settings = await call({ type: "get_settings" });
  const w: W = {
    step: startStep, provider: "git_lab", name: "", token: "", ends: "", config: "", parent: "", sinks: [], type: ".ENV", f: {},
    auto: true, interval: "", lead: 3, hosts: "", ...(startStep > 1 ? sample() : {}),
  };
  const err = h("div", { class: "err", role: "alert" });
  const picker = placePicker({ type: w.type, f: w.f });
  const draw = () => {
    err.textContent = "";
    const body = (): HTMLElement => {
      if (w.step === 1) {
        return h("div", { class: "chips", role: "radiogroup", "aria-label": "Provider" }, ...PROVIDERS.map((p) => h("button", { type: "button", role: "radio", "aria-checked": w.provider === p.kind, class: `chip${w.provider === p.kind ? " on" : ""}`, onclick: () => { w.provider = p.kind; draw(); } }, p.label.toUpperCase())));
      }
      if (w.step === 2) {
        return h(
          "div",
          { class: "grid2" },
          field("NAME", h("input", { value: w.name, placeholder: "gitlab-ci-deploy", oninput: (e: Event) => { w.name = (e.target as HTMLInputElement).value; } })),
          field("END DATE", h("input", { type: "date", value: w.ends, oninput: (e: Event) => { w.ends = (e.target as HTMLInputElement).value; } })),
          field("ADMIN TOKEN OR KEY", h("input", { type: "password", autocomplete: "off", value: w.token, oninput: (e: Event) => { w.token = (e.target as HTMLInputElement).value; } })),
          field("DERIVED FROM (OPTIONAL)", (() => { const s = h("select", { onchange: () => { w.parent = s.value; } }, h("option", { value: "" }, "none: this is an admin token"), ...admins.map((a) => h("option", { value: a.id, selected: a.id === w.parent }, a.name))); return s; })()),
          field("PROVIDER CONFIG, JSON (OPTIONAL)", h("textarea", { placeholder: '{"base_url":"https://gitlab.example.org"}', spellcheck: false, value: w.config, oninput: (e: Event) => { w.config = (e.target as HTMLTextAreaElement).value; } })),
        );
      }
      if (w.step === 3) return picker.el;
      return h(
        "div",
        { class: "grid2" },
        h("label", { class: "check" }, h("input", { type: "checkbox", checked: w.auto, onchange: (e: Event) => { w.auto = (e.target as HTMLInputElement).checked; } }), "Rotate on its own"),
        h("span", {}),
        field("EVERY", (() => { const s = h("select", { onchange: () => { w.interval = s.value; } }, ...opts([7, 14, 30, 90], null, `default (${Math.round((settings["default_interval"] as number) / DAY)} d)`).map(([v, l]) => h("option", { value: v, selected: v === w.interval }, l))); return s; })()),
        field("BEFORE END DATE", (() => { const s = h("select", { onchange: () => { w.lead = Number(s.value); } }, ...opts([3, 7, 14], null, null).map(([v, l]) => h("option", { value: v, selected: v === String(w.lead) }, l))); return s; })()),
        field("MCP HOSTS (COMMA SEPARATED)", h("input", { value: w.hosts, placeholder: "gitlab.com", spellcheck: false, oninput: (e: Event) => { w.hosts = (e.target as HTMLInputElement).value; } })),
      );
    };

    const addPlace = () => {
      const s = picker.read();
      if (typeof s === "string") return void (err.textContent = s);
      w.sinks.push(s);
      picker.reset();
      draw();
    };

    const finish = async () => {
      let config: unknown = {};
      if (w.config.trim()) {
        try { config = JSON.parse(w.config); } catch { return void (err.textContent = "The provider config is not valid JSON."); }
      }
      const hosts = w.hosts.split(",").map((x) => x.trim()).filter(Boolean);
      try {
        await call({
          type: "add_item",
          draft: {
            name: w.name.trim(), slug: slugify(w.name), kind: w.parent ? { type: "derived", parent: w.parent } : { type: "admin" },
            provider: { kind: w.provider, config }, expires_at: w.ends ? new Date(`${w.ends}T00:00:00Z`).toISOString() : null,
            policy: { auto_rotate: w.auto && w.provider !== "manual", interval: w.interval ? Number(w.interval) * DAY : null, lead_time: w.lead * DAY, grace: DAY },
            sinks: w.sinks, mcp: { allowed_hosts: hosts, header_name: "Authorization", header_template: "Bearer {{secret}}", run_with_secret: false }, tags: [],
          },
          secret: w.token,
        });
        w.token = "";
        toast("ok", "ADDED", `${w.name} is in the vault.`);
        S.go("tokens");
      } catch (e) {
        err.textContent = errText(e);
      }
    };

    const next = () => {
      if (w.step === 2) {
        if (!w.name.trim()) return void (err.textContent = "Give the token a name.");
        if (!w.token) return void (err.textContent = "Enter the admin token.");
      }
      if (w.step === 4) return void finish();
      w.step += 1;
      draw();
    };

    replace(
      root,
      simpleBar(h("a", { href: "#tokens", class: "crumb" }, "CANCEL")),
      h(
        "div",
        { class: "page tight" },
        h(
          "main",
          { class: "col" },
          eyebrow(`NEW TOKEN \u00B7 STEP ${w.step} OF 4 \u00B7 ${STEPS[w.step - 1]}`),
          h("h1", { class: "disp" }, TITLES[w.step - 1]),
          h("p", { class: "lead" }, LEADS[w.step - 1]),
          h("div", { class: "bar" }),
          body(),
          err,
        ),
        h(
          "aside",
          { class: "side" },
          h("span", { class: "side-head" }, "SO FAR"),
          h("div", { class: "kv" }, h("span", {}, "Provider"), h("span", { class: "mono" }, providerLabel(w.provider))),
          h("div", { class: "kv" }, h("span", {}, "Admin token"), h("span", { class: "mono" }, w.token ? `entered${w.ends ? " \u00B7 ends " + w.ends : ""}` : "not yet")),
          h("div", { class: "kv" }, h("span", {}, "New tokens named"), h("span", { class: "mono" }, "aivw_\u2026")),
          h("span", { class: "side-head gap" }, `PLACES \u00B7 ${w.sinks.length}`),
          ...w.sinks.map((s, i) => { const v = sinkView(s); return h("div", { class: "row set" }, h("span", { class: "grow" }, h("span", { class: "a" }, v.main), h("span", { class: "b" }, v.sub)), h("button", { class: "link danger", type: "button", onclick: () => { w.sinks.splice(i, 1); draw(); } }, "Remove")); }),
          w.step === 3 ? btn("Add this place", addPlace) : null,
          w.step > 1 ? h("button", { class: "link", type: "button", onclick: () => { w.step -= 1; draw(); } }, "Back") : null,
          cta(w.step === 4 ? "Add token" : `Next: ${["token", "places", "policy"][w.step - 1]}`, next),
        ),
      ),
    );
  };
  draw();
}

// ----------------------------------------------------------------- settings

function row(title: string, sub: string | null, ...right: (Node | string)[]): HTMLElement {
  return h("div", { class: "row set" }, h("span", { class: "grow" }, h("span", { class: "a" }, title), sub ? h("span", { class: "b" }, sub) : null), ...right);
}

function chk(on: boolean, change: (v: boolean) => void, disabled = false): HTMLInputElement {
  return h("input", { type: "checkbox", class: "chk", checked: on, disabled, onchange: (e: Event) => change((e.target as HTMLInputElement).checked) });
}

/** Settings > App: tray icon, login entries, close button and the background service. */
function appRows(p: AppPrefs, reload: () => void): HTMLElement[] {
  const noTray = "Needs the tray icon.";
  const hiddenSub = h("span", { class: "b" });
  const closeSub = h("span", { class: "b" });
  const save = async (patch: Partial<AppPrefs>, box: HTMLInputElement) => {
    const next = { show_tray: p.show_tray, start_hidden: p.start_hidden, close_to_tray: p.close_to_tray, ...patch };
    try {
      await setAppPrefs(next);
      Object.assign(p, next);
    } catch (e) {
      box.checked = !box.checked;
      toast("bad", "NOT SAVED", errText(e));
    }
    sync();
  };
  const hidden = chk(p.start_hidden, (v) => void save({ start_hidden: v }, hidden));
  const close = chk(p.close_to_tray, (v) => void save({ close_to_tray: v }, close));
  const tray = chk(p.show_tray, (v) => void save({ show_tray: v }, tray));
  const sync = () => {
    hidden.disabled = !p.show_tray;
    close.disabled = !p.show_tray;
    hiddenSub.textContent = p.show_tray ? "At login, the window stays closed. Click the tray icon to open it." : noTray;
    closeSub.textContent = p.show_tray ? "The close button hides the window. Use the tray menu to quit." : noTray;
  };
  sync();
  const login = chk(p.open_at_login, async (on) => {
    try {
      await setOpenAtLogin(on);
    } catch (e) {
      login.checked = !on;
      toast("bad", "NOT SAVED", errText(e));
    }
  });
  const service = async () => {
    try {
      if (p.service_installed) {
        if (!window.confirm("Turn off background rotation? Warden stops the service now, and tokens do not rotate until you turn it on again.")) return;
        await removeService();
        await S.refresh();
      } else {
        await startService();
      }
    } catch (e) {
      toast("bad", "NOT CHANGED", errText(e));
    }
    reload();
  };
  const sub = (title: string, b: HTMLElement, right: Node) => h("div", { class: "row set" }, h("span", { class: "grow" }, h("span", { class: "a" }, title), b), right);
  return [
    row("Background rotation", p.service_installed ? "On. The service starts at login and rotates tokens when this window is closed." : "Off. Tokens rotate only while a daemon runs.", btn(p.service_installed ? "Turn off" : "Turn on", () => void service())),
    row("Show the tray icon", "Off: the close button quits the app. Rotation keeps running.", tray),
    row("Open Warden at login", "Starts the app when you sign in to this computer.", login),
    sub("Start in the tray", hiddenSub, hidden),
    sub("Close to the tray", closeSub, close),
  ];
}

export async function settings(root: HTMLElement): Promise<void> {
  const cur = (await call({ type: "get_settings" })) as unknown as Settings;
  const coffee = (await call({ type: "coffee_status" })) as unknown as Coffee;
  S.coffee = coffee;
  const clients: McpClient[] = await listMcpClients().catch(() => []);
  const devices: Device[] = await listDevices().catch(() => []);
  const aiTools = await aiToolsList(() => void settings(root));
  const save = async (patch: Partial<Settings>) => {
    Object.assign(cur, patch);
    try {
      if (!cur.keychain_cache) cur.quick_unlock = false;
      await call({ type: "set_settings", settings: { default_interval: cur.default_interval, coffee_reminder: cur.coffee_reminder, keychain_cache: cur.keychain_cache, quick_unlock: cur.quick_unlock } });
      if (patch.keychain_cache !== undefined) await settings(root);
    } catch (e) {
      toast("bad", "NOT SAVED", errText(e));
    }
  };
  const quick = await quickUnlockInfo().catch(() => ({ available: false, label: "" }));
  const app = await appPrefs().catch(() => null);
  const appSection = app ? appRows(app, () => void settings(root)) : [h("div", { class: "empty" }, "The app settings are not available.")];
  const lockForget = async () => {
    try {
      await call({ type: "lock_forget" });
      await S.refresh();
      S.go("unlock");
    } catch (e) {
      toast("bad", "NOT LOCKED", errText(e));
    }
  };
  const iv = h("select", { class: "sel", onchange: () => void save({ default_interval: Number(iv.value) * DAY }) }, ...opts([7, 14, 30, 90], Math.round(cur.default_interval / DAY), null).map(([v, l]) => h("option", { value: v, selected: v === String(Math.round(cur.default_interval / DAY)) }, l)));
  const pairBox = h("div", { class: "stack" });
  const pairName = h("input", { class: "inp", placeholder: "Claude Code" });
  const pairCaps = h("select", { class: "sel" }, h("option", { value: "use" }, "USE"), h("option", { value: "admin" }, "USE + POLICY"));
  const year = new Date().getFullYear();
  const status = coffee.paid_year === year ? "Paid. Thank you." : "Not paid yet";
  const payFlow = async () => {
    if (await buyCoffee()) await settings(root);
  };
  const capsLabel = (c: string[]) => (c.includes("mcp_admin") ? "USE + POLICY" : "USE");
  const reloadClients = () => void settings(root);

  replace(
    root,
    topbar("settings"),
    h(
      "div",
      { class: "page tight" },
      h(
        "main",
        { class: "col" },
        h("h1", { class: "disp" }, "Settings"),
        h("div", { class: "bar" }),
        h("span", { class: "label" }, "APP"),
        h("div", { class: "rows" }, ...appSection),
        h("span", { class: "label" }, "ROTATION"),
        h("div", { class: "rows" }, row("Default interval", "For each token without its own interval.", iv)),
        h("span", { class: "label" }, "SECURITY"),
        h("div", { class: "rows" }, row("Keychain cache", "Off: rotations wait until you unlock.", h("input", { type: "checkbox", class: "chk", checked: cur.keychain_cache, onchange: (e: Event) => void save({ keychain_cache: (e.target as HTMLInputElement).checked }) })),
          ...(quick.available && cur.keychain_cache
            ? [row(`Unlock with ${quick.label}`, "Lock keeps the key on this device, and your fingerprint, face or PIN unlocks it. It stops a person at your keyboard. It does not stop malware that runs as you.", h("input", { type: "checkbox", class: "chk", checked: cur.quick_unlock, onchange: (e: Event) => void save({ quick_unlock: (e.target as HTMLInputElement).checked }) }))]
            : []),
          row("Lock and forget", "Locks the vault and removes the cached key. The next unlock needs your password.", btn("Lock and forget", () => void lockForget()))),
        h("span", { class: "label" }, "DEVICES"),
        h(
          "div",
          { class: "rows" },
          ...(devices.length === 0 ? [h("div", { class: "empty" }, "No device is registered.")] : []),
          ...devices.map((d) => row(`${d.name}${d.id === S.app?.status?.device_id ? " \u00B7 this device" : ""}`, d.last_seen ? `last change ${fmtDate(d.last_seen)}` : "no change yet", h("span", { class: `stamp sm${d.is_rotator_for > 0 ? " accent" : ""}` }, `ROTATOR \u00B7 ${d.is_rotator_for}`))),
        ),
        h("span", { class: "label" }, "MCP CLIENTS"),
        h("span", { class: "hint" }, "Connect your AI tools. Warden adds its MCP server and pairs each tool by itself."),
        aiTools,
        h(
          "div",
          { class: "rows" },
          ...(clients.length === 0 ? [h("div", { class: "empty" }, "No MCP client is paired.")] : []),
          ...clients.map((c) => row(`${c.name} \u00B7 paired ${fmtDate(c.paired_at)}`, null, h("span", { class: "mono small" }, capsLabel(c.capabilities)), h("button", { class: "link danger", type: "button", onclick: async () => { if (!window.confirm(`Unpair ${c.name}?`)) return; try { await unpairMcpClient(c.id); reloadClients(); } catch (e) { toast("bad", "NOT UNPAIRED", errText(e)); } } }, "Unpair"))),
        ),
        h("div", { class: "grid2" }, field("PAIR A NEW CLIENT", pairName), field("ACCESS", pairCaps)),
        btn("Pair client", async () => {
          if (!pairName.value.trim()) return;
          try {
            const caps = pairCaps.value === "admin" ? ["mcp_use", "mcp_admin"] : ["mcp_use"];
            const r = await call({ type: "pair", name: pairName.value.trim(), capabilities: caps });
            replace(pairBox, h("div", { class: "paired" }, h("span", { class: "mono small steel" }, "PAIRING TOKEN, SHOWN ONCE"), h("span", { class: "v" }, String(r["token"])), h("span", { class: "hint" }, "Give it to the client as the env var WARDEN_TOKEN.")));
            pairName.value = "";
          } catch (e) {
            toast("bad", "NOT PAIRED", errText(e));
          }
        }),
        pairBox,
      ),
      h(
        "aside",
        { class: "side" },
        h("span", { class: "side-head" }, `COFFEE \u00B7 ${year}`),
        h("span", { class: "disp mid" }, status),
        coffee.ticket ? h("span", { class: "mono small steel" }, `TICKET ${coffee.ticket}`) : null,
        h("p", { class: "lead small" }, "Warden is free and open source. One coffee a year stops the weekly note. Rotation works the same either way."),
        cta("Buy a coffee", () => void payFlow()),
        coffee.price_label ? h("span", { class: "mono small steel" }, coffee.price_label.toUpperCase()) : null,
        h("label", { class: "check" }, h("input", { type: "checkbox", checked: cur.coffee_reminder, onchange: (e: Event) => void save({ coffee_reminder: (e.target as HTMLInputElement).checked }) }), "Show the weekly coffee note"),
      ),
    ),
  );
}
