/** Add wizard and settings. */
import { h, replace } from "./dom.js";
import { call, isTauri, listMcpClients, openUrl, unpairMcpClient } from "./api.js";
import { S, PROVIDERS, btn, cta, errText, eyebrow, field, fmtDate, providerLabel, simpleBar, slugify, toast, topbar } from "./view.js";
import { opts, sinkView } from "./screens_tokens.js";
import type { Coffee, McpClient, Settings, Sink, Summary } from "./types.js";
import { DAY } from "./types.js";

type PlaceType = ".ENV" | "JSON" | "TOML" | "YAML" | "SSH FILE" | "ENV VARIABLE";
const PLACE_TYPES: PlaceType[] = [".ENV", "JSON", "TOML", "YAML", "SSH FILE", "ENV VARIABLE"];
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
  const draw = () => {
    err.textContent = "";
    const set = (k: string) => (e: Event) => { w.f[k] = (e.target as HTMLInputElement).value; };
    const val = (k: string) => w.f[k] ?? "";
    const inp = (k: string, label: string, ph = "", cls = "") => field(label, h("input", { value: val(k), placeholder: ph, class: cls, spellcheck: false, oninput: set(k) }));
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
      if (w.step === 3) {
        const grid: HTMLElement[] = [];
        switch (w.type) {
          case ".ENV": grid.push(inp("path", "FILE", "C:\\project\\.env"), inp("key", "VARIABLE", "GITLAB_TOKEN")); break;
          case "JSON": grid.push(inp("path", "FILE"), inp("pointer", "JSON POINTER", "/auth/token")); break;
          case "TOML": case "YAML": grid.push(inp("path", "FILE"), inp("keypath", "KEY PATH", "runners.token")); break;
          case "ENV VARIABLE": grid.push(inp("name", "VARIABLE NAME", "GITLAB_TOKEN")); break;
          case "SSH FILE": {
            const fm = h("select", { onchange: () => { w.f["format"] = fm.value; } }, ...["dotenv", "json", "toml", "yaml"].map((x) => h("option", { value: x, selected: (val("format") || "toml") === x }, x.toUpperCase())));
            grid.push(inp("host", "HOST", "build-01.example.org"), inp("user", "USER", "deploy"), inp("remote", "REMOTE FILE", "/etc/runner/config.toml"), inp("key", "KEY IN FILE", "runners.token"), inp("ssh", "SSH KEY"), field("FILE FORMAT", fm), inp("known", "HOST KEYS (KNOWN_HOSTS)", "", "dashed"));
          }
        }
        return h("div", {}, h("div", { class: "chips", role: "radiogroup", "aria-label": "Place type" }, ...PLACE_TYPES.map((t) => h("button", { type: "button", role: "radio", "aria-checked": w.type === t, class: `chip${w.type === t ? " on" : ""}`, onclick: () => { w.type = t; draw(); } }, t))), h("div", { class: "grid2" }, ...grid));
      }
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

    const readSink = (): Sink | string => {
      const v = (k: string) => val(k).trim();
      const need = (...ks: string[]) => ks.find((k) => !v(k));
      const miss = (ks: string[]) => { const m = need(...ks); return m ? `Fill in the ${m} field.` : null; };
      switch (w.type) {
        case ".ENV": return miss(["path", "key"]) ?? { type: "dotenv", path: v("path"), key: v("key") };
        case "JSON": return miss(["path", "pointer"]) ?? { type: "json", path: v("path"), pointer: v("pointer") };
        case "TOML": return miss(["path", "keypath"]) ?? { type: "toml", path: v("path"), key_path: v("keypath").split(".") };
        case "YAML": return miss(["path", "keypath"]) ?? { type: "yaml", path: v("path"), key_path: v("keypath").split(".") };
        case "ENV VARIABLE": return miss(["name"]) ?? { type: "env_var", name: v("name") };
        case "SSH FILE": {
          const m = miss(["host", "user", "remote", "key", "ssh", "known"]);
          if (m) return m;
          const fmt = v("format") || "toml";
          const format = fmt === "dotenv" ? { type: "dotenv", key: v("key") } : fmt === "json" ? { type: "json", pointer: v("key") } : { type: fmt, key_path: v("key").split(".") };
          return { type: "ssh", host: v("host"), port: 22, user: v("user"), identity_file: v("ssh"), known_hosts: v("known"), remote_path: v("remote"), format };
        }
      }
    };

    const addPlace = () => {
      const s = readSink();
      if (typeof s === "string") return void (err.textContent = s);
      w.sinks.push(s);
      w.f = { ssh: w.f["ssh"] ?? "", known: w.f["known"] ?? "" };
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

export async function settings(root: HTMLElement): Promise<void> {
  const cur = (await call({ type: "get_settings" })) as unknown as Settings;
  const coffee = (await call({ type: "coffee_status" })) as unknown as Coffee;
  S.coffee = coffee;
  const clients: McpClient[] = await listMcpClients().catch(() => []);
  const save = async (patch: Partial<Settings>) => {
    Object.assign(cur, patch);
    try {
      await call({ type: "set_settings", settings: { default_interval: cur.default_interval, coffee_reminder: cur.coffee_reminder, keychain_cache: cur.keychain_cache } });
    } catch (e) {
      toast("bad", "NOT SAVED", errText(e));
    }
  };
  const iv = h("select", { class: "sel", onchange: () => void save({ default_interval: Number(iv.value) * DAY }) }, ...opts([7, 14, 30, 90], Math.round(cur.default_interval / DAY), null).map(([v, l]) => h("option", { value: v, selected: v === String(Math.round(cur.default_interval / DAY)) }, l)));
  const pairBox = h("div", { class: "stack" });
  const pairName = h("input", { class: "inp", placeholder: "Claude Code" });
  const pairCaps = h("select", { class: "sel" }, h("option", { value: "use" }, "USE"), h("option", { value: "admin" }, "USE + POLICY"));
  const receipt = h("input", { placeholder: "aivw-receipt-\u2026", spellcheck: false });
  const year = new Date().getFullYear();
  const status = coffee.paid_year === year ? "Paid. Thank you." : "Not paid yet";
  const rcErr = h("div", { class: "err", role: "alert" });
  const applyReceipt = async () => {
    rcErr.textContent = "";
    try {
      await call({ type: "coffee_receipt", code: receipt.value.trim() });
      toast("ok", "RECEIPT APPLIED", "Thank you for the coffee.");
      await settings(root);
    } catch (e) {
      rcErr.textContent = errText(e);
    }
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
        h("span", { class: "label" }, "ROTATION"),
        h("div", { class: "rows" }, row("Default interval", "For each token without its own interval.", iv)),
        h("span", { class: "label" }, "SECURITY"),
        h("div", { class: "rows" }, row("Keychain cache", "Off: rotations wait until you unlock.", h("input", { type: "checkbox", class: "chk", checked: cur.keychain_cache, onchange: (e: Event) => void save({ keychain_cache: (e.target as HTMLInputElement).checked }) }))),
        h("span", { class: "label" }, "DEVICES"),
        h("div", { class: "rows" }, row(`${S.app?.status ? S.app.status.device_id.slice(-8).toUpperCase() : "this device"} \u00B7 this device`, null, h("span", { class: "stamp sm accent" }, `ROTATOR \u00B7 ${S.app?.status?.item_count ?? 0}`))),
        h("p", { class: "hint" }, "Other devices of the vault are not listed. The daemon has no request for them yet."),
        h("span", { class: "label" }, "MCP CLIENTS"),
        h(
          "div",
          { class: "rows" },
          ...(clients.length === 0 ? [h("div", { class: "empty" }, "No MCP client is paired.")] : []),
          ...clients.map((c) => row(`${c.name} \u00B7 paired ${fmtDate(c.created_at)}`, null, h("span", { class: "mono small" }, capsLabel(c.caps)), h("button", { class: "link danger", type: "button", onclick: async () => { if (!window.confirm(`Unpair ${c.name}?`)) return; try { await unpairMcpClient(c.id); reloadClients(); } catch (e) { toast("bad", "NOT UNPAIRED", errText(e)); } } }, "Unpair"))),
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
        cta("Buy a coffee", () => void openUrl(coffee.link || "https://aivory.net/coffee")),
        coffee.price_label ? h("span", { class: "mono small steel" }, coffee.price_label.toUpperCase()) : null,
        field("RECEIPT CODE", receipt, "lg"),
        btn("Apply receipt", () => void applyReceipt()),
        rcErr,
        h("label", { class: "check" }, h("input", { type: "checkbox", checked: cur.coffee_reminder, onchange: (e: Event) => void save({ coffee_reminder: (e.target as HTMLInputElement).checked }) }), "Show the weekly coffee note"),
      ),
    ),
  );
}
