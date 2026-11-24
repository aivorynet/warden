/** The form that describes one place (sink). The wizard and the token detail use it. */
import { h, replace } from "./dom.js";
import { field } from "./view.js";
import type { Sink } from "./types.js";

export type PlaceType = ".ENV" | "JSON" | "TOML" | "YAML" | "SSH FILE" | "ENV VARIABLE";
export const PLACE_TYPES: PlaceType[] = [".ENV", "JSON", "TOML", "YAML", "SSH FILE", "ENV VARIABLE"];

export type PlacePicker = {
  el: HTMLElement;
  /** Return the sink, or a message when a field is empty. */
  read: () => Sink | string;
  /** Clear the fields. The SSH key and known_hosts stay. */
  reset: () => void;
};

export function placePicker(init: { type?: PlaceType; f?: Record<string, string> } = {}): PlacePicker {
  let type: PlaceType = init.type ?? ".ENV";
  let f: Record<string, string> = { ...(init.f ?? {}) };
  const el = h("div", {});
  const val = (k: string) => f[k] ?? "";
  const inp = (k: string, label: string, ph = "", cls = "") =>
    field(label, h("input", { value: val(k), placeholder: ph, class: cls, spellcheck: false, oninput: (e: Event) => { f[k] = (e.target as HTMLInputElement).value; } }));

  const draw = () => {
    const grid: HTMLElement[] = [];
    switch (type) {
      case ".ENV": grid.push(inp("path", "FILE", "C:\\project\\.env"), inp("key", "VARIABLE", "GITLAB_TOKEN")); break;
      case "JSON": grid.push(inp("path", "FILE"), inp("pointer", "JSON POINTER", "/auth/token")); break;
      case "TOML": case "YAML": grid.push(inp("path", "FILE"), inp("keypath", "KEY PATH", "runners.token")); break;
      case "ENV VARIABLE": grid.push(inp("name", "VARIABLE NAME", "GITLAB_TOKEN")); break;
      case "SSH FILE": {
        const fm = h("select", { onchange: () => { f["format"] = fm.value; } }, ...["dotenv", "json", "toml", "yaml"].map((x) => h("option", { value: x, selected: (val("format") || "toml") === x }, x.toUpperCase())));
        grid.push(inp("host", "HOST", "build-01.example.org"), inp("user", "USER", "deploy"), inp("remote", "REMOTE FILE", "/etc/runner/config.toml"), inp("key", "KEY IN FILE", "runners.token"), inp("ssh", "SSH KEY"), field("FILE FORMAT", fm), inp("known", "HOST KEYS (KNOWN_HOSTS)", "", "dashed"));
      }
    }
    replace(
      el,
      h("div", { class: "chips", role: "radiogroup", "aria-label": "Place type" }, ...PLACE_TYPES.map((t) => h("button", { type: "button", role: "radio", "aria-checked": type === t, class: `chip${type === t ? " on" : ""}`, onclick: () => { type = t; draw(); } }, t))),
      h("div", { class: "grid2" }, ...grid),
    );
  };

  const read = (): Sink | string => {
    const v = (k: string) => val(k).trim();
    const miss = (ks: string[]) => { const m = ks.find((k) => !v(k)); return m ? `Fill in the ${m} field.` : null; };
    switch (type) {
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

  draw();
  return { el, read, reset: () => { f = { ssh: f["ssh"] ?? "", known: f["known"] ?? "" }; draw(); } };
}
