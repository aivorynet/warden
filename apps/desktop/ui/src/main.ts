import { appState, isTauri, listen, call } from "./api.js";
import { S, errText, toast } from "./view.js";
import * as start from "./screens_start.js";
import * as tok from "./screens_tokens.js";
import * as setup from "./screens_setup.js";
import { connect } from "./screens_connect.js";
import type { Kit } from "./types.js";

const root = document.getElementById("app") as HTMLElement;
const SAMPLE_KIT: Kit = { secret_key: "A3-7KQ2M-9XW4T-PR8D6-F2HNC-5JV9Q", vault: "0193f2c4-8e1a-7b3d-9a52-4c6e1f0d2b77", device: "PAUL-LAPTOP", ticket: "AIVW-2026-6909" };

function route(): string {
  return location.hash.replace(/^#/, "");
}

S.go = (r: string) => {
  if (route() === r) void render();
  else location.hash = `#${r}`;
};

S.refresh = async () => {
  S.app = await appState();
  if (S.app.daemon_up) {
    try {
      S.coffee = (await call({ type: "coffee_status" })) as never;
    } catch { /* locked or old daemon */ }
    S.inbox = S.app.status?.inbox_count ?? 0;
  }
};

/** In the Tauri shell the state decides the screen. In the browser the hash decides. */
function gate(r: string): string | null {
  const a = S.app;
  if (!a) return null;
  // The Emergency Kit shows the Secret Key once. Never route away from it.
  if (r === "kit" && S.kit) return null;
  // First run: no vault means no client token, so the daemon cannot answer yet.
  if (!a.vault_exists) return S.firstRunPledged ? "init" : "pledge";
  // The AI tools screen writes the pairing file itself, so it needs no daemon.
  if (r === "connect") return null;
  if (!a.daemon_up) return "down";
  if (S.coffee && !S.coffee.pledged) return "pledge";
  if (a.status?.locked) return "unlock";
  if (["pledge", "init", "unlock", "down"].includes(r)) return "tokens";
  return null;
}

let seq = 0;
async function render(): Promise<void> {
  const mine = ++seq;
  let r = route() || "tokens";
  try {
    if (!S.app) await S.refresh();
    if (isTauri) {
      const forced = r === "kit" && S.kit ? null : gate(r);
      if (forced && forced !== r) {
        r = forced;
        history.replaceState(null, "", `#${r}`);
      }
    }
    if (mine !== seq) return;
    const [name, arg] = r.split("/") as [string, string | undefined];
    switch (name) {
      case "pledge": return start.pledge(root);
      case "unlock": return start.unlock(root, isTauri ? undefined : SAMPLE_KIT);
      case "init": return start.init(root);
      case "kit": if (!isTauri && !S.kit) S.kit = SAMPLE_KIT; return start.kit(root);
      case "connect": return await connect(root);
      case "down": return start.down(root);
      case "detail": {
        let id = arg;
        if (!id && !isTauri) id = ((await call({ type: "list_items" })) as { items: { id: string }[] }).items[1]?.id;
        return await tok.detail(root, id ?? "");
      }
      case "wizard": return await setup.wizard(root, Number(arg ?? 1) || 1);
      case "settings": return await setup.settings(root);
      case "inbox": return await tok.inbox(root);
      case "audit": return await tok.auditScreen(root);
      default: return await tok.tokens(root);
    }
  } catch (e) {
    if (mine === seq) toast("bad", "ERROR", errText(e));
  }
}

window.addEventListener("hashchange", () => void render());

async function boot(): Promise<void> {
  await S.refresh().catch(() => undefined);
  if (isTauri) {
    await listen("navigate", (to: string) => S.go(to));
    await listen("state-changed", () => void S.refresh().then(render));
    setInterval(() => {
      if (["", "tokens", "inbox"].includes(route())) void S.refresh().then(render);
    }, 20000);
  }
  await render();
}

void boot();
