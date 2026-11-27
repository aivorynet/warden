/** Connect AI tools to the Warden MCP server: the first-run screen and the Settings list. */
import { h, replace } from "./dom.js";
import { mcpSetupConnect, mcpSetupList, mcpSetupRemove } from "./api.js";
import { S, btn, cta, errText, eyebrow, simpleBar, toast } from "./view.js";
import type { AiClient } from "./types.js";

const DIM = "opacity:.5";

function row(c: AiClient, ...right: (Node | string)[]): HTMLElement {
  return h(
    "div",
    { class: "row set", style: c.installed ? null : DIM },
    h("span", { class: "grow" }, h("span", { class: "a" }, c.name), h("span", { class: "b" }, c.installed ? c.config : "not found")),
    ...right,
  );
}

function report(results: { id: string; ok: boolean; message: string }[], names: Map<string, string>): void {
  for (const r of results) {
    const name = names.get(r.id) ?? r.id;
    if (r.ok) toast("ok", name.toUpperCase(), `${r.message}. Restart the tool to load it.`);
    else toast("bad", `${name.toUpperCase()} NOT CONNECTED`, r.message);
  }
}

/** One-time screen after the Emergency Kit: a checkbox for each installed tool. */
export async function connect(root: HTMLElement): Promise<void> {
  const clients = await mcpSetupList().catch(() => [] as AiClient[]);
  const finish = async () => {
    // Wait for the service start from the vault creation, then read the new state.
    await S.service;
    S.service = null;
    await S.refresh();
    S.go("tokens");
  };
  const picks = new Map<string, HTMLInputElement>();
  const rows = clients.map((c) => {
    if (!c.installed) return row(c, h("span", { class: "mono small steel" }, "NOT FOUND"));
    const box = h("input", { type: "checkbox", class: "chk", checked: !c.connected, disabled: c.connected });
    picks.set(c.id, box);
    return row(c, c.connected ? h("span", { class: "mono small steel" }, "CONNECTED") : box);
  });
  const go = cta("Connect", async () => {
    const ids = [...picks].filter(([, b]) => b.checked && !b.disabled).map(([id]) => id);
    if (ids.length === 0) return finish();
    go.disabled = true;
    try {
      report(await mcpSetupConnect(ids), new Map(clients.map((c) => [c.id, c.name])));
      finish();
    } catch (e) {
      toast("bad", "NOT CONNECTED", errText(e));
      go.disabled = false;
    }
  });
  replace(
    root,
    simpleBar(null),
    h(
      "div",
      { class: "pair" },
      h(
        "form",
        { onsubmit: (e: Event) => e.preventDefault() },
        eyebrow("AI TOOLS"),
        h("h1", { class: "disp" }, "Connect your AI tools"),
        h("p", { class: "lead" }, "Warden adds its MCP server to the tools you pick. Each tool gets its own pairing, so you can unpair one at any time. An agent never sees a secret value."),
        h("div", { class: "bar" }),
        h("div", { class: "rows" }, ...(rows.length ? rows : [h("div", { class: "empty" }, "No AI tool found.")])),
        h("div", { class: "btns" }, go, btn("Skip", finish)),
      ),
    ),
  );
}

/** The list for Settings > MCP clients: connect or remove each tool. */
export async function aiToolsList(reload: () => void): Promise<HTMLElement> {
  const clients = await mcpSetupList().catch(() => [] as AiClient[]);
  const names = new Map(clients.map((c) => [c.id, c.name]));
  return h(
    "div",
    { class: "rows" },
    ...clients.map((c) => {
      if (!c.installed) return row(c, h("span", { class: "mono small steel" }, "NOT FOUND"));
      if (c.connected) {
        return row(
          c,
          h("span", { class: "mono small" }, "CONNECTED"),
          h("button", { class: "link danger", type: "button", onclick: async () => {
            if (!window.confirm(`Remove Warden from ${c.name} and unpair it?`)) return;
            try {
              await mcpSetupRemove(c.id);
              reload();
            } catch (e) {
              toast("bad", "NOT REMOVED", errText(e));
            }
          } }, "Remove"),
        );
      }
      return row(c, btn("Connect", async () => {
        try {
          report(await mcpSetupConnect([c.id]), names);
          reload();
        } catch (e) {
          toast("bad", "NOT CONNECTED", errText(e));
        }
      }));
    }),
  );
}
