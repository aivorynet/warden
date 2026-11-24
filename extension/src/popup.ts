// Popup. The token value stays in this module's memory and goes only to the native host.

import { collectPageText } from "./collect.js";
import { defaultLabel, detectTokens, maskPair, maskValue, type Candidate, type Provider } from "./detect.js";
import { ago, originOf, sendToHost, type InboxAdd } from "./host.js";
import type { Pending } from "./background.js";

const $ = <T extends HTMLElement>(id: string): T => document.getElementById(id) as T;

let origin: string | null = null;
let current: Candidate | null = null;

function setMsg(text: string, error = false): void {
  const m = $("msg");
  m.textContent = text;
  m.className = error ? "note err" : "note";
}

function mask(c: Candidate): string {
  return c.provider === "aws" && c.value.includes(":") ? maskPair(c.value) : maskValue(c.value);
}

function select(c: Candidate): void {
  current = c;
  $("masked").textContent = mask(c);
  ($("label") as HTMLInputElement).value = defaultLabel(c.provider);
  ($("provider") as HTMLSelectElement).value = c.provider satisfies Provider;
  $("form").hidden = false;
  document.querySelectorAll<HTMLElement>(".cand").forEach((b) => {
    b.setAttribute("aria-pressed", String(b.dataset.value === mask(c)));
  });
}

function showCandidates(cands: Candidate[]): void {
  const box = $("cands");
  box.replaceChildren();
  $("form").hidden = true;
  current = null;
  if (cands.length === 0) {
    box.hidden = true;
    setMsg("No token found. Select the value on the page and use the right-click menu.", true);
    return;
  }
  setMsg(`${cands.length} possible ${cands.length === 1 ? "token" : "tokens"} found.`);
  box.hidden = cands.length === 1;
  for (const c of cands) {
    const b = document.createElement("button");
    b.type = "button";
    b.className = "cand";
    b.dataset.value = mask(c);
    const v = document.createElement("span");
    v.className = "mono";
    v.textContent = mask(c);
    const k = document.createElement("span");
    k.textContent = c.kind;
    b.append(v, k);
    b.addEventListener("click", () => select(c));
    box.append(b);
  }
  if (cands.length === 1 && cands[0]) select(cands[0]);
}

async function scan(): Promise<void> {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  origin = originOf(tab?.url);
  if (!tab?.id || !origin) {
    setMsg("This page cannot be scanned.", true);
    return;
  }
  $("page").textContent = `${new URL(origin).hostname} · ${tab.title ?? ""}`.trim();
  try {
    const res = await chrome.scripting.executeScript({ target: { tabId: tab.id }, func: collectPageText });
    const texts = (res[0]?.result as string[] | undefined) ?? [];
    const seen = new Set<string>();
    const cands = texts
      .flatMap((t) => detectTokens(t, new URL(origin as string).hostname))
      .filter((c) => !seen.has(c.value) && seen.add(c.value));
    showCandidates(cands);
  } catch {
    setMsg("Warden cannot read this page.", true);
  }
}

async function send(ev: SubmitEvent): Promise<void> {
  ev.preventDefault();
  if (!current || !origin) return;
  const btn = $("send") as HTMLButtonElement;
  btn.disabled = true;
  const expires = ($("expires") as HTMLInputElement).value;
  const msg: InboxAdd = {
    type: "inbox_add",
    origin,
    label: ($("label") as HTMLInputElement).value.trim(),
    provider_hint: ($("provider") as HTMLSelectElement).value,
    value: current.value,
    ...(expires ? { expires_at: `${expires}T00:00:00Z` } : {}),
  };
  const reply = await sendToHost(msg);
  btn.disabled = false;
  if (reply.type === "inbox_added") {
    current = null;
    $("form").hidden = true;
    $("cands").replaceChildren();
    setMsg("Sent. Confirm it in the Warden app.");
    await refreshInbox();
  } else if (reply.type === "error") {
    setMsg(reply.message, true);
  }
}

async function refreshInbox(): Promise<void> {
  const list = $("inbox");
  const status = $("status");
  const reply = await sendToHost({ type: "inbox_list" });
  list.replaceChildren();
  if (reply.type === "inbox") {
    status.textContent = "connected";
    status.className = "status ok";
    if (reply.inbox.length === 0) {
      const p = document.createElement("p");
      p.className = "note";
      p.textContent = "Nothing is waiting.";
      list.append(p);
    }
    for (const e of reply.inbox) {
      const row = document.createElement("div");
      row.className = "row";
      const t = document.createElement("div");
      t.className = "t";
      const a = document.createElement("span");
      a.textContent = e.label;
      const b = document.createElement("span");
      b.textContent = `${e.origin.replace(/^https?:\/\//, "")} · ${ago(e.captured_at)}`;
      t.append(a, b);
      const st = document.createElement("span");
      st.className = "st";
      st.textContent = "confirm in app";
      row.append(t, st);
      list.append(row);
    }
    return;
  }
  const unreachable = reply.type === "error" && reply.code === "unavailable";
  status.textContent = unreachable ? "offline" : "connected";
  status.className = unreachable ? "status bad" : "status ok";
  const p = document.createElement("p");
  p.className = "note";
  p.textContent = unreachable ? "Start the Warden app to see the inbox." : "The inbox list is visible in the Warden app.";
  list.append(p);
}

async function init(): Promise<void> {
  $("scan").addEventListener("click", () => void scan());
  $("form").addEventListener("submit", (e) => void send(e as SubmitEvent));
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const o = originOf(tab?.url);
  $("page").textContent = o ? new URL(o).hostname : "this page cannot be captured";
  void refreshInbox();
  const p = (await chrome.runtime.sendMessage({ type: "take_pending" })) as Pending | null;
  if (p) {
    origin = p.origin;
    if (p.origin) $("page").textContent = `${new URL(p.origin).hostname} · selection`;
    if (p.error) setMsg(p.error, true);
    else showCandidates(p.candidates);
  } else {
    origin = o;
  }
}

void init();
