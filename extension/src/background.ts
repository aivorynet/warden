// Service worker. Capture runs only after a click on the context menu entry.

import { detectSelection, type Candidate } from "./detect.js";
import { originOf } from "./host.js";

const MENU_ID = "save-selection";

export interface Pending {
  origin: string | null;
  candidates: Candidate[];
  error?: string;
}

// Held in memory only. The service worker never writes a value to chrome.storage.
let pending: Pending | null = null;

chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({ id: MENU_ID, title: "Save selection to Warden", contexts: ["selection"] });
});

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  if (info.menuItemId !== MENU_ID) return;
  // The origin comes from the browser (the tab URL), never from page content.
  const origin = originOf(tab?.url ?? info.pageUrl);
  if (!origin) {
    pending = { origin: null, candidates: [], error: "This page cannot be captured." };
  } else {
    const candidates = detectSelection(info.selectionText ?? "", new URL(origin).hostname);
    pending = { origin, candidates, error: candidates.length ? undefined : "The selection has no token." };
  }
  try {
    await chrome.action.openPopup();
  } catch {
    await chrome.action.setBadgeText({ text: "1" });
  }
});

chrome.runtime.onMessage.addListener((msg: { type?: string }, sender, sendResponse) => {
  if (sender.id !== chrome.runtime.id) return false;
  if (msg.type === "take_pending") {
    const p = pending;
    pending = null;
    void chrome.action.setBadgeText({ text: "" });
    sendResponse(p);
  }
  return false;
});
