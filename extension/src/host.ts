// Messages to the native host `net.aivory.warden`. The value never goes to chrome.storage.

export const HOST_NAME = "net.aivory.warden";

export interface InboxAdd {
  type: "inbox_add";
  origin: string;
  label: string;
  provider_hint: string;
  expires_at?: string;
  value: string;
}

export interface InboxEntry {
  id: string;
  origin: string;
  label: string;
  captured_at: string;
}

export type HostReply =
  | { type: "inbox_added"; id: string }
  | { type: "inbox"; inbox: InboxEntry[] }
  | { type: "error"; code: string; message: string };

/** Return the origin of a browser-provided URL, or null for a page that we must not scan. */
export function originOf(url: string | undefined): string | null {
  if (!url) return null;
  try {
    const u = new URL(url);
    return u.protocol === "https:" || u.protocol === "http:" ? u.origin : null;
  } catch {
    return null;
  }
}

/** Send one message to the host and wait for the reply. */
export function sendToHost(msg: InboxAdd | { type: "inbox_list" }): Promise<HostReply> {
  return new Promise((resolve) => {
    chrome.runtime.sendNativeMessage(HOST_NAME, msg, (reply: HostReply | undefined) => {
      if (chrome.runtime.lastError || !reply) {
        resolve({ type: "error", code: "unavailable", message: "Warden app is not reachable." });
      } else {
        resolve(reply);
      }
    });
  });
}

/** Format "2 min ago" style text. */
export function ago(iso: string, now = Date.now()): string {
  const s = Math.max(0, Math.round((now - Date.parse(iso)) / 1000));
  if (Number.isNaN(s)) return "";
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  return `${Math.floor(s / 86400)} d ago`;
}
