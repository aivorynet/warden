import { mockApp, mockCall } from "./mock.js";
import type { AppState, Device, Kit, McpClient } from "./types.js";

type Invoke = (cmd: string, args?: Record<string, unknown>) => Promise<unknown>;
type Listen = (event: string, cb: (e: { payload: unknown }) => void) => Promise<() => void>;
declare global {
  interface Window {
    __TAURI__?: { core: { invoke: Invoke }; event: { listen: Listen } };
  }
}

/** True inside the Tauri shell. In a plain browser the UI runs on sample data. */
export const isTauri = typeof window.__TAURI__ !== "undefined";

export class ApiError extends Error {
  constructor(public code: string, message: string) {
    super(message);
  }
}

async function invoke<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  try {
    return (await window.__TAURI__!.core.invoke(cmd, args)) as T;
  } catch (e) {
    throw new ApiError("backend", typeof e === "string" ? e : String(e));
  }
}

/** Send a request to the daemon. An `error` response becomes an ApiError. */
export async function call<T = Record<string, any>>(req: Record<string, unknown>): Promise<T> {
  const resp = (isTauri ? await invoke<Record<string, any>>("daemon_call", { request: req }) : await mockCall(req)) as Record<string, any>;
  if (resp["type"] === "error") throw new ApiError(String(resp["code"]), String(resp["message"]));
  return resp as T;
}

export const appState = (): Promise<AppState> => (isTauri ? invoke("app_state") : mockApp());
export const signPledge = (): Promise<void> => (isTauri ? invoke("sign_pledge") : mockCall({ type: "sign_pledge", user: "preview" }).then(() => undefined));
export const initVault = (password: string, deviceName: string): Promise<Kit> =>
  isTauri ? invoke("init_vault", { password, deviceName }) : mockCall({ type: "init" }).then((r) => r["kit"] as Kit);
/** Whether the OS user check exists on this device, and its name for the button. */
export type QuickInfo = { available: boolean; label: string };
export const quickUnlockInfo = (): Promise<QuickInfo> => (isTauri ? invoke("quick_unlock_info") : Promise.resolve({ available: true, label: "Windows Hello" }));
/** Run the OS user check in the app, then unlock. A cancelled check throws an ApiError. */
export async function quickUnlock(): Promise<void> {
  const resp = (isTauri ? await invoke<Record<string, any>>("quick_unlock") : await mockCall({ type: "unlock_quick" })) as Record<string, any>;
  if (resp["type"] === "error") throw new ApiError(String(resp["code"]), String(resp["message"]));
}
export const startService =(): Promise<void> => (isTauri ? invoke("start_service") : Promise.resolve());
/** Paired clients that are not Full (CLI and desktop manage their own tokens). */
export const listMcpClients = async (): Promise<McpClient[]> =>
  (await call<{ clients: McpClient[] }>({ type: "list_clients" })).clients.filter((c) => !c.capabilities.includes("full"));
export const unpairMcpClient = async (id: string): Promise<void> => {
  await call({ type: "unpair", id });
};
export const listDevices = async (): Promise<Device[]> => (await call<{ devices: Device[] }>({ type: "list_devices" })).devices;
export const openUrl = (url: string): Promise<void> => {
  if (isTauri) return invoke("open_url", { url });
  window.open(url, "_blank", "noopener");
  return Promise.resolve();
};

export async function listen(event: string, cb: (payload: any) => void): Promise<void> {
  if (isTauri) await window.__TAURI__!.event.listen(event, (e) => cb(e.payload));
}
