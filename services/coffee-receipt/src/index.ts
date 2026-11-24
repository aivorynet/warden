/**
 * Coffee receipt Worker for Aivory Warden.
 *
 * GET /coffee/receipt?session_id=cs_...
 *   1. Fetch the Stripe Checkout session.
 *   2. Require payment_status == "paid".
 *   3. Sign {year, receipt_id, issued} with Ed25519 and return an HTML page.
 *
 * Code format (matches crates/warden-coffee verify_with_key):
 *   aivw-receipt-<base64url(payload JSON)>.<base64url(ed25519 signature over payload bytes)>
 */

export interface Env {
  STRIPE_SECRET_KEY: string;
  RECEIPT_SIGNING_KEY: string;
}

export interface ReceiptPayload {
  year: number;
  receipt_id: string;
  issued: string;
}

const RECEIPT_PREFIX = "aivw-receipt-";
const DEEP_LINK_BASE = "aivory-warden://receipt/";
const SESSION_ID_PATTERN = /^cs_[A-Za-z0-9_]+$/;

export function base64url(bytes: Uint8Array): string {
  let binary = "";
  for (const b of bytes) {
    binary += String.fromCharCode(b);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function base64ToBytes(b64: string): Uint8Array {
  const binary = atob(b64.trim());
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/** Import the Ed25519 private key from a base64 PKCS8 DER string. */
export function importSigningKey(pkcs8Base64: string): Promise<CryptoKey> {
  return crypto.subtle.importKey("pkcs8", base64ToBytes(pkcs8Base64), { name: "Ed25519" }, false, [
    "sign",
  ]);
}

/** Build the receipt code. The payload field order must match the Rust struct. */
export async function signReceipt(privateKey: CryptoKey, payload: ReceiptPayload): Promise<string> {
  const payloadBytes = new TextEncoder().encode(JSON.stringify(payload));
  const signature = new Uint8Array(await crypto.subtle.sign("Ed25519", privateKey, payloadBytes));
  return `${RECEIPT_PREFIX}${base64url(payloadBytes)}.${base64url(signature)}`;
}

/** Format a Date like chrono's default UTC serialization, e.g. 2026-11-24T10:00:00Z. */
function chronoTimestamp(date: Date): string {
  return date.toISOString().replace(/\.\d{3}Z$/, "Z");
}

interface StripeSession {
  id?: string;
  payment_status?: string;
  created?: number;
}

function textResponse(status: number, message: string): Response {
  return new Response(message, {
    status,
    headers: { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" },
  });
}

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function receiptPage(code: string): string {
  const safeCode = escapeHtml(code);
  const deepLink = escapeHtml(DEEP_LINK_BASE + code);
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Your Aivory Warden receipt</title>
<style>
  body { font-family: system-ui, sans-serif; margin: 0; padding: 16px; background: #fbfaf7; color: #1d1d1b; }
  main { max-width: 640px; margin: 40px auto; }
  code { display: block; word-break: break-all; background: #fff; border: 1px solid #d9d6cc; border-radius: 6px; padding: 12px; font-size: 14px; }
  button, a.button { display: inline-block; margin-top: 12px; padding: 10px 16px; border-radius: 6px; border: 0; background: #1d1d1b; color: #fff; font-size: 15px; text-decoration: none; cursor: pointer; }
  p { line-height: 1.5; }
</style>
</head>
<body>
<main>
  <h1>Thank you for the coffee</h1>
  <p>Paste this receipt code in Aivory Warden under Settings, or run <code style="display:inline;border:0;padding:0">awd coffee --receipt &lt;code&gt;</code>.</p>
  <code id="receipt">${safeCode}</code>
  <button id="copy" type="button">Copy code</button>
  <p><a class="button" href="${deepLink}">Open in Aivory Warden</a></p>
</main>
<script>
  document.getElementById("copy").addEventListener("click", function () {
    var text = document.getElementById("receipt").textContent;
    navigator.clipboard.writeText(text).then(function () {
      document.getElementById("copy").textContent = "Copied";
    });
  });
</script>
</body>
</html>`;
}

/**
 * Handle one request. `fetchImpl` lets tests replace the Stripe call.
 */
export async function handleRequest(
  request: Request,
  env: Env,
  fetchImpl: typeof fetch = fetch,
): Promise<Response> {
  const url = new URL(request.url);
  if (request.method !== "GET" || url.pathname !== "/coffee/receipt") {
    return textResponse(404, "Not found");
  }

  const sessionId = (url.searchParams.get("session_id") ?? "").trim();
  if (sessionId === "") {
    return textResponse(400, "Missing session_id");
  }
  if (!SESSION_ID_PATTERN.test(sessionId)) {
    return textResponse(400, "Invalid session_id");
  }

  const stripeResponse = await fetchImpl(
    `https://api.stripe.com/v1/checkout/sessions/${encodeURIComponent(sessionId)}`,
    { headers: { Authorization: `Bearer ${env.STRIPE_SECRET_KEY}` } },
  );
  if (stripeResponse.status === 404) {
    return textResponse(404, "Unknown session");
  }
  if (!stripeResponse.ok) {
    return textResponse(502, "Stripe request failed");
  }

  const session = (await stripeResponse.json()) as StripeSession;
  if (session.payment_status !== "paid") {
    return textResponse(402, "Payment is not complete");
  }
  if (session.id !== sessionId || typeof session.created !== "number") {
    return textResponse(502, "Unexpected Stripe response");
  }

  const created = new Date(session.created * 1000);
  const payload: ReceiptPayload = {
    year: created.getUTCFullYear(),
    receipt_id: sessionId,
    issued: chronoTimestamp(new Date()),
  };
  const key = await importSigningKey(env.RECEIPT_SIGNING_KEY);
  const code = await signReceipt(key, payload);

  return new Response(receiptPage(code), {
    status: 200,
    headers: {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store",
      "content-security-policy": "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'",
    },
  });
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    return handleRequest(request, env);
  },
} satisfies ExportedHandler<Env>;
